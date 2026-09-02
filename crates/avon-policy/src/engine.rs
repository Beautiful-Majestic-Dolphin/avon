use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, Request};
use serde::Serialize;
use uuid::Uuid;

use crate::compile::{compile, CompileError, Compiled};
use crate::entities::{build_entities, DeviceAttrs, SnapshotData};
use crate::spec::Protocol;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Destination {
    Device(Uuid),
    Ip(IpAddr),
}

#[derive(Clone, Debug)]
pub struct DecisionRequest {
    pub device: Uuid,
    pub destination: Destination,
    pub dst_ip: IpAddr,
    pub protocol: Protocol,
    pub dst_port: u16,
    pub admission: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DecisionResult {
    pub allow: bool,
    pub policy_ids: Vec<Uuid>,
    pub reason: String,
    pub snapshot_version: u64,
}

struct Loaded {
    data: SnapshotData,
    compiled: Compiled,
    entities: Entities,
    #[allow(dead_code)]
    compiled_at: i64,
}

pub struct Engine {
    tenant: Uuid,
    inner: ArcSwap<Option<Loaded>>,
    authorizer: Authorizer,
}

fn deny(reason: impl Into<String>, version: u64) -> DecisionResult {
    DecisionResult {
        allow: false,
        policy_ids: vec![],
        reason: reason.into(),
        snapshot_version: version,
    }
}

impl Engine {
    pub fn empty(tenant: Uuid) -> Self {
        Self {
            tenant,
            inner: ArcSwap::from_pointee(None),
            authorizer: Authorizer::new(),
        }
    }

    pub fn version(&self) -> u64 {
        self.inner
            .load()
            .as_ref()
            .as_ref()
            .map(|l| l.data.version)
            .unwrap_or(0)
    }

    /// Whether this tenant has authored any policy at all. A tenant with none
    /// is treated as unconfigured, not as deny-everything: enforcement points
    /// are permissive until the first policy exists (the same stance session
    /// admission takes in the control plane), and zero-trust default-deny
    /// begins the moment a tenant authors a policy.
    pub fn has_policies(&self) -> bool {
        self.inner
            .load()
            .as_ref()
            .as_ref()
            .map(|l| !l.data.policies.is_empty())
            .unwrap_or(false)
    }

    pub fn load(&self, data: SnapshotData, now: i64) -> Result<(), CompileError> {
        if data.tenant_id != self.tenant {
            return Err(CompileError::Tenant);
        }
        let compiled = compile(&data, now)?;
        let entities = build_entities(&data, now)?;
        self.inner.store(Arc::new(Some(Loaded {
            data,
            compiled,
            entities,
            compiled_at: now,
        })));
        metrics::counter!("avon_policy_snapshots_loaded_total").increment(1);
        Ok(())
    }

    pub fn patch_device(&self, id: Uuid, attrs: DeviceAttrs, now: i64) -> Result<(), CompileError> {
        let guard = self.inner.load();
        let Some(loaded) = guard.as_ref().as_ref() else {
            return Err(CompileError::NotLoaded);
        };
        let mut data = loaded.data.clone();
        match data.devices.iter_mut().find(|d| d.id == id) {
            Some(d) => d.attrs = attrs,
            None => data.devices.push(crate::entities::DeviceEntity {
                id,
                pods: vec![],
                attrs,
            }),
        }
        let entities = build_entities(&data, now)?;
        let compiled = compile(&data, now)?;
        self.inner.store(Arc::new(Some(Loaded {
            data,
            compiled,
            entities,
            compiled_at: now,
        })));
        Ok(())
    }

    pub fn needs_recompile(&self, now: i64) -> bool {
        self.inner
            .load()
            .as_ref()
            .as_ref()
            .and_then(|l| l.compiled.next_window_change)
            .is_some_and(|t| now >= t)
    }

    pub fn recompile(&self, now: i64) -> Result<(), CompileError> {
        let guard = self.inner.load();
        let Some(loaded) = guard.as_ref().as_ref() else {
            return Ok(());
        };
        self.load(loaded.data.clone(), now)
    }

    fn request(&self, req: &DecisionRequest) -> Result<Request, CompileError> {
        let principal: EntityUid = format!("Avon::Device::\"{}\"", req.device)
            .parse()
            .map_err(|_| CompileError::Uid)?;
        let resource: EntityUid = match &req.destination {
            Destination::Device(d) => format!("Avon::Device::\"{d}\"")
                .parse()
                .map_err(|_| CompileError::Uid)?,
            Destination::Ip(_) => "Avon::Network::\"external\""
                .parse()
                .map_err(|_| CompileError::Uid)?,
        };
        let proto = match req.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => "icmp",
            Protocol::Any => "any",
        };
        let ctx = Context::from_json_value(
            serde_json::json!({
                "protocol": proto, "dst_port": req.dst_port as i64,
                "dst_ip": { "__extn": { "fn": "ip", "arg": req.dst_ip.to_string() } },
                "admission": req.admission,
            }),
            None,
        )
        .map_err(|e| CompileError::Cedar(e.to_string()))?;
        Request::new(
            principal,
            "Avon::Action::\"connect\""
                .parse()
                .map_err(|_| CompileError::Uid)?,
            resource,
            ctx,
            None,
        )
        .map_err(|e| CompileError::Cedar(e.to_string()))
    }

    pub fn decide(&self, req: &DecisionRequest) -> DecisionResult {
        let guard = self.inner.load();
        let Some(loaded) = guard.as_ref().as_ref() else {
            return deny("no policy snapshot loaded", 0);
        };
        let version = loaded.data.version;
        let Some(device) = loaded.data.devices.iter().find(|d| d.id == req.device) else {
            return deny("unknown device", version);
        };
        if device.attrs.status != "active" {
            return deny(format!("device status {}", device.attrs.status), version);
        }
        let request = match self.request(req) {
            Ok(r) => r,
            Err(e) => return deny(format!("request build failed: {e}"), version),
        };
        let response =
            self.authorizer
                .is_authorized(&request, &loaded.compiled.policies, &loaded.entities);
        let ids: Vec<Uuid> = response
            .diagnostics()
            .reason()
            .filter_map(|p| p.to_string().parse().ok())
            .collect();
        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(|e| e.to_string())
            .collect();
        match response.decision() {
            Decision::Allow if errors.is_empty() => DecisionResult {
                allow: true,
                policy_ids: ids,
                reason: "permit".into(),
                snapshot_version: version,
            },
            Decision::Allow => deny(format!("evaluation errors: {}", errors.join("; ")), version),
            Decision::Deny if ids.is_empty() => deny("no matching permit", version),
            Decision::Deny => DecisionResult {
                allow: false,
                policy_ids: ids,
                reason: "forbid".into(),
                snapshot_version: version,
            },
        }
    }

    pub fn explain(&self, req: &DecisionRequest) -> String {
        let d = self.decide(req);
        serde_json::to_string_pretty(&d).unwrap_or_else(|_| d.reason.clone())
    }
}
