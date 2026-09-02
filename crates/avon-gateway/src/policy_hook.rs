//! Where flow authorization plugs in. Phase 3 ships `AllowAll`; phase 4
//! replaces it with the Cedar engine without touching the data plane.

use std::net::IpAddr;
use std::sync::Arc;

use avon_common::ids::{DeviceId, SessionId, TenantId};
use avon_policy::compile::CompileError;
use avon_policy::engine::{DecisionRequest, Destination, Engine};
use avon_policy::entities::{DeviceAttrs, SnapshotData};
use avon_policy::spec::Protocol;
use avon_protocol::v2::{DecisionRecord, Uuid as PbUuid};
use dashmap::DashMap;
use tokio::sync::mpsc;

#[derive(Clone, Debug)]
pub struct Flow {
    pub session: SessionId,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub dst_port: Option<u16>,
}

#[derive(Clone, Copy, Debug)]
pub struct Decision {
    pub allow: bool,
    pub reason: &'static str,
}

pub trait FlowPolicy: Send + Sync {
    fn allow(&self, flow: &Flow) -> Decision;
}

/// Phase-3 default. Replaced by the Cedar engine in phase 4.
pub struct AllowAll;

impl FlowPolicy for AllowAll {
    fn allow(&self, _flow: &Flow) -> Decision {
        Decision {
            allow: true,
            reason: "allow-all",
        }
    }
}

pub struct FlowContext {
    pub session: SessionId,
    pub tenant: TenantId,
    pub device: DeviceId,
    pub destination_device: Option<DeviceId>,
    pub flow: Flow,
}

pub struct CedarFlowPolicy {
    engines: DashMap<TenantId, Arc<Engine>>,
    cache: DashMap<FlowKey, CachedDecision>,
    log: mpsc::Sender<DecisionRecord>,
}

#[derive(Hash, PartialEq, Eq, Clone)]
struct FlowKey {
    session: SessionId,
    dst: IpAddr,
    protocol: u8,
    dst_port: u16,
}

struct CachedDecision {
    allow: bool,
    #[allow(dead_code)]
    reason: Arc<str>,
    version: u64,
}

impl CedarFlowPolicy {
    pub fn new(log: mpsc::Sender<DecisionRecord>) -> Self {
        Self {
            engines: DashMap::new(),
            cache: DashMap::new(),
            log,
        }
    }

    pub fn apply_snapshot(&self, tenant: TenantId, data: SnapshotData) -> Result<(), CompileError> {
        let engine = self
            .engines
            .entry(tenant)
            .or_insert_with(|| Arc::new(Engine::empty(tenant.as_uuid())))
            .clone();
        engine.load(data, chrono::Utc::now().timestamp())?;
        self.cache.clear();
        Ok(())
    }

    pub fn patch_device(&self, tenant: TenantId, device: DeviceId, attrs: DeviceAttrs) {
        if let Some(engine) = self.engines.get(&tenant) {
            let _ = engine.patch_device(device.as_uuid(), attrs, chrono::Utc::now().timestamp());
        }
        self.cache.clear();
    }

    pub fn version(&self, tenant: TenantId) -> u64 {
        self.engines.get(&tenant).map(|e| e.version()).unwrap_or(0)
    }

    pub fn allow(&self, ctx: &FlowContext) -> Decision {
        // A tenant with no engine, or an engine that has loaded a snapshot
        // carrying no policies, is unconfigured rather than deny-everything.
        // The data plane is permissive until the first policy is authored,
        // matching the control plane's session admission; the moment a tenant
        // has any policy, this falls through to default-deny with explicit
        // permits.
        let Some(engine) = self.engines.get(&ctx.tenant).map(|e| e.clone()) else {
            return Decision {
                allow: true,
                reason: "no-policy-permissive",
            };
        };
        if !engine.has_policies() {
            return Decision {
                allow: true,
                reason: "no-policy-permissive",
            };
        }
        let version = engine.version();
        let key = FlowKey {
            session: ctx.session,
            dst: ctx.flow.dst,
            protocol: ctx.flow.protocol,
            dst_port: ctx.flow.dst_port.unwrap_or(0),
        };
        if let Some(cached) = self.cache.get(&key) {
            if cached.version == version {
                return Decision {
                    allow: cached.allow,
                    reason: "cached",
                };
            }
        }

        let request = DecisionRequest {
            device: ctx.device.as_uuid(),
            destination: match ctx.destination_device {
                Some(d) => Destination::Device(d.as_uuid()),
                None => Destination::Ip(ctx.flow.dst),
            },
            dst_ip: ctx.flow.dst,
            protocol: match ctx.flow.protocol {
                6 => Protocol::Tcp,
                17 => Protocol::Udp,
                1 | 58 => Protocol::Icmp,
                _ => Protocol::Any,
            },
            dst_port: ctx.flow.dst_port.unwrap_or(0),
            admission: false,
        };
        let result = engine.decide(&request);
        metrics::counter!("avon_policy_decisions_total", "effect" => if result.allow { "allow" } else { "deny" }).increment(1);
        self.cache.insert(
            key,
            CachedDecision {
                allow: result.allow,
                reason: Arc::from(result.reason.as_str()),
                version,
            },
        );

        let _ = self.log.try_send(DecisionRecord {
            tenant_id: Some(PbUuid {
                value: ctx.tenant.as_bytes().to_vec(),
            }),
            device_id: Some(PbUuid {
                value: ctx.device.as_bytes().to_vec(),
            }),
            session_id: ctx.session.to_vec(),
            destination: format!(
                "{}:{}/{}",
                ctx.flow.dst,
                request.dst_port,
                protocol_name(ctx.flow.protocol)
            ),
            allow: result.allow,
            policy_ids: result.policy_ids.iter().map(|u| u.to_string()).collect(),
            reason: result.reason.clone(),
            decided_at_unix: chrono::Utc::now().timestamp(),
        });

        Decision {
            allow: result.allow,
            reason: if result.allow { "permit" } else { "deny" },
        }
    }
}

fn protocol_name(p: u8) -> &'static str {
    match p {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        58 => "icmpv6",
        _ => "other",
    }
}

impl FlowPolicy for CedarFlowPolicy {
    fn allow(&self, flow: &Flow) -> Decision {
        // Flow alone lacks tenant/device context; deny. Dataplane should use FlowContext.
        let _ = flow;
        Decision {
            allow: false,
            reason: "no context",
        }
    }
}

/// Version, addresses, protocol and — for TCP/UDP — the destination port.
/// Returns `None` for anything that is not a well-formed IPv4/IPv6 packet, so
/// the caller drops it rather than guessing.
pub fn parse_flow(session: SessionId, packet: &[u8]) -> Option<Flow> {
    let version = packet.first()? >> 4;
    match version {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let ihl = (packet[0] & 0x0f) as usize * 4;
            if ihl < 20 || packet.len() < ihl {
                return None;
            }
            let protocol = packet[9];
            let src = IpAddr::from([packet[12], packet[13], packet[14], packet[15]]);
            let dst = IpAddr::from([packet[16], packet[17], packet[18], packet[19]]);
            let dst_port = match protocol {
                6 | 17 if packet.len() >= ihl + 4 => {
                    Some(u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]))
                }
                _ => None,
            };
            Some(Flow {
                session,
                src,
                dst,
                protocol,
                dst_port,
            })
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            // Next-header only; extension headers are not walked, so a flow
            // carrying them is treated as portless rather than misparsed.
            let protocol = packet[6];
            let mut s = [0u8; 16];
            s.copy_from_slice(&packet[8..24]);
            let mut d = [0u8; 16];
            d.copy_from_slice(&packet[24..40]);
            let dst_port = match protocol {
                6 | 17 if packet.len() >= 44 => Some(u16::from_be_bytes([packet[42], packet[43]])),
                _ => None,
            };
            Some(Flow {
                session,
                src: IpAddr::from(s),
                dst: IpAddr::from(d),
                protocol,
                dst_port,
            })
        }
        _ => None,
    }
}
