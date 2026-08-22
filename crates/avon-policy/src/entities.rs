use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use cedar_policy::{Entities, Entity, EntityUid, RestrictedExpression, Schema};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::compile::CompileError;
use crate::spec::PolicySpec;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SnapshotData {
    pub tenant_id: Uuid,
    pub version: u64,
    pub generated_at: i64,
    pub pods: Vec<PodEntity>,
    pub device_classes: Vec<Uuid>,
    pub devices: Vec<DeviceEntity>,
    pub policies: Vec<PolicyEntry>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PodEntity {
    pub id: Uuid,
    pub parent: Option<Uuid>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DeviceAttrs {
    pub status: String,
    pub class: Option<Uuid>,
    pub firewall_enabled: Option<bool>,
    pub disk_encrypted: Option<bool>,
    pub screen_lock_enabled: Option<bool>,
    pub os_version: Option<String>,
    pub last_update_unix: Option<i64>,
    pub attestation: String,
    pub risk_score: u8,
    pub overlay_v4: Option<Ipv4Addr>,
    pub overlay_v6: Option<Ipv6Addr>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DeviceEntity {
    pub id: Uuid,
    pub pods: Vec<Uuid>,
    pub attrs: DeviceAttrs,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PolicyEntry {
    pub id: Uuid,
    pub name: String,
    pub spec: PolicySpec,
}

const CEDAR_SCHEMA: &str = r#"
namespace Avon {
  entity Pod in [Pod];
  entity DeviceClass;
  entity Device in [Pod, DeviceClass] = {
    status: String,
    attestation: String,
    risk_score: Long,
    firewall_enabled?: Bool,
    disk_encrypted?: Bool,
    screen_lock_enabled?: Bool,
    os_version_major?: Long,
    os_version_minor?: Long,
    hours_since_update?: Long,
  };
  entity Network;
  action connect appliesTo {
    principal: [Device],
    resource: [Device, Network],
    context: {
      protocol: String,
      dst_port: Long,
      dst_ip: ipaddr,
      admission: Bool
    }
  };
}
"#;

pub(crate) fn cedar_schema() -> Result<Schema, CompileError> {
    Schema::from_str(CEDAR_SCHEMA).map_err(|e| CompileError::Schema(e.to_string()))
}

fn uid(ty: &str, id: Uuid) -> Result<EntityUid, CompileError> {
    format!("Avon::{ty}::\"{id}\"")
        .parse()
        .map_err(|_| CompileError::Uid)
}

fn restricted(s: &str) -> Result<RestrictedExpression, CompileError> {
    RestrictedExpression::from_str(s).map_err(|e| CompileError::Cedar(e.to_string()))
}

pub fn build_entities(data: &SnapshotData, now: i64) -> Result<Entities, CompileError> {
    let schema = cedar_schema()?;
    let mut entities: Vec<Entity> = Vec::new();

    // Pods
    for pod in &data.pods {
        let parents: HashSet<EntityUid> = pod
            .parent
            .iter()
            .filter_map(|p| uid("Pod", *p).ok())
            .collect();
        let e = Entity::new(uid("Pod", pod.id)?, HashMap::new(), parents)
            .map_err(|e| CompileError::Cedar(e.to_string()))?;
        entities.push(e);
    }

    // DeviceClasses
    for class in &data.device_classes {
        let e = Entity::new(uid("DeviceClass", *class)?, HashMap::new(), HashSet::new())
            .map_err(|e| CompileError::Cedar(e.to_string()))?;
        entities.push(e);
    }

    // Network::"external"
    let network: EntityUid = "Avon::Network::\"external\""
        .parse()
        .map_err(|_| CompileError::Uid)?;
    entities.push(
        Entity::new(network, HashMap::new(), HashSet::new())
            .map_err(|e| CompileError::Cedar(e.to_string()))?,
    );

    // Devices
    for dev in &data.devices {
        let mut parents: HashSet<EntityUid> = HashSet::new();
        for p in &dev.pods {
            parents.insert(uid("Pod", *p)?);
        }
        if let Some(class) = dev.attrs.class {
            parents.insert(uid("DeviceClass", class)?);
        }

        let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
        attrs.insert(
            "status".into(),
            restricted(&format!("\"{}\"", dev.attrs.status.escape_default()))?,
        );
        attrs.insert(
            "attestation".into(),
            restricted(&format!("\"{}\"", dev.attrs.attestation.escape_default()))?,
        );
        attrs.insert(
            "risk_score".into(),
            restricted(&dev.attrs.risk_score.to_string())?,
        );

        if let Some(v) = dev.attrs.firewall_enabled {
            attrs.insert("firewall_enabled".into(), restricted(&v.to_string())?);
        }
        if let Some(v) = dev.attrs.disk_encrypted {
            attrs.insert("disk_encrypted".into(), restricted(&v.to_string())?);
        }
        if let Some(v) = dev.attrs.screen_lock_enabled {
            attrs.insert("screen_lock_enabled".into(), restricted(&v.to_string())?);
        }
        if let Some(ref os) = dev.attrs.os_version {
            let (major, minor) = parse_os_version(os);
            attrs.insert("os_version_major".into(), restricted(&major.to_string())?);
            attrs.insert("os_version_minor".into(), restricted(&minor.to_string())?);
        }
        if let Some(ts) = dev.attrs.last_update_unix {
            let hours = ((now - ts) / 3600).max(0);
            attrs.insert("hours_since_update".into(), restricted(&hours.to_string())?);
        }

        let e = Entity::new(uid("Device", dev.id)?, attrs, parents)
            .map_err(|e| CompileError::Cedar(e.to_string()))?;
        entities.push(e);
    }

    Entities::from_entities(entities, Some(&schema)).map_err(|e| CompileError::Cedar(e.to_string()))
}

fn parse_os_version(s: &str) -> (i64, i64) {
    let mut parts = s.split('.');
    let major = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    (major, minor)
}
