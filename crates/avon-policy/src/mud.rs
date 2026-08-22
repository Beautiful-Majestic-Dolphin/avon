//! RFC 8520 (MUD) import.
//!
//! A MUD file says what a device is *supposed* to talk to; AVON turns that into
//! policies attached to a device class. Two decisions matter for safety: an ACE
//! whose destination cannot be resolved is skipped rather than widened into an
//! allow-any, and a terminal deny is always appended because MUD's model is
//! "anything not listed is forbidden".

use ipnet::IpNet;
use serde_json::Value;
use uuid::Uuid;

use crate::spec::{Effect, L4Rule, PolicySpec, PortSet, Protocol, Selector};

#[derive(Debug, thiserror::Error)]
pub enum MudError {
    #[error("mud document is not valid json: {0}")]
    Json(String),
    #[error("unsupported mud construct: {0}")]
    Unsupported(String),
    #[error("mud document contains no from-device access lists")]
    Empty,
}

pub struct MudImport {
    pub policies: Vec<(String, PolicySpec)>,
    pub skipped: Vec<String>,
}

fn protocol_of(number: Option<u64>) -> Protocol {
    match number {
        Some(6) => Protocol::Tcp,
        Some(17) => Protocol::Udp,
        Some(1) | Some(58) => Protocol::Icmp,
        _ => Protocol::Any,
    }
}

fn ports_of(matches: &Value, key: &str) -> Option<PortSet> {
    let port = matches.get(key)?.get("destination-port")?;
    if let Some(p) = port.get("port").and_then(Value::as_u64) {
        return PortSet::parse(&p.to_string()).ok();
    }
    let lower = port.get("lower-port").and_then(Value::as_u64)?;
    let upper = port
        .get("upper-port")
        .and_then(Value::as_u64)
        .unwrap_or(lower);
    PortSet::parse(&format!("{lower}-{upper}")).ok()
}

pub fn import(
    mud_json: &str,
    device_class: Uuid,
    resolve: &dyn Fn(&str) -> Vec<IpNet>,
) -> Result<MudImport, MudError> {
    let doc: Value = serde_json::from_str(mud_json).map_err(|e| MudError::Json(e.to_string()))?;
    let mud = doc.get("ietf-mud:mud").ok_or(MudError::Empty)?;

    let from_lists: Vec<String> = mud
        .pointer("/from-device-policy/access-lists/access-list")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|l| l.get("name").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if from_lists.is_empty() {
        return Err(MudError::Empty);
    }
    let to_lists: Vec<String> = mud
        .pointer("/to-device-policy/access-lists/access-list")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|l| l.get("name").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let mut policies = Vec::new();
    let mut skipped = Vec::new();
    for name in &to_lists {
        skipped.push(format!(
            "to-device access list {name}: inbound policy is enforced by the upstream router, not imported"
        ));
    }

    let acls = doc
        .pointer("/ietf-access-control-list:acls/acl")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for acl in acls {
        let acl_name = acl
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if !from_lists.contains(&acl_name) {
            continue;
        }
        let aces = acl
            .pointer("/aces/ace")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for ace in aces {
            let ace_name = ace
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("ace")
                .to_string();
            let matches = ace.get("matches").cloned().unwrap_or(Value::Null);
            let action = ace
                .pointer("/actions/forwarding")
                .and_then(Value::as_str)
                .unwrap_or("drop");
            let effect = match action {
                "accept" => Effect::Allow,
                "drop" => Effect::Deny,
                other => {
                    skipped.push(format!(
                        "{acl_name}/{ace_name}: unsupported forwarding action {other}"
                    ));
                    continue;
                }
            };

            // Destination: an explicit network, or a DNS name the caller resolves.
            let mut cidrs: Vec<IpNet> = Vec::new();
            for family in ["ipv4", "ipv6"] {
                if let Some(net) = matches
                    .pointer(&format!("/{family}/destination-{family}-network"))
                    .and_then(Value::as_str)
                {
                    if let Ok(parsed) = net.parse::<IpNet>() {
                        cidrs.push(parsed);
                    }
                }
                if let Some(name) = matches
                    .pointer(&format!("/{family}/ietf-acldns:dst-dnsname"))
                    .and_then(Value::as_str)
                {
                    let resolved = resolve(name);
                    if resolved.is_empty() {
                        skipped.push(format!("{acl_name}/{ace_name}: could not resolve {name}"));
                    }
                    cidrs.extend(resolved);
                }
            }
            if cidrs.is_empty() {
                skipped.push(format!(
                    "{acl_name}/{ace_name}: no usable destination, skipped rather than widened"
                ));
                continue;
            }

            let protocol = protocol_of(
                matches
                    .pointer("/ipv4/protocol")
                    .and_then(Value::as_u64)
                    .or_else(|| matches.pointer("/ipv6/protocol").and_then(Value::as_u64)),
            );
            let ports = ports_of(&matches, "tcp")
                .or_else(|| ports_of(&matches, "udp"))
                .unwrap_or_default();
            let l4 = match protocol {
                Protocol::Any => Vec::new(),
                p => vec![L4Rule { protocol: p, ports }],
            };

            policies.push((
                format!("mud-{acl_name}-{ace_name}"),
                PolicySpec {
                    version: 2,
                    effect,
                    priority: 100,
                    source: Selector {
                        device_classes: vec![device_class],
                        ..Default::default()
                    },
                    destination: Selector {
                        cidrs,
                        ..Default::default()
                    },
                    l4,
                    conditions: Default::default(),
                },
            ));
        }
    }

    // MUD is an allow-list: everything the manufacturer did not describe is denied.
    policies.push((
        "mud-default-deny".to_string(),
        PolicySpec {
            version: 2,
            effect: Effect::Deny,
            priority: 9000,
            source: Selector {
                device_classes: vec![device_class],
                ..Default::default()
            },
            destination: Selector {
                any: true,
                ..Default::default()
            },
            l4: Vec::new(),
            conditions: Default::default(),
        },
    ));

    Ok(MudImport { policies, skipped })
}
