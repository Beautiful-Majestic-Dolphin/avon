use std::str::FromStr;

use cedar_policy::{PolicySet, Schema};
use uuid::Uuid;

use crate::entities::{PolicyEntry, SnapshotData};
use crate::spec::{AttestationRequirement, Effect, Protocol, SpecError};
use crate::time::{next_window_change, window_active};

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("cedar schema: {0}")]
    Schema(String),
    #[error("cedar: {0}")]
    Cedar(String),
    #[error("invalid entity uid")]
    Uid,
    #[error("unknown tenant")]
    Tenant,
    #[error("no snapshot loaded")]
    NotLoaded,
    #[error("policy validation: {0}")]
    Spec(#[from] SpecError),
}

pub struct Compiled {
    pub policies: PolicySet,
    pub schema: Schema,
    pub active_ids: Vec<Uuid>,
    pub next_window_change: Option<i64>,
}

pub fn cedar_source(entry: &PolicyEntry) -> Result<String, CompileError> {
    entry.spec.validate()?;
    let effect = match entry.spec.effect {
        Effect::Allow => "permit",
        Effect::Deny => "forbid",
    };
    let id = entry.id;
    let annotation = format!("@id(\"{id}\")\n");

    // Source expression
    let source_expr = if entry.spec.source.any {
        "true".to_string()
    } else {
        let mut parts = Vec::new();
        if !entry.spec.source.pods.is_empty() {
            let list = entry
                .spec
                .source
                .pods
                .iter()
                .map(|u| format!("Avon::Pod::\"{u}\""))
                .collect::<Vec<_>>()
                .join(", ");
            parts.push(format!("principal in [{list}]"));
        }
        if !entry.spec.source.device_classes.is_empty() {
            let list = entry
                .spec
                .source
                .device_classes
                .iter()
                .map(|u| format!("Avon::DeviceClass::\"{u}\""))
                .collect::<Vec<_>>()
                .join(", ");
            parts.push(format!("principal in [{list}]"));
        }
        if !entry.spec.source.devices.is_empty() {
            let list = entry
                .spec
                .source
                .devices
                .iter()
                .map(|u| format!("Avon::Device::\"{u}\""))
                .collect::<Vec<_>>()
                .join(", ");
            parts.push(format!("principal in [{list}]"));
        }
        if parts.is_empty() {
            // Should have been caught by validate, but fallback to true
            "true".to_string()
        } else if parts.len() == 1 {
            parts.remove(0)
        } else {
            format!("({})", parts.join(" || "))
        }
    };

    // Destination expression
    let dest_expr = if entry.spec.destination.any {
        "true".to_string()
    } else {
        let mut ors = Vec::new();
        if !entry.spec.destination.pods.is_empty() {
            let list = entry
                .spec
                .destination
                .pods
                .iter()
                .map(|u| format!("Avon::Pod::\"{u}\""))
                .collect::<Vec<_>>()
                .join(", ");
            ors.push(format!("resource in [{list}]"));
        }
        if !entry.spec.destination.devices.is_empty() {
            let list = entry
                .spec
                .destination
                .devices
                .iter()
                .map(|u| format!("Avon::Device::\"{u}\""))
                .collect::<Vec<_>>()
                .join(", ");
            ors.push(format!("resource in [{list}]"));
        }
        if !entry.spec.destination.cidrs.is_empty() {
            // For CIDRs: (resource == Network::"external" && (ip in range...)) || (resource is Device && ...)
            // But plan says: (resource == Avon::Network::"external" && (context.dst_ip.isInRange...)) plus also device dest via overlay
            let mut cidr_checks: Vec<String> = entry
                .spec
                .destination
                .cidrs
                .iter()
                .map(|c| format!("context.dst_ip.isInRange(ip(\"{c}\"))"))
                .collect();
            // cidr_checks join with ||
            let cidr_or = if cidr_checks.len() == 1 {
                cidr_checks.remove(0)
            } else {
                format!("({})", cidr_checks.join(" || "))
            };
            // Network external part
            ors.push(format!(
                "(resource == Avon::Network::\"external\" && {cidr_or})"
            ));
            // Also allow device destinations by overlay address: (resource is Avon::Device && (context.dst_ip.isInRange...))
            // Reuse same cidr_or for device overlay
            let device_cidr_or = entry
                .spec
                .destination
                .cidrs
                .iter()
                .map(|c| format!("context.dst_ip.isInRange(ip(\"{c}\"))"))
                .collect::<Vec<_>>()
                .join(" || ");
            let device_cidr_expr = if entry.spec.destination.cidrs.len() == 1 {
                device_cidr_or
            } else {
                format!("({device_cidr_or})")
            };
            ors.push(format!("(resource is Avon::Device && {device_cidr_expr})"));
        }
        if ors.is_empty() {
            "true".to_string()
        } else if ors.len() == 1 {
            ors.remove(0)
        } else {
            format!("({})", ors.join(" || "))
        }
    };

    // L4 expression
    let l4_expr = if entry.spec.l4.is_empty() {
        "true".to_string()
    } else {
        let mut rule_exprs = Vec::new();
        for rule in &entry.spec.l4 {
            let proto = match rule.protocol {
                Protocol::Tcp => "tcp",
                Protocol::Udp => "udp",
                Protocol::Icmp => "icmp",
                Protocol::Any => "any",
            };
            let base: String = match rule.protocol {
                Protocol::Any => "true".to_string(),
                Protocol::Icmp => "context.protocol == \"icmp\"".to_string(),
                Protocol::Tcp | Protocol::Udp => {
                    if rule.ports.is_all() {
                        format!("context.protocol == \"{proto}\"")
                    } else {
                        let port_checks: Vec<String> = rule
                            .ports
                            .0
                            .iter()
                            .map(|r| {
                                if r.start() == r.end() {
                                    format!("context.dst_port == {}", r.start())
                                } else {
                                    format!(
                                        "(context.dst_port >= {} && context.dst_port <= {})",
                                        r.start(),
                                        r.end()
                                    )
                                }
                            })
                            .collect();
                        let port_expr = if port_checks.len() == 1 {
                            port_checks[0].clone()
                        } else {
                            format!("({})", port_checks.join(" || "))
                        };
                        format!("(context.protocol == \"{proto}\" && {port_expr})")
                    }
                }
            };
            // admission matches any l4 rule regardless of port
            rule_exprs.push(format!("(context.admission || {base})"));
        }
        if rule_exprs.len() == 1 {
            rule_exprs.remove(0)
        } else {
            format!("({})", rule_exprs.join(" || "))
        }
    };

    // Conditions expression
    let mut cond_parts: Vec<String> = Vec::new();
    if let Some(posture) = &entry.spec.conditions.posture {
        if let Some(v) = posture.firewall_enabled {
            cond_parts.push(format!(
                "(principal has firewall_enabled && principal.firewall_enabled == {v})"
            ));
        }
        if let Some(v) = posture.disk_encrypted {
            cond_parts.push(format!(
                "(principal has disk_encrypted && principal.disk_encrypted == {v})"
            ));
        }
        if let Some(v) = posture.screen_lock_enabled {
            cond_parts.push(format!(
                "(principal has screen_lock_enabled && principal.screen_lock_enabled == {v})"
            ));
        }
        if let Some(ref os) = posture.min_os_version {
            let (major, minor) = parse_os_version(os);
            cond_parts.push(format!(
                "(principal has os_version_major && (principal.os_version_major > {major} || (principal.os_version_major == {major} && principal.os_version_minor >= {minor})))"
            ));
        }
        if let Some(max_hours) = posture.max_hours_since_update {
            cond_parts.push(format!(
                "(principal has hours_since_update && principal.hours_since_update <= {max_hours})"
            ));
        }
    }
    if let Some(att) = &entry.spec.conditions.attestation {
        if *att == AttestationRequirement::Verified {
            cond_parts.push("principal.attestation == \"verified\"".to_string());
        }
    }
    if let Some(max_risk) = entry.spec.conditions.max_risk_score {
        cond_parts.push(format!("principal.risk_score <= {max_risk}"));
    }
    // Note: time_window is handled at compile-time (filtering), not as Cedar `when` clause.
    // But for completeness, if we included it we'd add time check; instead compile() skips inactive policies.

    let cond_expr = if cond_parts.is_empty() {
        "true".to_string()
    } else {
        cond_parts.join(" && ")
    };

    let when_expr = format!("({source_expr}) && ({dest_expr}) && ({l4_expr}) && ({cond_expr})");

    let src = format!(
        "{annotation}{effect}(principal, action == Avon::Action::\"connect\", resource) when {{ {when_expr} }};"
    );
    Ok(src)
}

fn parse_os_version(s: &str) -> (i64, i64) {
    let mut parts = s.split('.');
    let major = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    (major, minor)
}

pub fn compile(data: &SnapshotData, now: i64) -> Result<Compiled, CompileError> {
    let schema = crate::entities::cedar_schema()?;
    let mut policy_texts: Vec<String> = Vec::new();
    let mut active_ids: Vec<Uuid> = Vec::new();
    let mut next_change: Option<i64> = None;

    for entry in &data.policies {
        // Validate spec
        entry.spec.validate()?;

        // Time window handling: skip inactive policies, compute next change
        if let Some(tw) = &entry.spec.conditions.time_window {
            let active = window_active(tw, now)?;
            let nc = next_window_change(tw, now)?;
            next_change = Some(match next_change {
                Some(existing) => existing.min(nc),
                None => nc,
            });
            if !active {
                continue;
            }
        }

        let src = cedar_source(entry)?;
        policy_texts.push(src);
        active_ids.push(entry.id);
    }

    let combined = policy_texts.join("\n");
    let policies = if combined.trim().is_empty() {
        PolicySet::new()
    } else {
        PolicySet::from_str(&combined).map_err(|e| CompileError::Cedar(e.to_string()))?
    };

    Ok(Compiled {
        policies,
        schema,
        active_ids,
        next_window_change: next_change,
    })
}
