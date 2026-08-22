#![allow(clippy::unwrap_used, clippy::panic)]
use std::str::FromStr;

use avon_policy::compile::{cedar_source, compile};
use avon_policy::entities::{
    build_entities, DeviceAttrs, DeviceEntity, PodEntity, PolicyEntry, SnapshotData,
};
use avon_policy::spec::PolicySpec;
use cedar_policy::{Authorizer, Context, Decision, EntityUid, Request};
use uuid::Uuid;

fn uid(ty: &str, id: Uuid) -> EntityUid {
    format!("Avon::{ty}::\"{id}\"").parse().unwrap()
}

fn data() -> (SnapshotData, Uuid, Uuid, Uuid) {
    let pod_eng = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
    let pod_all = Uuid::new_v4();
    let dev = Uuid::new_v4();
    let spec: PolicySpec = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/tests/fixtures/allow_ssh.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let data = SnapshotData {
        tenant_id: Uuid::new_v4(),
        version: 1,
        generated_at: 0,
        pods: vec![
            PodEntity {
                id: pod_all,
                parent: None,
            },
            PodEntity {
                id: pod_eng,
                parent: Some(pod_all),
            },
        ],
        device_classes: vec![],
        devices: vec![DeviceEntity {
            id: dev,
            pods: vec![pod_eng],
            attrs: DeviceAttrs {
                status: "active".into(),
                firewall_enabled: Some(true),
                attestation: "none".into(),
                ..Default::default()
            },
        }],
        policies: vec![PolicyEntry {
            id: Uuid::new_v4(),
            name: "allow-ssh".into(),
            spec,
        }],
    };
    (data, pod_eng, pod_all, dev)
}

fn request(dev: Uuid, dst_ip: &str, proto: &str, port: i64) -> Request {
    let ctx = Context::from_json_value(
        serde_json::json!({ "protocol": proto, "dst_port": port, "dst_ip": { "__extn": { "fn": "ip", "arg": dst_ip } }, "admission": false }),
        None,
    )
    .unwrap();
    Request::new(
        uid("Device", dev),
        "Avon::Action::\"connect\"".parse().unwrap(),
        "Avon::Network::\"external\"".parse().unwrap(),
        ctx,
        None,
    )
    .unwrap()
}

#[test]
fn compiled_policy_allows_ssh_to_cidr_for_pod_member_with_firewall() {
    let (data, _, _, dev) = data();
    let compiled = compile(&data, 0).unwrap();
    let entities = build_entities(&data, 0).unwrap();
    let auth = Authorizer::new();
    assert_eq!(
        auth.is_authorized(
            &request(dev, "10.20.0.5", "tcp", 22),
            &compiled.policies,
            &entities
        )
        .decision(),
        Decision::Allow
    );
    assert_eq!(
        auth.is_authorized(
            &request(dev, "10.20.0.5", "tcp", 23),
            &compiled.policies,
            &entities
        )
        .decision(),
        Decision::Deny
    );
    assert_eq!(
        auth.is_authorized(
            &request(dev, "10.21.0.5", "tcp", 22),
            &compiled.policies,
            &entities
        )
        .decision(),
        Decision::Deny
    );
    assert_eq!(
        auth.is_authorized(
            &request(dev, "10.20.0.5", "icmp", 0),
            &compiled.policies,
            &entities
        )
        .decision(),
        Decision::Allow
    );
}

#[test]
fn posture_failure_denies_and_hierarchy_applies_to_parent_pod_policies() {
    let (mut data, _pod_eng, pod_all, dev) = data();
    data.devices[0].attrs.firewall_enabled = Some(false);
    let compiled = compile(&data, 0).unwrap();
    let entities = build_entities(&data, 0).unwrap();
    assert_eq!(
        Authorizer::new()
            .is_authorized(
                &request(dev, "10.20.0.5", "tcp", 22),
                &compiled.policies,
                &entities
            )
            .decision(),
        Decision::Deny
    );

    // A policy on the parent pod covers the child pod's members.
    data.devices[0].attrs.firewall_enabled = Some(true);
    data.policies[0].spec.source.pods = vec![pod_all];
    let compiled = compile(&data, 0).unwrap();
    let entities = build_entities(&data, 0).unwrap();
    assert_eq!(
        Authorizer::new()
            .is_authorized(
                &request(dev, "10.20.0.5", "tcp", 22),
                &compiled.policies,
                &entities
            )
            .decision(),
        Decision::Allow
    );
}

#[test]
fn deny_overrides_allow() {
    let (mut data, _, _, dev) = data();
    let deny: PolicySpec =
        serde_json::from_str(r#"{"version":2,"effect":"deny","source":{"any":true},"destination":{"cidrs":["10.20.0.0/24"]}}"#).unwrap();
    data.policies.push(PolicyEntry {
        id: Uuid::new_v4(),
        name: "deny-subnet".into(),
        spec: deny,
    });
    let compiled = compile(&data, 0).unwrap();
    let entities = build_entities(&data, 0).unwrap();
    let auth = Authorizer::new();
    assert_eq!(
        auth.is_authorized(
            &request(dev, "10.20.0.5", "tcp", 22),
            &compiled.policies,
            &entities
        )
        .decision(),
        Decision::Deny
    );
    assert_eq!(
        auth.is_authorized(
            &request(dev, "10.20.1.5", "tcp", 22),
            &compiled.policies,
            &entities
        )
        .decision(),
        Decision::Allow
    );
}

#[test]
fn time_window_policies_are_only_active_inside_the_window() {
    let (mut data, _, _, _) = data();
    let tw: PolicySpec = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/tests/fixtures/time_window.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    data.policies = vec![PolicyEntry {
        id: Uuid::new_v4(),
        name: "hours".into(),
        spec: tw,
    }];
    // 2026-08-19 (Wed) 15:00 America/New_York = 19:00 UTC → active; 23:00 NY → inactive
    let active_at = chrono::DateTime::parse_from_rfc3339("2026-08-19T19:00:00Z")
        .unwrap()
        .timestamp();
    let inactive_at = chrono::DateTime::parse_from_rfc3339("2026-08-20T03:00:00Z")
        .unwrap()
        .timestamp();
    assert_eq!(compile(&data, active_at).unwrap().active_ids.len(), 1);
    let c = compile(&data, inactive_at).unwrap();
    assert_eq!(c.active_ids.len(), 0);
    assert!(c.next_window_change.unwrap() > inactive_at);
}

#[test]
fn cedar_source_is_well_formed_for_all_fixtures() {
    for f in [
        "allow_ssh.json",
        "deny_all_cameras.json",
        "time_window.json",
    ] {
        let spec: PolicySpec = serde_json::from_str(
            &std::fs::read_to_string(format!("{}/tests/fixtures/{f}", env!("CARGO_MANIFEST_DIR")))
                .unwrap(),
        )
        .unwrap();
        let src = cedar_source(&PolicyEntry {
            id: Uuid::new_v4(),
            name: f.into(),
            spec,
        })
        .unwrap();
        cedar_policy::PolicySet::from_str(&src).unwrap_or_else(|e| panic!("{f}: {e}\n{src}"));
    }
}
