#![allow(clippy::unwrap_used, clippy::panic)]
use std::net::IpAddr;

use avon_policy::engine::{DecisionRequest, Destination, Engine};
use avon_policy::entities::*;
use avon_policy::spec::{PolicySpec, Protocol};
use uuid::Uuid;

fn snapshot(n_devices: usize) -> (SnapshotData, Uuid) {
    let pod = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
    let spec: PolicySpec = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/tests/fixtures/allow_ssh.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let devices: Vec<DeviceEntity> = (0..n_devices)
        .map(|_| DeviceEntity {
            id: Uuid::new_v4(),
            pods: vec![pod],
            attrs: DeviceAttrs {
                status: "active".into(),
                firewall_enabled: Some(true),
                attestation: "none".into(),
                ..Default::default()
            },
        })
        .collect();
    let first = devices[0].id;
    (
        SnapshotData {
            tenant_id: Uuid::new_v4(),
            version: 7,
            generated_at: 0,
            pods: vec![PodEntity {
                id: pod,
                parent: None,
            }],
            device_classes: vec![],
            devices,
            policies: vec![PolicyEntry {
                id: Uuid::new_v4(),
                name: "ssh".into(),
                spec,
            }],
        },
        first,
    )
}

fn req(dev: Uuid, ip: &str, port: u16) -> DecisionRequest {
    DecisionRequest {
        device: dev,
        destination: Destination::Ip(ip.parse().unwrap()),
        dst_ip: ip.parse::<IpAddr>().unwrap(),
        protocol: Protocol::Tcp,
        dst_port: port,
        admission: false,
    }
}

#[test]
fn empty_engine_denies_everything_with_a_reason() {
    let e = Engine::empty(Uuid::new_v4());
    let d = e.decide(&req(Uuid::new_v4(), "10.20.0.1", 22));
    assert!(!d.allow);
    assert!(d.reason.contains("unknown device") || d.reason.contains("no policy"));
}

#[test]
fn loaded_engine_decides_and_reports_policy_ids() {
    let (data, dev) = snapshot(3);
    let pid = data.policies[0].id;
    let e = Engine::empty(data.tenant_id);
    e.load(data, 0).unwrap();
    let d = e.decide(&req(dev, "10.20.0.1", 22));
    assert!(d.allow);
    assert_eq!(d.policy_ids, vec![pid]);
    assert_eq!(d.snapshot_version, 7);
    assert!(!e.decide(&req(dev, "10.20.0.1", 80)).allow);
}

#[test]
fn patch_device_changes_decisions_without_full_reload() {
    let (data, dev) = snapshot(3);
    let e = Engine::empty(data.tenant_id);
    e.load(data, 0).unwrap();
    assert!(e.decide(&req(dev, "10.20.0.1", 22)).allow);
    e.patch_device(
        dev,
        DeviceAttrs {
            status: "active".into(),
            firewall_enabled: Some(false),
            attestation: "none".into(),
            ..Default::default()
        },
        0,
    )
    .unwrap();
    assert!(!e.decide(&req(dev, "10.20.0.1", 22)).allow);
    e.patch_device(
        dev,
        DeviceAttrs {
            status: "suspended".into(),
            firewall_enabled: Some(true),
            attestation: "none".into(),
            ..Default::default()
        },
        0,
    )
    .unwrap();
    let d = e.decide(&req(dev, "10.20.0.1", 22));
    assert!(!d.allow);
    assert!(d.reason.contains("status"));
}

#[test]
fn admission_ignores_ports() {
    let (mut data, dev) = snapshot(2);
    let target = data.devices[1].id;
    data.policies[0].spec.destination = avon_policy::spec::Selector {
        devices: vec![target],
        ..Default::default()
    };
    let e = Engine::empty(data.tenant_id);
    e.load(data, 0).unwrap();
    let d = e.decide(&DecisionRequest {
        device: dev,
        destination: Destination::Device(target),
        dst_ip: "100.64.0.9".parse().unwrap(),
        protocol: Protocol::Any,
        dst_port: 0,
        admission: true,
    });
    assert!(d.allow);
}

#[test]
fn snapshot_roundtrip() {
    let (data, _) = snapshot(5);
    let bytes = avon_policy::snapshot::encode(&data);
    assert_eq!(avon_policy::snapshot::decode(&bytes).unwrap(), data);
}
