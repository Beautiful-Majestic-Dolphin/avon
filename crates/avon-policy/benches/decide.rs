#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use avon_policy::engine::{DecisionRequest, Destination, Engine};
use avon_policy::entities::*;
use avon_policy::spec::{PolicySpec, Protocol};
use criterion::{criterion_group, criterion_main, Criterion};
use uuid::Uuid;

fn bench(c: &mut Criterion) {
    let pod = Uuid::new_v4();
    let devices: Vec<DeviceEntity> = (0..10_000)
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
    let policies: Vec<PolicyEntry> = (0..1_000)
        .map(|i| {
            let spec: PolicySpec = serde_json::from_str(&format!(
                r#"{{"version":2,"effect":"allow","source":{{"pods":["{pod}"]}},"destination":{{"cidrs":["10.{}.0.0/16"]}},"l4":[{{"protocol":"tcp","ports":"22,443"}}]}}"#,
                i % 250
            ))
            .expect("valid spec");
            PolicyEntry {
                id: Uuid::new_v4(),
                name: format!("p{i}"),
                spec,
            }
        })
        .collect();
    let dev = devices[0].id;
    let data = SnapshotData {
        tenant_id: Uuid::new_v4(),
        version: 1,
        generated_at: 0,
        pods: vec![PodEntity {
            id: pod,
            parent: None,
        }],
        device_classes: vec![],
        devices,
        policies,
    };
    let e = Engine::empty(data.tenant_id);
    e.load(data, 0).expect("load should succeed");
    let ip: std::net::IpAddr = "10.7.1.1".parse().expect("valid ip");
    let req = DecisionRequest {
        device: dev,
        destination: Destination::Ip(ip),
        dst_ip: ip,
        protocol: Protocol::Tcp,
        dst_port: 443,
        admission: false,
    };
    c.bench_function("decide/1000p-10000d", |b| b.iter(|| e.decide(&req)));
}
criterion_group!(benches, bench);
criterion_main!(benches);
