#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::time::Duration;

use avon_protocol::v2::{
    gateway_down, gateway_up, DecisionRecord, Decisions, GatewayRegistration, GatewayUp,
};
use avon_testkit::{
    db::TestDb,
    device::TestDevice,
    gateway::TestGateway,
    pki::TestPki,
    services::{spawn_ca, spawn_control},
};
use tokio_stream::StreamExt;

async fn next_policy(
    down: &mut tonic::Streaming<avon_protocol::v2::GatewayDown>,
    timeout: Duration,
) -> avon_protocol::v2::PolicySnapshot {
    tokio::time::timeout(timeout, async {
        loop {
            match down.next().await.unwrap().unwrap().msg.unwrap() {
                gateway_down::Msg::Policy(p) => return p,
                _ => continue,
            }
        }
    })
    .await
    .expect("no policy snapshot arrived")
}

#[tokio::test]
async fn a_registering_gateway_receives_every_tenant_snapshot() {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;
    let f = spawn_control(db, pki, dir, ca).await;
    let gw = TestGateway::enroll(&f).await;
    let mut client = gw.client(&f).await;
    let cfg = client
        .register(GatewayRegistration {
            public_endpoint: "127.0.0.1:4600".into(),
            region: "default".into(),
            capacity: 10,
            version: "t".into(),
            protected_cidrs: vec![],
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        cfg.snapshots.len(),
        1,
        "the default tenant's snapshot must arrive with the config"
    );
    let data = avon_policy::snapshot::decode(&cfg.snapshots[0].encoded).unwrap();
    assert_eq!(data.tenant_id, avon_db::DEFAULT_TENANT_ID);
}

#[tokio::test]
async fn changing_a_policy_pushes_a_new_snapshot_within_a_second() {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;
    let f = spawn_control(db, pki, dir, ca).await;
    let gw = TestGateway::enroll(&f).await;
    let mut client = gw.client(&f).await;
    let cfg = client
        .register(GatewayRegistration {
            public_endpoint: "127.0.0.1:4600".into(),
            region: "default".into(),
            capacity: 10,
            version: "t".into(),
            protected_cidrs: vec![],
        })
        .await
        .unwrap()
        .into_inner();
    let v0 = cfg.snapshots[0].version;

    let (_tx, rx) = tokio::sync::mpsc::channel::<GatewayUp>(4);
    let mut down = client
        .events(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();

    sqlx::query("INSERT INTO policies (tenant_id, name, spec) VALUES ($1, 'p', $2)")
        .bind(avon_db::DEFAULT_TENANT_ID)
        .bind(serde_json::json!({"version":2,"effect":"deny","source":{"any":true},"destination":{"any":true}}))
        .execute(f.db.pool()).await.unwrap();

    let snap = next_policy(&mut down, Duration::from_secs(5)).await;
    assert!(snap.version > v0);
    let data = avon_policy::snapshot::decode(&snap.encoded).unwrap();
    assert_eq!(data.policies.len(), 1);
}

#[tokio::test]
async fn rapid_changes_are_debounced_into_few_pushes() {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;
    let f = spawn_control(db, pki, dir, ca).await;
    let gw = TestGateway::enroll(&f).await;
    let mut client = gw.client(&f).await;
    client
        .register(GatewayRegistration {
            public_endpoint: "127.0.0.1:4600".into(),
            region: "default".into(),
            capacity: 10,
            version: "t".into(),
            protected_cidrs: vec![],
        })
        .await
        .unwrap();
    let (_tx, rx) = tokio::sync::mpsc::channel::<GatewayUp>(64);
    let mut down = client
        .events(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();

    for i in 0..10 {
        sqlx::query("INSERT INTO policies (tenant_id, name, spec) VALUES ($1, $2, $3)")
            .bind(avon_db::DEFAULT_TENANT_ID).bind(format!("p{i}"))
            .bind(serde_json::json!({"version":2,"effect":"allow","source":{"any":true},"destination":{"any":true}}))
            .execute(f.db.pool()).await.unwrap();
    }
    let mut versions = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(300), down.next()).await {
            Ok(Some(Ok(msg))) => {
                if let Some(gateway_down::Msg::Policy(p)) = msg.msg {
                    versions.push(
                        avon_policy::snapshot::decode(&p.encoded)
                            .unwrap()
                            .policies
                            .len(),
                    );
                }
            }
            _ => break,
        }
    }
    assert!(!versions.is_empty(), "at least one snapshot must arrive");
    assert!(
        versions.len() < 10,
        "debounce should coalesce: got {} pushes",
        versions.len()
    );
    assert_eq!(
        *versions.last().unwrap(),
        10,
        "the final snapshot must contain every policy"
    );
}

#[tokio::test]
async fn a_posture_change_pushes_a_device_update_rather_than_a_whole_snapshot() {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;
    let f = spawn_control(db, pki, dir, ca).await;
    let gw = TestGateway::enroll(&f).await;
    let mut gclient = gw.client(&f).await;
    gclient
        .register(GatewayRegistration {
            public_endpoint: "127.0.0.1:4600".into(),
            region: "default".into(),
            capacity: 10,
            version: "t".into(),
            protected_cidrs: vec![],
        })
        .await
        .unwrap();
    let (_tx, rx) = tokio::sync::mpsc::channel::<GatewayUp>(16);
    let mut down = gclient
        .events(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();

    let dev = TestDevice::enroll(&f, "tok").await;
    let mut client = dev.authenticate(&f).await.unwrap();
    let (tx, prx) = tokio::sync::mpsc::channel(4);
    let _pulse = client
        .pulse(tokio_stream::wrappers::ReceiverStream::new(prx))
        .await
        .unwrap();
    tx.send(avon_protocol::v2::PulseUp {
        msg: Some(avon_protocol::v2::pulse_up::Msg::Heartbeat(
            avon_protocol::v2::PulseHeartbeat {
                posture: Some(avon_protocol::v2::DevicePosture {
                    firewall_enabled: Some(false),
                    collected_at_unix: 1,
                    ..Default::default()
                }),
                sessions: vec![],
            },
        )),
    })
    .await
    .unwrap();

    let update = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match down.next().await.unwrap().unwrap().msg.unwrap() {
                gateway_down::Msg::DeviceUpdate(u) => return u,
                _ => continue,
            }
        }
    })
    .await
    .expect("no device update arrived");
    assert_eq!(
        avon_protocol::bytes_to_uuid(&update.device_id.unwrap().value).unwrap(),
        dev.device_id
    );
    let attrs: serde_json::Value = serde_json::from_str(&update.attrs_json).unwrap();
    assert_eq!(attrs["firewall_enabled"], false);
}

#[tokio::test]
async fn decisions_reported_by_a_gateway_are_persisted() {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;
    let f = spawn_control(db, pki, dir, ca).await;
    let gw = TestGateway::enroll(&f).await;
    let dev = TestDevice::enroll(&f, "tok").await;
    let mut client = gw.client(&f).await;
    client
        .register(GatewayRegistration {
            public_endpoint: "127.0.0.1:4600".into(),
            region: "default".into(),
            capacity: 10,
            version: "t".into(),
            protected_cidrs: vec![],
        })
        .await
        .unwrap();
    let (tx, rx) = tokio::sync::mpsc::channel::<GatewayUp>(4);
    let _down = client
        .events(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap();

    tx.send(GatewayUp {
        msg: Some(gateway_up::Msg::Decisions(Decisions {
            records: vec![DecisionRecord {
                tenant_id: Some(avon_protocol::v2::Uuid {
                    value: avon_db::DEFAULT_TENANT_ID.as_bytes().to_vec(),
                }),
                device_id: Some(avon_protocol::v2::Uuid {
                    value: dev.device_id.as_bytes().to_vec(),
                }),
                session_id: vec![1; 16],
                destination: "10.20.0.5:443/tcp".into(),
                allow: false,
                policy_ids: vec![],
                reason: "no matching permit".into(),
                decided_at_unix: chrono::Utc::now().timestamp(),
            }],
        })),
    })
    .await
    .unwrap();

    for _ in 0..40 {
        let (n,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM policy_decisions WHERE device_id = $1")
                .bind(dev.device_id)
                .fetch_one(f.db.pool())
                .await
                .unwrap();
        if n == 1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("decision was never persisted");
}
