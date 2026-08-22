#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::time::{Duration, Instant};

use avon_testkit::{
    agent_fixture::TestAgentCore,
    db::TestDb,
    gateway_fixture::spawn_gateway,
    memtun::MemoryTun,
    packets::udp_v4,
    pki::TestPki,
    services::{spawn_ca, spawn_control},
};

async fn allow_policy(
    f: &avon_testkit::services::ControlFixture,
    device: uuid::Uuid,
    extra: serde_json::Value,
) -> uuid::Uuid {
    let (pod,): (uuid::Uuid,) =
        sqlx::query_as("INSERT INTO pods (tenant_id, name) VALUES ($1, 'p') RETURNING id")
            .bind(avon_db::DEFAULT_TENANT_ID)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    sqlx::query("INSERT INTO device_pods (device_id, pod_id) VALUES ($1, $2)")
        .bind(device)
        .bind(pod)
        .execute(f.db.pool())
        .await
        .unwrap();
    let mut spec = serde_json::json!({
        "version": 2, "effect": "allow", "source": {"pods": [pod]},
        "destination": {"cidrs": ["10.20.0.0/16"]}, "l4": [{"protocol": "udp", "ports": "53"}]
    });
    if let Some(conditions) = extra.as_object() {
        spec["conditions"] = serde_json::Value::Object(conditions.clone());
    }
    let (pid,): (uuid::Uuid,) = sqlx::query_as(
        "INSERT INTO policies (tenant_id, name, spec) VALUES ($1, 'allow', $2) RETURNING id",
    )
    .bind(avon_db::DEFAULT_TENANT_ID)
    .bind(spec)
    .fetch_one(f.db.pool())
    .await
    .unwrap();
    pid
}

#[tokio::test]
async fn a_posture_regression_stops_traffic_within_one_pulse() {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;
    let f = spawn_control(db, pki, dir, ca).await;
    let gw_tun = MemoryTun::new();
    let gw = spawn_gateway(&f, gw_tun.clone(), vec!["10.20.0.0/16".parse().unwrap()]).await;
    let a = TestAgentCore::enroll_and_connect_with_posture(&f, "tok", true).await;
    let ip = a.overlay_v4().addr();
    let pid = allow_policy(
        &f,
        a.device_id(),
        serde_json::json!({"posture": {"firewall_enabled": true}}),
    )
    .await;
    gw.wait_for_snapshot_containing(pid, Duration::from_secs(5))
        .await;

    a.tun
        .inject(udp_v4(ip, "10.20.0.5".parse().unwrap(), 53, b"ok"))
        .await;
    assert!(tokio::time::timeout(Duration::from_secs(2), gw_tun.recv())
        .await
        .is_ok());

    a.set_posture_firewall(false).await;
    let start = Instant::now();
    loop {
        a.tun
            .inject(udp_v4(ip, "10.20.0.5".parse().unwrap(), 53, b"x"))
            .await;
        if tokio::time::timeout(Duration::from_millis(200), gw_tun.recv())
            .await
            .is_err()
        {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "posture regression must take effect within a pulse"
        );
    }

    a.set_posture_firewall(true).await;
    let start = Instant::now();
    loop {
        a.tun
            .inject(udp_v4(ip, "10.20.0.5".parse().unwrap(), 53, b"y"))
            .await;
        if tokio::time::timeout(Duration::from_millis(200), gw_tun.recv())
            .await
            .is_ok()
        {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "restored posture must re-allow"
        );
    }
}

#[tokio::test]
async fn suspending_a_device_closes_its_sessions_not_just_new_flows() {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;
    let f = spawn_control(db, pki, dir, ca).await;
    let gw_tun = MemoryTun::new();
    let gw = spawn_gateway(&f, gw_tun.clone(), vec!["10.20.0.0/16".parse().unwrap()]).await;
    let a = TestAgentCore::enroll_and_connect(&f, "tok").await;
    let pid = allow_policy(&f, a.device_id(), serde_json::json!({})).await;
    gw.wait_for_snapshot_containing(pid, Duration::from_secs(5))
        .await;
    assert_eq!(gw.sessions(), 1);

    avon_control::gateway_stream::suspend_device(&f.state(), a.device_id().into(), "e2e")
        .await
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if gw.sessions() == 0 {
            let (state,): (String,) = sqlx::query_as("SELECT state::text FROM sessions WHERE device_id = $1 ORDER BY created_at DESC LIMIT 1")
                .bind(a.device_id()).fetch_one(f.db.pool()).await.unwrap();
            assert_eq!(state, "closed");
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("suspension did not close the session");
}

#[tokio::test]
async fn attestation_becoming_verified_admits_a_previously_denied_flow() {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;
    let f = spawn_control(db, pki, dir, ca).await;
    let gw_tun = MemoryTun::new();
    let gw = spawn_gateway(&f, gw_tun.clone(), vec!["10.20.0.0/16".parse().unwrap()]).await;
    let a = TestAgentCore::enroll_and_connect(&f, "tok").await;
    let ip = a.overlay_v4().addr();
    let pid = allow_policy(
        &f,
        a.device_id(),
        serde_json::json!({"attestation": "verified"}),
    )
    .await;
    gw.wait_for_snapshot_containing(pid, Duration::from_secs(5))
        .await;

    a.tun
        .inject(udp_v4(ip, "10.20.0.5".parse().unwrap(), 53, b"x"))
        .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(500), gw_tun.recv())
            .await
            .is_err(),
        "unattested device must be denied"
    );

    sqlx::query("UPDATE devices SET attestation_state = 'verified' WHERE id = $1")
        .bind(a.device_id())
        .execute(f.db.pool())
        .await
        .unwrap();
    let start = Instant::now();
    loop {
        a.tun
            .inject(udp_v4(ip, "10.20.0.5".parse().unwrap(), 53, b"y"))
            .await;
        if tokio::time::timeout(Duration::from_millis(200), gw_tun.recv())
            .await
            .is_ok()
        {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "attestation change must reach the gateway"
        );
    }
}
