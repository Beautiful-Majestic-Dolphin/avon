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

#[tokio::test]
async fn default_deny_then_allow_by_port_then_deny_again_within_two_seconds() {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;
    let f = spawn_control(db, pki, dir, ca).await;
    let gw_tun = MemoryTun::new();
    let gw = spawn_gateway(&f, gw_tun.clone(), vec!["10.20.0.0/16".parse().unwrap()]).await;
    let a = TestAgentCore::enroll_and_connect(&f, "tok").await;
    let ip = a.overlay_v4().addr();

    // No policy: denied.
    a.tun
        .inject(udp_v4(ip, "10.20.0.5".parse().unwrap(), 53, b"q"))
        .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(500), gw_tun.recv())
            .await
            .is_err()
    );
    assert!(gw.metric("avon_gateway_flows_denied_total", &[]) >= 1.0);

    // Allow UDP 53 for the device's pod.
    let (pod,): (uuid::Uuid,) =
        sqlx::query_as("INSERT INTO pods (tenant_id, name) VALUES ($1, 'eng') RETURNING id")
            .bind(avon_db::DEFAULT_TENANT_ID)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    sqlx::query("INSERT INTO device_pods (device_id, pod_id) VALUES ($1, $2)")
        .bind(a.device_id())
        .bind(pod)
        .execute(f.db.pool())
        .await
        .unwrap();
    let (pid,): (uuid::Uuid,) = sqlx::query_as("INSERT INTO policies (tenant_id, name, spec) VALUES ($1, 'dns', $2) RETURNING id")
        .bind(avon_db::DEFAULT_TENANT_ID)
        .bind(serde_json::json!({"version":2,"effect":"allow","source":{"pods":[pod]},"destination":{"cidrs":["10.20.0.0/16"]},"l4":[{"protocol":"udp","ports":"53"}]}))
        .fetch_one(f.db.pool()).await.unwrap();
    gw.wait_for_snapshot_containing(pid, Duration::from_secs(5))
        .await;

    a.tun
        .inject(udp_v4(ip, "10.20.0.5".parse().unwrap(), 53, b"q"))
        .await;
    let out = tokio::time::timeout(Duration::from_secs(2), gw_tun.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&out[28..], b"q");

    // A different port stays denied — the L4 rule is not a wildcard.
    a.tun
        .inject(udp_v4(ip, "10.20.0.5".parse().unwrap(), 5353, b"x"))
        .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(500), gw_tun.recv())
            .await
            .is_err()
    );

    // Disabling the policy must stop the allowed flow quickly, cache or not.
    sqlx::query("UPDATE policies SET enabled = false WHERE id = $1")
        .bind(pid)
        .execute(f.db.pool())
        .await
        .unwrap();
    let start = Instant::now();
    loop {
        a.tun
            .inject(udp_v4(ip, "10.20.0.5".parse().unwrap(), 53, b"q"))
            .await;
        if tokio::time::timeout(Duration::from_millis(200), gw_tun.recv())
            .await
            .is_err()
        {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "a disabled policy must stop traffic within 2 s"
        );
    }
}

#[tokio::test]
async fn decisions_are_batched_back_to_control() {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;
    let f = spawn_control(db, pki, dir, ca).await;
    let gw_tun = MemoryTun::new();
    let _gw = spawn_gateway(&f, gw_tun.clone(), vec!["10.20.0.0/16".parse().unwrap()]).await;
    let a = TestAgentCore::enroll_and_connect(&f, "tok").await;
    let ip = a.overlay_v4().addr();
    for port in [53u16, 80, 443] {
        a.tun
            .inject(udp_v4(ip, "10.20.0.5".parse().unwrap(), port, b"x"))
            .await;
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM policy_decisions WHERE device_id = $1")
        .bind(a.device_id())
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert!(n >= 3, "expected one decision per distinct flow, got {n}");
}

#[tokio::test]
async fn the_cache_serves_repeat_flows_without_re_deciding() {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;
    let f = spawn_control(db, pki, dir, ca).await;
    let gw_tun = MemoryTun::new();
    let gw = spawn_gateway(&f, gw_tun.clone(), vec!["10.20.0.0/16".parse().unwrap()]).await;
    let a = TestAgentCore::enroll_and_connect(&f, "tok").await;
    let ip = a.overlay_v4().addr();
    for _ in 0..20 {
        a.tun
            .inject(udp_v4(ip, "10.20.0.9".parse().unwrap(), 53, b"x"))
            .await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let decisions = gw.metric("avon_policy_decisions_total", &[("effect", "deny")]);
    assert!(
        decisions <= 3.0,
        "20 identical flows should not produce {decisions} decisions"
    );
}
