#![allow(clippy::unwrap_used)]
use std::time::Duration;

use avon_testkit::{
    agent_fixture::TestAgentCore,
    db::TestDb,
    gateway_fixture::spawn_gateway,
    memtun::MemoryTun,
    pki::TestPki,
    services::{spawn_ca, spawn_control},
};

#[tokio::test]
async fn agent_reaches_connected_state_and_reconnects_after_control_restart() {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;
    let mut f = spawn_control(db, pki, dir, ca).await;
    let gw_tun = MemoryTun::new();
    let _gw = spawn_gateway(&f, gw_tun.clone(), vec![]).await;
    let agent = TestAgentCore::enroll_and_connect(&f, "tok").await;
    assert_eq!(agent.status().state, "connected");

    // Control goes away; the data plane must survive and the agent must re-authenticate when control returns.
    f.restart_control().await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(matches!(
        agent.status().state.as_str(),
        "connected" | "degraded"
    ));
    tokio::time::timeout(
        Duration::from_secs(20),
        agent.wait_for_pulse_after(std::time::Instant::now()),
    )
    .await
    .unwrap();
    assert_eq!(agent.status().state, "connected");
}

#[tokio::test]
async fn agent_reopens_session_when_gateway_closes_it() {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;
    let f = spawn_control(db, pki, dir, ca).await;
    let gw_tun = MemoryTun::new();
    let gw = spawn_gateway(&f, gw_tun.clone(), vec![]).await;
    let agent = TestAgentCore::enroll_and_connect(&f, "tok").await;
    let first = agent.status().session_id.clone().unwrap();
    gw.close_all("test").await;
    tokio::time::timeout(Duration::from_secs(10), agent.wait_for_new_session(&first))
        .await
        .unwrap();
    assert_ne!(agent.status().session_id.unwrap(), first);
}
