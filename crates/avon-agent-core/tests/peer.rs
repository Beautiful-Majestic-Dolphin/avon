#![allow(clippy::unwrap_used)]
use avon_testkit::{
    agent_fixture::TestAgentCore,
    db::TestDb,
    gateway_fixture::spawn_gateway,
    memtun::MemoryTun,
    pki::TestPki,
    services::{spawn_ca, spawn_control},
};
use std::time::Duration;

fn packets_udp_v4(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p[20..22].copy_from_slice(&40000u16.to_be_bytes());
    p[22..24].copy_from_slice(&53u16.to_be_bytes());
    p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p[28..].copy_from_slice(payload);
    p
}

#[tokio::test]
async fn peers_on_the_same_host_establish_a_direct_session_and_bypass_the_gateway() {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;
    let f = spawn_control(db, pki, dir, ca).await;
    let gw = spawn_gateway(&f, MemoryTun::new(), vec![]).await;
    let a = TestAgentCore::enroll_and_connect(&f, "tok-a").await;
    let b = TestAgentCore::enroll_and_connect(&f, "tok-b").await;

    a.dial_peer(b.device_id()).await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        a.wait_for_direct_peer(b.device_id()),
    )
    .await
    .unwrap();

    let relayed_before = gw.metric("avon_gateway_packets_relayed_total", &[]);
    a.tun
        .inject(packets_udp_v4(
            a.overlay_v4().addr(),
            b.overlay_v4().addr(),
            b"direct",
        ))
        .await;
    let got = tokio::time::timeout(Duration::from_secs(3), b.tun.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got[28..], b"direct");
    assert_eq!(
        gw.metric("avon_gateway_packets_relayed_total", &[]),
        relayed_before,
        "packet must not traverse the gateway"
    );
}

#[tokio::test]
async fn unreachable_candidates_fall_back_to_the_hub_path() {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;
    let f = spawn_control(db, pki, dir, ca).await;
    let gw = spawn_gateway(&f, MemoryTun::new(), vec![]).await;
    let a = TestAgentCore::enroll_and_connect(&f, "tok-a").await;
    let b = TestAgentCore::enroll_and_connect_with_blackholed_candidates(&f, "tok-b").await;
    let _ = a.dial_peer(b.device_id()).await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(!a.has_direct_peer(b.device_id()));
    a.tun
        .inject(packets_udp_v4(
            a.overlay_v4().addr(),
            b.overlay_v4().addr(),
            b"relayed",
        ))
        .await;
    let got = tokio::time::timeout(Duration::from_secs(3), b.tun.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got[28..], b"relayed");
    assert!(gw.metric("avon_gateway_packets_relayed_total", &[]) >= 1.0);
}
