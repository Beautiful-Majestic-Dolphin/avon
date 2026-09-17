#![cfg(target_os = "windows")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The Windows data plane, exercised against the real driver. Creating an
//! adapter needs elevation, which the GitHub Windows runner has; elsewhere the
//! test says why it skipped rather than failing a developer's machine.

use avon_tun::Tun;
use avon_tunnel::{PacketSink, PacketSource};

fn ipv4_udp(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p[20..22].copy_from_slice(&4242u16.to_be_bytes());
    p[22..24].copy_from_slice(&4243u16.to_be_bytes());
    p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p[28..].copy_from_slice(payload);
    p
}

async fn adapter(name: &str) -> Option<Tun> {
    match Tun::create(name, 1280).await {
        Ok(t) => Some(t),
        Err(e) if std::env::var("CI").is_err() => {
            eprintln!("skipping: creating a WinTun adapter needs elevation ({e})");
            None
        }
        Err(e) => panic!("create adapter: {e}"),
    }
}

#[tokio::test]
async fn adapter_creates_sends_receives_and_is_removed() {
    let Some(tun) = adapter("avon9").await else {
        return;
    };
    assert_eq!(tun.name(), "avon9");
    assert_ne!(tun.luid(), 0);
    assert_eq!(tun.mtu(), 1280);

    // The write side: a packet handed to the driver is delivered to the
    // OS stack as if it had arrived from the wire. Nothing echoes it back
    // through the adapter, so the read side needs the stack to send.
    let packet = ipv4_udp([10, 90, 0, 1], [10, 90, 0, 2], b"wintun");
    tun.deliver(&packet).await.expect("write into the ring");

    // The read side: give the adapter an address, then send a datagram
    // from a socket bound to it towards an on-link neighbour. The stack
    // routes that out through the adapter, where it lands in our ring.
    // netsh needs the elevation adapter creation already required.
    let status = std::process::Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "add",
            "address",
            "avon9",
            "10.90.0.1",
            "255.255.255.0",
        ])
        .status()
        .expect("run netsh");
    assert!(status.success(), "netsh add address: {status}");

    // The address is tentative for a moment after it is added; binding
    // fails until it settles.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    let socket = loop {
        match std::net::UdpSocket::bind("10.90.0.1:0") {
            Ok(s) => break s,
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            Err(e) => panic!("bind to the adapter's address: {e}"),
        }
    };

    // Windows also emits its own traffic (neighbour discovery, multicast)
    // on a new interface, so read until our datagram shows up, resending
    // in case an early one was dropped while the interface came up.
    let mut buf = Vec::new();
    let found = loop {
        socket
            .send_to(b"wintun", "10.90.0.2:4243")
            .expect("send datagram");
        let read = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            tun.next_packet(&mut buf),
        )
        .await;
        if let Ok(Ok(n)) = read {
            if n >= 28 && buf[0] >> 4 == 4 && buf[9] == 17 && &buf[28..n] == b"wintun" {
                break true;
            }
            continue;
        }
        if tokio::time::Instant::now() >= deadline {
            break false;
        }
    };
    assert!(found, "our datagram never came out of the adapter's ring");

    drop(tun);
    // The session is shut down with the Tun, so the adapter can be opened again.
    let again = Tun::create("avon9", 1280).await.expect("recreate adapter");
    drop(again);
}

#[tokio::test]
async fn oversized_packets_are_refused_rather_than_truncated() {
    let Some(tun) = adapter("avon8").await else {
        return;
    };
    let huge = vec![0u8; u16::MAX as usize + 1];
    assert!(
        tun.deliver(&huge).await.is_err(),
        "a packet larger than the ring's frame must be refused"
    );
}
