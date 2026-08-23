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

    // A packet written into the ring comes back out of the read side: this is
    // the loopback the driver provides for a freshly created adapter with no
    // routes, and it exercises both halves of our wrapper.
    let packet = ipv4_udp([10, 90, 0, 1], [10, 90, 0, 2], b"wintun");
    tun.deliver(&packet).await.expect("write into the ring");

    let mut buf = Vec::new();
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), tun.next_packet(&mut buf))
        .await
        .expect("packet did not arrive")
        .expect("read error");
    assert!(n >= 28);
    assert_eq!(buf[0] >> 4, 4);
    assert_eq!(&buf[28..n], b"wintun");

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
