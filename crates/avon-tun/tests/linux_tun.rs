#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]
use avon_tun::Tun;
use avon_tunnel::{PacketSink, PacketSource};

#[tokio::test]
async fn tun_roundtrip_via_loopback_ping() {
    if std::env::var("AVON_TEST_ROOT").ok().as_deref() != Some("1") {
        eprintln!("skipping: requires root (set AVON_TEST_ROOT=1 inside the e2e container)");
        return;
    }
    let tun = Tun::create("avontest0", 1280).await.unwrap();
    avon_tun::config::configure(&tun, "100.127.0.1/30".parse().unwrap(), None, 1280)
        .await
        .unwrap();
    // Ping 100.127.0.2 in the background: the kernel routes it to the TUN.
    let mut child = tokio::process::Command::new("/bin/ping")
        .args(["-c", "1", "-W", "1", "100.127.0.2"])
        .spawn()
        .unwrap();
    let mut buf = Vec::new();
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), tun.next_packet(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(buf[0] >> 4, 4);
    assert_eq!(buf[9], 1, "ICMP");
    // Craft the echo reply and write it back; ping should then succeed.
    let mut reply = buf[..n].to_vec();
    reply.swap(12, 16);
    reply.swap(13, 17);
    reply.swap(14, 18);
    reply.swap(15, 19);
    reply[20] = 0; // echo reply
    avon_tun::checksum::fix_ipv4_and_icmp(&mut reply);
    tun.deliver(&reply).await.unwrap();
    let status = child.wait().await.unwrap();
    assert!(status.success());
}
