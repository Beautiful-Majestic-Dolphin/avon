#![allow(clippy::unwrap_used, clippy::panic)]
use std::sync::Arc;
use std::time::Duration;

use avon_common::ids::SessionId;
use avon_crypto::aead::Suite;
use avon_crypto::hybrid::kem::HybridKemKeyPair;
use avon_crypto::session::{Role, SessionKeys, Transcript};
use avon_protocol::v2::{tunnel_frame, MtuProbe, TunnelFrame};
use avon_testkit::net::free_udp_addr;
use avon_tunnel::{
    EndpointConfig, EndpointEvent, Inner, Session, SessionTable, TimerConfig, UdpEndpoint,
};

fn keys() -> (SessionKeys, SessionKeys) {
    let eph = HybridKemKeyPair::generate().unwrap();
    let stat = HybridKemKeyPair::generate().unwrap();
    let (ct_e, ss_e) = eph.public_key().encapsulate().unwrap();
    let (ct_s, ss_s) = stat.public_key().encapsulate().unwrap();
    let t = Transcript {
        session_id: [1; 16],
        initiator_cert_id: [2; 32],
        responder_cert_id: [3; 32],
        eph_kem_pk: eph.public_key().to_bytes(),
        ct_e: ct_e.to_bytes(),
        ct_s: ct_s.to_bytes(),
        suite: Suite::Aes256Gcm,
    };
    (
        SessionKeys::derive(&t, &ss_e, &ss_s).unwrap(),
        SessionKeys::derive(&t, &ss_e, &ss_s).unwrap(),
    )
}

#[tokio::test]
async fn two_endpoints_exchange_ip_and_control_and_learn_endpoints() {
    let timers = TimerConfig {
        keepalive: Duration::from_millis(200),
        rekey_after: Duration::from_secs(3600),
        rekey_after_packets: u64::MAX,
        epoch_overlap: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(60),
    };
    let ta = Arc::new(SessionTable::new());
    let tb = Arc::new(SessionTable::new());
    let a = UdpEndpoint::bind(
        EndpointConfig {
            bind: free_udp_addr(),
            overlay_mtu: 1280,
            timers: timers.clone(),
        },
        ta.clone(),
    )
    .await
    .unwrap();
    let b = UdpEndpoint::bind(
        EndpointConfig {
            bind: free_udp_addr(),
            overlay_mtu: 1280,
            timers,
        },
        tb.clone(),
    )
    .await
    .unwrap();

    let (ka, kb) = keys();
    let ia = ta.allocate_index().unwrap();
    let ib = tb.allocate_index().unwrap();
    let sid = SessionId::from_slice(&[1; 16]).unwrap();
    let sa = Session::new(
        sid,
        Role::Initiator,
        Suite::Aes256Gcm,
        [3; 32],
        ka,
        ia,
        ib,
        Some(b.local_addr()),
    );
    // B learns A's address from the first packet.
    let sb = Session::new(
        sid,
        Role::Responder,
        Suite::Aes256Gcm,
        [2; 32],
        kb,
        ib,
        ia,
        None,
    );
    ta.insert(sa.clone());
    tb.insert(sb.clone());

    let mut ev_a = a.clone().run();
    let mut ev_b = b.clone().run();

    a.send_inner(&sa, &Inner::Ip(&[0x45, 1, 2, 3]))
        .await
        .unwrap();
    match tokio::time::timeout(Duration::from_secs(2), ev_b.recv())
        .await
        .unwrap()
        .unwrap()
    {
        EndpointEvent::PeerEndpointChanged { endpoint, .. } => {
            assert_eq!(endpoint, a.local_addr())
        }
        other => panic!("expected endpoint learn, got {other:?}"),
    }
    match ev_b.recv().await.unwrap() {
        EndpointEvent::Ip { packet, .. } => assert_eq!(packet, vec![0x45, 1, 2, 3]),
        other => panic!("{other:?}"),
    }

    // B can now send back, including a control frame.
    let frame = TunnelFrame {
        msg: Some(tunnel_frame::Msg::MtuProbe(MtuProbe {
            size: 1200,
            padding: vec![0; 8],
        })),
    };
    b.send_frame(&sb, &frame).await.unwrap();
    match tokio::time::timeout(Duration::from_secs(2), ev_a.recv())
        .await
        .unwrap()
        .unwrap()
    {
        EndpointEvent::Control { frame: f, .. } => assert_eq!(f, frame),
        other => panic!("{other:?}"),
    }

    // Keepalives flow after 200ms of silence and keep the sessions from idling.
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(sb.idle_for() < Duration::from_millis(500));
    assert!(
        sa.stats()
            .packets_rx
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 2
    );
}

#[tokio::test]
async fn garbage_and_unknown_indexes_are_dropped_silently() {
    let t = Arc::new(SessionTable::new());
    let e = UdpEndpoint::bind(
        EndpointConfig {
            bind: free_udp_addr(),
            overlay_mtu: 1280,
            timers: TimerConfig::default(),
        },
        t,
    )
    .await
    .unwrap();
    let mut ev = e.clone().run();
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&[0u8; 5], e.local_addr()).await.unwrap();
    sock.send_to(
        &[1u8, 0, 0, 0, 9, 9, 9, 9, 0, 0, 0, 0, 0, 0, 0, 1, 0xAA, 0xBB],
        e.local_addr(),
    )
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(300), ev.recv())
            .await
            .is_err(),
        "no event for garbage"
    );
}
