//! End-to-end forwarding through a real gateway: a device brokers a session
//! through control, then packets move over UDP with real ATP/2 crypto.
//!
//! The device side here is a minimal tunnel peer built straight from
//! `avon-tunnel`. Task 3.7 replaces it with `TestAgentCore` from the testkit;
//! the gateway behaviour under test is the same either way.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use avon_common::ids::SessionId;
use avon_crypto::aead::Suite;
use avon_crypto::cert::Certificate;
use avon_protocol::v2::{OpenSessionRequest, Suite as PbSuite};
use avon_testkit::{
    db::TestDb,
    device::TestDevice,
    gateway_fixture::{spawn_gateway, GatewayFixture},
    memtun::MemoryTun,
    pki::TestPki,
    services::{spawn_ca, spawn_control, ControlFixture},
};
use avon_tunnel::{
    EndpointConfig, Initiator, Inner, PacketSink, Role, Session, SessionTable, TimerConfig,
    UdpEndpoint,
};
use ipnet::Ipv4Net;

async fn fixture() -> ControlFixture {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;
    spawn_control(db, pki, dir, ca).await
}

/// A UDP/IP header pair a gateway can actually parse.
fn ipv4_packet(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17; // UDP
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p[20..22].copy_from_slice(&40000u16.to_be_bytes());
    p[22..24].copy_from_slice(&53u16.to_be_bytes());
    p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p[28..].copy_from_slice(payload);
    p
}

/// The device half of a tunnel: its own socket, session and in-memory TUN.
struct TestPeer {
    pub tun: Arc<MemoryTun>,
    pub overlay_v4: Ipv4Net,
    session: Arc<Session>,
    endpoint: Arc<UdpEndpoint>,
}

impl TestPeer {
    /// Enrol, authenticate, open a session through control, and start moving
    /// packets between the tunnel and the in-memory TUN.
    async fn connect(f: &ControlFixture, token: &str, timers: TimerConfig) -> Self {
        let dev = TestDevice::enroll(f, token).await;
        let mut client = dev.authenticate(f).await.unwrap();

        let table = Arc::new(SessionTable::new());
        let my_index = table.allocate_index().unwrap();
        let pending = Initiator::offer(&[Suite::Aes256Gcm]).unwrap();
        let resp = client
            .open_session(OpenSessionRequest {
                eph_kem_pk: pending.eph_pk_bytes.clone(),
                suites: vec![PbSuite::Aes256Gcm as i32],
                wants_overlay_ip: true,
                initiator_index: my_index,
            })
            .await
            .unwrap()
            .into_inner();

        let answer = resp.answer.clone().unwrap();
        let gw_cert = Certificate::decode(&resp.gateway_certificate.unwrap().encoded).unwrap();
        let sid = SessionId::from_slice(&resp.session_id).unwrap();
        let est = Initiator::complete(
            pending,
            &answer,
            sid,
            dev.certificate.id(),
            &dev.kem,
            &gw_cert,
        )
        .unwrap();

        let endpoint = UdpEndpoint::bind(
            EndpointConfig {
                bind: "127.0.0.1:0".parse().unwrap(),
                overlay_mtu: 1380,
                timers,
            },
            table.clone(),
        )
        .await
        .unwrap();

        let session = Session::new(
            sid,
            Role::Initiator,
            est.suite,
            gw_cert.id(),
            est.keys,
            my_index,
            answer.responder_index,
            Some(answer.responder_endpoint.parse().unwrap()),
        );
        table.insert(session.clone());

        let tun = MemoryTun::new();
        let events = endpoint.clone().run();
        tokio::spawn(peer_loop(
            endpoint.clone(),
            session.clone(),
            tun.clone(),
            events,
        ));
        tokio::spawn(tun_to_tunnel(
            endpoint.clone(),
            session.clone(),
            tun.clone(),
        ));

        Self {
            overlay_v4: resp.overlay_ipv4.parse().unwrap(),
            tun,
            session,
            endpoint,
        }
    }

    fn addr(&self) -> [u8; 4] {
        self.overlay_v4.addr().octets()
    }

    fn epoch(&self) -> u32 {
        self.session.epoch()
    }

    /// Nudge the gateway so it learns this peer's endpoint before the test
    /// needs to receive anything.
    async fn hello(&self) {
        let _ = self
            .endpoint
            .send_inner(&self.session, &Inner::Keepalive)
            .await;
    }
}

/// Tunnel to TUN, plus the initiator half of rekey.
async fn peer_loop(
    endpoint: Arc<UdpEndpoint>,
    session: Arc<Session>,
    tun: Arc<MemoryTun>,
    mut events: tokio::sync::mpsc::Receiver<avon_tunnel::EndpointEvent>,
) {
    use avon_protocol::v2::{tunnel_frame, Rekey, TunnelFrame};
    use avon_tunnel::EndpointEvent;

    let mut pending_rekey = None;
    while let Some(ev) = events.recv().await {
        match ev {
            EndpointEvent::Ip { packet, .. } => {
                let _ = tun.deliver(&packet).await;
            }
            EndpointEvent::RekeyDue(s) => {
                let Ok((eph, pk)) = avon_tunnel::rekey_offer() else {
                    continue;
                };
                let Ok(new_index) = endpoint.table().allocate_index() else {
                    continue;
                };
                let frame = TunnelFrame {
                    msg: Some(tunnel_frame::Msg::Rekey(Rekey {
                        new_epoch: s.epoch() + 1,
                        eph_kem_pk: pk,
                        new_index,
                    })),
                };
                if endpoint.send_frame(&s, &frame).await.is_ok() {
                    pending_rekey = Some((eph, new_index));
                }
            }
            EndpointEvent::Control { session: s, frame } => {
                if let Some(tunnel_frame::Msg::RekeyAck(ack)) = frame.msg {
                    let Some((eph, new_index)) = pending_rekey.take() else {
                        continue;
                    };
                    let Ok(next) = s.complete_rekey(&eph, &ack.ct) else {
                        continue;
                    };
                    s.rotate(next, new_index, ack.new_index);
                    endpoint.table().rebind_index(&s, new_index);
                }
            }
            _ => {}
        }
    }
    drop(session);
}

/// TUN to tunnel.
async fn tun_to_tunnel(endpoint: Arc<UdpEndpoint>, session: Arc<Session>, tun: Arc<MemoryTun>) {
    use avon_tunnel::PacketSource;
    let mut buf = Vec::with_capacity(2048);
    while let Ok(n) = tun.next_packet(&mut buf).await {
        let _ = endpoint.send_inner(&session, &Inner::Ip(&buf[..n])).await;
    }
}

async fn gateway_and_control(
    protected: &[&str],
) -> (ControlFixture, GatewayFixture, Arc<MemoryTun>) {
    let f = fixture().await;
    let gw_tun = MemoryTun::new();
    let gw = spawn_gateway(
        &f,
        gw_tun.clone(),
        protected.iter().map(|c| c.parse().unwrap()).collect(),
    )
    .await;
    (f, gw, gw_tun)
}

#[tokio::test(flavor = "multi_thread")]
async fn device_to_protected_network_goes_out_the_gateway_tun_and_back() {
    let (f, gw, gw_tun) = gateway_and_control(&["10.20.0.0/16"]).await;
    let agent = TestPeer::connect(&f, "tok", TimerConfig::default()).await;
    assert!(gw.wait_for_sessions(1).await, "gateway accepted the offer");

    let my_ip = agent.addr();
    agent
        .tun
        .inject(ipv4_packet(my_ip, [10, 20, 0, 5], b"hello"))
        .await;
    let out = tokio::time::timeout(Duration::from_secs(5), gw_tun.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&out[28..], b"hello");
    assert_eq!(out[16..20], [10, 20, 0, 5]);

    // A reply from the protected network is routed back down the session.
    gw_tun
        .inject(ipv4_packet([10, 20, 0, 5], my_ip, b"world"))
        .await;
    let back = tokio::time::timeout(Duration::from_secs(5), agent.tun.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&back[28..], b"world");
    assert_eq!(gw.sessions(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn two_devices_relay_through_the_gateway_and_spoofed_sources_drop() {
    let (f, gw, _gw_tun) = gateway_and_control(&[]).await;
    let a = TestPeer::connect(&f, "tok-a", TimerConfig::default()).await;
    let b = TestPeer::connect(&f, "tok-b", TimerConfig::default()).await;
    assert!(gw.wait_for_sessions(2).await, "both sessions established");
    // B must have sent once for the gateway to know where to reach it.
    b.hello().await;

    a.tun.inject(ipv4_packet(a.addr(), b.addr(), b"ping")).await;
    let got = tokio::time::timeout(Duration::from_secs(5), b.tun.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got[28..], b"ping");

    let before = gw.metric(
        "avon_gateway_packets_dropped_total",
        &[("reason", "spoofed_source")],
    );
    // A claims B's address as its source: dropped, never delivered.
    a.tun
        .inject(ipv4_packet(b.addr(), a.addr(), b"spoof"))
        .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(500), a.tun.recv())
            .await
            .is_err(),
        "a spoofed packet is never relayed back"
    );
    assert!(
        gw.metric(
            "avon_gateway_packets_dropped_total",
            &[("reason", "spoofed_source")]
        ) > before,
        "the drop is attributed to the source check"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rekey_happens_and_traffic_continues() {
    let (f, gw, gw_tun) = gateway_and_control(&["10.20.0.0/16"]).await;
    let agent = TestPeer::connect(
        &f,
        "tok",
        TimerConfig {
            rekey_after: Duration::from_secs(1),
            ..Default::default()
        },
    )
    .await;
    assert!(gw.wait_for_sessions(1).await);

    let ip = agent.addr();
    for i in 0..6u8 {
        agent
            .tun
            .inject(ipv4_packet(ip, [10, 20, 0, 1], &[i]))
            .await;
        let out = tokio::time::timeout(Duration::from_secs(5), gw_tun.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(out[28], i, "traffic survives the rekey");
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    assert!(
        agent.epoch() >= 1,
        "at least one rekey in ~2.4 s, got epoch {}",
        agent.epoch()
    );
}
