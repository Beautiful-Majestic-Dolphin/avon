#![allow(clippy::unwrap_used)]
use avon_protocol::v2::{
    gateway_down, gateway_up, GatewayRegistration, GatewayUp, OpenSessionRequest, SessionReport,
    Suite,
};
use avon_testkit::{
    db::TestDb,
    device::TestDevice,
    gateway::TestGateway,
    pki::TestPki,
    services::{spawn_ca, spawn_control, ControlFixture},
};
use avon_tunnel::{Initiator, Responder};
use tokio_stream::StreamExt;

async fn fixture() -> ControlFixture {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;
    spawn_control(db, pki, dir, ca).await
}

/// A fake gateway registered with control that answers every session offer
/// with a real `avon-tunnel` responder answer. Held by the caller so its
/// control stream stays open for the life of the test.
async fn spawn_answering_gateway(f: &ControlFixture) -> TestGateway {
    let gw = TestGateway::enroll(f).await;
    let mut gclient = gw.client(f).await;
    gclient
        .register(GatewayRegistration {
            public_endpoint: "127.0.0.1:4600".into(),
            region: "default".into(),
            capacity: 10,
            version: "t".into(),
            protected_cidrs: vec!["10.20.0.0/16".into()],
        })
        .await
        .unwrap();
    let (gtx, grx) = tokio::sync::mpsc::channel::<GatewayUp>(8);
    let mut down = gclient
        .events(tokio_stream::wrappers::ReceiverStream::new(grx))
        .await
        .unwrap()
        .into_inner();
    let gw_signing = gw.signing_keypair();
    let gw_cert_id = gw.certificate.id();
    tokio::spawn(async move {
        while let Some(Ok(msg)) = down.next().await {
            if let Some(gateway_down::Msg::SessionOffer(offer)) = msg.msg {
                let cert = avon_crypto::cert::Certificate::decode(
                    &offer.device_certificate.unwrap().encoded,
                )
                .unwrap();
                let sid = avon_common::ids::SessionId::from_slice(&offer.session_id).unwrap();
                let (answer, _) = Responder::answer(
                    sid,
                    &cert,
                    &offer.eph_kem_pk,
                    avon_crypto::aead::Suite::Aes256Gcm,
                    gw_cert_id,
                    &gw_signing,
                    7,
                    Some("127.0.0.1:4600".into()),
                )
                .unwrap();
                gtx.send(GatewayUp {
                    msg: Some(gateway_up::Msg::SessionAnswer(answer)),
                })
                .await
                .unwrap();
            }
        }
    });

    gw
}

#[tokio::test(flavor = "multi_thread")]
async fn open_session_brokers_a_signed_answer_and_assigns_overlay_ip() {
    let f = fixture().await;

    let _gw = spawn_answering_gateway(&f).await;

    let dev = TestDevice::enroll(&f, "tok").await;
    let mut client = dev.authenticate(&f).await.unwrap();
    let pending = Initiator::offer(&[avon_crypto::aead::Suite::Aes256Gcm]).unwrap();
    let resp = client
        .open_session(OpenSessionRequest {
            eph_kem_pk: pending.eph_pk_bytes.clone(),
            suites: vec![Suite::Aes256Gcm as i32],
            wants_overlay_ip: true,
            initiator_index: 0x1234,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(resp.overlay_ipv4.starts_with("100.64."));
    // The prefix is the tenant pool's, not /32: the agent configures it as an
    // interface address and needs to know the overlay is on-link.
    assert!(
        resp.overlay_ipv4.ends_with("/10"),
        "overlay_ipv4 carries the pool prefix, got {}",
        resp.overlay_ipv4
    );
    assert!(
        resp.overlay_ipv6.ends_with("/48"),
        "overlay_ipv6 carries the pool prefix, got {}",
        resp.overlay_ipv6
    );
    assert_eq!(resp.routes.len(), 1);
    assert_eq!(resp.routes[0].cidrs, vec!["10.20.0.0/16"]);
    let gw_cert =
        avon_crypto::cert::Certificate::decode(&resp.gateway_certificate.unwrap().encoded).unwrap();
    let sid = avon_common::ids::SessionId::from_slice(&resp.session_id).unwrap();
    let est = Initiator::complete(
        pending,
        &resp.answer.unwrap(),
        sid,
        dev.certificate.id(),
        &dev.kem,
        &gw_cert,
    )
    .unwrap();
    assert_eq!(est.keys.epoch, 0);
    let (state,): (String,) = sqlx::query_as("SELECT state::text FROM sessions WHERE id = $1")
        .bind(&resp.session_id)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(state, "active");
}

#[tokio::test(flavor = "multi_thread")]
async fn open_session_without_gateway_is_unavailable() {
    let f = fixture().await;
    let dev = TestDevice::enroll(&f, "tok").await;
    let mut client = dev.authenticate(&f).await.unwrap();
    let pending = Initiator::offer(&[avon_crypto::aead::Suite::Aes256Gcm]).unwrap();
    let err = client
        .open_session(OpenSessionRequest {
            eph_kem_pk: pending.eph_pk_bytes,
            suites: vec![Suite::Aes256Gcm as i32],
            wants_overlay_ip: true,
            initiator_index: 0x1234,
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unavailable);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_reporting_its_session_closed_closes_it_in_the_database() {
    let f = fixture().await;
    let _gw = spawn_answering_gateway(&f).await;

    let dev = TestDevice::enroll(&f, "tok").await;
    let mut client = dev.authenticate(&f).await.unwrap();
    let pending = Initiator::offer(&[avon_crypto::aead::Suite::Aes256Gcm]).unwrap();
    let resp = client
        .open_session(OpenSessionRequest {
            eph_kem_pk: pending.eph_pk_bytes,
            suites: vec![Suite::Aes256Gcm as i32],
            wants_overlay_ip: true,
            initiator_index: 0x1234,
        })
        .await
        .unwrap()
        .into_inner();

    client
        .report_session(SessionReport {
            session_id: resp.session_id.clone(),
            event: "closed".into(),
            reason: "agent shutdown".into(),
        })
        .await
        .unwrap();

    let (state, reason): (String, Option<String>) =
        sqlx::query_as("SELECT state::text, close_reason FROM sessions WHERE id = $1")
            .bind(&resp.session_id)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(state, "closed");
    assert_eq!(reason.as_deref(), Some("agent shutdown"));
}
