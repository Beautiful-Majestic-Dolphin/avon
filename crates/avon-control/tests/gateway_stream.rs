#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use avon_protocol::v2::{gateway_down, GatewayRegistration, GatewayUp};
use avon_testkit::{
    db::TestDb,
    device::TestDevice,
    gateway::TestGateway,
    pki::TestPki,
    services::{spawn_ca, spawn_control, ControlFixture},
};
use tokio_stream::StreamExt;

async fn fixture() -> ControlFixture {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;
    spawn_control(db, pki, dir, ca).await
}

#[tokio::test(flavor = "multi_thread")]
async fn gateway_registers_receives_chain_and_crl_updates_on_revocation() {
    let f = fixture().await;
    let gw = TestGateway::enroll(&f).await;
    let mut client = gw.client(&f).await;
    let cfg = client
        .register(GatewayRegistration {
            public_endpoint: "127.0.0.1:4600".into(),
            region: "default".into(),
            capacity: 100,
            version: "test".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(cfg.chain.is_some() && cfg.crl.is_some());
    let (tx, rx) = tokio::sync::mpsc::channel::<GatewayUp>(4);
    let mut down = client
        .events(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();

    let dev = TestDevice::enroll(&f, "tok").await;
    avon_control::gateway_stream::revoke_device(&f.state(), dev.device_id.into(), "test")
        .await
        .unwrap();
    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), down.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    match msg.msg.unwrap() {
        gateway_down::Msg::Crl(crl) => {
            let issuing = f.issuing_cert();
            let parsed = avon_crypto::cert::crl::Crl::verify(
                &crl.tbs,
                &crl.signature,
                &issuing.tbs.signing_key,
            )
            .unwrap();
            assert!(parsed.contains(&dev.certificate.tbs.serial));
        }
        other => panic!("expected crl, got {other:?}"),
    }
    drop(tx);
    let (status,): (String,) = sqlx::query_as("SELECT status::text FROM devices WHERE id = $1")
        .bind(dev.device_id)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(status, "revoked");
}

#[tokio::test(flavor = "multi_thread")]
async fn non_gateway_principals_cannot_use_gateway_service() {
    let f = fixture().await;
    let dev = TestDevice::enroll(&f, "tok").await;
    let mut client = dev.gateway_client(&f).await;
    let err = client
        .register(GatewayRegistration::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}
