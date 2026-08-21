#![allow(clippy::unwrap_used, clippy::expect_used)]
use avon_protocol::v2::Empty;
use avon_testkit::{
    db::TestDb,
    device::TestDevice,
    pki::TestPki,
    services::{spawn_ca, spawn_control, ControlFixture},
};

async fn fixture() -> ControlFixture {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;
    spawn_control(db, pki, dir, ca).await
}

#[tokio::test(flavor = "multi_thread")]
async fn full_authentication_yields_a_usable_session_token() {
    let f = fixture().await;
    let device = TestDevice::enroll(&f, "tok").await;
    let mut client = device.authenticate(&f).await.unwrap();
    let who = client.who_am_i(Empty {}).await.unwrap().into_inner();
    assert!(who.reflexive_address.contains("127.0.0.1"));
}

#[tokio::test(flavor = "multi_thread")]
async fn token_cannot_be_used_from_another_tls_identity() {
    let f = fixture().await;
    let a = TestDevice::enroll(&f, "tok-a").await;
    let b = TestDevice::enroll(&f, "tok-b").await;
    let token = a.authenticate_raw(&f).await.unwrap();
    let err = b
        .client_with_token(&f, token)
        .await
        .who_am_i(Empty {})
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test(flavor = "multi_thread")]
async fn proof_from_wrong_key_is_rejected_and_no_token_is_issued() {
    let f = fixture().await;
    let mut a = TestDevice::enroll(&f, "tok-a").await;
    a.swap_signing_key();
    assert_eq!(
        a.authenticate_raw(&f).await.unwrap_err().code(),
        tonic::Code::Unauthenticated
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_suspended_and_pending_devices_cannot_authenticate() {
    let f = fixture().await;
    let a = TestDevice::enroll(&f, "tok-a").await;
    for status in ["suspended", "revoked", "pending"] {
        sqlx::query("UPDATE devices SET status = $1::device_status WHERE id = $2")
            .bind(status)
            .bind(a.device_id)
            .execute(f.db.pool())
            .await
            .unwrap();
        assert_eq!(
            a.authenticate_raw(&f).await.unwrap_err().code(),
            tonic::Code::PermissionDenied,
            "status {status}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn existing_session_dies_when_device_is_revoked() {
    let f = fixture().await;
    let a = TestDevice::enroll(&f, "tok-a").await;
    let mut client = a.authenticate(&f).await.unwrap();
    client.who_am_i(Empty {}).await.unwrap();
    avon_control::session_token::SessionStore::new(f.redis.client().await, 60)
        .revoke_device(a.device_id.into())
        .await
        .unwrap();
    assert_eq!(
        client.who_am_i(Empty {}).await.unwrap_err().code(),
        tonic::Code::Unauthenticated
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn session_token_encapsulation_requires_the_static_kem_secret() {
    let f = fixture().await;
    let mut a = TestDevice::enroll(&f, "tok-a").await;
    a.swap_kem_key();
    assert!(
        a.authenticate_raw(&f).await.is_err(),
        "token must be unrecoverable without the ML-KEM secret"
    );
}
