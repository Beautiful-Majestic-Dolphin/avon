#![allow(clippy::unwrap_used, clippy::expect_used)]
use avon_protocol::v2::RenewRequest;
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
async fn renewal_issues_a_new_certificate_for_the_same_device() {
    let f = fixture().await;
    let mut dev = TestDevice::enroll(&f, "tok").await;
    let mut client = dev.authenticate(&f).await.unwrap();
    let csr = dev.new_csr();
    let cred = client
        .renew_credential(RenewRequest { csr: Some(csr) })
        .await
        .unwrap()
        .into_inner()
        .credential
        .unwrap();
    let cert = avon_crypto::cert::Certificate::decode(&cred.certificate.unwrap().encoded).unwrap();
    assert_eq!(cert.tbs.subject_id, *dev.device_id.as_bytes());
    assert_ne!(cert.tbs.serial, dev.certificate.tbs.serial);
    dev.adopt(cred.tls_certificate_pem, cert);
    dev.authenticate(&f).await.unwrap();
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM certificates WHERE subject_id = $1")
        .bind(dev.device_id)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(n, 2);
}
