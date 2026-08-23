#![allow(clippy::unwrap_used)]
use avon_agent_core::identity::{enroll, load};
use avon_keystore::ProviderChoice;
use avon_testkit::{
    agent_fixture::{insert_token, TestFingerprint},
    db::TestDb,
    pki::TestPki,
    services::{spawn_ca, spawn_control},
};

#[tokio::test]
async fn enroll_writes_0600_files_and_reloads() {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;
    let f = spawn_control(db, pki, dir, ca).await;
    insert_token(&f, "tok", 1).await;
    let data = tempfile::tempdir().unwrap();
    let ca_pem = std::fs::read(f.trust_bundle()).unwrap();
    let id = enroll(
        &format!("https://localhost:{}", f.control.addr.port()),
        "tok",
        data.path(),
        &ca_pem,
        "localhost",
        ProviderChoice::Software,
        &TestFingerprint,
        "test",
    )
    .await
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in ["identity.bin", "identity.key", "identity.json"] {
            let mode = std::fs::metadata(data.path().join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{name}");
        }
        assert_eq!(
            std::fs::metadata(data.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    let reloaded = load(data.path()).await.unwrap();
    assert_eq!(reloaded.device_id, id.device_id);
    assert_eq!(reloaded.certificate.id(), id.certificate.id());
    assert_eq!(
        reloaded.provider.signing_public().to_bytes(),
        id.provider.signing_public().to_bytes()
    );
}

#[tokio::test]
async fn enroll_refuses_to_overwrite_an_existing_identity() {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;
    let f = spawn_control(db, pki, dir, ca).await;
    insert_token(&f, "tok", 2).await;
    let data = tempfile::tempdir().unwrap();
    let ca_pem = std::fs::read(f.trust_bundle()).unwrap();
    let url = format!("https://localhost:{}", f.control.addr.port());
    enroll(
        &url,
        "tok",
        data.path(),
        &ca_pem,
        "localhost",
        ProviderChoice::Software,
        &TestFingerprint,
        "test",
    )
    .await
    .unwrap();
    assert!(enroll(
        &url,
        "tok",
        data.path(),
        &ca_pem,
        "localhost",
        ProviderChoice::Software,
        &TestFingerprint,
        "test"
    )
    .await
    .is_err());
}
