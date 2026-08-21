#![allow(clippy::unwrap_used, clippy::expect_used)]
use avon_ca::keys::{load_or_init, KeyError, SealProvider, SealedFileProvider};
use avon_testkit::db::TestDb;

#[tokio::test]
async fn sealed_file_roundtrip_and_aad_binding() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("master.key");
    SealedFileProvider::generate_master_key(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let p = SealedFileProvider::from_file(&path).unwrap();
    let sealed = p.seal(&[1; 32], b"secret").await.unwrap();
    assert_eq!(
        p.unseal(&[1; 32], &sealed).await.unwrap().as_slice(),
        b"secret"
    );
    assert!(matches!(
        p.unseal(&[2; 32], &sealed).await,
        Err(KeyError::Unseal)
    ));
}

#[tokio::test]
async fn init_creates_chain_and_reload_is_stable() {
    let db = TestDb::new().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("master.key");
    SealedFileProvider::generate_master_key(&path).unwrap();
    let p = SealedFileProvider::from_file(&path).unwrap();

    let first = load_or_init(db.pool(), &p, true).await.unwrap();
    let second = load_or_init(db.pool(), &p, false).await.unwrap();
    assert_eq!(first.issuing_cert.id(), second.issuing_cert.id());
    assert_eq!(first.root_cert.id(), second.root_cert.id());
    assert_eq!(first.tls_ca_cert_pem, second.tls_ca_cert_pem);
    // The issuing key works and chains to the root.
    assert!(second
        .issuing_cert
        .verify_signature(&second.root_cert.tbs.signing_key)
        .is_ok());
    // Without init on an empty DB, loading fails loudly.
    let empty = TestDb::new().await;
    assert!(matches!(
        load_or_init(empty.pool(), &p, false).await,
        Err(KeyError::NotInitialized)
    ));
}

#[tokio::test]
async fn wrong_master_key_cannot_unseal_persisted_keys() {
    let db = TestDb::new().await;
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.key");
    let b = dir.path().join("b.key");
    SealedFileProvider::generate_master_key(&a).unwrap();
    SealedFileProvider::generate_master_key(&b).unwrap();
    load_or_init(db.pool(), &SealedFileProvider::from_file(&a).unwrap(), true)
        .await
        .unwrap();
    assert!(matches!(
        load_or_init(
            db.pool(),
            &SealedFileProvider::from_file(&b).unwrap(),
            false
        )
        .await,
        Err(KeyError::Unseal)
    ));
}
