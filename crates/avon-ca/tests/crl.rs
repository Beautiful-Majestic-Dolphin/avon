#![allow(clippy::unwrap_used, clippy::expect_used)]
use avon_ca::keys::{load_or_init, SealedFileProvider};
use avon_ca::pki::{current_crl, revoke};
use avon_crypto::cert::crl::Crl;
use avon_testkit::db::TestDb;

#[tokio::test]
async fn revocation_produces_a_verifiable_monotonic_crl() {
    let db = TestDb::new().await;
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("m.key");
    SealedFileProvider::generate_master_key(&p).unwrap();
    let keys = load_or_init(db.pool(), &SealedFileProvider::from_file(&p).unwrap(), true)
        .await
        .unwrap();

    let first = current_crl(db.pool(), &keys).await.unwrap();
    let c1 = Crl::verify(&first.tbs, &first.signature, &keys.issuing.verifying_key()).unwrap();
    assert_eq!(c1.version, 1);
    assert!(c1.serials.is_empty());

    // Insert a certificate row to revoke.
    sqlx::query(
        "INSERT INTO certificates (serial, subject_id, kind, certificate, tls_certificate_der, \
         not_before, not_after, issuer_key_id) \
         VALUES ($1, gen_random_uuid(), 'device', '\\x00', '\\x00', now(), now() + interval '1 day', $2)",
    )
    .bind(&[9u8; 16][..])
    .bind(&keys.issuing.verifying_key().key_id()[..])
    .execute(db.pool())
    .await
    .unwrap();

    let second = revoke(db.pool(), &keys, &[9; 16], "key compromise")
        .await
        .unwrap();
    let c2 = Crl::verify(
        &second.tbs,
        &second.signature,
        &keys.issuing.verifying_key(),
    )
    .unwrap();
    assert_eq!(c2.version, 2);
    assert!(c2.contains(&[9; 16]));

    // Tampering breaks verification.
    let mut bad = second.tbs.clone();
    bad[8] ^= 1;
    assert!(Crl::verify(&bad, &second.signature, &keys.issuing.verifying_key()).is_err());

    // Revoking an unknown serial is an error; revoking twice is idempotent.
    assert!(revoke(db.pool(), &keys, &[1; 16], "x").await.is_err());
    let third = revoke(db.pool(), &keys, &[9; 16], "again").await.unwrap();
    assert_eq!(
        Crl::verify(&third.tbs, &third.signature, &keys.issuing.verifying_key())
            .unwrap()
            .version,
        3
    );
}
