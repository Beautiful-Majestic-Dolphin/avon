#![allow(clippy::unwrap_used, clippy::expect_used)]
use avon_ca::keys::{load_or_init, SealedFileProvider};
use avon_ca::pki::{verify_csr, Issuer, PkiError, DEVICE_LIFETIME_SECS};
use avon_crypto::cert::{ChainVerifier, SubjectKind};
use avon_crypto::hybrid::kem::HybridKemKeyPair;
use avon_crypto::hybrid::signature::HybridSigningKeyPair;
use avon_testkit::db::TestDb;
use avon_testkit::pki::make_csr;
use rcgen::{KeyPair, PKCS_ED25519};
use sha2::{Digest, Sha256};
use uuid::Uuid;

async fn keys(db: &TestDb) -> avon_ca::keys::CaKeys {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("m.key");
    SealedFileProvider::generate_master_key(&p).unwrap();
    let prov = SealedFileProvider::from_file(&p).unwrap();
    let k = load_or_init(db.pool(), &prov, true).await.unwrap();
    std::mem::forget(dir);
    k
}

#[tokio::test]
async fn issues_device_credential_that_chains_and_binds_tls_cert() {
    let db = TestDb::new().await;
    let keys = keys(&db).await;
    let signing = HybridSigningKeyPair::generate().unwrap();
    let kem = HybridKemKeyPair::generate().unwrap();
    let tls_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let tenant = "00000000-0000-0000-0000-000000000001";
    let subject = Uuid::new_v4();
    let csr = make_csr(
        &signing,
        &kem.public_key(),
        &tls_key,
        SubjectKind::Device,
        tenant,
        *subject.as_bytes(),
    );

    let data = verify_csr(&csr).unwrap();
    let issued = Issuer { keys: &keys }
        .issue(
            data,
            SubjectKind::Device,
            Some(tenant.parse().unwrap()),
            subject,
            vec![format!("spiffe://avon/{tenant}/device/{subject}")],
            DEVICE_LIFETIME_SECS,
        )
        .unwrap();

    let verifier = ChainVerifier::new(vec![keys.root_cert.clone()]).unwrap();
    let now = chrono::Utc::now().timestamp();
    verifier
        .verify(
            &issued.certificate,
            std::slice::from_ref(&keys.issuing_cert),
            now,
        )
        .unwrap();
    assert_eq!(
        issued.certificate.tbs.tls_cert_sha256.unwrap(),
        <[u8; 32]>::from(Sha256::digest(&issued.tls_cert_der))
    );
    assert_eq!(
        issued.certificate.tbs.kem_key.as_ref().unwrap().to_bytes(),
        kem.public_key().to_bytes()
    );
    assert!(
        issued.not_after - now <= DEVICE_LIFETIME_SECS
            && issued.not_after - now > DEVICE_LIFETIME_SECS - 60
    );

    // X.509 leaf validates against the TLS CA and carries the SPIFFE SAN.
    let (_, leaf) = x509_parser::parse_x509_certificate(&issued.tls_cert_der).unwrap();
    let (_, ca) = x509_parser::parse_x509_certificate(&keys.tls_ca_cert_der).unwrap();
    leaf.verify_signature(Some(ca.public_key())).unwrap();
    let spiffe = avon_tls::spiffe_from_cert_der(&issued.tls_cert_der)
        .unwrap()
        .unwrap();
    assert_eq!(
        spiffe.raw,
        format!("spiffe://avon/{tenant}/device/{subject}")
    );
}

#[tokio::test]
async fn csr_with_bad_proof_is_rejected() {
    let signing = HybridSigningKeyPair::generate().unwrap();
    let other = HybridSigningKeyPair::generate().unwrap();
    let kem = HybridKemKeyPair::generate().unwrap();
    let tls_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut csr = make_csr(
        &signing,
        &kem.public_key(),
        &tls_key,
        SubjectKind::Device,
        "t",
        [3; 16],
    );
    csr.proof = other
        .sign(
            avon_crypto::hybrid::signature::Domain::Csr,
            &csr.tbs_template,
        )
        .unwrap()
        .to_bytes();
    assert!(matches!(verify_csr(&csr), Err(PkiError::CsrProof)));
}

#[tokio::test]
async fn csr_cannot_request_ca_kind_or_non_zero_issuer() {
    let signing = HybridSigningKeyPair::generate().unwrap();
    let kem = HybridKemKeyPair::generate().unwrap();
    let tls_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let csr = make_csr(
        &signing,
        &kem.public_key(),
        &tls_key,
        SubjectKind::IssuingCa,
        "",
        [0; 16],
    );
    assert!(matches!(verify_csr(&csr), Err(PkiError::CsrTemplate(_))));
}

#[tokio::test]
async fn issued_certificates_are_persisted_with_unique_serials() {
    let db = TestDb::new().await;
    let keys = keys(&db).await;
    for _ in 0..3 {
        let signing = HybridSigningKeyPair::generate().unwrap();
        let kem = HybridKemKeyPair::generate().unwrap();
        let tls_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let subject = Uuid::new_v4();
        let csr = make_csr(
            &signing,
            &kem.public_key(),
            &tls_key,
            SubjectKind::Device,
            "00000000-0000-0000-0000-000000000001",
            *subject.as_bytes(),
        );
        let issued = Issuer { keys: &keys }
            .issue(
                verify_csr(&csr).unwrap(),
                SubjectKind::Device,
                Some(avon_db::DEFAULT_TENANT_ID.into()),
                subject,
                vec![],
                DEVICE_LIFETIME_SECS,
            )
            .unwrap();
        avon_ca::pki::store_issued(
            db.pool(),
            &issued,
            Some(avon_db::DEFAULT_TENANT_ID.into()),
            subject,
            "device",
            &keys.issuing.verifying_key().key_id(),
        )
        .await
        .unwrap();
    }
    let (n,): (i64,) = sqlx::query_as("SELECT count(DISTINCT serial) FROM certificates")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(n, 3);
}

#[tokio::test]
async fn issuance_accepts_a_template_with_empty_tenant_and_zero_subject() {
    // A device signs its CSR before enrollment tells it who it is, so control
    // assigns the tenant and device id.
    let db = TestDb::new().await;
    let keys = keys(&db).await;
    let signing = HybridSigningKeyPair::generate().unwrap();
    let kem = HybridKemKeyPair::generate().unwrap();
    let tls_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let csr = make_csr(
        &signing,
        &kem.public_key(),
        &tls_key,
        SubjectKind::Device,
        "",
        [0; 16],
    );
    let subject = Uuid::new_v4();
    let issued = Issuer { keys: &keys }
        .issue(
            verify_csr(&csr).unwrap(),
            SubjectKind::Device,
            Some(avon_db::DEFAULT_TENANT_ID.into()),
            subject,
            vec![],
            DEVICE_LIFETIME_SECS,
        )
        .unwrap();
    assert_eq!(issued.certificate.tbs.subject_id, *subject.as_bytes());
    assert_eq!(
        issued.certificate.tbs.tenant_id,
        avon_db::DEFAULT_TENANT_ID.to_string()
    );
}
