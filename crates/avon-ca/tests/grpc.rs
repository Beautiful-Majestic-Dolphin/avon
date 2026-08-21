#![allow(clippy::unwrap_used, clippy::expect_used)]
use avon_crypto::cert::{Certificate, ChainVerifier, SubjectKind};
use avon_crypto::hybrid::kem::HybridKemKeyPair;
use avon_crypto::hybrid::signature::HybridSigningKeyPair;
use avon_protocol::v2::{Empty, IssueDeviceRequest, RevokeRequest, Uuid as PbUuid};
use avon_testkit::{
    db::TestDb,
    pki::{make_csr, TestPki},
    services::{ca_client, spawn_ca},
};
use rcgen::{KeyPair, PKCS_ED25519};

#[tokio::test]
async fn control_can_issue_and_revoke_but_gateway_cannot() {
    let db = TestDb::new().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = spawn_ca(&db, &pki, dir.path()).await;

    let mut control = ca_client(&pki, dir.path(), ca.addr, "spiffe://avon/service/control").await;
    let chain = control.get_chain(Empty {}).await.unwrap().into_inner();
    let root = Certificate::decode(&chain.root.unwrap().encoded).unwrap();
    let issuing = Certificate::decode(&chain.issuing.unwrap().encoded).unwrap();

    let signing = HybridSigningKeyPair::generate().unwrap();
    let kem = HybridKemKeyPair::generate().unwrap();
    let tls_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let device = uuid::Uuid::new_v4();
    let tenant = avon_db::DEFAULT_TENANT_ID;
    let csr = make_csr(
        &signing,
        &kem.public_key(),
        &tls_key,
        SubjectKind::Device,
        &tenant.to_string(),
        *device.as_bytes(),
    );
    let resp = control
        .issue_device_credential(IssueDeviceRequest {
            tenant_id: Some(PbUuid {
                value: tenant.as_bytes().to_vec(),
            }),
            device_id: Some(PbUuid {
                value: device.as_bytes().to_vec(),
            }),
            csr: Some(csr),
            kind: 3,
            sans: vec![format!("spiffe://avon/{tenant}/device/{device}")],
        })
        .await
        .unwrap()
        .into_inner();
    let cred = resp.credential.unwrap();
    let leaf = Certificate::decode(&cred.certificate.unwrap().encoded).unwrap();
    ChainVerifier::new(vec![root])
        .unwrap()
        .verify(
            &leaf,
            std::slice::from_ref(&issuing),
            chrono::Utc::now().timestamp(),
        )
        .unwrap();

    let crl = control
        .revoke(RevokeRequest {
            serial: resp.serial.clone(),
            reason: "test".into(),
        })
        .await
        .unwrap()
        .into_inner();
    let parsed =
        avon_crypto::cert::crl::Crl::verify(&crl.tbs, &crl.signature, &issuing.tbs.signing_key)
            .unwrap();
    assert!(parsed.contains(&resp.serial.as_slice().try_into().unwrap()));

    let mut gateway = ca_client(
        &pki,
        dir.path(),
        ca.addr,
        "spiffe://avon/service/gateway/00000000-0000-0000-0000-000000000009",
    )
    .await;
    let err = gateway.current_crl(Empty {}).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    ca.shutdown();
}
