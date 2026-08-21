#![allow(clippy::unwrap_used, clippy::expect_used)]

use avon_crypto::cert::{CertError, Certificate, ChainVerifier, SubjectKind, TbsCertificate};
use avon_crypto::hybrid::kem::HybridKemKeyPair;
use avon_crypto::hybrid::signature::HybridSigningKeyPair;

fn tbs(
    kind: SubjectKind,
    key: &HybridSigningKeyPair,
    issuer: &HybridSigningKeyPair,
    nb: i64,
    na: i64,
) -> TbsCertificate {
    TbsCertificate {
        version: 2,
        serial: [0xAB; 16],
        tenant_id: if matches!(kind, SubjectKind::Device) {
            "00000000-0000-0000-0000-000000000001".into()
        } else {
            String::new()
        },
        subject_id: [0x11; 16],
        kind,
        signing_key: key.verifying_key(),
        kem_key: if matches!(
            kind,
            SubjectKind::Device | SubjectKind::Gateway | SubjectKind::Service
        ) {
            Some(HybridKemKeyPair::generate().unwrap().public_key())
        } else {
            None
        },
        not_before: nb,
        not_after: na,
        issuer_key_id: issuer.verifying_key().key_id(),
        sans: vec!["spiffe://avon/t/device/x".into()],
        tls_cert_sha256: Some([0x22; 32]),
    }
}

struct Pki {
    root_kp: HybridSigningKeyPair,
    root: Certificate,
    issuing_kp: HybridSigningKeyPair,
    issuing: Certificate,
}

fn pki() -> Pki {
    let root_kp = HybridSigningKeyPair::generate().unwrap();
    let root = Certificate::sign(
        tbs(SubjectKind::RootCa, &root_kp, &root_kp, 0, 4_000_000_000),
        &root_kp,
    )
    .unwrap();
    let issuing_kp = HybridSigningKeyPair::generate().unwrap();
    let issuing = Certificate::sign(
        tbs(
            SubjectKind::IssuingCa,
            &issuing_kp,
            &root_kp,
            0,
            3_000_000_000,
        ),
        &root_kp,
    )
    .unwrap();
    Pki {
        root_kp,
        root,
        issuing_kp,
        issuing,
    }
}

#[test]
fn encode_decode_roundtrip() {
    let p = pki();
    let bytes = p.issuing.encode();
    let decoded = Certificate::decode(&bytes).unwrap();
    assert_eq!(decoded, p.issuing);
    assert_eq!(decoded.id(), p.issuing.id());
}

#[test]
fn valid_chain_verifies() {
    let p = pki();
    let dev_kp = HybridSigningKeyPair::generate().unwrap();
    let leaf = Certificate::sign(
        tbs(SubjectKind::Device, &dev_kp, &p.issuing_kp, 1_000, 2_000),
        &p.issuing_kp,
    )
    .unwrap();
    let v = ChainVerifier::new(vec![p.root.clone()]).unwrap();
    let verified = v
        .verify(&leaf, std::slice::from_ref(&p.issuing), 1_500)
        .unwrap();
    assert_eq!(verified.chain, vec![p.root.id(), p.issuing.id(), leaf.id()]);
}

#[test]
fn expired_and_not_yet_valid_are_rejected() {
    let p = pki();
    let dev_kp = HybridSigningKeyPair::generate().unwrap();
    let leaf = Certificate::sign(
        tbs(SubjectKind::Device, &dev_kp, &p.issuing_kp, 1_000, 2_000),
        &p.issuing_kp,
    )
    .unwrap();
    let v = ChainVerifier::new(vec![p.root.clone()]).unwrap();
    assert!(matches!(
        v.verify(&leaf, std::slice::from_ref(&p.issuing), 2_001),
        Err(CertError::Expired)
    ));
    assert!(matches!(
        v.verify(&leaf, std::slice::from_ref(&p.issuing), 999),
        Err(CertError::NotYetValid)
    ));
}

#[test]
fn leaf_signed_by_unknown_issuer_is_rejected() {
    let p = pki();
    let rogue = HybridSigningKeyPair::generate().unwrap();
    let dev_kp = HybridSigningKeyPair::generate().unwrap();
    let leaf = Certificate::sign(
        tbs(SubjectKind::Device, &dev_kp, &rogue, 1_000, 2_000),
        &rogue,
    )
    .unwrap();
    let v = ChainVerifier::new(vec![p.root.clone()]).unwrap();
    assert!(matches!(
        v.verify(&leaf, std::slice::from_ref(&p.issuing), 1_500),
        Err(CertError::UnknownIssuer)
    ));
}

#[test]
fn tampered_tbs_fails_signature() {
    let p = pki();
    let mut bytes = p.issuing.encode();
    bytes[4 + 1 + 3] ^= 1; // inside serial
    let tampered = Certificate::decode(&bytes).unwrap();
    assert!(matches!(
        tampered.verify_signature(&p.root_kp.verifying_key()),
        Err(CertError::Signature)
    ));
}

#[test]
fn a_device_cert_cannot_act_as_an_issuer() {
    let p = pki();
    let dev_kp = HybridSigningKeyPair::generate().unwrap();
    let dev = Certificate::sign(
        tbs(
            SubjectKind::Device,
            &dev_kp,
            &p.issuing_kp,
            0,
            9_000_000_000,
        ),
        &dev_kp,
    )
    .unwrap();
    let victim_kp = HybridSigningKeyPair::generate().unwrap();
    let forged = Certificate::sign(
        tbs(SubjectKind::Device, &victim_kp, &dev_kp, 0, 9_000_000_000),
        &dev_kp,
    )
    .unwrap();
    let v = ChainVerifier::new(vec![p.root.clone()]).unwrap();
    let err = v.verify(&forged, &[p.issuing.clone(), dev], 1).unwrap_err();
    assert!(
        matches!(err, CertError::WrongKind { .. } | CertError::UnknownIssuer),
        "{err:?}"
    );
}

#[test]
fn truncated_and_garbage_inputs_do_not_panic() {
    let p = pki();
    let bytes = p.root.encode();
    for cut in [0usize, 1, 4, 5, 40, bytes.len() - 1] {
        assert!(Certificate::decode(&bytes[..cut]).is_err());
    }
    assert!(Certificate::decode(&[0xFF; 7000]).is_err());
}

#[test]
fn root_must_be_self_signed_root_kind() {
    let p = pki();
    assert!(ChainVerifier::new(vec![p.issuing.clone()]).is_err());
}
