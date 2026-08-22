#![allow(clippy::unwrap_used)]
use avon_common::ids::SessionId;
use avon_crypto::aead::Suite;
use avon_crypto::cert::{Certificate, SubjectKind, TbsCertificate};
use avon_crypto::hybrid::kem::HybridKemKeyPair;
use avon_crypto::hybrid::signature::HybridSigningKeyPair;
use avon_tunnel::{choose_suite, rekey_answer, rekey_complete, rekey_offer, Initiator, Responder};

struct Party {
    signing: HybridSigningKeyPair,
    kem: HybridKemKeyPair,
    cert: Certificate,
}

fn party(kind: SubjectKind) -> Party {
    let issuer = HybridSigningKeyPair::generate().unwrap();
    let signing = HybridSigningKeyPair::generate().unwrap();
    let kem = HybridKemKeyPair::generate().unwrap();
    let cert = Certificate::sign(
        TbsCertificate {
            version: 2,
            serial: [1; 16],
            tenant_id: "t".into(),
            subject_id: [2; 16],
            kind,
            signing_key: signing.verifying_key(),
            kem_key: Some(kem.public_key()),
            not_before: 0,
            not_after: i64::MAX,
            issuer_key_id: issuer.verifying_key().key_id(),
            sans: vec![],
            tls_cert_sha256: None,
        },
        &issuer,
    )
    .unwrap();
    Party { signing, kem, cert }
}

#[test]
fn both_sides_establish_identical_keys_and_responder_is_authenticated() {
    let device = party(SubjectKind::Device);
    let gateway = party(SubjectKind::Gateway);
    let sid = SessionId::random().unwrap();
    let pending = Initiator::offer(&[Suite::Aes256Gcm, Suite::ChaCha20Poly1305]).unwrap();
    let (answer, gw_est) = Responder::answer(
        sid,
        &device.cert,
        &pending.eph_pk_bytes,
        Suite::Aes256Gcm,
        gateway.cert.id(),
        &gateway.signing,
        42,
        Some("gw:4600".into()),
    )
    .unwrap();
    let dev_est = Initiator::complete(
        pending,
        &answer,
        sid,
        device.cert.id(),
        &device.kem,
        &gateway.cert,
    )
    .unwrap();
    assert_eq!(dev_est.keys.k_i2r, gw_est.keys.k_i2r);
    assert_eq!(dev_est.keys.k_r2i, gw_est.keys.k_r2i);
    assert_eq!(dev_est.transcript_hash, gw_est.transcript_hash);
    assert_eq!(answer.responder_index, 42);
}

#[test]
fn answer_signed_by_someone_else_is_rejected() {
    let device = party(SubjectKind::Device);
    let gateway = party(SubjectKind::Gateway);
    let impostor = party(SubjectKind::Gateway);
    let sid = SessionId::random().unwrap();
    let pending = Initiator::offer(&[Suite::Aes256Gcm]).unwrap();
    let (answer, _) = Responder::answer(
        sid,
        &device.cert,
        &pending.eph_pk_bytes,
        Suite::Aes256Gcm,
        impostor.cert.id(),
        &impostor.signing,
        1,
        None,
    )
    .unwrap();
    assert!(Initiator::complete(
        pending,
        &answer,
        sid,
        device.cert.id(),
        &device.kem,
        &gateway.cert
    )
    .is_err());
}

#[test]
fn wrong_static_kem_secret_yields_different_keys() {
    // A device without the certificate's ML-KEM secret cannot derive the session keys.
    let device = party(SubjectKind::Device);
    let other_kem = HybridKemKeyPair::generate().unwrap();
    let gateway = party(SubjectKind::Gateway);
    let sid = SessionId::random().unwrap();
    let pending = Initiator::offer(&[Suite::Aes256Gcm]).unwrap();
    let (answer, gw_est) = Responder::answer(
        sid,
        &device.cert,
        &pending.eph_pk_bytes,
        Suite::Aes256Gcm,
        gateway.cert.id(),
        &gateway.signing,
        1,
        None,
    )
    .unwrap();
    let dev_est = Initiator::complete(
        pending,
        &answer,
        sid,
        device.cert.id(),
        &other_kem,
        &gateway.cert,
    )
    .unwrap();
    assert_ne!(dev_est.keys.k_i2r, gw_est.keys.k_i2r);
}

#[test]
fn suite_choice_prefers_responder_order() {
    assert_eq!(
        choose_suite(
            &[Suite::ChaCha20Poly1305, Suite::Aes256Gcm],
            &[Suite::Aes256Gcm, Suite::ChaCha20Poly1305]
        ),
        Some(Suite::Aes256Gcm)
    );
    assert_eq!(
        choose_suite(&[Suite::ChaCha20Poly1305], &[Suite::Aes256Gcm]),
        None
    );
}

#[test]
fn rekey_round_trip() {
    let device = party(SubjectKind::Device);
    let gateway = party(SubjectKind::Gateway);
    let sid = SessionId::random().unwrap();
    let pending = Initiator::offer(&[Suite::Aes256Gcm]).unwrap();
    let (answer, gw_est) = Responder::answer(
        sid,
        &device.cert,
        &pending.eph_pk_bytes,
        Suite::Aes256Gcm,
        gateway.cert.id(),
        &gateway.signing,
        1,
        None,
    )
    .unwrap();
    let dev_est = Initiator::complete(
        pending,
        &answer,
        sid,
        device.cert.id(),
        &device.kem,
        &gateway.cert,
    )
    .unwrap();

    let (eph, eph_pk) = rekey_offer().unwrap();
    let (ct, gw_next) = rekey_answer(&eph_pk, &gw_est.keys).unwrap();
    let dev_next = rekey_complete(&eph, &ct, &dev_est.keys).unwrap();
    assert_eq!(gw_next.epoch, 1);
    assert_eq!(gw_next.k_i2r, dev_next.k_i2r);
    assert_ne!(gw_next.k_i2r, gw_est.keys.k_i2r);
}
