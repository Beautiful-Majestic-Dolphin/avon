#![allow(clippy::unwrap_used, clippy::expect_used)]

use avon_crypto::hybrid::signature::{
    framed_message, Domain, HybridSignature, HybridSigningKeyPair, HybridVerifyingKey,
    HYBRID_SIGNATURE_BYTES, HYBRID_VERIFYING_KEY_BYTES,
};

#[test]
fn sign_verify_in_domain() {
    let kp = HybridSigningKeyPair::generate().unwrap();
    let sig = kp.sign(Domain::Cert, b"tbs").unwrap();
    kp.verifying_key()
        .verify(Domain::Cert, b"tbs", &sig)
        .unwrap();
}

#[test]
fn signature_is_not_valid_in_another_domain() {
    let kp = HybridSigningKeyPair::generate().unwrap();
    let sig = kp.sign(Domain::Cert, b"tbs").unwrap();
    assert!(kp
        .verifying_key()
        .verify(Domain::Csr, b"tbs", &sig)
        .is_err());
}

#[test]
fn both_components_are_required() {
    let kp = HybridSigningKeyPair::generate().unwrap();
    let sig = kp.sign(Domain::Auth, b"m").unwrap();
    let mut bytes = sig.to_bytes();
    bytes[0] ^= 1; // Ed25519 half
    assert!(kp
        .verifying_key()
        .verify(
            Domain::Auth,
            b"m",
            &HybridSignature::from_bytes(&bytes).unwrap()
        )
        .is_err());
    let mut bytes = sig.to_bytes();
    bytes[64 + 10] ^= 1; // ML-DSA half
    assert!(kp
        .verifying_key()
        .verify(
            Domain::Auth,
            b"m",
            &HybridSignature::from_bytes(&bytes).unwrap()
        )
        .is_err());
}

#[test]
fn framing_is_label_len_message() {
    let framed = framed_message(Domain::Session, b"abc");
    let mut expected = b"AVON-SESSION-V2".to_vec();
    expected.extend_from_slice(&3u32.to_be_bytes());
    expected.extend_from_slice(b"abc");
    assert_eq!(framed, expected);
}

#[test]
fn sizes_and_byte_roundtrips() {
    let kp = HybridSigningKeyPair::generate().unwrap();
    let vk = kp.verifying_key();
    assert_eq!(vk.to_bytes().len(), HYBRID_VERIFYING_KEY_BYTES);
    let sig = kp.sign(Domain::Crl, b"x").unwrap();
    assert_eq!(sig.to_bytes().len(), HYBRID_SIGNATURE_BYTES);
    let vk2 = HybridVerifyingKey::from_bytes(&vk.to_bytes()).unwrap();
    vk2.verify(
        Domain::Crl,
        b"x",
        &HybridSignature::from_bytes(&sig.to_bytes()).unwrap(),
    )
    .unwrap();
    assert_eq!(vk.key_id(), vk2.key_id());
}

#[test]
fn secret_roundtrip() {
    let kp = HybridSigningKeyPair::generate().unwrap();
    let restored = HybridSigningKeyPair::from_secret_bytes(&kp.to_secret_bytes()).unwrap();
    assert_eq!(
        restored.verifying_key().to_bytes(),
        kp.verifying_key().to_bytes()
    );
    let sig = restored.sign(Domain::Offer, b"m").unwrap();
    kp.verifying_key()
        .verify(Domain::Offer, b"m", &sig)
        .unwrap();
}
