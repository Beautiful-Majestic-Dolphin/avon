#![allow(clippy::unwrap_used, clippy::expect_used)]

use avon_crypto::pqc::mldsa::{
    MlDsaKeyPair, MlDsaSignature, MlDsaSigningKey, MlDsaVerifyingKey, MLDSA65_PUBLIC_KEY_BYTES,
    MLDSA65_SECRET_KEY_BYTES, MLDSA65_SIGNATURE_BYTES,
};

#[test]
fn sign_verify_roundtrip() {
    let kp = MlDsaKeyPair::generate().unwrap();
    let sig = kp.sign(b"hello").unwrap();
    kp.verifying_key().verify(b"hello", &sig).unwrap();
}

#[test]
fn sizes_match_fips_204() {
    let kp = MlDsaKeyPair::generate().unwrap();
    assert_eq!(
        kp.verifying_key().as_bytes().len(),
        MLDSA65_PUBLIC_KEY_BYTES
    );
    assert_eq!(kp.signing_key().as_bytes().len(), MLDSA65_SECRET_KEY_BYTES);
    assert_eq!(
        kp.sign(b"x").unwrap().as_bytes().len(),
        MLDSA65_SIGNATURE_BYTES
    );
    assert_eq!(
        (
            MLDSA65_PUBLIC_KEY_BYTES,
            MLDSA65_SECRET_KEY_BYTES,
            MLDSA65_SIGNATURE_BYTES
        ),
        (1952, 4032, 3309)
    );
}

#[test]
fn modified_message_fails() {
    let kp = MlDsaKeyPair::generate().unwrap();
    let sig = kp.sign(b"hello").unwrap();
    assert!(kp.verifying_key().verify(b"hellp", &sig).is_err());
}

#[test]
fn modified_signature_fails() {
    let kp = MlDsaKeyPair::generate().unwrap();
    let sig = kp.sign(b"hello").unwrap();
    let mut bytes = sig.as_bytes().to_vec();
    bytes[100] ^= 0xff;
    let bad = MlDsaSignature::from_bytes(&bytes).unwrap();
    assert!(kp.verifying_key().verify(b"hello", &bad).is_err());
}

#[test]
fn other_key_fails() {
    let a = MlDsaKeyPair::generate().unwrap();
    let b = MlDsaKeyPair::generate().unwrap();
    let sig = a.sign(b"hello").unwrap();
    assert!(b.verifying_key().verify(b"hello", &sig).is_err());
}

#[test]
fn keys_roundtrip_through_bytes() {
    let kp = MlDsaKeyPair::generate().unwrap();
    let sk = MlDsaSigningKey::from_bytes(kp.signing_key().as_bytes()).unwrap();
    let vk = MlDsaVerifyingKey::from_bytes(kp.verifying_key().as_bytes()).unwrap();
    let restored = MlDsaKeyPair::from_keys(sk, vk);
    let sig = restored.sign(b"persisted").unwrap();
    kp.verifying_key().verify(b"persisted", &sig).unwrap();
}

#[test]
fn wrong_lengths_rejected() {
    assert!(MlDsaVerifyingKey::from_bytes(&[0u8; 3]).is_err());
    assert!(MlDsaSigningKey::from_bytes(&[0u8; 3]).is_err());
    assert!(MlDsaSignature::from_bytes(&[0u8; 3]).is_err());
}
