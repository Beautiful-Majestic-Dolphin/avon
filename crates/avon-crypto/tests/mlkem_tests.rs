#![allow(clippy::unwrap_used, clippy::expect_used)]

use avon_crypto::pqc::mlkem::{
    MlKemCiphertext, MlKemKeyPair, MlKemPublicKey, MlKemSecretKey, MLKEM768_CIPHERTEXT_BYTES,
    MLKEM768_PUBLIC_KEY_BYTES, MLKEM768_SECRET_KEY_BYTES,
};

#[test]
fn roundtrip_produces_equal_secrets() {
    let kp = MlKemKeyPair::generate().unwrap();
    let (ct, ss_sender) = kp.public_key().encapsulate().unwrap();
    let ss_receiver = kp.decapsulate(&ct).unwrap();
    assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
}

#[test]
fn sizes_match_fips_203() {
    let kp = MlKemKeyPair::generate().unwrap();
    assert_eq!(kp.public_key().as_bytes().len(), MLKEM768_PUBLIC_KEY_BYTES);
    assert_eq!(kp.secret_key().as_bytes().len(), MLKEM768_SECRET_KEY_BYTES);
    let (ct, _) = kp.public_key().encapsulate().unwrap();
    assert_eq!(ct.as_bytes().len(), MLKEM768_CIPHERTEXT_BYTES);
    assert_eq!(MLKEM768_PUBLIC_KEY_BYTES, 1184);
    assert_eq!(MLKEM768_SECRET_KEY_BYTES, 2400);
    assert_eq!(MLKEM768_CIPHERTEXT_BYTES, 1088);
}

#[test]
fn tampered_ciphertext_yields_different_secret_without_error() {
    // FIPS 203 implicit rejection: decapsulation never fails, it returns a
    // pseudorandom secret unrelated to the sender's.
    let kp = MlKemKeyPair::generate().unwrap();
    let (ct, ss_sender) = kp.public_key().encapsulate().unwrap();
    let mut bytes = ct.as_bytes().to_vec();
    bytes[7] ^= 0x01;
    let tampered = MlKemCiphertext::from_bytes(&bytes).unwrap();
    let ss = kp.decapsulate(&tampered).unwrap();
    assert_ne!(ss.as_bytes(), ss_sender.as_bytes());
}

#[test]
fn wrong_lengths_are_rejected() {
    assert!(MlKemPublicKey::from_bytes(&[0u8; 10]).is_err());
    assert!(MlKemSecretKey::from_bytes(&[0u8; 10]).is_err());
    assert!(MlKemCiphertext::from_bytes(&[0u8; 10]).is_err());
}

#[test]
fn keypair_restores_from_secret_key() {
    let kp = MlKemKeyPair::generate().unwrap();
    let sk = MlKemSecretKey::from_bytes(kp.secret_key().as_bytes()).unwrap();
    let restored = MlKemKeyPair::from_secret_key(sk).unwrap();
    assert_eq!(restored.public_key().as_bytes(), kp.public_key().as_bytes());
    let (ct, ss) = kp.public_key().encapsulate().unwrap();
    assert_eq!(restored.decapsulate(&ct).unwrap().as_bytes(), ss.as_bytes());
}

#[test]
fn different_keypairs_do_not_share_secrets() {
    let a = MlKemKeyPair::generate().unwrap();
    let b = MlKemKeyPair::generate().unwrap();
    let (ct, ss_a) = a.public_key().encapsulate().unwrap();
    let ss_b = b.decapsulate(&ct).unwrap();
    assert_ne!(ss_a.as_bytes(), ss_b.as_bytes());
}
