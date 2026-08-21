#![allow(clippy::unwrap_used, clippy::expect_used)]

use avon_crypto::hybrid::kem::{
    combine, HybridKemCiphertext, HybridKemKeyPair, HybridKemPublicKey,
    HYBRID_KEM_CIPHERTEXT_BYTES, HYBRID_KEM_PUBLIC_KEY_BYTES,
};
use sha2::{Digest, Sha256};

#[test]
fn roundtrip() {
    let kp = HybridKemKeyPair::generate().unwrap();
    let (ct, ss_a) = kp.public_key().encapsulate().unwrap();
    let ss_b = kp.decapsulate(&ct).unwrap();
    assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
}

#[test]
fn serialized_sizes() {
    let kp = HybridKemKeyPair::generate().unwrap();
    assert_eq!(
        kp.public_key().to_bytes().len(),
        HYBRID_KEM_PUBLIC_KEY_BYTES
    );
    let (ct, _) = kp.public_key().encapsulate().unwrap();
    assert_eq!(ct.to_bytes().len(), HYBRID_KEM_CIPHERTEXT_BYTES);
    assert_eq!(HYBRID_KEM_PUBLIC_KEY_BYTES, 32 + 1184);
    assert_eq!(HYBRID_KEM_CIPHERTEXT_BYTES, 32 + 1088);
}

#[test]
fn public_key_and_ciphertext_roundtrip_bytes() {
    let kp = HybridKemKeyPair::generate().unwrap();
    let pk = HybridKemPublicKey::from_bytes(&kp.public_key().to_bytes()).unwrap();
    let (ct, ss) = pk.encapsulate().unwrap();
    let ct2 = HybridKemCiphertext::from_bytes(&ct.to_bytes()).unwrap();
    assert_eq!(kp.decapsulate(&ct2).unwrap().as_bytes(), ss.as_bytes());
}

#[test]
fn combiner_binds_the_mlkem_ciphertext() {
    // Flipping a ciphertext byte changes the ML-KEM secret (implicit rejection)
    // AND is bound into the combiner; either way the result differs.
    let kp = HybridKemKeyPair::generate().unwrap();
    let (ct, ss) = kp.public_key().encapsulate().unwrap();
    let mut bytes = ct.to_bytes();
    bytes[40] ^= 1; // inside the ML-KEM ciphertext region
    let bad = HybridKemCiphertext::from_bytes(&bytes).unwrap();
    assert_ne!(kp.decapsulate(&bad).unwrap().as_bytes(), ss.as_bytes());
}

#[test]
fn combiner_binds_the_x25519_ephemeral_key() {
    let kp = HybridKemKeyPair::generate().unwrap();
    let (ct, ss) = kp.public_key().encapsulate().unwrap();
    let mut bytes = ct.to_bytes();
    bytes[3] ^= 1; // inside the X25519 ephemeral public key
    let bad = HybridKemCiphertext::from_bytes(&bytes).unwrap();
    assert_ne!(kp.decapsulate(&bad).unwrap().as_bytes(), ss.as_bytes());
}

#[test]
fn combine_is_sha256_over_labelled_transcript() {
    let ss_x = [1u8; 32];
    let ss_m = [2u8; 32];
    let eph = [3u8; 32];
    let xpk = [4u8; 32];
    let ct = vec![5u8; 1088];
    let mpk = vec![6u8; 1184];
    let got = combine(&ss_x, &ss_m, &eph, &xpk, &ct, &mpk);
    let mut h = Sha256::new();
    h.update(b"AVON-HYBRID-KEM-V2");
    h.update(ss_x);
    h.update(ss_m);
    h.update(eph);
    h.update(xpk);
    h.update(&ct);
    h.update(&mpk);
    let expected: [u8; 32] = h.finalize().into();
    assert_eq!(got, expected);
}

#[test]
fn secret_bytes_roundtrip() {
    let kp = HybridKemKeyPair::generate().unwrap();
    let restored = HybridKemKeyPair::from_secret_bytes(&kp.to_secret_bytes()).unwrap();
    assert_eq!(restored.public_key().to_bytes(), kp.public_key().to_bytes());
    let (ct, ss) = kp.public_key().encapsulate().unwrap();
    assert_eq!(restored.decapsulate(&ct).unwrap().as_bytes(), ss.as_bytes());
    assert!(HybridKemKeyPair::from_secret_bytes(&[0u8; 5]).is_err());
}
