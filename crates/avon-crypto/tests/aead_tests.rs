#![allow(clippy::unwrap_used, clippy::expect_used)]

use avon_crypto::aead::{AeadKey, Suite};

fn suites() -> [Suite; 2] {
    [Suite::Aes256Gcm, Suite::ChaCha20Poly1305]
}

#[test]
fn seal_open_roundtrip_all_suites() {
    for suite in suites() {
        let key = AeadKey::new(suite, &[7u8; 32]);
        let mut buf = b"payload".to_vec();
        key.seal_in_place(&[1u8; 12], b"aad", &mut buf).unwrap();
        assert_eq!(buf.len(), 7 + Suite::TAG_LEN);
        key.open_in_place(&[1u8; 12], b"aad", &mut buf).unwrap();
        assert_eq!(buf, b"payload");
    }
}

#[test]
fn wrong_aad_or_nonce_or_tag_fails() {
    for suite in suites() {
        let key = AeadKey::new(suite, &[7u8; 32]);
        let mut sealed = b"payload".to_vec();
        key.seal_in_place(&[1u8; 12], b"aad", &mut sealed).unwrap();

        let mut b = sealed.clone();
        assert!(key.open_in_place(&[1u8; 12], b"bad", &mut b).is_err());
        let mut b = sealed.clone();
        assert!(key.open_in_place(&[2u8; 12], b"aad", &mut b).is_err());
        let mut b = sealed.clone();
        let last = b.len() - 1;
        b[last] ^= 1;
        assert!(key.open_in_place(&[1u8; 12], b"aad", &mut b).is_err());
        let mut short = vec![0u8; 5];
        assert!(key.open_in_place(&[1u8; 12], b"aad", &mut short).is_err());
    }
}

#[test]
fn suite_ids_are_stable() {
    assert_eq!(Suite::Aes256Gcm.id(), 1);
    assert_eq!(Suite::ChaCha20Poly1305.id(), 2);
    assert_eq!(Suite::from_id(1), Some(Suite::Aes256Gcm));
    assert_eq!(Suite::from_id(2), Some(Suite::ChaCha20Poly1305));
    assert_eq!(Suite::from_id(3), None);
}

#[test]
fn aes_gcm_matches_known_vector() {
    // NIST GCM test case (AES-256, 96-bit IV, empty AAD): key/iv/pt/ct/tag from gcmEncryptExtIV256 count 0.
    let key =
        hex::decode("b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4").unwrap();
    let iv = hex::decode("516c33929df5a3284ff463d7").unwrap();
    let mut buf = Vec::new(); // empty plaintext
    let k = AeadKey::new(Suite::Aes256Gcm, key.as_slice().try_into().unwrap());
    k.seal_in_place(iv.as_slice().try_into().unwrap(), b"", &mut buf)
        .unwrap();
    assert_eq!(hex::encode(&buf), "bdc1ac884d332457a1d2664f168c76f0");
}
