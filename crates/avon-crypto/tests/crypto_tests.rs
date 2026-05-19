//! Comprehensive tests for AVON cryptographic primitives.
//!
//! This module contains tests including RFC test vectors for HKDF and HMAC.

use avon_crypto::{
    aead::Aes256GcmCipher,
    error::CryptoError,
    hmac::{hmac_sha256, hmac_sha256_verify},
    kdf::{hkdf_sha256, hkdf_sha384},
    random::{random_bytes, random_bytes_fixed},
};

// =============================================================================
// AES-GCM Tests
// =============================================================================

mod aes_gcm_tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key: [u8; 32] = random_bytes_fixed().unwrap();
        let cipher = Aes256GcmCipher::new(&key).unwrap();

        let nonce: [u8; 12] = random_bytes_fixed().unwrap();
        let plaintext = b"Hello, AVON! This is a test message.";
        let aad = b"additional authenticated data";

        let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_empty_plaintext() {
        let key: [u8; 32] = random_bytes_fixed().unwrap();
        let cipher = Aes256GcmCipher::new(&key).unwrap();

        let nonce: [u8; 12] = random_bytes_fixed().unwrap();
        let plaintext = b"";
        let aad = b"aad";

        let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_empty_aad() {
        let key: [u8; 32] = random_bytes_fixed().unwrap();
        let cipher = Aes256GcmCipher::new(&key).unwrap();

        let nonce: [u8; 12] = random_bytes_fixed().unwrap();
        let plaintext = b"test message";
        let aad = b"";

        let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1: [u8; 32] = random_bytes_fixed().unwrap();
        let key2: [u8; 32] = random_bytes_fixed().unwrap();

        let cipher1 = Aes256GcmCipher::new(&key1).unwrap();
        let cipher2 = Aes256GcmCipher::new(&key2).unwrap();

        let nonce: [u8; 12] = random_bytes_fixed().unwrap();
        let plaintext = b"secret message";
        let aad = b"aad";

        let ciphertext = cipher1.encrypt(&nonce, plaintext, aad).unwrap();
        let result = cipher2.decrypt(&nonce, &ciphertext, aad);

        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::DecryptionFailed(_))));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key: [u8; 32] = random_bytes_fixed().unwrap();
        let cipher = Aes256GcmCipher::new(&key).unwrap();

        let nonce: [u8; 12] = random_bytes_fixed().unwrap();
        let plaintext = b"secret message";
        let aad = b"aad";

        let mut ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();

        // Tamper with the ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xff;
        }

        let result = cipher.decrypt(&nonce, &ciphertext, aad);
        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::DecryptionFailed(_))));
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key: [u8; 32] = random_bytes_fixed().unwrap();
        let cipher = Aes256GcmCipher::new(&key).unwrap();

        let nonce: [u8; 12] = random_bytes_fixed().unwrap();
        let plaintext = b"secret message";
        let aad1 = b"correct aad";
        let aad2 = b"wrong aad";

        let ciphertext = cipher.encrypt(&nonce, plaintext, aad1).unwrap();
        let result = cipher.decrypt(&nonce, &ciphertext, aad2);

        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::DecryptionFailed(_))));
    }

    #[test]
    fn test_wrong_nonce_fails() {
        let key: [u8; 32] = random_bytes_fixed().unwrap();
        let cipher = Aes256GcmCipher::new(&key).unwrap();

        let nonce1: [u8; 12] = random_bytes_fixed().unwrap();
        let nonce2: [u8; 12] = random_bytes_fixed().unwrap();
        let plaintext = b"secret message";
        let aad = b"aad";

        let ciphertext = cipher.encrypt(&nonce1, plaintext, aad).unwrap();
        let result = cipher.decrypt(&nonce2, &ciphertext, aad);

        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::DecryptionFailed(_))));
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = [0u8; 16];
        let result = Aes256GcmCipher::new(&short_key);

        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 16
            })
        ));
    }
}

// =============================================================================
// HKDF Tests - RFC 5869 Test Vectors
// =============================================================================

mod hkdf_tests {
    use super::*;

    // RFC 5869 Test Case 1
    #[test]
    fn test_hkdf_sha256_rfc5869_test_case_1() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let expected_okm = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();

        let okm = hkdf_sha256(&ikm, Some(&salt), &info, 42).unwrap();
        assert_eq!(okm, expected_okm);
    }

    // RFC 5869 Test Case 2
    #[test]
    fn test_hkdf_sha256_rfc5869_test_case_2() {
        let ikm = hex::decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f",
        )
        .unwrap();
        let salt = hex::decode(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        )
        .unwrap();
        let info = hex::decode(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        )
        .unwrap();
        let expected_okm = hex::decode(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87",
        )
        .unwrap();

        let okm = hkdf_sha256(&ikm, Some(&salt), &info, 82).unwrap();
        assert_eq!(okm, expected_okm);
    }

    // RFC 5869 Test Case 3 - Zero-length salt and info
    #[test]
    fn test_hkdf_sha256_rfc5869_test_case_3() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let expected_okm = hex::decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8",
        )
        .unwrap();

        let okm = hkdf_sha256(&ikm, None, &[], 42).unwrap();
        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn test_hkdf_sha384_basic() {
        let ikm = b"input key material";
        let salt = Some(b"salt value".as_slice());
        let info = b"application context";

        let okm = hkdf_sha384(ikm, salt, info, 48).unwrap();
        assert_eq!(okm.len(), 48);

        // Verify determinism
        let okm2 = hkdf_sha384(ikm, salt, info, 48).unwrap();
        assert_eq!(okm, okm2);
    }

    #[test]
    fn test_hkdf_different_info_produces_different_output() {
        let ikm = b"input key material";
        let salt = Some(b"salt".as_slice());

        let okm1 = hkdf_sha256(ikm, salt, b"info1", 32).unwrap();
        let okm2 = hkdf_sha256(ikm, salt, b"info2", 32).unwrap();

        assert_ne!(okm1, okm2);
    }
}

// =============================================================================
// HMAC Tests - RFC 4231 Test Vectors
// =============================================================================

mod hmac_tests {
    use super::*;

    // RFC 4231 Test Case 1
    #[test]
    fn test_hmac_sha256_rfc4231_test_case_1() {
        let key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = b"Hi There";
        let expected =
            hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
                .unwrap();

        let tag = hmac_sha256(&key, data);
        assert_eq!(tag.as_slice(), expected.as_slice());
    }

    // RFC 4231 Test Case 2
    #[test]
    fn test_hmac_sha256_rfc4231_test_case_2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected =
            hex::decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
                .unwrap();

        let tag = hmac_sha256(key, data);
        assert_eq!(tag.as_slice(), expected.as_slice());
    }

    // RFC 4231 Test Case 3
    #[test]
    fn test_hmac_sha256_rfc4231_test_case_3() {
        let key = hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let data = hex::decode(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\
             dddddddddddddddddddddddddddddddddddd",
        )
        .unwrap();
        let expected =
            hex::decode("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
                .unwrap();

        let tag = hmac_sha256(&key, &data);
        assert_eq!(tag.as_slice(), expected.as_slice());
    }

    // RFC 4231 Test Case 4
    #[test]
    fn test_hmac_sha256_rfc4231_test_case_4() {
        let key = hex::decode("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap();
        let data = hex::decode(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
             cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        )
        .unwrap();
        let expected =
            hex::decode("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b")
                .unwrap();

        let tag = hmac_sha256(&key, &data);
        assert_eq!(tag.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_hmac_verify_valid() {
        let key = b"secret key";
        let data = b"message to authenticate";

        let tag = hmac_sha256(key, data);
        assert!(hmac_sha256_verify(key, data, &tag));
    }

    #[test]
    fn test_hmac_verify_rejects_tampered_tag() {
        let key = b"secret key";
        let data = b"message to authenticate";

        let mut tag = hmac_sha256(key, data);
        tag[0] ^= 0xff; // Tamper with first byte

        assert!(!hmac_sha256_verify(key, data, &tag));
    }

    #[test]
    fn test_hmac_verify_rejects_truncated_tag() {
        let key = b"secret key";
        let data = b"message to authenticate";

        let tag = hmac_sha256(key, data);
        let truncated = &tag[..16];

        assert!(!hmac_sha256_verify(key, data, truncated));
    }

    #[test]
    fn test_hmac_verify_rejects_wrong_key() {
        let key1 = b"key1";
        let key2 = b"key2";
        let data = b"message";

        let tag = hmac_sha256(key1, data);
        assert!(!hmac_sha256_verify(key2, data, &tag));
    }

    #[test]
    fn test_hmac_verify_rejects_wrong_data() {
        let key = b"key";
        let data1 = b"message1";
        let data2 = b"message2";

        let tag = hmac_sha256(key, data1);
        assert!(!hmac_sha256_verify(key, data2, &tag));
    }
}

// =============================================================================
// Random Generation Tests
// =============================================================================

mod random_tests {
    use super::*;

    #[test]
    fn test_random_bytes_correct_length() {
        for len in [0, 1, 16, 32, 64, 128, 256] {
            let bytes = random_bytes(len).unwrap();
            assert_eq!(bytes.len(), len);
        }
    }

    #[test]
    fn test_random_bytes_fixed_correct_length() {
        let bytes16: [u8; 16] = random_bytes_fixed().unwrap();
        assert_eq!(bytes16.len(), 16);

        let bytes32: [u8; 32] = random_bytes_fixed().unwrap();
        assert_eq!(bytes32.len(), 32);

        let bytes64: [u8; 64] = random_bytes_fixed().unwrap();
        assert_eq!(bytes64.len(), 64);
    }

    #[test]
    fn test_random_generates_unique_values() {
        let mut values = Vec::new();
        for _ in 0..100 {
            let bytes = random_bytes(32).unwrap();
            assert!(!values.contains(&bytes), "Random collision detected!");
            values.push(bytes);
        }
    }

    #[test]
    fn test_random_fixed_generates_unique_values() {
        let mut values: Vec<[u8; 32]> = Vec::new();
        for _ in 0..100 {
            let bytes: [u8; 32] = random_bytes_fixed().unwrap();
            assert!(!values.contains(&bytes), "Random collision detected!");
            values.push(bytes);
        }
    }

    #[test]
    fn test_random_bytes_not_all_zeros() {
        // Generate multiple random values and ensure they're not all zeros
        for _ in 0..10 {
            let bytes = random_bytes(32).unwrap();
            let all_zeros = bytes.iter().all(|&b| b == 0);
            assert!(!all_zeros, "Random bytes should not be all zeros");
        }
    }
}
