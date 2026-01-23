//! Tests for CRYSTALS-Dilithium Digital Signature Algorithm.

use avon_crypto::error::CryptoError;
use avon_crypto::pqc::dilithium::{
    DilithiumKeyPair, DilithiumSignature, DilithiumSigningKey, DilithiumVerifyingKey,
    DILITHIUM3_PUBLIC_KEY_BYTES, DILITHIUM3_SECRET_KEY_BYTES, DILITHIUM3_SIGNATURE_BYTES,
};

// =============================================================================
// Size Constants Tests
// =============================================================================

mod size_constants_tests {
    use super::*;

    #[test]
    fn test_public_key_size() {
        assert_eq!(DILITHIUM3_PUBLIC_KEY_BYTES, 1952);
    }

    #[test]
    fn test_secret_key_size() {
        assert_eq!(DILITHIUM3_SECRET_KEY_BYTES, 4016);
    }

    #[test]
    fn test_signature_size() {
        assert_eq!(DILITHIUM3_SIGNATURE_BYTES, 3309);
    }
}

// =============================================================================
// Key Generation Tests
// =============================================================================

mod key_generation_tests {
    use super::*;

    #[test]
    fn test_keypair_generation_produces_valid_keypair() {
        let keypair = DilithiumKeyPair::generate().unwrap();
        let verifying_bytes = keypair.verifying_key().to_bytes();

        // Verifying key should be correct size
        assert_eq!(verifying_bytes.len(), DILITHIUM3_PUBLIC_KEY_BYTES);

        // Verifying key should not be all zeros
        assert!(!verifying_bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_multiple_keypairs_are_different() {
        let keypair1 = DilithiumKeyPair::generate().unwrap();
        let keypair2 = DilithiumKeyPair::generate().unwrap();

        assert_ne!(
            keypair1.verifying_key().to_bytes(),
            keypair2.verifying_key().to_bytes()
        );
    }
}

// =============================================================================
// Sign and Verify Tests
// =============================================================================

mod sign_verify_tests {
    use super::*;

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let keypair = DilithiumKeyPair::generate().unwrap();
        let message = b"Hello, post-quantum world!";

        let signature = keypair.sign(message);
        let result = keypair.verifying_key().verify(message, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn test_signature_is_correct_size() {
        let keypair = DilithiumKeyPair::generate().unwrap();
        let signature = keypair.sign(b"test message");

        assert_eq!(signature.to_bytes().len(), DILITHIUM3_SIGNATURE_BYTES);
    }

    #[test]
    fn test_sign_empty_message() {
        let keypair = DilithiumKeyPair::generate().unwrap();
        let message = b"";

        let signature = keypair.sign(message);
        let result = keypair.verifying_key().verify(message, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn test_sign_large_message() {
        let keypair = DilithiumKeyPair::generate().unwrap();
        let message = vec![0xab; 10000];

        let signature = keypair.sign(&message);
        let result = keypair.verifying_key().verify(&message, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn test_verification_fails_for_wrong_message() {
        let keypair = DilithiumKeyPair::generate().unwrap();
        let message = b"original message";
        let wrong_message = b"wrong message";

        let signature = keypair.sign(message);
        let result = keypair.verifying_key().verify(wrong_message, &signature);

        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn test_verification_fails_for_tampered_signature() {
        let keypair = DilithiumKeyPair::generate().unwrap();
        let message = b"test message";

        let signature = keypair.sign(message);

        // Tamper with the signature
        let mut tampered_bytes = signature.to_bytes();
        tampered_bytes[0] ^= 0xff;
        let tampered_signature = DilithiumSignature::from_bytes(&tampered_bytes).unwrap();

        let result = keypair.verifying_key().verify(message, &tampered_signature);
        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn test_verification_fails_for_wrong_public_key() {
        let keypair1 = DilithiumKeyPair::generate().unwrap();
        let keypair2 = DilithiumKeyPair::generate().unwrap();
        let message = b"test message";

        // Sign with keypair1
        let signature = keypair1.sign(message);

        // Verify with keypair2's verifying key
        let result = keypair2.verifying_key().verify(message, &signature);
        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn test_different_messages_produce_different_signatures() {
        let keypair = DilithiumKeyPair::generate().unwrap();

        let sig1 = keypair.sign(b"message 1");
        let sig2 = keypair.sign(b"message 2");

        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }
}

// =============================================================================
// Serialization Tests
// =============================================================================

mod serialization_tests {
    use super::*;

    #[test]
    fn test_verifying_key_to_bytes_roundtrip() {
        let keypair = DilithiumKeyPair::generate().unwrap();
        let original_bytes = keypair.verifying_key().to_bytes();

        let restored = DilithiumVerifyingKey::from_bytes(&original_bytes).unwrap();
        assert_eq!(original_bytes, restored.to_bytes());
    }

    #[test]
    fn test_verifying_key_from_bytes_invalid_length() {
        let short_bytes = vec![0u8; 100];
        let result = DilithiumVerifyingKey::from_bytes(&short_bytes);

        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 1952,
                actual: 100
            })
        ));
    }

    #[test]
    fn test_signature_to_bytes_roundtrip() {
        let keypair = DilithiumKeyPair::generate().unwrap();
        let signature = keypair.sign(b"test message");

        let original_bytes = signature.to_bytes();
        let restored = DilithiumSignature::from_bytes(&original_bytes).unwrap();

        assert_eq!(original_bytes, restored.to_bytes());
    }

    #[test]
    fn test_signature_from_bytes_invalid_length() {
        let short_bytes = vec![0u8; 100];
        let result = DilithiumSignature::from_bytes(&short_bytes);

        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 3309,
                actual: 100
            })
        ));
    }

    #[test]
    fn test_signing_key_from_bytes_invalid_length() {
        let short_bytes = vec![0u8; 100];
        let result = DilithiumSigningKey::from_bytes(&short_bytes);

        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 4016,
                actual: 100
            })
        ));
    }

    #[test]
    fn test_restored_verifying_key_can_verify() {
        let keypair = DilithiumKeyPair::generate().unwrap();
        let message = b"test message";
        let signature = keypair.sign(message);

        // Serialize and restore verifying key
        let vk_bytes = keypair.verifying_key().to_bytes();
        let restored_vk = DilithiumVerifyingKey::from_bytes(&vk_bytes).unwrap();

        // Verify with restored key
        let result = restored_vk.verify(message, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_restored_signature_can_be_verified() {
        let keypair = DilithiumKeyPair::generate().unwrap();
        let message = b"test message";
        let signature = keypair.sign(message);

        // Serialize and restore signature
        let sig_bytes = signature.to_bytes();
        let restored_sig = DilithiumSignature::from_bytes(&sig_bytes).unwrap();

        // Verify with restored signature
        let result = keypair.verifying_key().verify(message, &restored_sig);
        assert!(result.is_ok());
    }
}

// =============================================================================
// Zeroize Tests
// =============================================================================

mod zeroize_tests {
    use super::*;

    #[test]
    fn test_signing_key_is_zeroized_on_drop() {
        let keypair = DilithiumKeyPair::generate().unwrap();

        // Verify we can use the keypair before drop
        let message = b"test message";
        let signature = keypair.sign(message);
        assert!(keypair.verifying_key().verify(message, &signature).is_ok());

        // Drop happens here - zeroization should occur
        drop(keypair);

        // Note: We can't verify the memory is zeroed after drop in safe Rust,
        // but the ZeroizeOnDrop derive ensures it happens
    }
}

// =============================================================================
// API Consistency Tests
// =============================================================================

mod api_consistency_tests {
    use super::*;

    #[test]
    fn test_api_similar_to_ed25519() {
        // This test verifies that the Dilithium API follows a similar pattern to Ed25519

        // Generate keypair (similar to Ed25519KeyPair::generate())
        let keypair = DilithiumKeyPair::generate().unwrap();

        // Get verifying key (similar to keypair.verifying_key())
        let _verifying_key = keypair.verifying_key();

        // Sign a message (similar to keypair.sign())
        let message = b"test message";
        let signature = keypair.sign(message);

        // Verify signature (similar to verifying_key.verify())
        let result = keypair.verifying_key().verify(message, &signature);
        assert!(result.is_ok());
    }
}
