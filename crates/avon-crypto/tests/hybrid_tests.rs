//! Tests for Hybrid Classical + Post-Quantum Cryptography.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use avon_crypto::error::CryptoError;
use avon_crypto::hybrid::signature::{HybridSignature, HybridSigningKeyPair, HybridVerifyingKey};

// =============================================================================
// Hybrid Signature Tests
// =============================================================================

mod signature_tests {
    use super::*;

    #[test]
    fn test_hybrid_sign_and_verify_roundtrip() {
        let keypair = HybridSigningKeyPair::generate().unwrap();
        let message = b"Hello, hybrid world!";

        let signature = keypair.sign(message);
        let result = keypair.verifying_key().verify(message, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn test_verification_fails_for_wrong_message() {
        let keypair = HybridSigningKeyPair::generate().unwrap();
        let message = b"original message";
        let wrong_message = b"wrong message";

        let signature = keypair.sign(message);
        let result = keypair.verifying_key().verify(wrong_message, &signature);

        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn test_verification_fails_for_wrong_public_key() {
        let keypair1 = HybridSigningKeyPair::generate().unwrap();
        let keypair2 = HybridSigningKeyPair::generate().unwrap();
        let message = b"test message";

        // Sign with keypair1
        let signature = keypair1.sign(message);

        // Verify with keypair2's verifying key
        let result = keypair2.verifying_key().verify(message, &signature);
        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn test_sign_empty_message() {
        let keypair = HybridSigningKeyPair::generate().unwrap();
        let message = b"";

        let signature = keypair.sign(message);
        let result = keypair.verifying_key().verify(message, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn test_sign_large_message() {
        let keypair = HybridSigningKeyPair::generate().unwrap();
        let message = vec![0xab; 10000];

        let signature = keypair.sign(&message);
        let result = keypair.verifying_key().verify(&message, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn test_different_messages_produce_different_signatures() {
        let keypair = HybridSigningKeyPair::generate().unwrap();

        let sig1 = keypair.sign(b"message 1");
        let sig2 = keypair.sign(b"message 2");

        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_verifying_key_size() {
        let keypair = HybridSigningKeyPair::generate().unwrap();
        let bytes = keypair.verifying_key().to_bytes();

        // Ed25519 (32) + Dilithium3 (1952) = 1984 bytes
        assert_eq!(bytes.len(), 32 + 1952);
    }

    #[test]
    fn test_signature_size() {
        let keypair = HybridSigningKeyPair::generate().unwrap();
        let signature = keypair.sign(b"test message");
        let bytes = signature.to_bytes();

        // Ed25519 (64) + Dilithium3 (3309) = 3373 bytes
        assert_eq!(bytes.len(), 64 + 3309);
    }
}

// =============================================================================
// Hybrid Signature Component Tests
// =============================================================================

mod signature_component_tests {
    use super::*;

    #[test]
    fn test_verification_fails_if_classical_signature_is_wrong() {
        let keypair = HybridSigningKeyPair::generate().unwrap();
        let message = b"test message";

        let signature = keypair.sign(message);

        // Tamper with the classical (Ed25519) signature
        let mut tampered_bytes = signature.to_bytes();
        tampered_bytes[0] ^= 0xff; // Tamper with first byte of Ed25519 signature

        let tampered_signature = HybridSignature::from_bytes(&tampered_bytes).unwrap();
        let result = keypair.verifying_key().verify(message, &tampered_signature);

        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn test_verification_fails_if_pqc_signature_is_wrong() {
        let keypair = HybridSigningKeyPair::generate().unwrap();
        let message = b"test message";

        let signature = keypair.sign(message);

        // Tamper with the PQC (Dilithium) signature
        let mut tampered_bytes = signature.to_bytes();
        tampered_bytes[64] ^= 0xff; // Tamper with first byte of Dilithium signature

        let tampered_signature = HybridSignature::from_bytes(&tampered_bytes).unwrap();
        let result = keypair.verifying_key().verify(message, &tampered_signature);

        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn test_can_access_signature_components() {
        let keypair = HybridSigningKeyPair::generate().unwrap();
        let message = b"test message";

        let signature = keypair.sign(message);

        // Access individual components
        let classical = signature.classical();
        let pqc = signature.pqc();

        // Verify sizes
        assert_eq!(classical.to_bytes().len(), 64);
        assert_eq!(pqc.to_bytes().len(), 3309);
    }
}

// =============================================================================
// Hybrid Signature Serialization Tests
// =============================================================================

mod signature_serialization_tests {
    use super::*;

    #[test]
    fn test_verifying_key_to_bytes_roundtrip() {
        let keypair = HybridSigningKeyPair::generate().unwrap();
        let original_bytes = keypair.verifying_key().to_bytes();

        let restored = HybridVerifyingKey::from_bytes(&original_bytes).unwrap();
        assert_eq!(original_bytes, restored.to_bytes());
    }

    #[test]
    fn test_verifying_key_from_bytes_invalid_length() {
        let short_bytes = vec![0u8; 100];
        let result = HybridVerifyingKey::from_bytes(&short_bytes);

        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 1984,
                actual: 100
            })
        ));
    }

    #[test]
    fn test_signature_to_bytes_roundtrip() {
        let keypair = HybridSigningKeyPair::generate().unwrap();
        let signature = keypair.sign(b"test message");

        let original_bytes = signature.to_bytes();
        let restored = HybridSignature::from_bytes(&original_bytes).unwrap();

        assert_eq!(original_bytes, restored.to_bytes());
    }

    #[test]
    fn test_signature_from_bytes_invalid_length() {
        let short_bytes = vec![0u8; 100];
        let result = HybridSignature::from_bytes(&short_bytes);

        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 3373,
                actual: 100
            })
        ));
    }

    #[test]
    fn test_restored_verifying_key_can_verify() {
        let keypair = HybridSigningKeyPair::generate().unwrap();
        let message = b"test message";
        let signature = keypair.sign(message);

        // Serialize and restore verifying key
        let vk_bytes = keypair.verifying_key().to_bytes();
        let restored_vk = HybridVerifyingKey::from_bytes(&vk_bytes).unwrap();

        // Verify with restored key
        let result = restored_vk.verify(message, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_restored_signature_can_be_verified() {
        let keypair = HybridSigningKeyPair::generate().unwrap();
        let message = b"test message";
        let signature = keypair.sign(message);

        // Serialize and restore signature
        let sig_bytes = signature.to_bytes();
        let restored_sig = HybridSignature::from_bytes(&sig_bytes).unwrap();

        // Verify with restored signature
        let result = keypair.verifying_key().verify(message, &restored_sig);
        assert!(result.is_ok());
    }
}

// =============================================================================
// Zeroize Tests
// =============================================================================

mod zeroize_tests {
    use avon_crypto::hybrid::kem::HybridKemKeyPair;

    #[test]
    fn test_hybrid_shared_secret_is_zeroized_on_drop() {
        let kp = HybridKemKeyPair::generate().unwrap();
        let (_, secret) = kp.public_key().encapsulate().unwrap();

        // Verify we can access the secret before drop
        assert_eq!(secret.as_bytes().len(), 32);

        // Drop happens here - zeroization should occur
        drop(secret);

        // Note: We can't verify the memory is zeroed after drop in safe Rust,
        // but the ZeroizeOnDrop derive ensures it happens
    }
}
