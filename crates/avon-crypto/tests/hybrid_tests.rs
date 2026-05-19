//! Tests for Hybrid Classical + Post-Quantum Cryptography.

use avon_crypto::error::CryptoError;
use avon_crypto::hybrid::key_exchange::{
    hybrid_encapsulate, HybridEncapsulation, HybridKeyPair, HybridPublicKey,
};
use avon_crypto::hybrid::signature::{HybridSignature, HybridSigningKeyPair, HybridVerifyingKey};

// =============================================================================
// Hybrid Key Exchange Tests
// =============================================================================

mod key_exchange_tests {
    use super::*;

    #[test]
    fn test_hybrid_key_exchange_produces_same_secret() {
        let recipient = HybridKeyPair::generate().unwrap();
        let (encapsulation, sender_secret) = hybrid_encapsulate(&recipient.public_key()).unwrap();
        let recipient_secret = recipient.decapsulate(&encapsulation).unwrap();

        assert_eq!(sender_secret.as_bytes(), recipient_secret.as_bytes());
    }

    #[test]
    fn test_shared_secret_is_32_bytes() {
        let recipient = HybridKeyPair::generate().unwrap();
        let (_, secret) = hybrid_encapsulate(&recipient.public_key()).unwrap();

        assert_eq!(secret.as_bytes().len(), 32);
    }

    #[test]
    fn test_shared_secret_is_not_all_zeros() {
        let recipient = HybridKeyPair::generate().unwrap();
        let (_, secret) = hybrid_encapsulate(&recipient.public_key()).unwrap();

        assert!(!secret.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_different_recipients_produce_different_secrets() {
        let recipient1 = HybridKeyPair::generate().unwrap();
        let recipient2 = HybridKeyPair::generate().unwrap();

        let (_, secret1) = hybrid_encapsulate(&recipient1.public_key()).unwrap();
        let (_, secret2) = hybrid_encapsulate(&recipient2.public_key()).unwrap();

        assert_ne!(secret1.as_bytes(), secret2.as_bytes());
    }

    #[test]
    fn test_different_encapsulations_produce_different_secrets() {
        let recipient = HybridKeyPair::generate().unwrap();

        let (_, secret1) = hybrid_encapsulate(&recipient.public_key()).unwrap();
        let (_, secret2) = hybrid_encapsulate(&recipient.public_key()).unwrap();

        // Each encapsulation should produce a different shared secret
        // (due to ephemeral keys and Kyber randomness)
        assert_ne!(secret1.as_bytes(), secret2.as_bytes());
    }

    #[test]
    fn test_wrong_recipient_produces_different_secret() {
        let recipient1 = HybridKeyPair::generate().unwrap();
        let recipient2 = HybridKeyPair::generate().unwrap();

        // Encapsulate to recipient1
        let (encapsulation, sender_secret) = hybrid_encapsulate(&recipient1.public_key()).unwrap();

        // Try to decapsulate with recipient2
        let wrong_secret = recipient2.decapsulate(&encapsulation).unwrap();

        // The secrets should be different
        assert_ne!(sender_secret.as_bytes(), wrong_secret.as_bytes());
    }

    #[test]
    fn test_public_key_size() {
        let keypair = HybridKeyPair::generate().unwrap();
        let bytes = keypair.public_key().to_bytes();

        // X25519 (32) + Kyber768 (1184) = 1216 bytes
        assert_eq!(bytes.len(), 32 + 1184);
    }

    #[test]
    fn test_encapsulation_size() {
        let recipient = HybridKeyPair::generate().unwrap();
        let (encapsulation, _) = hybrid_encapsulate(&recipient.public_key()).unwrap();
        let bytes = encapsulation.to_bytes();

        // X25519 ephemeral (32) + Kyber ciphertext (1088) = 1120 bytes
        assert_eq!(bytes.len(), 32 + 1088);
    }
}

// =============================================================================
// Hybrid Key Exchange Serialization Tests
// =============================================================================

mod key_exchange_serialization_tests {
    use super::*;

    #[test]
    fn test_public_key_to_bytes_roundtrip() {
        let keypair = HybridKeyPair::generate().unwrap();
        let original_bytes = keypair.public_key().to_bytes();

        let restored = HybridPublicKey::from_bytes(&original_bytes).unwrap();
        assert_eq!(original_bytes, restored.to_bytes());
    }

    #[test]
    fn test_public_key_from_bytes_invalid_length() {
        let short_bytes = vec![0u8; 100];
        let result = HybridPublicKey::from_bytes(&short_bytes);

        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 1216,
                actual: 100
            })
        ));
    }

    #[test]
    fn test_encapsulation_to_bytes_roundtrip() {
        let recipient = HybridKeyPair::generate().unwrap();
        let (encapsulation, _) = hybrid_encapsulate(&recipient.public_key()).unwrap();

        let original_bytes = encapsulation.to_bytes();
        let restored = HybridEncapsulation::from_bytes(&original_bytes).unwrap();

        assert_eq!(original_bytes, restored.to_bytes());
    }

    #[test]
    fn test_encapsulation_from_bytes_invalid_length() {
        let short_bytes = vec![0u8; 100];
        let result = HybridEncapsulation::from_bytes(&short_bytes);

        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 1120,
                actual: 100
            })
        ));
    }

    #[test]
    fn test_restored_public_key_can_encapsulate() {
        let keypair = HybridKeyPair::generate().unwrap();
        let public_bytes = keypair.public_key().to_bytes();

        // Restore the public key
        let restored_public = HybridPublicKey::from_bytes(&public_bytes).unwrap();

        // Encapsulate with restored public key
        let (encapsulation, sender_secret) = hybrid_encapsulate(&restored_public).unwrap();

        // Decapsulate with original keypair
        let recipient_secret = keypair.decapsulate(&encapsulation).unwrap();

        // Shared secrets should match
        assert_eq!(sender_secret.as_bytes(), recipient_secret.as_bytes());
    }

    #[test]
    fn test_restored_encapsulation_can_be_decapsulated() {
        let keypair = HybridKeyPair::generate().unwrap();
        let (encapsulation, sender_secret) = hybrid_encapsulate(&keypair.public_key()).unwrap();

        // Serialize and restore encapsulation
        let enc_bytes = encapsulation.to_bytes();
        let restored_encapsulation = HybridEncapsulation::from_bytes(&enc_bytes).unwrap();

        // Decapsulate with restored encapsulation
        let recipient_secret = keypair.decapsulate(&restored_encapsulation).unwrap();

        // Shared secrets should match
        assert_eq!(sender_secret.as_bytes(), recipient_secret.as_bytes());
    }
}

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
    use super::*;

    #[test]
    fn test_hybrid_shared_secret_is_zeroized_on_drop() {
        let recipient = HybridKeyPair::generate().unwrap();
        let (_, secret) = hybrid_encapsulate(&recipient.public_key()).unwrap();

        // Verify we can access the secret before drop
        assert_eq!(secret.as_bytes().len(), 32);

        // Drop happens here - zeroization should occur
        drop(secret);

        // Note: We can't verify the memory is zeroed after drop in safe Rust,
        // but the ZeroizeOnDrop derive ensures it happens
    }
}
