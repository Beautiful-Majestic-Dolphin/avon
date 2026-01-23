//! Tests for CRYSTALS-Kyber Key Encapsulation Mechanism.

use avon_crypto::error::CryptoError;
use avon_crypto::pqc::kyber::{
    KyberCiphertext, KyberKeyPair, KyberPublicKey, KyberSecretKey,
    KYBER768_CIPHERTEXT_BYTES, KYBER768_PUBLIC_KEY_BYTES, KYBER768_SECRET_KEY_BYTES,
    KYBER768_SHARED_SECRET_BYTES,
};

// =============================================================================
// Size Constants Tests
// =============================================================================

mod size_constants_tests {
    use super::*;

    #[test]
    fn test_public_key_size() {
        assert_eq!(KYBER768_PUBLIC_KEY_BYTES, 1184);
    }

    #[test]
    fn test_secret_key_size() {
        assert_eq!(KYBER768_SECRET_KEY_BYTES, 2400);
    }

    #[test]
    fn test_ciphertext_size() {
        assert_eq!(KYBER768_CIPHERTEXT_BYTES, 1088);
    }

    #[test]
    fn test_shared_secret_size() {
        assert_eq!(KYBER768_SHARED_SECRET_BYTES, 32);
    }
}

// =============================================================================
// Key Generation Tests
// =============================================================================

mod key_generation_tests {
    use super::*;

    #[test]
    fn test_keypair_generation_produces_valid_keypair() {
        let keypair = KyberKeyPair::generate().unwrap();
        let public_bytes = keypair.public_key().to_bytes();

        // Public key should be correct size
        assert_eq!(public_bytes.len(), KYBER768_PUBLIC_KEY_BYTES);

        // Public key should not be all zeros
        assert!(!public_bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_multiple_keypairs_are_different() {
        let keypair1 = KyberKeyPair::generate().unwrap();
        let keypair2 = KyberKeyPair::generate().unwrap();

        assert_ne!(keypair1.public_key().to_bytes(), keypair2.public_key().to_bytes());
    }
}

// =============================================================================
// Encapsulate/Decapsulate Tests
// =============================================================================

mod encapsulate_decapsulate_tests {
    use super::*;

    #[test]
    fn test_encapsulate_decapsulate_produces_same_shared_secret() {
        let keypair = KyberKeyPair::generate().unwrap();

        let (ciphertext, sender_shared) = keypair.public_key().encapsulate().unwrap();
        let receiver_shared = keypair.decapsulate(&ciphertext).unwrap();

        assert_eq!(sender_shared.as_bytes(), receiver_shared.as_bytes());
    }

    #[test]
    fn test_shared_secret_is_32_bytes() {
        let keypair = KyberKeyPair::generate().unwrap();
        let (_, shared) = keypair.public_key().encapsulate().unwrap();

        assert_eq!(shared.as_bytes().len(), 32);
    }

    #[test]
    fn test_shared_secret_is_not_all_zeros() {
        let keypair = KyberKeyPair::generate().unwrap();
        let (_, shared) = keypair.public_key().encapsulate().unwrap();

        assert!(!shared.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_ciphertext_is_correct_size() {
        let keypair = KyberKeyPair::generate().unwrap();
        let (ciphertext, _) = keypair.public_key().encapsulate().unwrap();

        assert_eq!(ciphertext.to_bytes().len(), KYBER768_CIPHERTEXT_BYTES);
    }

    #[test]
    fn test_different_encapsulations_produce_different_shared_secrets() {
        let keypair = KyberKeyPair::generate().unwrap();

        let (_, shared1) = keypair.public_key().encapsulate().unwrap();
        let (_, shared2) = keypair.public_key().encapsulate().unwrap();

        // Each encapsulation should produce a different shared secret
        assert_ne!(shared1.as_bytes(), shared2.as_bytes());
    }

    #[test]
    fn test_wrong_secret_key_produces_different_shared_secret() {
        let keypair1 = KyberKeyPair::generate().unwrap();
        let keypair2 = KyberKeyPair::generate().unwrap();

        // Encapsulate with keypair1's public key
        let (ciphertext, sender_shared) = keypair1.public_key().encapsulate().unwrap();

        // Try to decapsulate with keypair2's secret key
        let wrong_shared = keypair2.decapsulate(&ciphertext).unwrap();

        // The shared secrets should be different
        assert_ne!(sender_shared.as_bytes(), wrong_shared.as_bytes());
    }

    #[test]
    fn test_tampered_ciphertext_produces_different_shared_secret() {
        let keypair = KyberKeyPair::generate().unwrap();

        let (ciphertext, sender_shared) = keypair.public_key().encapsulate().unwrap();

        // Tamper with the ciphertext
        let mut tampered_bytes = ciphertext.to_bytes();
        tampered_bytes[0] ^= 0xff;
        let tampered_ciphertext = KyberCiphertext::from_bytes(&tampered_bytes).unwrap();

        // Decapsulation with tampered ciphertext should produce different shared secret
        // (Kyber uses implicit rejection, so it doesn't fail but produces wrong result)
        let tampered_shared = keypair.decapsulate(&tampered_ciphertext).unwrap();
        assert_ne!(sender_shared.as_bytes(), tampered_shared.as_bytes());
    }
}

// =============================================================================
// Serialization Tests
// =============================================================================

mod serialization_tests {
    use super::*;

    #[test]
    fn test_public_key_to_bytes_roundtrip() {
        let keypair = KyberKeyPair::generate().unwrap();
        let original_bytes = keypair.public_key().to_bytes();

        let restored = KyberPublicKey::from_bytes(&original_bytes).unwrap();
        assert_eq!(original_bytes, restored.to_bytes());
    }

    #[test]
    fn test_public_key_from_bytes_invalid_length() {
        let short_bytes = vec![0u8; 100];
        let result = KyberPublicKey::from_bytes(&short_bytes);

        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 1184,
                actual: 100
            })
        ));
    }

    #[test]
    fn test_ciphertext_to_bytes_roundtrip() {
        let keypair = KyberKeyPair::generate().unwrap();
        let (ciphertext, _) = keypair.public_key().encapsulate().unwrap();

        let original_bytes = ciphertext.to_bytes();
        let restored = KyberCiphertext::from_bytes(&original_bytes).unwrap();

        assert_eq!(original_bytes, restored.to_bytes());
    }

    #[test]
    fn test_ciphertext_from_bytes_invalid_length() {
        let short_bytes = vec![0u8; 100];
        let result = KyberCiphertext::from_bytes(&short_bytes);

        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 1088,
                actual: 100
            })
        ));
    }

    #[test]
    fn test_secret_key_from_bytes_invalid_length() {
        let short_bytes = vec![0u8; 100];
        let result = KyberSecretKey::from_bytes(&short_bytes);

        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 2400,
                actual: 100
            })
        ));
    }

    #[test]
    fn test_restored_public_key_can_encapsulate() {
        let keypair = KyberKeyPair::generate().unwrap();
        let public_bytes = keypair.public_key().to_bytes();

        // Restore the public key
        let restored_public = KyberPublicKey::from_bytes(&public_bytes).unwrap();

        // Encapsulate with restored public key
        let (ciphertext, sender_shared) = restored_public.encapsulate().unwrap();

        // Decapsulate with original keypair
        let receiver_shared = keypair.decapsulate(&ciphertext).unwrap();

        // Shared secrets should match
        assert_eq!(sender_shared.as_bytes(), receiver_shared.as_bytes());
    }

    #[test]
    fn test_restored_ciphertext_can_be_decapsulated() {
        let keypair = KyberKeyPair::generate().unwrap();
        let (ciphertext, sender_shared) = keypair.public_key().encapsulate().unwrap();

        // Serialize and restore ciphertext
        let ct_bytes = ciphertext.to_bytes();
        let restored_ciphertext = KyberCiphertext::from_bytes(&ct_bytes).unwrap();

        // Decapsulate with restored ciphertext
        let receiver_shared = keypair.decapsulate(&restored_ciphertext).unwrap();

        // Shared secrets should match
        assert_eq!(sender_shared.as_bytes(), receiver_shared.as_bytes());
    }
}

// =============================================================================
// Zeroize Tests
// =============================================================================

mod zeroize_tests {
    use super::*;

    #[test]
    fn test_secret_key_is_zeroized_on_drop() {
        let keypair = KyberKeyPair::generate().unwrap();

        // Verify we can use the keypair before drop
        let (ciphertext, _) = keypair.public_key().encapsulate().unwrap();
        let _shared = keypair.decapsulate(&ciphertext).unwrap();

        // Drop happens here - zeroization should occur
        drop(keypair);

        // Note: We can't verify the memory is zeroed after drop in safe Rust,
        // but the ZeroizeOnDrop derive ensures it happens
    }

    #[test]
    fn test_shared_secret_is_zeroized_on_drop() {
        let keypair = KyberKeyPair::generate().unwrap();
        let (_, shared) = keypair.public_key().encapsulate().unwrap();

        // Verify we can access the shared secret before drop
        assert_eq!(shared.as_bytes().len(), 32);

        // Drop happens here - zeroization should occur
        drop(shared);

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
    fn test_api_similar_to_ecdh() {
        // This test verifies that the Kyber API follows a similar pattern to ECDH
        
        // Generate keypair (similar to X25519KeyPair::generate())
        let keypair = KyberKeyPair::generate().unwrap();
        
        // Get public key (similar to keypair.public_key())
        let _public_key = keypair.public_key();
        
        // Encapsulate (KEM equivalent of DH)
        let (ciphertext, sender_shared) = keypair.public_key().encapsulate().unwrap();
        
        // Decapsulate (KEM equivalent of DH from other side)
        let receiver_shared = keypair.decapsulate(&ciphertext).unwrap();
        
        // Both parties have same shared secret (like DH)
        assert_eq!(sender_shared.as_bytes(), receiver_shared.as_bytes());
    }
}
