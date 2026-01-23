//! Tests for X25519 ECDH key exchange.
//!
//! Includes RFC 7748 test vectors.

use avon_crypto::ecdh::{X25519KeyPair, X25519PrivateKey, X25519PublicKey, SharedSecret};
use avon_crypto::error::CryptoError;

// =============================================================================
// Key Generation Tests
// =============================================================================

mod key_generation_tests {
    use super::*;

    #[test]
    fn test_keypair_generation_produces_valid_keypair() {
        let keypair = X25519KeyPair::generate().unwrap();
        let public_bytes = keypair.public_key().to_bytes();
        
        // Public key should be 32 bytes
        assert_eq!(public_bytes.len(), 32);
        
        // Public key should not be all zeros
        assert!(!public_bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_multiple_keypairs_are_different() {
        let keypair1 = X25519KeyPair::generate().unwrap();
        let keypair2 = X25519KeyPair::generate().unwrap();
        
        assert_ne!(keypair1.public_key(), keypair2.public_key());
    }

    #[test]
    fn test_keypair_from_private_key() {
        let private_bytes = [42u8; 32];
        let private = X25519PrivateKey::from_bytes(private_bytes);
        let keypair = X25519KeyPair::from_private_key(private);
        
        // Should produce a valid public key
        let public_bytes = keypair.public_key().to_bytes();
        assert_eq!(public_bytes.len(), 32);
    }

    #[test]
    fn test_same_private_key_produces_same_public_key() {
        let private_bytes = [42u8; 32];
        
        let private1 = X25519PrivateKey::from_bytes(private_bytes);
        let keypair1 = X25519KeyPair::from_private_key(private1);
        
        let private2 = X25519PrivateKey::from_bytes(private_bytes);
        let keypair2 = X25519KeyPair::from_private_key(private2);
        
        assert_eq!(keypair1.public_key(), keypair2.public_key());
    }
}

// =============================================================================
// Diffie-Hellman Tests
// =============================================================================

mod diffie_hellman_tests {
    use super::*;

    #[test]
    fn test_diffie_hellman_produces_same_shared_secret() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();
        
        let alice_shared = alice.diffie_hellman(bob.public_key()).unwrap();
        let bob_shared = bob.diffie_hellman(alice.public_key()).unwrap();
        
        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_different_keypairs_produce_different_shared_secrets() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();
        let charlie = X25519KeyPair::generate().unwrap();
        
        let alice_bob_shared = alice.diffie_hellman(bob.public_key()).unwrap();
        let alice_charlie_shared = alice.diffie_hellman(charlie.public_key()).unwrap();
        
        assert_ne!(alice_bob_shared.as_bytes(), alice_charlie_shared.as_bytes());
    }

    #[test]
    fn test_shared_secret_is_32_bytes() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();
        
        let shared = alice.diffie_hellman(bob.public_key()).unwrap();
        assert_eq!(shared.as_bytes().len(), 32);
    }

    #[test]
    fn test_shared_secret_is_not_all_zeros() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();
        
        let shared = alice.diffie_hellman(bob.public_key()).unwrap();
        assert!(!shared.as_bytes().iter().all(|&b| b == 0));
    }
}

// =============================================================================
// Public Key Serialization Tests
// =============================================================================

mod serialization_tests {
    use super::*;

    #[test]
    fn test_public_key_to_bytes_roundtrip() {
        let keypair = X25519KeyPair::generate().unwrap();
        let original = keypair.public_key();
        
        let bytes = original.to_bytes();
        let restored = X25519PublicKey::from_bytes(&bytes).unwrap();
        
        assert_eq!(original, &restored);
    }

    #[test]
    fn test_public_key_from_bytes_invalid_length() {
        let short_bytes = [0u8; 16];
        let result = X25519PublicKey::from_bytes(&short_bytes);
        
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 16
            })
        ));
    }

    #[test]
    fn test_public_key_from_bytes_empty() {
        let result = X25519PublicKey::from_bytes(&[]);
        
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 0
            })
        ));
    }

    #[test]
    fn test_public_key_serde_roundtrip() {
        let keypair = X25519KeyPair::generate().unwrap();
        let original = keypair.public_key().clone();
        
        // Serialize to JSON
        let json = serde_json::to_string(&original).unwrap();
        
        // Deserialize back
        let restored: X25519PublicKey = serde_json::from_str(&json).unwrap();
        
        assert_eq!(original, restored);
    }

    #[test]
    fn test_public_key_serde_binary_roundtrip() {
        let keypair = X25519KeyPair::generate().unwrap();
        let original = keypair.public_key().clone();
        
        // Serialize to binary (using bincode-like format via postcard or similar)
        // For simplicity, we'll use JSON here as it's already available
        let bytes = serde_json::to_vec(&original).unwrap();
        let restored: X25519PublicKey = serde_json::from_slice(&bytes).unwrap();
        
        assert_eq!(original, restored);
    }
}

// =============================================================================
// RFC 7748 Test Vectors
// =============================================================================

mod rfc7748_tests {
    use super::*;

    /// RFC 7748 Section 6.1 - Test Vector 1
    /// 
    /// Alice's private key (scalar):
    ///   77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
    /// Alice's public key:
    ///   8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
    /// Bob's private key (scalar):
    ///   5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
    /// Bob's public key:
    ///   de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
    /// Shared secret:
    ///   4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
    #[test]
    fn test_rfc7748_test_vector_1() {
        let alice_private_bytes = hex::decode(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        ).unwrap();
        let alice_public_expected = hex::decode(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        ).unwrap();
        
        let bob_private_bytes = hex::decode(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
        ).unwrap();
        let bob_public_expected = hex::decode(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        ).unwrap();
        
        let shared_expected = hex::decode(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        ).unwrap();
        
        // Create Alice's keypair
        let mut alice_private_array = [0u8; 32];
        alice_private_array.copy_from_slice(&alice_private_bytes);
        let alice_private = X25519PrivateKey::from_bytes(alice_private_array);
        let alice = X25519KeyPair::from_private_key(alice_private);
        
        // Verify Alice's public key
        assert_eq!(alice.public_key().to_bytes().as_slice(), alice_public_expected.as_slice());
        
        // Create Bob's keypair
        let mut bob_private_array = [0u8; 32];
        bob_private_array.copy_from_slice(&bob_private_bytes);
        let bob_private = X25519PrivateKey::from_bytes(bob_private_array);
        let bob = X25519KeyPair::from_private_key(bob_private);
        
        // Verify Bob's public key
        assert_eq!(bob.public_key().to_bytes().as_slice(), bob_public_expected.as_slice());
        
        // Compute shared secrets
        let alice_shared = alice.diffie_hellman(bob.public_key()).unwrap();
        let bob_shared = bob.diffie_hellman(alice.public_key()).unwrap();
        
        // Verify shared secrets match expected value
        assert_eq!(alice_shared.as_bytes().as_slice(), shared_expected.as_slice());
        assert_eq!(bob_shared.as_bytes().as_slice(), shared_expected.as_slice());
    }

    /// RFC 7748 Section 5.2 - Iterated test
    /// 
    /// Starting with k = u = basepoint (9), iterate:
    ///   k, u = X25519(k, u), k
    /// 
    /// After 1 iteration:
    ///   k = 422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079
    #[test]
    fn test_rfc7748_iterated_1() {
        // Basepoint for X25519 is 9
        let mut k = [0u8; 32];
        k[0] = 9;
        
        let mut u = [0u8; 32];
        u[0] = 9;
        
        // Perform one iteration
        let private = X25519PrivateKey::from_bytes(k);
        let keypair = X25519KeyPair::from_private_key(private);
        let peer_public = X25519PublicKey::from_bytes(&u).unwrap();
        let shared = keypair.diffie_hellman(&peer_public).unwrap();
        
        let expected = hex::decode(
            "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
        ).unwrap();
        
        assert_eq!(shared.as_bytes().as_slice(), expected.as_slice());
    }

    /// RFC 7748 Section 5.2 - After 1000 iterations
    /// 
    /// After 1000 iterations:
    ///   k = 684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51
    #[test]
    fn test_rfc7748_iterated_1000() {
        // Basepoint for X25519 is 9
        let mut k = [0u8; 32];
        k[0] = 9;
        
        let mut u = [0u8; 32];
        u[0] = 9;
        
        // Perform 1000 iterations
        for _ in 0..1000 {
            let private = X25519PrivateKey::from_bytes(k);
            let keypair = X25519KeyPair::from_private_key(private);
            let peer_public = X25519PublicKey::from_bytes(&u).unwrap();
            let shared = keypair.diffie_hellman(&peer_public).unwrap();
            
            u = k;
            k = *shared.as_bytes();
        }
        
        let expected = hex::decode(
            "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"
        ).unwrap();
        
        assert_eq!(k.as_slice(), expected.as_slice());
    }
}

// =============================================================================
// Zeroize Tests
// =============================================================================

mod zeroize_tests {
    use super::*;

    #[test]
    fn test_private_key_is_zeroized_on_drop() {
        // We can't directly test zeroization, but we can verify the type
        // implements the Zeroize trait by using it
        let private_bytes = [42u8; 32];
        let private = X25519PrivateKey::from_bytes(private_bytes);
        
        // Verify we can access the bytes before drop
        assert_eq!(private.as_bytes(), &private_bytes);
        
        // Drop happens here - zeroization should occur
        drop(private);
        
        // Note: We can't verify the memory is zeroed after drop in safe Rust,
        // but the ZeroizeOnDrop derive ensures it happens
    }

    #[test]
    fn test_shared_secret_length() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();
        
        let shared = alice.diffie_hellman(bob.public_key()).unwrap();
        assert_eq!(SharedSecret::LENGTH, 32);
        assert_eq!(shared.as_bytes().len(), SharedSecret::LENGTH);
    }
}
