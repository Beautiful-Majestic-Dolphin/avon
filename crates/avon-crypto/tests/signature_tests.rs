//! Tests for Ed25519 digital signatures.
//!
//! Includes RFC 8032 test vectors.

use avon_crypto::error::CryptoError;
use avon_crypto::signature::{Ed25519KeyPair, Ed25519Signature, Ed25519VerifyingKey};

// =============================================================================
// Key Generation Tests
// =============================================================================

mod key_generation_tests {
    use super::*;

    #[test]
    fn test_keypair_generation_produces_valid_keypair() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let verifying_bytes = keypair.verifying_key().to_bytes();

        // Verifying key should be 32 bytes
        assert_eq!(verifying_bytes.len(), 32);

        // Verifying key should not be all zeros
        assert!(!verifying_bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_multiple_keypairs_are_different() {
        let keypair1 = Ed25519KeyPair::generate().unwrap();
        let keypair2 = Ed25519KeyPair::generate().unwrap();

        assert_ne!(keypair1.verifying_key(), keypair2.verifying_key());
    }

    #[test]
    fn test_keypair_from_seed() {
        let seed = [42u8; 32];
        let keypair = Ed25519KeyPair::from_seed(&seed).unwrap();

        // Should produce a valid verifying key
        let verifying_bytes = keypair.verifying_key().to_bytes();
        assert_eq!(verifying_bytes.len(), 32);
    }

    #[test]
    fn test_deterministic_keypair_from_same_seed() {
        let seed = [42u8; 32];

        let keypair1 = Ed25519KeyPair::from_seed(&seed).unwrap();
        let keypair2 = Ed25519KeyPair::from_seed(&seed).unwrap();

        assert_eq!(keypair1.verifying_key(), keypair2.verifying_key());
    }

    #[test]
    fn test_different_seeds_produce_different_keypairs() {
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];

        let keypair1 = Ed25519KeyPair::from_seed(&seed1).unwrap();
        let keypair2 = Ed25519KeyPair::from_seed(&seed2).unwrap();

        assert_ne!(keypair1.verifying_key(), keypair2.verifying_key());
    }
}

// =============================================================================
// Sign and Verify Tests
// =============================================================================

mod sign_verify_tests {
    use super::*;

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let message = b"Hello, AVON!";

        let signature = keypair.sign(message);
        let result = keypair.verifying_key().verify(message, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn test_sign_empty_message() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let message = b"";

        let signature = keypair.sign(message);
        let result = keypair.verifying_key().verify(message, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn test_sign_large_message() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let message = vec![0xab; 10000];

        let signature = keypair.sign(&message);
        let result = keypair.verifying_key().verify(&message, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn test_verification_fails_for_wrong_message() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let message = b"correct message";
        let wrong_message = b"wrong message";

        let signature = keypair.sign(message);
        let result = keypair.verifying_key().verify(wrong_message, &signature);

        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn test_verification_fails_for_tampered_signature() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let message = b"test message";

        let signature = keypair.sign(message);
        let mut tampered_bytes = signature.to_bytes();
        tampered_bytes[0] ^= 0xff;
        let tampered_signature = Ed25519Signature::from_bytes(&tampered_bytes).unwrap();

        let result = keypair.verifying_key().verify(message, &tampered_signature);
        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn test_verification_fails_for_wrong_public_key() {
        let keypair1 = Ed25519KeyPair::generate().unwrap();
        let keypair2 = Ed25519KeyPair::generate().unwrap();
        let message = b"test message";

        let signature = keypair1.sign(message);
        let result = keypair2.verifying_key().verify(message, &signature);

        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn test_deterministic_signatures() {
        let seed = [42u8; 32];
        let keypair = Ed25519KeyPair::from_seed(&seed).unwrap();
        let message = b"test message";

        let signature1 = keypair.sign(message);
        let signature2 = keypair.sign(message);

        // Ed25519 signatures are deterministic
        assert_eq!(signature1, signature2);
    }

    #[test]
    fn test_signature_is_64_bytes() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let message = b"test";

        let signature = keypair.sign(message);
        assert_eq!(signature.to_bytes().len(), 64);
    }
}

// =============================================================================
// Serialization Tests
// =============================================================================

mod serialization_tests {
    use super::*;

    #[test]
    fn test_verifying_key_to_bytes_roundtrip() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let original = keypair.verifying_key();

        let bytes = original.to_bytes();
        let restored = Ed25519VerifyingKey::from_bytes(&bytes).unwrap();

        assert_eq!(original, &restored);
    }

    #[test]
    fn test_verifying_key_from_bytes_invalid_length() {
        let short_bytes = [0u8; 16];
        let result = Ed25519VerifyingKey::from_bytes(&short_bytes);

        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 16
            })
        ));
    }

    #[test]
    fn test_signature_to_bytes_roundtrip() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let message = b"test";

        let original = keypair.sign(message);
        let bytes = original.to_bytes();
        let restored = Ed25519Signature::from_bytes(&bytes).unwrap();

        assert_eq!(original, restored);
    }

    #[test]
    fn test_signature_from_bytes_invalid_length() {
        let short_bytes = [0u8; 32];
        let result = Ed25519Signature::from_bytes(&short_bytes);

        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 64,
                actual: 32
            })
        ));
    }

    #[test]
    fn test_verifying_key_serde_roundtrip() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let original = keypair.verifying_key().clone();

        let json = serde_json::to_string(&original).unwrap();
        let restored: Ed25519VerifyingKey = serde_json::from_str(&json).unwrap();

        assert_eq!(original, restored);
    }

    #[test]
    fn test_signature_serde_roundtrip() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let original = keypair.sign(b"test");

        let json = serde_json::to_string(&original).unwrap();
        let restored: Ed25519Signature = serde_json::from_str(&json).unwrap();

        assert_eq!(original, restored);
    }
}

// =============================================================================
// RFC 8032 Test Vectors
// =============================================================================

mod rfc8032_tests {
    use super::*;

    /// RFC 8032 Section 7.1 - Test 1
    /// 
    /// SECRET KEY:
    ///   9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
    /// PUBLIC KEY:
    ///   d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
    /// MESSAGE (length 0 bytes):
    ///   (empty)
    /// SIGNATURE:
    ///   e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155
    ///   5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
    #[test]
    fn test_rfc8032_test_vector_1() {
        let secret_key = hex::decode(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        ).unwrap();
        let expected_public_key = hex::decode(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        ).unwrap();
        let message: &[u8] = b"";
        let expected_signature = hex::decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ).unwrap();

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&secret_key);
        let keypair = Ed25519KeyPair::from_seed(&seed).unwrap();

        // Verify public key
        assert_eq!(
            keypair.verifying_key().to_bytes().as_slice(),
            expected_public_key.as_slice()
        );

        // Sign and verify signature
        let signature = keypair.sign(message);
        assert_eq!(signature.to_bytes().as_slice(), expected_signature.as_slice());

        // Verify the signature
        assert!(keypair.verifying_key().verify(message, &signature).is_ok());
    }

    /// RFC 8032 Section 7.1 - Test 2
    /// 
    /// SECRET KEY:
    ///   4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
    /// PUBLIC KEY:
    ///   3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
    /// MESSAGE (length 1 byte):
    ///   72
    /// SIGNATURE:
    ///   92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da
    ///   085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00
    #[test]
    fn test_rfc8032_test_vector_2() {
        let secret_key = hex::decode(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
        ).unwrap();
        let expected_public_key = hex::decode(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        ).unwrap();
        let message = hex::decode("72").unwrap();
        let expected_signature = hex::decode(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ).unwrap();

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&secret_key);
        let keypair = Ed25519KeyPair::from_seed(&seed).unwrap();

        // Verify public key
        assert_eq!(
            keypair.verifying_key().to_bytes().as_slice(),
            expected_public_key.as_slice()
        );

        // Sign and verify signature
        let signature = keypair.sign(&message);
        assert_eq!(signature.to_bytes().as_slice(), expected_signature.as_slice());

        // Verify the signature
        assert!(keypair.verifying_key().verify(&message, &signature).is_ok());
    }

    /// RFC 8032 Section 7.1 - Test 3
    /// 
    /// SECRET KEY:
    ///   c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7
    /// PUBLIC KEY:
    ///   fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025
    /// MESSAGE (length 2 bytes):
    ///   af82
    /// SIGNATURE:
    ///   6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac
    ///   18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a
    #[test]
    fn test_rfc8032_test_vector_3() {
        let secret_key = hex::decode(
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
        ).unwrap();
        let expected_public_key = hex::decode(
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
        ).unwrap();
        let message = hex::decode("af82").unwrap();
        let expected_signature = hex::decode(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        ).unwrap();

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&secret_key);
        let keypair = Ed25519KeyPair::from_seed(&seed).unwrap();

        // Verify public key
        assert_eq!(
            keypair.verifying_key().to_bytes().as_slice(),
            expected_public_key.as_slice()
        );

        // Sign and verify signature
        let signature = keypair.sign(&message);
        assert_eq!(signature.to_bytes().as_slice(), expected_signature.as_slice());

        // Verify the signature
        assert!(keypair.verifying_key().verify(&message, &signature).is_ok());
    }

    /// RFC 8032 Section 7.1 - Test 1024
    /// 
    /// This tests a longer message (1023 bytes).
    #[test]
    fn test_rfc8032_test_vector_1024() {
        let secret_key = hex::decode(
            "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5"
        ).unwrap();
        let expected_public_key = hex::decode(
            "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e"
        ).unwrap();
        let message = hex::decode(
            "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98\
             fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8\
             79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d\
             658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc\
             1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe\
             ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e\
             06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef\
             efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7\
             aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1\
             85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2\
             d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24\
             554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270\
             88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc\
             2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07\
             07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba\
             b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a\
             ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e\
             c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7\
             51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c\
             42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8\
             ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df\
             f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08\
             d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649\
             de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4\
             88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3\
             2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e\
             6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f\
             b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5\
             0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1\
             369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d\
             b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c\
             0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0"
        ).unwrap();
        let expected_signature = hex::decode(
            "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03"
        ).unwrap();

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&secret_key);
        let keypair = Ed25519KeyPair::from_seed(&seed).unwrap();

        // Verify public key
        assert_eq!(
            keypair.verifying_key().to_bytes().as_slice(),
            expected_public_key.as_slice()
        );

        // Sign and verify signature
        let signature = keypair.sign(&message);
        assert_eq!(signature.to_bytes().as_slice(), expected_signature.as_slice());

        // Verify the signature
        assert!(keypair.verifying_key().verify(&message, &signature).is_ok());
    }
}

// =============================================================================
// Zeroize Tests
// =============================================================================

mod zeroize_tests {
    use super::*;

    #[test]
    fn test_signing_key_is_zeroized_on_drop() {
        let seed = [42u8; 32];
        let keypair = Ed25519KeyPair::from_seed(&seed).unwrap();

        // Verify we can sign before drop
        let message = b"test";
        let _signature = keypair.sign(message);

        // Drop happens here - zeroization should occur
        drop(keypair);

        // Note: We can't verify the memory is zeroed after drop in safe Rust,
        // but the ZeroizeOnDrop derive ensures it happens
    }
}
