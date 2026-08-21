//! Hybrid Signatures combining Ed25519 (classical) and ML-DSA-65 (PQC).
//!
//! This module provides a hybrid signature scheme that combines classical
//! elliptic curve signatures (Ed25519) with post-quantum signatures (ML-DSA-65).
//!
//! # Security Property
//!
//! Forgery requires breaking BOTH Ed25519 AND ML-DSA-65. This provides
//! defense-in-depth against both classical and quantum attacks.
//!
//! # Example
//!
//! ```
//! use avon_crypto::hybrid::signature::HybridSigningKeyPair;
//!
//! // Generate a signing keypair
//! let keypair = HybridSigningKeyPair::generate().unwrap();
//!
//! // Sign a message
//! let message = b"Hello, hybrid world!";
//! let signature = keypair.sign(message);
//!
//! // Verify the signature (both Ed25519 and ML-DSA-65 must verify)
//! keypair.verifying_key().verify(message, &signature).unwrap();
//! ```

use crate::error::CryptoError;
use crate::pqc::mldsa::{
    MlDsaKeyPair, MlDsaSignature, MlDsaVerifyingKey, MLDSA65_PUBLIC_KEY_BYTES,
    MLDSA65_SIGNATURE_BYTES,
};
use crate::signature::{Ed25519KeyPair, Ed25519Signature, Ed25519VerifyingKey};

/// A hybrid signing key pair combining Ed25519 and ML-DSA-65.
pub struct HybridSigningKeyPair {
    classical: Ed25519KeyPair,
    pqc: MlDsaKeyPair,
}

impl HybridSigningKeyPair {
    /// Generates a new random hybrid signing key pair.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::RandomGenerationFailed` if key generation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::hybrid::signature::HybridSigningKeyPair;
    ///
    /// let keypair = HybridSigningKeyPair::generate().unwrap();
    /// ```
    pub fn generate() -> Result<Self, CryptoError> {
        let classical = Ed25519KeyPair::generate()?;
        let pqc = MlDsaKeyPair::generate()?;

        Ok(Self { classical, pqc })
    }

    /// Returns the hybrid verifying key.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::hybrid::signature::HybridSigningKeyPair;
    ///
    /// let keypair = HybridSigningKeyPair::generate().unwrap();
    /// let verifying_key = keypair.verifying_key();
    /// ```
    pub fn verifying_key(&self) -> HybridVerifyingKey {
        HybridVerifyingKey {
            classical: self.classical.verifying_key().clone(),
            pqc: self.pqc.verifying_key().clone(),
        }
    }

    /// Signs a message using both Ed25519 and ML-DSA-65.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign.
    ///
    /// # Returns
    ///
    /// A hybrid signature containing both Ed25519 and ML-DSA-65 signatures.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::hybrid::signature::HybridSigningKeyPair;
    ///
    /// let keypair = HybridSigningKeyPair::generate().unwrap();
    /// let message = b"Hello, hybrid world!";
    /// let signature = keypair.sign(message);
    ///
    /// // Verify the signature
    /// assert!(keypair.verifying_key().verify(message, &signature).is_ok());
    /// ```
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        let classical = self.classical.sign(message);
        let pqc = match self.pqc.sign(message) {
            Ok(sig) => sig,
            Err(_) => unreachable!("ML-DSA signing key has a fixed, validated length"),
        };

        HybridSignature { classical, pqc }
    }
}

/// A hybrid verifying key combining Ed25519 and ML-DSA-65 verifying keys.
#[derive(Clone)]
pub struct HybridVerifyingKey {
    classical: Ed25519VerifyingKey,
    pqc: MlDsaVerifyingKey,
}

impl HybridVerifyingKey {
    /// Verifies a hybrid signature on a message.
    ///
    /// BOTH the Ed25519 and ML-DSA-65 signatures must verify for the
    /// hybrid signature to be considered valid.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed.
    /// * `signature` - The hybrid signature to verify.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidSignature` if either signature is invalid.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::hybrid::signature::HybridSigningKeyPair;
    ///
    /// let keypair = HybridSigningKeyPair::generate().unwrap();
    /// let message = b"test message";
    /// let signature = keypair.sign(message);
    ///
    /// // Verification succeeds
    /// assert!(keypair.verifying_key().verify(message, &signature).is_ok());
    ///
    /// // Verification fails for wrong message
    /// assert!(keypair.verifying_key().verify(b"wrong message", &signature).is_err());
    /// ```
    pub fn verify(&self, message: &[u8], signature: &HybridSignature) -> Result<(), CryptoError> {
        // Both signatures must verify
        self.classical.verify(message, &signature.classical)?;
        self.pqc.verify(message, &signature.pqc)?;

        Ok(())
    }

    /// Returns the hybrid verifying key as bytes.
    ///
    /// Format: Ed25519 verifying key (32 bytes) || ML-DSA verifying key (1952 bytes)
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::hybrid::signature::HybridSigningKeyPair;
    ///
    /// let keypair = HybridSigningKeyPair::generate().unwrap();
    /// let bytes = keypair.verifying_key().to_bytes();
    /// assert_eq!(bytes.len(), 32 + 1952);
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + MLDSA65_PUBLIC_KEY_BYTES);
        bytes.extend_from_slice(&self.classical.to_bytes());
        bytes.extend_from_slice(&self.pqc.to_bytes());
        bytes
    }

    /// Creates a hybrid verifying key from bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The serialized hybrid verifying key.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKeyLength` if the bytes are not the correct length.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::hybrid::signature::{HybridSigningKeyPair, HybridVerifyingKey};
    ///
    /// let keypair = HybridSigningKeyPair::generate().unwrap();
    /// let bytes = keypair.verifying_key().to_bytes();
    /// let restored = HybridVerifyingKey::from_bytes(&bytes).unwrap();
    /// assert_eq!(keypair.verifying_key().to_bytes(), restored.to_bytes());
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        const EXPECTED_LEN: usize = 32 + MLDSA65_PUBLIC_KEY_BYTES;
        if bytes.len() != EXPECTED_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: EXPECTED_LEN,
                actual: bytes.len(),
            });
        }

        let classical = Ed25519VerifyingKey::from_bytes(&bytes[..32])?;
        let pqc = MlDsaVerifyingKey::from_bytes(&bytes[32..])?;

        Ok(Self { classical, pqc })
    }
}

/// A hybrid signature combining Ed25519 and ML-DSA-65 signatures.
#[derive(Clone)]
pub struct HybridSignature {
    classical: Ed25519Signature,
    pqc: MlDsaSignature,
}

impl HybridSignature {
    /// Returns the hybrid signature as bytes.
    ///
    /// Format: Ed25519 signature (64 bytes) || ML-DSA signature (3309 bytes)
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::hybrid::signature::HybridSigningKeyPair;
    ///
    /// let keypair = HybridSigningKeyPair::generate().unwrap();
    /// let signature = keypair.sign(b"test message");
    /// let bytes = signature.to_bytes();
    /// assert_eq!(bytes.len(), 64 + 3309);
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64 + MLDSA65_SIGNATURE_BYTES);
        bytes.extend_from_slice(&self.classical.to_bytes());
        bytes.extend_from_slice(&self.pqc.to_bytes());
        bytes
    }

    /// Creates a hybrid signature from bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The serialized hybrid signature.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKeyLength` if the bytes are not the correct length.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::hybrid::signature::{HybridSigningKeyPair, HybridSignature};
    ///
    /// let keypair = HybridSigningKeyPair::generate().unwrap();
    /// let signature = keypair.sign(b"test message");
    /// let bytes = signature.to_bytes();
    /// let restored = HybridSignature::from_bytes(&bytes).unwrap();
    /// assert_eq!(signature.to_bytes(), restored.to_bytes());
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        const EXPECTED_LEN: usize = 64 + MLDSA65_SIGNATURE_BYTES;
        if bytes.len() != EXPECTED_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: EXPECTED_LEN,
                actual: bytes.len(),
            });
        }

        let classical = Ed25519Signature::from_bytes(&bytes[..64])?;
        let pqc = MlDsaSignature::from_bytes(&bytes[64..])?;

        Ok(Self { classical, pqc })
    }

    /// Returns a reference to the classical (Ed25519) signature component.
    ///
    /// This is useful for testing or when you need to inspect individual components.
    pub fn classical(&self) -> &Ed25519Signature {
        &self.classical
    }

    /// Returns a reference to the PQC (ML-DSA-65) signature component.
    ///
    /// This is useful for testing or when you need to inspect individual components.
    pub fn pqc(&self) -> &MlDsaSignature {
        &self.pqc
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_hybrid_sign_and_verify() {
        let keypair = HybridSigningKeyPair::generate().unwrap();
        let message = b"test message";
        let signature = keypair.sign(message);

        assert!(keypair.verifying_key().verify(message, &signature).is_ok());
    }

    #[test]
    fn test_verifying_key_serialization() {
        let keypair = HybridSigningKeyPair::generate().unwrap();
        let bytes = keypair.verifying_key().to_bytes();
        let restored = HybridVerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(keypair.verifying_key().to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_signature_serialization() {
        let keypair = HybridSigningKeyPair::generate().unwrap();
        let signature = keypair.sign(b"test message");
        let bytes = signature.to_bytes();
        let restored = HybridSignature::from_bytes(&bytes).unwrap();
        assert_eq!(signature.to_bytes(), restored.to_bytes());
    }
}
