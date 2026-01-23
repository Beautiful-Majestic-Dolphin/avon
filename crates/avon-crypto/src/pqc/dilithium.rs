//! CRYSTALS-Dilithium Digital Signature Algorithm.
//!
//! This module provides Dilithium3, a post-quantum digital signature algorithm
//! that provides NIST Level 3 security (equivalent to AES-192). Dilithium is one
//! of the algorithms selected by NIST for post-quantum cryptography standardization.
//!
//! # Digital Signatures
//!
//! Dilithium provides the standard digital signature operations:
//! 1. Key generation produces a signing key and verifying key pair
//! 2. The signing key is used to sign messages
//! 3. The verifying key is used to verify signatures
//!
//! # Example
//!
//! ```
//! use avon_crypto::pqc::dilithium::DilithiumKeyPair;
//!
//! // Generate a keypair
//! let keypair = DilithiumKeyPair::generate().unwrap();
//!
//! // Sign a message
//! let message = b"Hello, post-quantum world!";
//! let signature = keypair.sign(message);
//!
//! // Verify the signature
//! keypair.verifying_key().verify(message, &signature).unwrap();
//! ```
//!
//! # Security Level
//!
//! Dilithium3 provides NIST Level 3 security, which is roughly equivalent to
//! AES-192 against classical computers, and is designed to resist attacks by
//! quantum computers.

use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

/// Size of a Dilithium3 public key in bytes.
pub const DILITHIUM3_PUBLIC_KEY_BYTES: usize = 1952;

/// Size of a Dilithium3 secret key in bytes.
pub const DILITHIUM3_SECRET_KEY_BYTES: usize = 4016;

/// Size of a Dilithium3 signature in bytes.
pub const DILITHIUM3_SIGNATURE_BYTES: usize = 3309;

/// A Dilithium3 signing key.
///
/// This key is automatically zeroed when dropped to prevent sensitive
/// data from remaining in memory.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DilithiumSigningKey(Vec<u8>);

impl DilithiumSigningKey {
    /// The length of a Dilithium3 signing key in bytes.
    pub const LENGTH: usize = DILITHIUM3_SECRET_KEY_BYTES;

    /// Creates a new signing key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The signing key bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKeyLength` if the bytes are not the correct length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != Self::LENGTH {
            return Err(CryptoError::InvalidKeyLength {
                expected: Self::LENGTH,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Returns the raw bytes of the signing key.
    ///
    /// # Security
    ///
    /// Be careful when using this method as it exposes the raw signing key.
    /// The returned reference should not be stored or logged.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A Dilithium3 verifying key (public key).
///
/// Verifying keys can be safely shared with other parties and are used
/// to verify signatures.
#[derive(Clone, Debug)]
pub struct DilithiumVerifyingKey(Vec<u8>);

impl DilithiumVerifyingKey {
    /// The length of a Dilithium3 verifying key in bytes.
    pub const LENGTH: usize = DILITHIUM3_PUBLIC_KEY_BYTES;

    /// Returns the verifying key as a byte vector.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::pqc::dilithium::DilithiumKeyPair;
    ///
    /// let keypair = DilithiumKeyPair::generate().unwrap();
    /// let bytes = keypair.verifying_key().to_bytes();
    /// assert_eq!(bytes.len(), 1952);
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    /// Creates a verifying key from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The verifying key bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKeyLength` if the bytes are not the correct length.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::pqc::dilithium::{DilithiumKeyPair, DilithiumVerifyingKey};
    ///
    /// let keypair = DilithiumKeyPair::generate().unwrap();
    /// let bytes = keypair.verifying_key().to_bytes();
    /// let restored = DilithiumVerifyingKey::from_bytes(&bytes).unwrap();
    /// assert_eq!(keypair.verifying_key().to_bytes(), restored.to_bytes());
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != Self::LENGTH {
            return Err(CryptoError::InvalidKeyLength {
                expected: Self::LENGTH,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Verifies a signature on a message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed.
    /// * `signature` - The signature to verify.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidSignature` if the signature is invalid.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::pqc::dilithium::DilithiumKeyPair;
    ///
    /// let keypair = DilithiumKeyPair::generate().unwrap();
    /// let message = b"test message";
    /// let signature = keypair.sign(message);
    ///
    /// // Verification succeeds
    /// assert!(keypair.verifying_key().verify(message, &signature).is_ok());
    ///
    /// // Verification fails for wrong message
    /// assert!(keypair.verifying_key().verify(b"wrong message", &signature).is_err());
    /// ```
    pub fn verify(
        &self,
        message: &[u8],
        signature: &DilithiumSignature,
    ) -> Result<(), CryptoError> {
        let pk = dilithium3::PublicKey::from_bytes(&self.0)
            .map_err(|_| CryptoError::InvalidSignature)?;

        let sig = dilithium3::DetachedSignature::from_bytes(&signature.0)
            .map_err(|_| CryptoError::InvalidSignature)?;

        dilithium3::verify_detached_signature(&sig, message, &pk)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

/// A Dilithium3 signature.
///
/// Signatures are produced by signing a message with a signing key and
/// can be verified using the corresponding verifying key.
#[derive(Clone, Debug)]
pub struct DilithiumSignature(Vec<u8>);

impl DilithiumSignature {
    /// The length of a Dilithium3 signature in bytes.
    pub const LENGTH: usize = DILITHIUM3_SIGNATURE_BYTES;

    /// Returns the signature as a byte vector.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::pqc::dilithium::DilithiumKeyPair;
    ///
    /// let keypair = DilithiumKeyPair::generate().unwrap();
    /// let signature = keypair.sign(b"test message");
    /// let bytes = signature.to_bytes();
    /// assert_eq!(bytes.len(), 3309);
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    /// Creates a signature from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The signature bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKeyLength` if the bytes are not the correct length.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::pqc::dilithium::{DilithiumKeyPair, DilithiumSignature};
    ///
    /// let keypair = DilithiumKeyPair::generate().unwrap();
    /// let signature = keypair.sign(b"test message");
    /// let bytes = signature.to_bytes();
    /// let restored = DilithiumSignature::from_bytes(&bytes).unwrap();
    /// assert_eq!(signature.to_bytes(), restored.to_bytes());
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != Self::LENGTH {
            return Err(CryptoError::InvalidKeyLength {
                expected: Self::LENGTH,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }
}

/// A Dilithium3 key pair consisting of a signing key and its corresponding verifying key.
///
/// This is the main type for performing Dilithium digital signatures.
pub struct DilithiumKeyPair {
    signing: DilithiumSigningKey,
    verifying: DilithiumVerifyingKey,
}

impl DilithiumKeyPair {
    /// Generates a new random Dilithium3 key pair.
    ///
    /// Uses a cryptographically secure random number generator.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::RandomGenerationFailed` if key generation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::pqc::dilithium::DilithiumKeyPair;
    ///
    /// let keypair = DilithiumKeyPair::generate().unwrap();
    /// ```
    pub fn generate() -> Result<Self, CryptoError> {
        let (pk, sk) = dilithium3::keypair();

        Ok(Self {
            signing: DilithiumSigningKey(sk.as_bytes().to_vec()),
            verifying: DilithiumVerifyingKey(pk.as_bytes().to_vec()),
        })
    }

    /// Returns a reference to the verifying key.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::pqc::dilithium::DilithiumKeyPair;
    ///
    /// let keypair = DilithiumKeyPair::generate().unwrap();
    /// let verifying_key = keypair.verifying_key();
    /// ```
    pub fn verifying_key(&self) -> &DilithiumVerifyingKey {
        &self.verifying
    }

    /// Signs a message using the signing key.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign.
    ///
    /// # Returns
    ///
    /// The signature for the message.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::pqc::dilithium::DilithiumKeyPair;
    ///
    /// let keypair = DilithiumKeyPair::generate().unwrap();
    /// let message = b"Hello, post-quantum world!";
    /// let signature = keypair.sign(message);
    ///
    /// // Verify the signature
    /// assert!(keypair.verifying_key().verify(message, &signature).is_ok());
    /// ```
    pub fn sign(&self, message: &[u8]) -> DilithiumSignature {
        let sk = dilithium3::SecretKey::from_bytes(&self.signing.0)
            .expect("signing key should be valid");

        let sig = dilithium3::detached_sign(message, &sk);
        DilithiumSignature(sig.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = DilithiumKeyPair::generate().unwrap();
        assert_eq!(
            keypair.verifying_key().to_bytes().len(),
            DILITHIUM3_PUBLIC_KEY_BYTES
        );
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = DilithiumKeyPair::generate().unwrap();
        let message = b"test message";
        let signature = keypair.sign(message);

        assert!(keypair.verifying_key().verify(message, &signature).is_ok());
    }

    #[test]
    fn test_verifying_key_serialization() {
        let keypair = DilithiumKeyPair::generate().unwrap();
        let bytes = keypair.verifying_key().to_bytes();
        let restored = DilithiumVerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(keypair.verifying_key().to_bytes(), restored.to_bytes());
    }
}
