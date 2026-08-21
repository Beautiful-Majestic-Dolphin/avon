//! Digital signature implementations using Ed25519.
//!
//! This module provides Ed25519 digital signatures for message authentication
//! and non-repudiation. Ed25519 is a modern, secure, and fast signature scheme.
//!
//! # Example
//!
//! ```
//! use avon_crypto::signature::Ed25519KeyPair;
//!
//! // Generate a keypair
//! let keypair = Ed25519KeyPair::generate().unwrap();
//!
//! // Sign a message
//! let message = b"Hello, AVON!";
//! let signature = keypair.sign(message);
//!
//! // Verify the signature
//! keypair.verifying_key().verify(message, &signature).unwrap();
//! ```

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

/// An Ed25519 signing (private) key.
///
/// This key is automatically zeroed when dropped to prevent sensitive
/// data from remaining in memory.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ed25519SigningKey([u8; 32]);

impl Ed25519SigningKey {
    /// The length of an Ed25519 signing key in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a new signing key from raw bytes (seed).
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 32-byte array containing the signing key seed.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes of the signing key.
    ///
    /// # Security
    ///
    /// Be careful when using this method as it exposes the raw private key.
    /// The returned reference should not be stored or logged.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// An Ed25519 verifying (public) key.
///
/// Verifying keys can be safely shared with other parties and are used
/// to verify signatures created by the corresponding signing key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519VerifyingKey(#[serde(with = "serde_bytes_array_32")] [u8; 32]);

impl Ed25519VerifyingKey {
    /// The length of an Ed25519 verifying key in bytes.
    pub const LENGTH: usize = 32;

    /// Returns the verifying key as a byte array.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::signature::Ed25519KeyPair;
    ///
    /// let keypair = Ed25519KeyPair::generate().unwrap();
    /// let bytes = keypair.verifying_key().to_bytes();
    /// assert_eq!(bytes.len(), 32);
    /// ```
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Creates a verifying key from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 32-byte slice containing the verifying key.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKeyLength` if the slice is not exactly 32 bytes.
    /// Returns `CryptoError::InvalidSignature` if the bytes don't represent a valid key.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::signature::{Ed25519KeyPair, Ed25519VerifyingKey};
    ///
    /// let keypair = Ed25519KeyPair::generate().unwrap();
    /// let bytes = keypair.verifying_key().to_bytes();
    /// let restored = Ed25519VerifyingKey::from_bytes(&bytes).unwrap();
    /// assert_eq!(keypair.verifying_key(), &restored);
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != Self::LENGTH {
            return Err(CryptoError::InvalidKeyLength {
                expected: Self::LENGTH,
                actual: bytes.len(),
            });
        }

        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);

        // Validate that the bytes represent a valid Ed25519 public key
        VerifyingKey::from_bytes(&array).map_err(|_| CryptoError::InvalidSignature)?;

        Ok(Self(array))
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
    /// use avon_crypto::signature::Ed25519KeyPair;
    ///
    /// let keypair = Ed25519KeyPair::generate().unwrap();
    /// let message = b"test message";
    /// let signature = keypair.sign(message);
    ///
    /// // Verification succeeds
    /// assert!(keypair.verifying_key().verify(message, &signature).is_ok());
    ///
    /// // Verification fails for wrong message
    /// assert!(keypair.verifying_key().verify(b"wrong message", &signature).is_err());
    /// ```
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> Result<(), CryptoError> {
        let verifying_key =
            VerifyingKey::from_bytes(&self.0).map_err(|_| CryptoError::InvalidSignature)?;

        let sig = ed25519_dalek::Signature::from_bytes(&signature.0);

        verifying_key
            .verify(message, &sig)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

/// An Ed25519 signature.
///
/// Signatures are 64 bytes and can be safely shared and stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519Signature(#[serde(with = "serde_bytes_array_64")] [u8; 64]);

impl Ed25519Signature {
    /// The length of an Ed25519 signature in bytes.
    pub const LENGTH: usize = 64;

    /// Returns the signature as a byte array.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::signature::Ed25519KeyPair;
    ///
    /// let keypair = Ed25519KeyPair::generate().unwrap();
    /// let signature = keypair.sign(b"message");
    /// let bytes = signature.to_bytes();
    /// assert_eq!(bytes.len(), 64);
    /// ```
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }

    /// Creates a signature from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 64-byte slice containing the signature.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKeyLength` if the slice is not exactly 64 bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::signature::{Ed25519KeyPair, Ed25519Signature};
    ///
    /// let keypair = Ed25519KeyPair::generate().unwrap();
    /// let signature = keypair.sign(b"message");
    /// let bytes = signature.to_bytes();
    /// let restored = Ed25519Signature::from_bytes(&bytes).unwrap();
    /// assert_eq!(signature, restored);
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != Self::LENGTH {
            return Err(CryptoError::InvalidKeyLength {
                expected: Self::LENGTH,
                actual: bytes.len(),
            });
        }

        let mut array = [0u8; 64];
        array.copy_from_slice(bytes);
        Ok(Self(array))
    }
}

/// An Ed25519 key pair consisting of a signing key and its corresponding verifying key.
///
/// This is the main type for creating Ed25519 digital signatures.
pub struct Ed25519KeyPair {
    signing: Ed25519SigningKey,
    verifying: Ed25519VerifyingKey,
}

impl Ed25519KeyPair {
    /// Generates a new random Ed25519 key pair.
    ///
    /// Uses the operating system's cryptographically secure random number
    /// generator to generate the signing key.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::RandomGenerationFailed` if random number
    /// generation fails (extremely rare on modern systems).
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::signature::Ed25519KeyPair;
    ///
    /// let keypair = Ed25519KeyPair::generate().unwrap();
    /// ```
    pub fn generate() -> Result<Self, CryptoError> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing: Ed25519SigningKey(signing_key.to_bytes()),
            verifying: Ed25519VerifyingKey(verifying_key.to_bytes()),
        })
    }

    /// Creates a key pair from a 32-byte seed.
    ///
    /// This allows deterministic key generation from a seed value.
    /// The same seed will always produce the same key pair.
    ///
    /// # Arguments
    ///
    /// * `seed` - A 32-byte seed value.
    ///
    /// # Errors
    ///
    /// This function currently cannot fail, but returns a Result for
    /// API consistency and future compatibility.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::signature::Ed25519KeyPair;
    ///
    /// let seed = [42u8; 32];
    /// let keypair1 = Ed25519KeyPair::from_seed(&seed).unwrap();
    /// let keypair2 = Ed25519KeyPair::from_seed(&seed).unwrap();
    ///
    /// // Same seed produces same keypair
    /// assert_eq!(keypair1.verifying_key(), keypair2.verifying_key());
    /// ```
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, CryptoError> {
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing: Ed25519SigningKey(signing_key.to_bytes()),
            verifying: Ed25519VerifyingKey(verifying_key.to_bytes()),
        })
    }

    /// Returns a reference to the verifying (public) key.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::signature::Ed25519KeyPair;
    ///
    /// let keypair = Ed25519KeyPair::generate().unwrap();
    /// let verifying_key = keypair.verifying_key();
    /// ```
    pub fn verifying_key(&self) -> &Ed25519VerifyingKey {
        &self.verifying
    }

    /// Signs a message with the signing key.
    ///
    /// Ed25519 signatures are deterministic - signing the same message
    /// with the same key will always produce the same signature.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign.
    ///
    /// # Returns
    ///
    /// A 64-byte Ed25519 signature.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::signature::Ed25519KeyPair;
    ///
    /// let keypair = Ed25519KeyPair::generate().unwrap();
    /// let message = b"Hello, AVON!";
    /// let signature = keypair.sign(message);
    ///
    /// // Verify the signature
    /// keypair.verifying_key().verify(message, &signature).unwrap();
    /// ```
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let signing_key = SigningKey::from_bytes(self.signing.as_bytes());
        let signature = signing_key.sign(message);
        Ed25519Signature(signature.to_bytes())
    }
}

/// Helper module for serde serialization of 32-byte arrays.
mod serde_bytes_array_32 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<u8> = Vec::deserialize(deserializer)?;
        if vec.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes, got {}",
                vec.len()
            )));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&vec);
        Ok(array)
    }
}

/// Helper module for serde serialization of 64-byte arrays.
mod serde_bytes_array_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<u8> = Vec::deserialize(deserializer)?;
        if vec.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 bytes, got {}",
                vec.len()
            )));
        }
        let mut array = [0u8; 64];
        array.copy_from_slice(&vec);
        Ok(array)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        assert_eq!(keypair.verifying_key().to_bytes().len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let message = b"test message";
        let signature = keypair.sign(message);

        assert!(keypair.verifying_key().verify(message, &signature).is_ok());
    }

    #[test]
    fn test_verifying_key_serialization() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let bytes = keypair.verifying_key().to_bytes();
        let restored = Ed25519VerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(keypair.verifying_key(), &restored);
    }
}
