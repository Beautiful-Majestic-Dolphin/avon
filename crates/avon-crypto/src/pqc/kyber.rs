//! CRYSTALS-Kyber Key Encapsulation Mechanism (KEM).
//!
//! This module provides Kyber768, a post-quantum key encapsulation mechanism
//! that provides NIST Level 3 security (equivalent to AES-192). Kyber is one
//! of the algorithms selected by NIST for post-quantum cryptography standardization.
//!
//! # Key Encapsulation Mechanism (KEM)
//!
//! Unlike Diffie-Hellman key exchange, a KEM works differently:
//! 1. One party generates a keypair and shares the public key
//! 2. The other party uses the public key to "encapsulate" - this produces
//!    both a ciphertext and a shared secret
//! 3. The first party uses their secret key to "decapsulate" the ciphertext,
//!    recovering the same shared secret
//!
//! # Example
//!
//! ```
//! use avon_crypto::pqc::kyber::KyberKeyPair;
//!
//! // Alice generates a keypair
//! let alice = KyberKeyPair::generate().unwrap();
//!
//! // Bob encapsulates using Alice's public key
//! let (ciphertext, bob_shared) = alice.public_key().encapsulate().unwrap();
//!
//! // Alice decapsulates to get the same shared secret
//! let alice_shared = alice.decapsulate(&ciphertext).unwrap();
//!
//! assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
//! ```
//!
//! # Security Level
//!
//! Kyber768 provides NIST Level 3 security, which is roughly equivalent to
//! AES-192 or 3072-bit RSA against classical computers, and is designed to
//! resist attacks by quantum computers.

use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

/// Size of a Kyber768 public key in bytes.
pub const KYBER768_PUBLIC_KEY_BYTES: usize = 1184;

/// Size of a Kyber768 secret key in bytes.
pub const KYBER768_SECRET_KEY_BYTES: usize = 2400;

/// Size of a Kyber768 ciphertext in bytes.
pub const KYBER768_CIPHERTEXT_BYTES: usize = 1088;

/// Size of a Kyber768 shared secret in bytes.
pub const KYBER768_SHARED_SECRET_BYTES: usize = 32;

/// A Kyber768 secret key.
///
/// This key is automatically zeroed when dropped to prevent sensitive
/// data from remaining in memory.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KyberSecretKey(Vec<u8>);

impl KyberSecretKey {
    /// The length of a Kyber768 secret key in bytes.
    pub const LENGTH: usize = KYBER768_SECRET_KEY_BYTES;

    /// Creates a new secret key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The secret key bytes.
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

    /// Returns the raw bytes of the secret key.
    ///
    /// # Security
    ///
    /// Be careful when using this method as it exposes the raw secret key.
    /// The returned reference should not be stored or logged.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A Kyber768 public key.
///
/// Public keys can be safely shared with other parties and are used
/// to encapsulate shared secrets.
#[derive(Clone, Debug)]
pub struct KyberPublicKey(Vec<u8>);

impl KyberPublicKey {
    /// The length of a Kyber768 public key in bytes.
    pub const LENGTH: usize = KYBER768_PUBLIC_KEY_BYTES;

    /// Returns the public key as a byte vector.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::pqc::kyber::KyberKeyPair;
    ///
    /// let keypair = KyberKeyPair::generate().unwrap();
    /// let bytes = keypair.public_key().to_bytes();
    /// assert_eq!(bytes.len(), 1184);
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    /// Creates a public key from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The public key bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKeyLength` if the bytes are not the correct length.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::pqc::kyber::{KyberKeyPair, KyberPublicKey};
    ///
    /// let keypair = KyberKeyPair::generate().unwrap();
    /// let bytes = keypair.public_key().to_bytes();
    /// let restored = KyberPublicKey::from_bytes(&bytes).unwrap();
    /// assert_eq!(keypair.public_key().to_bytes(), restored.to_bytes());
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

    /// Encapsulates a shared secret using this public key.
    ///
    /// This generates a random shared secret and encrypts it using the public key.
    /// The ciphertext can only be decapsulated by the holder of the corresponding
    /// secret key.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - The ciphertext that should be sent to the secret key holder
    /// - The shared secret that can be used for symmetric encryption
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EncryptionFailed` if encapsulation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::pqc::kyber::KyberKeyPair;
    ///
    /// let keypair = KyberKeyPair::generate().unwrap();
    /// let (ciphertext, shared_secret) = keypair.public_key().encapsulate().unwrap();
    /// ```
    pub fn encapsulate(&self) -> Result<(KyberCiphertext, KyberSharedSecret), CryptoError> {
        let pk = kyber768::PublicKey::from_bytes(&self.0)
            .map_err(|_| CryptoError::EncryptionFailed("invalid public key".to_string()))?;

        let (ss, ct) = kyber768::encapsulate(&pk);

        Ok((
            KyberCiphertext(ct.as_bytes().to_vec()),
            KyberSharedSecret(ss.as_bytes().try_into().map_err(|_| {
                CryptoError::EncryptionFailed("invalid shared secret length".to_string())
            })?),
        ))
    }
}

/// A Kyber768 ciphertext.
///
/// Ciphertexts are produced by encapsulation and can be decapsulated
/// by the holder of the corresponding secret key.
#[derive(Clone, Debug)]
pub struct KyberCiphertext(Vec<u8>);

impl KyberCiphertext {
    /// The length of a Kyber768 ciphertext in bytes.
    pub const LENGTH: usize = KYBER768_CIPHERTEXT_BYTES;

    /// Returns the ciphertext as a byte vector.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::pqc::kyber::KyberKeyPair;
    ///
    /// let keypair = KyberKeyPair::generate().unwrap();
    /// let (ciphertext, _) = keypair.public_key().encapsulate().unwrap();
    /// let bytes = ciphertext.to_bytes();
    /// assert_eq!(bytes.len(), 1088);
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    /// Creates a ciphertext from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The ciphertext bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKeyLength` if the bytes are not the correct length.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::pqc::kyber::{KyberKeyPair, KyberCiphertext};
    ///
    /// let keypair = KyberKeyPair::generate().unwrap();
    /// let (ciphertext, _) = keypair.public_key().encapsulate().unwrap();
    /// let bytes = ciphertext.to_bytes();
    /// let restored = KyberCiphertext::from_bytes(&bytes).unwrap();
    /// assert_eq!(ciphertext.to_bytes(), restored.to_bytes());
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

/// A shared secret derived from Kyber768 key encapsulation.
///
/// This secret is automatically zeroed when dropped to prevent sensitive
/// data from remaining in memory. The shared secret should be used as
/// input to a key derivation function (KDF) to derive actual encryption keys.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KyberSharedSecret([u8; 32]);

impl KyberSharedSecret {
    /// The length of a shared secret in bytes.
    pub const LENGTH: usize = KYBER768_SHARED_SECRET_BYTES;

    /// Returns the shared secret as a byte array reference.
    ///
    /// # Security
    ///
    /// The shared secret should typically be passed to a KDF (like HKDF)
    /// to derive actual encryption keys rather than being used directly.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::pqc::kyber::KyberKeyPair;
    /// use avon_crypto::kdf::hkdf_sha256;
    ///
    /// let keypair = KyberKeyPair::generate().unwrap();
    /// let (ciphertext, shared) = keypair.public_key().encapsulate().unwrap();
    ///
    /// // Derive an encryption key from the shared secret
    /// let encryption_key = hkdf_sha256(
    ///     shared.as_bytes(),
    ///     None,
    ///     b"encryption key",
    ///     32
    /// ).unwrap();
    /// ```
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A Kyber768 key pair consisting of a secret key and its corresponding public key.
///
/// This is the main type for performing Kyber key encapsulation.
pub struct KyberKeyPair {
    secret: KyberSecretKey,
    public: KyberPublicKey,
}

impl KyberKeyPair {
    /// Generates a new random Kyber768 key pair.
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
    /// use avon_crypto::pqc::kyber::KyberKeyPair;
    ///
    /// let keypair = KyberKeyPair::generate().unwrap();
    /// ```
    pub fn generate() -> Result<Self, CryptoError> {
        let (pk, sk) = kyber768::keypair();

        Ok(Self {
            secret: KyberSecretKey(sk.as_bytes().to_vec()),
            public: KyberPublicKey(pk.as_bytes().to_vec()),
        })
    }

    /// Returns a reference to the public key.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::pqc::kyber::KyberKeyPair;
    ///
    /// let keypair = KyberKeyPair::generate().unwrap();
    /// let public_key = keypair.public_key();
    /// ```
    pub fn public_key(&self) -> &KyberPublicKey {
        &self.public
    }

    /// Decapsulates a ciphertext to recover the shared secret.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ciphertext produced by encapsulation.
    ///
    /// # Returns
    ///
    /// The shared secret that was encapsulated.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::DecryptionFailed` if decapsulation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::pqc::kyber::KyberKeyPair;
    ///
    /// let keypair = KyberKeyPair::generate().unwrap();
    /// let (ciphertext, sender_shared) = keypair.public_key().encapsulate().unwrap();
    /// let receiver_shared = keypair.decapsulate(&ciphertext).unwrap();
    ///
    /// assert_eq!(sender_shared.as_bytes(), receiver_shared.as_bytes());
    /// ```
    pub fn decapsulate(
        &self,
        ciphertext: &KyberCiphertext,
    ) -> Result<KyberSharedSecret, CryptoError> {
        let sk = kyber768::SecretKey::from_bytes(&self.secret.0)
            .map_err(|_| CryptoError::DecryptionFailed("invalid secret key".to_string()))?;

        let ct = kyber768::Ciphertext::from_bytes(&ciphertext.0)
            .map_err(|_| CryptoError::DecryptionFailed("invalid ciphertext".to_string()))?;

        let ss = kyber768::decapsulate(&ct, &sk);

        Ok(KyberSharedSecret(ss.as_bytes().try_into().map_err(
            |_| CryptoError::DecryptionFailed("invalid shared secret length".to_string()),
        )?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = KyberKeyPair::generate().unwrap();
        assert_eq!(
            keypair.public_key().to_bytes().len(),
            KYBER768_PUBLIC_KEY_BYTES
        );
    }

    #[test]
    fn test_encapsulate_decapsulate() {
        let keypair = KyberKeyPair::generate().unwrap();
        let (ciphertext, sender_shared) = keypair.public_key().encapsulate().unwrap();
        let receiver_shared = keypair.decapsulate(&ciphertext).unwrap();

        assert_eq!(sender_shared.as_bytes(), receiver_shared.as_bytes());
    }

    #[test]
    fn test_public_key_serialization() {
        let keypair = KyberKeyPair::generate().unwrap();
        let bytes = keypair.public_key().to_bytes();
        let restored = KyberPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(keypair.public_key().to_bytes(), restored.to_bytes());
    }
}
