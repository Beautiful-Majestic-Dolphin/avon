//! Elliptic Curve Diffie-Hellman (ECDH) key exchange using X25519.
//!
//! This module provides X25519 key exchange functionality for establishing
//! shared secrets between two parties. X25519 is a modern, secure, and fast
//! elliptic curve Diffie-Hellman function.
//!
//! # Example
//!
//! ```
//! use avon_crypto::ecdh::X25519KeyPair;
//!
//! // Alice generates her keypair
//! let alice = X25519KeyPair::generate().unwrap();
//!
//! // Bob generates his keypair
//! let bob = X25519KeyPair::generate().unwrap();
//!
//! // They exchange public keys and compute the shared secret
//! let alice_shared = alice.diffie_hellman(bob.public_key()).unwrap();
//! let bob_shared = bob.diffie_hellman(alice.public_key()).unwrap();
//!
//! // Both parties now have the same shared secret
//! assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
//! ```

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

/// An X25519 private key.
///
/// This key is automatically zeroed when dropped to prevent sensitive
/// data from remaining in memory.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519PrivateKey([u8; 32]);

impl X25519PrivateKey {
    /// The length of an X25519 private key in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a new private key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 32-byte array containing the private key.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::ecdh::X25519PrivateKey;
    /// use avon_crypto::random::random_bytes_fixed;
    ///
    /// let bytes: [u8; 32] = random_bytes_fixed().unwrap();
    /// let private_key = X25519PrivateKey::from_bytes(bytes);
    /// ```
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes of the private key.
    ///
    /// # Security
    ///
    /// Be careful when using this method as it exposes the raw private key.
    /// The returned reference should not be stored or logged.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// An X25519 public key.
///
/// Public keys can be safely shared with other parties and are used
/// in the Diffie-Hellman key exchange to compute shared secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct X25519PublicKey(#[serde(with = "serde_bytes_array")] [u8; 32]);

impl X25519PublicKey {
    /// The length of an X25519 public key in bytes.
    pub const LENGTH: usize = 32;

    /// Returns the public key as a byte array.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::ecdh::X25519KeyPair;
    ///
    /// let keypair = X25519KeyPair::generate().unwrap();
    /// let bytes = keypair.public_key().to_bytes();
    /// assert_eq!(bytes.len(), 32);
    /// ```
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Creates a public key from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 32-byte slice containing the public key.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKeyLength` if the slice is not exactly 32 bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::ecdh::{X25519KeyPair, X25519PublicKey};
    ///
    /// let keypair = X25519KeyPair::generate().unwrap();
    /// let bytes = keypair.public_key().to_bytes();
    /// let restored = X25519PublicKey::from_bytes(&bytes).unwrap();
    /// assert_eq!(keypair.public_key(), &restored);
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
        Ok(Self(array))
    }
}

/// A shared secret derived from X25519 Diffie-Hellman key exchange.
///
/// This secret is automatically zeroed when dropped to prevent sensitive
/// data from remaining in memory. The shared secret should be used as
/// input to a key derivation function (KDF) to derive actual encryption keys.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    /// The length of a shared secret in bytes.
    pub const LENGTH: usize = 32;

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
    /// use avon_crypto::ecdh::X25519KeyPair;
    /// use avon_crypto::kdf::hkdf_sha256;
    ///
    /// let alice = X25519KeyPair::generate().unwrap();
    /// let bob = X25519KeyPair::generate().unwrap();
    ///
    /// let shared = alice.diffie_hellman(bob.public_key()).unwrap();
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

/// An X25519 key pair consisting of a private key and its corresponding public key.
///
/// This is the main type for performing X25519 Diffie-Hellman key exchange.
pub struct X25519KeyPair {
    private: X25519PrivateKey,
    public: X25519PublicKey,
}

impl X25519KeyPair {
    /// Generates a new random X25519 key pair.
    ///
    /// Uses the operating system's cryptographically secure random number
    /// generator to generate the private key.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::RandomGenerationFailed` if random number
    /// generation fails (extremely rare on modern systems).
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::ecdh::X25519KeyPair;
    ///
    /// let keypair = X25519KeyPair::generate().unwrap();
    /// ```
    pub fn generate() -> Result<Self, CryptoError> {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        Ok(Self {
            private: X25519PrivateKey(secret.to_bytes()),
            public: X25519PublicKey(public.to_bytes()),
        })
    }

    /// Creates a key pair from an existing private key.
    ///
    /// The corresponding public key is computed from the private key.
    ///
    /// # Arguments
    ///
    /// * `private` - The private key to use.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::ecdh::{X25519KeyPair, X25519PrivateKey};
    ///
    /// let private = X25519PrivateKey::from_bytes([0u8; 32]);
    /// let keypair = X25519KeyPair::from_private_key(private);
    /// ```
    pub fn from_private_key(private: X25519PrivateKey) -> Self {
        let secret = StaticSecret::from(*private.as_bytes());
        let public = PublicKey::from(&secret);

        Self {
            private,
            public: X25519PublicKey(public.to_bytes()),
        }
    }

    /// Returns a reference to the public key.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::ecdh::X25519KeyPair;
    ///
    /// let keypair = X25519KeyPair::generate().unwrap();
    /// let public_key = keypair.public_key();
    /// ```
    pub fn public_key(&self) -> &X25519PublicKey {
        &self.public
    }

    /// Performs Diffie-Hellman key exchange with a peer's public key.
    ///
    /// Computes a shared secret that will be identical when computed by
    /// both parties using their own private key and the other's public key.
    ///
    /// # Arguments
    ///
    /// * `peer_public` - The peer's public key.
    ///
    /// # Returns
    ///
    /// A shared secret that can be used to derive encryption keys.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::AuthenticationFailed` if the peer's public key
    /// is a low-order point (which would result in an all-zero shared secret).
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::ecdh::X25519KeyPair;
    ///
    /// let alice = X25519KeyPair::generate().unwrap();
    /// let bob = X25519KeyPair::generate().unwrap();
    ///
    /// let alice_shared = alice.diffie_hellman(bob.public_key()).unwrap();
    /// let bob_shared = bob.diffie_hellman(alice.public_key()).unwrap();
    ///
    /// assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    /// ```
    pub fn diffie_hellman(
        &self,
        peer_public: &X25519PublicKey,
    ) -> Result<SharedSecret, CryptoError> {
        let secret = StaticSecret::from(*self.private.as_bytes());
        let peer_pk = PublicKey::from(peer_public.0);

        let shared = secret.diffie_hellman(&peer_pk);
        let shared_bytes = shared.to_bytes();

        // Check for all-zero shared secret (indicates low-order point)
        if shared_bytes.iter().all(|&b| b == 0) {
            return Err(CryptoError::AuthenticationFailed);
        }

        Ok(SharedSecret(shared_bytes))
    }
}

/// Helper module for serde serialization of fixed-size byte arrays.
mod serde_bytes_array {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = X25519KeyPair::generate().unwrap();
        assert_eq!(keypair.public_key().to_bytes().len(), 32);
    }

    #[test]
    fn test_diffie_hellman_shared_secret() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();

        let alice_shared = alice.diffie_hellman(bob.public_key()).unwrap();
        let bob_shared = bob.diffie_hellman(alice.public_key()).unwrap();

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_public_key_serialization() {
        let keypair = X25519KeyPair::generate().unwrap();
        let bytes = keypair.public_key().to_bytes();
        let restored = X25519PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(keypair.public_key(), &restored);
    }
}
