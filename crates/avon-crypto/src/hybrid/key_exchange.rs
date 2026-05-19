//! Hybrid Key Exchange combining X25519 (classical) and Kyber768 (PQC).
//!
//! This module provides a hybrid key exchange mechanism that combines classical
//! elliptic curve Diffie-Hellman (X25519) with post-quantum key encapsulation
//! (Kyber768).
//!
//! # Security Property
//!
//! The hybrid scheme is secure if EITHER algorithm remains unbroken. This provides
//! defense-in-depth against both classical and quantum attacks.
//!
//! # Protocol
//!
//! 1. Recipient generates a hybrid keypair (X25519 + Kyber768)
//! 2. Sender generates ephemeral X25519 keypair
//! 3. Sender performs ECDH with recipient's X25519 public key
//! 4. Sender performs Kyber encapsulation with recipient's Kyber public key
//! 5. Both secrets are combined using HKDF-SHA384
//! 6. Result is a 32-byte shared secret
//!
//! # Example
//!
//! ```
//! use avon_crypto::hybrid::key_exchange::{HybridKeyPair, hybrid_encapsulate};
//!
//! // Recipient generates a keypair
//! let recipient = HybridKeyPair::generate().unwrap();
//!
//! // Sender encapsulates to recipient's public key
//! let (encapsulation, sender_secret) = hybrid_encapsulate(&recipient.public_key()).unwrap();
//!
//! // Recipient decapsulates to get the same shared secret
//! let recipient_secret = recipient.decapsulate(&encapsulation).unwrap();
//!
//! assert_eq!(sender_secret.as_bytes(), recipient_secret.as_bytes());
//! ```

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ecdh::{X25519KeyPair, X25519PublicKey};
use crate::error::CryptoError;
use crate::kdf::hkdf_sha384;
use crate::pqc::kyber::{KyberCiphertext, KyberKeyPair, KyberPublicKey};

/// Domain separator for hybrid key exchange.
const HYBRID_KEX_INFO: &[u8] = b"AVON-hybrid-kex-v1";

/// A hybrid key pair combining X25519 and Kyber768.
///
/// This keypair is used by the recipient in a hybrid key exchange.
pub struct HybridKeyPair {
    classical: X25519KeyPair,
    pqc: KyberKeyPair,
}

impl HybridKeyPair {
    /// Generates a new random hybrid key pair.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::RandomGenerationFailed` if key generation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::hybrid::key_exchange::HybridKeyPair;
    ///
    /// let keypair = HybridKeyPair::generate().unwrap();
    /// ```
    pub fn generate() -> Result<Self, CryptoError> {
        let classical = X25519KeyPair::generate()?;
        let pqc = KyberKeyPair::generate()?;

        Ok(Self { classical, pqc })
    }

    /// Returns the hybrid public key.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::hybrid::key_exchange::HybridKeyPair;
    ///
    /// let keypair = HybridKeyPair::generate().unwrap();
    /// let public_key = keypair.public_key();
    /// ```
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            classical: self.classical.public_key().clone(),
            pqc: self.pqc.public_key().clone(),
        }
    }

    /// Decapsulates a hybrid encapsulation to recover the shared secret.
    ///
    /// # Arguments
    ///
    /// * `encapsulation` - The encapsulation from the sender.
    ///
    /// # Returns
    ///
    /// The shared secret that matches what the sender computed.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::DecryptionFailed` if decapsulation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::hybrid::key_exchange::{HybridKeyPair, hybrid_encapsulate};
    ///
    /// let recipient = HybridKeyPair::generate().unwrap();
    /// let (encapsulation, sender_secret) = hybrid_encapsulate(&recipient.public_key()).unwrap();
    /// let recipient_secret = recipient.decapsulate(&encapsulation).unwrap();
    ///
    /// assert_eq!(sender_secret.as_bytes(), recipient_secret.as_bytes());
    /// ```
    pub fn decapsulate(
        &self,
        encapsulation: &HybridEncapsulation,
    ) -> Result<HybridSharedSecret, CryptoError> {
        // Perform ECDH with sender's ephemeral public key
        let ecdh_secret = self
            .classical
            .diffie_hellman(&encapsulation.classical_public)?;

        // Decapsulate Kyber ciphertext
        let kyber_secret = self.pqc.decapsulate(&encapsulation.pqc_ciphertext)?;

        // Combine secrets using HKDF
        combine_secrets(ecdh_secret.as_bytes(), kyber_secret.as_bytes())
    }
}

/// A hybrid public key combining X25519 and Kyber768 public keys.
///
/// This is shared with senders who want to establish a shared secret.
#[derive(Clone)]
pub struct HybridPublicKey {
    classical: X25519PublicKey,
    pqc: KyberPublicKey,
}

impl HybridPublicKey {
    /// Returns the hybrid public key as bytes.
    ///
    /// Format: X25519 public key (32 bytes) || Kyber public key (1184 bytes)
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::hybrid::key_exchange::HybridKeyPair;
    ///
    /// let keypair = HybridKeyPair::generate().unwrap();
    /// let bytes = keypair.public_key().to_bytes();
    /// assert_eq!(bytes.len(), 32 + 1184);
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 1184);
        bytes.extend_from_slice(&self.classical.to_bytes());
        bytes.extend_from_slice(&self.pqc.to_bytes());
        bytes
    }

    /// Creates a hybrid public key from bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The serialized hybrid public key.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKeyLength` if the bytes are not the correct length.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::hybrid::key_exchange::{HybridKeyPair, HybridPublicKey};
    ///
    /// let keypair = HybridKeyPair::generate().unwrap();
    /// let bytes = keypair.public_key().to_bytes();
    /// let restored = HybridPublicKey::from_bytes(&bytes).unwrap();
    /// assert_eq!(keypair.public_key().to_bytes(), restored.to_bytes());
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        const EXPECTED_LEN: usize = 32 + 1184;
        if bytes.len() != EXPECTED_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: EXPECTED_LEN,
                actual: bytes.len(),
            });
        }

        let classical = X25519PublicKey::from_bytes(&bytes[..32])?;
        let pqc = KyberPublicKey::from_bytes(&bytes[32..])?;

        Ok(Self { classical, pqc })
    }
}

/// A hybrid encapsulation containing the data needed to derive the shared secret.
///
/// This is sent from the initiator to the recipient.
#[derive(Clone)]
pub struct HybridEncapsulation {
    /// Ephemeral X25519 public key for ECDH.
    pub classical_public: X25519PublicKey,
    /// Kyber ciphertext.
    pub pqc_ciphertext: KyberCiphertext,
}

impl HybridEncapsulation {
    /// Returns the encapsulation as bytes.
    ///
    /// Format: X25519 ephemeral public key (32 bytes) || Kyber ciphertext (1088 bytes)
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::hybrid::key_exchange::{HybridKeyPair, hybrid_encapsulate};
    ///
    /// let recipient = HybridKeyPair::generate().unwrap();
    /// let (encapsulation, _) = hybrid_encapsulate(&recipient.public_key()).unwrap();
    /// let bytes = encapsulation.to_bytes();
    /// assert_eq!(bytes.len(), 32 + 1088);
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 1088);
        bytes.extend_from_slice(&self.classical_public.to_bytes());
        bytes.extend_from_slice(&self.pqc_ciphertext.to_bytes());
        bytes
    }

    /// Creates an encapsulation from bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The serialized encapsulation.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKeyLength` if the bytes are not the correct length.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::hybrid::key_exchange::{HybridKeyPair, HybridEncapsulation, hybrid_encapsulate};
    ///
    /// let recipient = HybridKeyPair::generate().unwrap();
    /// let (encapsulation, _) = hybrid_encapsulate(&recipient.public_key()).unwrap();
    /// let bytes = encapsulation.to_bytes();
    /// let restored = HybridEncapsulation::from_bytes(&bytes).unwrap();
    /// assert_eq!(encapsulation.to_bytes(), restored.to_bytes());
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        const EXPECTED_LEN: usize = 32 + 1088;
        if bytes.len() != EXPECTED_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: EXPECTED_LEN,
                actual: bytes.len(),
            });
        }

        let classical_public = X25519PublicKey::from_bytes(&bytes[..32])?;
        let pqc_ciphertext = KyberCiphertext::from_bytes(&bytes[32..])?;

        Ok(Self {
            classical_public,
            pqc_ciphertext,
        })
    }
}

/// A hybrid shared secret derived from the key exchange.
///
/// This secret is automatically zeroed when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridSharedSecret([u8; 32]);

impl HybridSharedSecret {
    /// Returns the shared secret as a byte array reference.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::hybrid::key_exchange::{HybridKeyPair, hybrid_encapsulate};
    ///
    /// let recipient = HybridKeyPair::generate().unwrap();
    /// let (_, secret) = hybrid_encapsulate(&recipient.public_key()).unwrap();
    /// assert_eq!(secret.as_bytes().len(), 32);
    /// ```
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Performs hybrid encapsulation to a recipient's public key.
///
/// This is the initiator side of the hybrid key exchange. It generates an
/// ephemeral X25519 keypair, performs ECDH, performs Kyber encapsulation,
/// and combines the secrets.
///
/// # Arguments
///
/// * `recipient_public` - The recipient's hybrid public key.
///
/// # Returns
///
/// A tuple containing:
/// - The encapsulation to send to the recipient
/// - The shared secret
///
/// # Errors
///
/// Returns `CryptoError` if any cryptographic operation fails.
///
/// # Example
///
/// ```
/// use avon_crypto::hybrid::key_exchange::{HybridKeyPair, hybrid_encapsulate};
///
/// let recipient = HybridKeyPair::generate().unwrap();
/// let (encapsulation, sender_secret) = hybrid_encapsulate(&recipient.public_key()).unwrap();
///
/// // Send encapsulation to recipient...
/// let recipient_secret = recipient.decapsulate(&encapsulation).unwrap();
///
/// assert_eq!(sender_secret.as_bytes(), recipient_secret.as_bytes());
/// ```
pub fn hybrid_encapsulate(
    recipient_public: &HybridPublicKey,
) -> Result<(HybridEncapsulation, HybridSharedSecret), CryptoError> {
    // Generate ephemeral X25519 keypair
    let ephemeral = X25519KeyPair::generate()?;

    // Perform ECDH with recipient's classical public key
    let ecdh_secret = ephemeral.diffie_hellman(&recipient_public.classical)?;

    // Perform Kyber encapsulation with recipient's PQC public key
    let (kyber_ciphertext, kyber_secret) = recipient_public.pqc.encapsulate()?;

    // Combine secrets using HKDF
    let shared_secret = combine_secrets(ecdh_secret.as_bytes(), kyber_secret.as_bytes())?;

    let encapsulation = HybridEncapsulation {
        classical_public: ephemeral.public_key().clone(),
        pqc_ciphertext: kyber_ciphertext,
    };

    Ok((encapsulation, shared_secret))
}

/// Combines ECDH and Kyber secrets using HKDF-SHA384.
fn combine_secrets(
    ecdh_secret: &[u8; 32],
    kyber_secret: &[u8; 32],
) -> Result<HybridSharedSecret, CryptoError> {
    // Concatenate secrets: ECDH || Kyber
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(ecdh_secret);
    combined[32..].copy_from_slice(kyber_secret);

    // Derive final secret using HKDF-SHA384
    let derived = hkdf_sha384(&combined, None, HYBRID_KEX_INFO, 32)?;

    // Zeroize the combined secret
    combined.zeroize();

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&derived);

    Ok(HybridSharedSecret(secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_key_exchange() {
        let recipient = HybridKeyPair::generate().unwrap();
        let (encapsulation, sender_secret) = hybrid_encapsulate(&recipient.public_key()).unwrap();
        let recipient_secret = recipient.decapsulate(&encapsulation).unwrap();

        assert_eq!(sender_secret.as_bytes(), recipient_secret.as_bytes());
    }

    #[test]
    fn test_public_key_serialization() {
        let keypair = HybridKeyPair::generate().unwrap();
        let bytes = keypair.public_key().to_bytes();
        let restored = HybridPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(keypair.public_key().to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_encapsulation_serialization() {
        let recipient = HybridKeyPair::generate().unwrap();
        let (encapsulation, _) = hybrid_encapsulate(&recipient.public_key()).unwrap();
        let bytes = encapsulation.to_bytes();
        let restored = HybridEncapsulation::from_bytes(&bytes).unwrap();
        assert_eq!(encapsulation.to_bytes(), restored.to_bytes());
    }
}
