//! Session key derivation for AVON tunnels.
//!
//! This module provides key derivation functions for establishing tunnel
//! encryption keys from a hybrid shared secret. It derives separate keys
//! for the initiator and responder directions, ensuring that each direction
//! uses a unique key.
//!
//! # Key Derivation
//!
//! The tunnel keys are derived using HKDF-SHA384 with the following inputs:
//! - IKM: The hybrid shared secret (from X25519 + Kyber768)
//! - Salt: None (uses default)
//! - Info: Domain separator || session_id || initiator_public || responder_public
//!
//! This produces 64 bytes which are split into:
//! - Bytes 0-31: Initiator encryption key
//! - Bytes 32-63: Responder encryption key
//!
//! # Example
//!
//! ```
//! use avon_crypto::session::TunnelKeys;
//! use avon_crypto::hybrid::key_exchange::{HybridKeyPair, hybrid_encapsulate};
//!
//! // Perform hybrid key exchange
//! let initiator_kp = HybridKeyPair::generate().unwrap();
//! let responder_kp = HybridKeyPair::generate().unwrap();
//!
//! let (encapsulation, initiator_secret) = hybrid_encapsulate(&responder_kp.public_key()).unwrap();
//! let responder_secret = responder_kp.decapsulate(&encapsulation).unwrap();
//!
//! // Both sides have the same shared secret
//! assert_eq!(initiator_secret.as_bytes(), responder_secret.as_bytes());
//!
//! // Derive tunnel keys
//! let session_id = [0x01u8; 16];
//! let initiator_pub = initiator_kp.public_key().to_bytes();
//! let responder_pub = responder_kp.public_key().to_bytes();
//!
//! let keys = TunnelKeys::derive(
//!     &initiator_secret,
//!     &initiator_pub,
//!     &responder_pub,
//!     &session_id,
//! ).unwrap();
//!
//! // Keys are different for each direction
//! assert_ne!(keys.initiator_key, keys.responder_key);
//! ```

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;
use crate::hybrid::key_exchange::HybridSharedSecret;
use crate::kdf::hkdf_sha384;

/// Domain separator for tunnel key derivation.
const TUNNEL_KEYS_INFO_PREFIX: &[u8] = b"AVON-tunnel-keys-v1";

/// Derived tunnel encryption keys for both directions.
///
/// Contains separate 256-bit keys for the initiator and responder,
/// ensuring that each direction uses a unique key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TunnelKeys {
    /// Encryption key for the initiator (tunnel creator).
    pub initiator_key: [u8; 32],
    /// Encryption key for the responder.
    pub responder_key: [u8; 32],
}

impl TunnelKeys {
    /// Derives tunnel keys from a hybrid shared secret.
    ///
    /// Uses HKDF-SHA384 to derive 64 bytes of key material, which is
    /// split into two 32-byte keys for initiator and responder.
    ///
    /// # Arguments
    ///
    /// * `shared_secret` - The hybrid shared secret from key exchange
    /// * `initiator_public` - The initiator's public key bytes
    /// * `responder_public` - The responder's public key bytes
    /// * `session_id` - Unique 16-byte session identifier
    ///
    /// # Returns
    ///
    /// `TunnelKeys` containing the derived keys for both directions.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::KeyDerivationFailed` if HKDF fails.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::session::TunnelKeys;
    /// use avon_crypto::hybrid::key_exchange::{HybridKeyPair, hybrid_encapsulate};
    ///
    /// let responder_kp = HybridKeyPair::generate().unwrap();
    /// let (_, shared_secret) = hybrid_encapsulate(&responder_kp.public_key()).unwrap();
    ///
    /// let keys = TunnelKeys::derive(
    ///     &shared_secret,
    ///     &[0u8; 32],  // initiator public (simplified)
    ///     &[1u8; 32],  // responder public (simplified)
    ///     &[0x42u8; 16],
    /// ).unwrap();
    /// ```
    pub fn derive(
        shared_secret: &HybridSharedSecret,
        initiator_public: &[u8],
        responder_public: &[u8],
        session_id: &[u8; 16],
    ) -> Result<Self, CryptoError> {
        // Build info: prefix || session_id || initiator_public || responder_public
        let mut info = Vec::with_capacity(
            TUNNEL_KEYS_INFO_PREFIX.len() + 16 + initiator_public.len() + responder_public.len(),
        );
        info.extend_from_slice(TUNNEL_KEYS_INFO_PREFIX);
        info.extend_from_slice(session_id);
        info.extend_from_slice(initiator_public);
        info.extend_from_slice(responder_public);

        // Derive 64 bytes using HKDF-SHA384
        let derived = hkdf_sha384(shared_secret.as_bytes(), None, &info, 64)?;

        // Split into two 32-byte keys
        let mut initiator_key = [0u8; 32];
        let mut responder_key = [0u8; 32];
        initiator_key.copy_from_slice(&derived[..32]);
        responder_key.copy_from_slice(&derived[32..64]);

        Ok(Self {
            initiator_key,
            responder_key,
        })
    }

    /// Returns the initiator's encryption key.
    pub fn initiator_key(&self) -> &[u8; 32] {
        &self.initiator_key
    }

    /// Returns the responder's encryption key.
    pub fn responder_key(&self) -> &[u8; 32] {
        &self.responder_key
    }
}

/// Session context for a tunnel connection.
///
/// Contains all the cryptographic material needed for a tunnel session,
/// including the session ID and derived keys.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionContext {
    /// Unique session identifier.
    session_id: [u8; 16],
    /// Derived tunnel keys.
    keys: TunnelKeys,
}

impl SessionContext {
    /// Creates a new session context.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Unique 16-byte session identifier
    /// * `keys` - Derived tunnel keys
    pub fn new(session_id: [u8; 16], keys: TunnelKeys) -> Self {
        Self { session_id, keys }
    }

    /// Returns the session ID.
    pub fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    /// Returns the tunnel keys.
    pub fn keys(&self) -> &TunnelKeys {
        &self.keys
    }

    /// Returns the initiator's encryption key.
    pub fn initiator_key(&self) -> &[u8; 32] {
        &self.keys.initiator_key
    }

    /// Returns the responder's encryption key.
    pub fn responder_key(&self) -> &[u8; 32] {
        &self.keys.responder_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid::key_exchange::{hybrid_encapsulate, HybridKeyPair};

    #[test]
    fn test_derive_produces_different_keys() {
        let responder_kp = HybridKeyPair::generate().unwrap();
        let (_, shared_secret) = hybrid_encapsulate(&responder_kp.public_key()).unwrap();

        let keys =
            TunnelKeys::derive(&shared_secret, &[0u8; 32], &[1u8; 32], &[0x42u8; 16]).unwrap();

        assert_ne!(keys.initiator_key, keys.responder_key);
    }

    #[test]
    fn test_derive_is_deterministic() {
        let responder_kp = HybridKeyPair::generate().unwrap();
        let (_, shared_secret) = hybrid_encapsulate(&responder_kp.public_key()).unwrap();

        let keys1 =
            TunnelKeys::derive(&shared_secret, &[0u8; 32], &[1u8; 32], &[0x42u8; 16]).unwrap();

        let keys2 =
            TunnelKeys::derive(&shared_secret, &[0u8; 32], &[1u8; 32], &[0x42u8; 16]).unwrap();

        assert_eq!(keys1.initiator_key, keys2.initiator_key);
        assert_eq!(keys1.responder_key, keys2.responder_key);
    }

    #[test]
    fn test_different_session_ids_produce_different_keys() {
        let responder_kp = HybridKeyPair::generate().unwrap();
        let (_, shared_secret) = hybrid_encapsulate(&responder_kp.public_key()).unwrap();

        let keys1 =
            TunnelKeys::derive(&shared_secret, &[0u8; 32], &[1u8; 32], &[0x01u8; 16]).unwrap();

        let keys2 =
            TunnelKeys::derive(&shared_secret, &[0u8; 32], &[1u8; 32], &[0x02u8; 16]).unwrap();

        assert_ne!(keys1.initiator_key, keys2.initiator_key);
        assert_ne!(keys1.responder_key, keys2.responder_key);
    }

    #[test]
    fn test_session_context() {
        let responder_kp = HybridKeyPair::generate().unwrap();
        let (_, shared_secret) = hybrid_encapsulate(&responder_kp.public_key()).unwrap();

        let session_id = [0x42u8; 16];
        let keys = TunnelKeys::derive(&shared_secret, &[0u8; 32], &[1u8; 32], &session_id).unwrap();

        let context = SessionContext::new(session_id, keys);

        assert_eq!(context.session_id(), &session_id);
    }
}
