//! High-performance tunnel encryption for AVON data plane.
//!
//! This module provides AES-256-GCM encryption optimized for tunnel traffic.
//! It uses an atomic 64-bit nonce counter to prevent nonce reuse while
//! maintaining thread safety for concurrent encryption operations.
//!
//! # Nonce Management
//!
//! The nonce is constructed as follows:
//! - Byte 0: Direction bit (0 for initiator, 1 for responder)
//! - Bytes 1-3: Reserved (zeros)
//! - Bytes 4-11: 64-bit counter (big-endian)
//!
//! This ensures that:
//! - Initiator and responder nonces never collide
//! - Each direction can encrypt up to 2^64 packets before nonce exhaustion
//! - Nonce generation is lock-free and thread-safe
//!
//! # Example
//!
//! ```
//! use avon_crypto::tunnel::{TunnelCipher, TunnelDirection};
//!
//! // Create ciphers for both ends of the tunnel
//! let key = [0x42u8; 32];
//! let initiator = TunnelCipher::new(key, TunnelDirection::Initiator);
//! let responder = TunnelCipher::new(key, TunnelDirection::Responder);
//!
//! // Encrypt from initiator
//! let plaintext = b"Hello, tunnel!";
//! let aad = b"session-id";
//! let packet = initiator.encrypt(plaintext, aad).unwrap();
//!
//! // Decrypt at responder
//! let decrypted = responder.decrypt(&packet, aad).unwrap();
//! assert_eq!(decrypted, plaintext);
//! ```

use std::sync::atomic::{AtomicU64, Ordering};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::aead::Aes256GcmCipher;
use crate::error::CryptoError;

/// Direction of the tunnel endpoint.
///
/// This determines the nonce space used by the cipher:
/// - `Initiator` uses even nonces (direction bit = 0)
/// - `Responder` uses odd nonces (direction bit = 1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelDirection {
    /// The endpoint that initiated the tunnel (even nonces).
    Initiator,
    /// The endpoint that responded to the tunnel (odd nonces).
    Responder,
}

impl TunnelDirection {
    /// Returns the direction byte for nonce construction.
    fn direction_byte(&self) -> u8 {
        match self {
            TunnelDirection::Initiator => 0x00,
            TunnelDirection::Responder => 0x01,
        }
    }
}

/// High-performance AES-256-GCM cipher for tunnel data encryption.
///
/// Uses an atomic 64-bit nonce counter to prevent nonce reuse while
/// maintaining thread safety. The direction ensures that initiator
/// and responder nonces never collide.
///
/// # Thread Safety
///
/// The nonce counter uses atomic operations, making it safe to encrypt
/// from multiple threads concurrently.
///
/// # Nonce Exhaustion
///
/// The cipher can encrypt up to 2^64 packets before nonce exhaustion.
/// Use `remaining_nonces()` to monitor usage and rekey before exhaustion.
pub struct TunnelCipher {
    #[allow(dead_code)] // Kept for Zeroize on drop and potential rekeying
    key: TunnelKey,
    cipher: Aes256GcmCipher,
    nonce_counter: AtomicU64,
    direction: TunnelDirection,
}

/// Wrapper for the tunnel key that implements Zeroize.
#[derive(Zeroize, ZeroizeOnDrop)]
struct TunnelKey([u8; 32]);

impl TunnelCipher {
    /// Creates a new tunnel cipher with the given key and direction.
    ///
    /// # Arguments
    ///
    /// * `key` - 256-bit encryption key
    /// * `direction` - Whether this is the initiator or responder
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::tunnel::{TunnelCipher, TunnelDirection};
    ///
    /// let key = [0x42u8; 32];
    /// let cipher = TunnelCipher::new(key, TunnelDirection::Initiator);
    /// ```
    pub fn new(key: [u8; 32], direction: TunnelDirection) -> Self {
        let Ok(cipher) = Aes256GcmCipher::new(&key) else {
            // `key` is `[u8; 32]`, exactly the AES-256 key length.
            unreachable!("AES-256-GCM accepts a 32-byte key")
        };
        Self {
            key: TunnelKey(key),
            cipher,
            nonce_counter: AtomicU64::new(0),
            direction,
        }
    }

    /// Returns the direction of this tunnel endpoint.
    pub fn direction(&self) -> TunnelDirection {
        self.direction
    }

    /// Encrypts plaintext and returns a tunnel packet.
    ///
    /// Atomically increments the nonce counter and constructs a unique nonce.
    /// The nonce is prepended to the ciphertext in the returned packet.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Additional authenticated data (not encrypted, but authenticated)
    ///
    /// # Returns
    ///
    /// A `TunnelPacket` containing the nonce and ciphertext with auth tag.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EncryptionFailed` if encryption fails or
    /// if the nonce counter has been exhausted.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::tunnel::{TunnelCipher, TunnelDirection};
    ///
    /// let cipher = TunnelCipher::new([0x42u8; 32], TunnelDirection::Initiator);
    /// let packet = cipher.encrypt(b"secret data", b"aad").unwrap();
    /// ```
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<TunnelPacket, CryptoError> {
        let nonce = self.next_nonce()?;
        let ciphertext = self.cipher.encrypt(&nonce, plaintext, aad)?;

        Ok(TunnelPacket { nonce, ciphertext })
    }

    /// Decrypts a tunnel packet and returns the plaintext.
    ///
    /// # Arguments
    ///
    /// * `packet` - The tunnel packet to decrypt
    /// * `aad` - Additional authenticated data (must match what was used for encryption)
    ///
    /// # Returns
    ///
    /// The decrypted plaintext.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::DecryptionFailed` if decryption fails or
    /// authentication fails.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::tunnel::{TunnelCipher, TunnelDirection};
    ///
    /// let key = [0x42u8; 32];
    /// let initiator = TunnelCipher::new(key, TunnelDirection::Initiator);
    /// let responder = TunnelCipher::new(key, TunnelDirection::Responder);
    ///
    /// let packet = initiator.encrypt(b"hello", b"aad").unwrap();
    /// let plaintext = responder.decrypt(&packet, b"aad").unwrap();
    /// assert_eq!(plaintext, b"hello");
    /// ```
    pub fn decrypt(&self, packet: &TunnelPacket, aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.cipher.decrypt(&packet.nonce, &packet.ciphertext, aad)
    }

    /// Encrypts data in place for zero-copy operation.
    ///
    /// The buffer is modified to contain: nonce || ciphertext || tag
    ///
    /// # Arguments
    ///
    /// * `buffer` - Buffer containing plaintext, will be modified to contain the packet
    /// * `aad` - Additional authenticated data
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EncryptionFailed` if encryption fails.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::tunnel::{TunnelCipher, TunnelDirection, TunnelPacket};
    ///
    /// let cipher = TunnelCipher::new([0x42u8; 32], TunnelDirection::Initiator);
    /// let mut buffer = b"secret data".to_vec();
    /// cipher.encrypt_in_place(&mut buffer, b"aad").unwrap();
    ///
    /// // Buffer now contains: nonce || ciphertext || tag
    /// assert_eq!(buffer.len(), 11 + TunnelPacket::overhead());
    /// ```
    pub fn encrypt_in_place(&self, buffer: &mut Vec<u8>, aad: &[u8]) -> Result<(), CryptoError> {
        let nonce = self.next_nonce()?;

        // Encrypt the plaintext
        let ciphertext = self.cipher.encrypt(&nonce, buffer, aad)?;

        // Replace buffer contents with nonce || ciphertext
        buffer.clear();
        buffer.extend_from_slice(&nonce);
        buffer.extend_from_slice(&ciphertext);

        Ok(())
    }

    /// Returns the number of remaining nonces before exhaustion.
    ///
    /// The tunnel should be rekeyed well before this reaches zero.
    /// A typical threshold might be to rekey when fewer than 2^32 nonces remain.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::tunnel::{TunnelCipher, TunnelDirection};
    ///
    /// let cipher = TunnelCipher::new([0x42u8; 32], TunnelDirection::Initiator);
    /// assert_eq!(cipher.remaining_nonces(), u64::MAX);
    ///
    /// cipher.encrypt(b"data", b"").unwrap();
    /// assert_eq!(cipher.remaining_nonces(), u64::MAX - 1);
    /// ```
    pub fn remaining_nonces(&self) -> u64 {
        let current = self.nonce_counter.load(Ordering::Relaxed);
        u64::MAX - current
    }

    /// Returns the current nonce counter value.
    pub fn nonce_counter(&self) -> u64 {
        self.nonce_counter.load(Ordering::Relaxed)
    }

    /// Generates the next nonce atomically.
    fn next_nonce(&self) -> Result<[u8; 12], CryptoError> {
        // Atomically increment and get the previous value
        let counter = self.nonce_counter.fetch_add(1, Ordering::SeqCst);

        // Check for overflow (extremely unlikely but must be handled)
        if counter == u64::MAX {
            return Err(CryptoError::EncryptionFailed(
                "Nonce counter exhausted".to_string(),
            ));
        }

        // Construct nonce: direction_byte || 3 zeros || 8-byte counter (big-endian)
        let mut nonce = [0u8; 12];
        nonce[0] = self.direction.direction_byte();
        // Bytes 1-3 are zeros (reserved)
        nonce[4..12].copy_from_slice(&counter.to_be_bytes());

        Ok(nonce)
    }
}

/// A tunnel packet containing encrypted data.
///
/// The packet format is: nonce (12 bytes) || ciphertext || auth tag (16 bytes)
#[derive(Debug, Clone)]
pub struct TunnelPacket {
    /// The nonce used for encryption.
    pub nonce: [u8; 12],
    /// The ciphertext including the 16-byte authentication tag.
    pub ciphertext: Vec<u8>,
}

impl TunnelPacket {
    /// Returns the overhead in bytes added by encryption.
    ///
    /// This is 12 bytes for the nonce plus 16 bytes for the auth tag.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::tunnel::TunnelPacket;
    ///
    /// assert_eq!(TunnelPacket::overhead(), 28);
    /// ```
    pub const fn overhead() -> usize {
        12 + 16 // nonce + auth tag
    }

    /// Serializes the packet to bytes.
    ///
    /// Format: nonce (12 bytes) || ciphertext (includes 16-byte tag)
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::tunnel::{TunnelCipher, TunnelDirection, TunnelPacket};
    ///
    /// let cipher = TunnelCipher::new([0x42u8; 32], TunnelDirection::Initiator);
    /// let packet = cipher.encrypt(b"hello", b"").unwrap();
    /// let bytes = packet.to_bytes();
    ///
    /// assert_eq!(bytes.len(), 5 + TunnelPacket::overhead());
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12 + self.ciphertext.len());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Deserializes a packet from bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The serialized packet bytes
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::DecryptionFailed` if the bytes are too short.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::tunnel::{TunnelCipher, TunnelDirection, TunnelPacket};
    ///
    /// let cipher = TunnelCipher::new([0x42u8; 32], TunnelDirection::Initiator);
    /// let packet = cipher.encrypt(b"hello", b"").unwrap();
    /// let bytes = packet.to_bytes();
    ///
    /// let restored = TunnelPacket::from_bytes(&bytes).unwrap();
    /// assert_eq!(restored.nonce, packet.nonce);
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        // Minimum size: 12 (nonce) + 16 (tag) = 28 bytes
        if bytes.len() < Self::overhead() {
            return Err(CryptoError::DecryptionFailed(format!(
                "Packet too short: {} bytes, minimum {}",
                bytes.len(),
                Self::overhead()
            )));
        }

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[..12]);
        let ciphertext = bytes[12..].to_vec();

        Ok(Self { nonce, ciphertext })
    }

    /// Returns the length of the plaintext (ciphertext length minus tag).
    pub fn plaintext_len(&self) -> usize {
        self.ciphertext.len().saturating_sub(16)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let cipher = TunnelCipher::new(key, TunnelDirection::Initiator);

        let plaintext = b"Hello, tunnel!";
        let aad = b"session-id";

        let packet = cipher.encrypt(plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&packet, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_nonce_counter_increments() {
        let cipher = TunnelCipher::new([0x42u8; 32], TunnelDirection::Initiator);

        assert_eq!(cipher.nonce_counter(), 0);

        cipher.encrypt(b"test", b"").unwrap();
        assert_eq!(cipher.nonce_counter(), 1);

        cipher.encrypt(b"test", b"").unwrap();
        assert_eq!(cipher.nonce_counter(), 2);
    }

    #[test]
    fn test_direction_nonces_differ() {
        let key = [0x42u8; 32];
        let initiator = TunnelCipher::new(key, TunnelDirection::Initiator);
        let responder = TunnelCipher::new(key, TunnelDirection::Responder);

        let packet1 = initiator.encrypt(b"test", b"").unwrap();
        let packet2 = responder.encrypt(b"test", b"").unwrap();

        // First byte should differ (direction)
        assert_ne!(packet1.nonce[0], packet2.nonce[0]);
        assert_eq!(packet1.nonce[0], 0x00); // Initiator
        assert_eq!(packet2.nonce[0], 0x01); // Responder
    }

    #[test]
    fn test_packet_overhead() {
        assert_eq!(TunnelPacket::overhead(), 28);
    }

    #[test]
    fn test_remaining_nonces() {
        let cipher = TunnelCipher::new([0x42u8; 32], TunnelDirection::Initiator);
        assert_eq!(cipher.remaining_nonces(), u64::MAX);

        cipher.encrypt(b"test", b"").unwrap();
        assert_eq!(cipher.remaining_nonces(), u64::MAX - 1);
    }
}
