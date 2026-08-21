//! Authenticated Encryption with Associated Data (AEAD) implementations.
//!
//! This module provides AES-256-GCM encryption and decryption with proper
//! key handling and zeroization of sensitive data.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

/// AES-256-GCM cipher for authenticated encryption.
///
/// This cipher provides confidentiality and authenticity for data using
/// the AES-256-GCM algorithm. The key is automatically zeroed when the
/// cipher is dropped.
///
/// # Example
///
/// ```
/// use avon_crypto::aead::Aes256GcmCipher;
/// use avon_crypto::random::random_bytes_fixed;
///
/// let key = random_bytes_fixed::<32>().unwrap();
/// let cipher = Aes256GcmCipher::new(&key).unwrap();
///
/// let nonce: [u8; 12] = random_bytes_fixed().unwrap();
/// let plaintext = b"Hello, AVON!";
/// let aad = b"additional data";
///
/// let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
/// let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();
///
/// assert_eq!(plaintext.as_slice(), decrypted.as_slice());
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Aes256GcmCipher {
    key: [u8; 32],
}

impl Aes256GcmCipher {
    /// The required key length in bytes (256 bits).
    pub const KEY_LENGTH: usize = 32;

    /// The required nonce length in bytes (96 bits).
    pub const NONCE_LENGTH: usize = 12;

    /// The authentication tag length in bytes (128 bits).
    pub const TAG_LENGTH: usize = 16;

    /// Creates a new AES-256-GCM cipher with the given key.
    ///
    /// # Arguments
    ///
    /// * `key` - A 32-byte (256-bit) key for encryption/decryption.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKeyLength` if the key is not exactly 32 bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use avon_crypto::aead::Aes256GcmCipher;
    ///
    /// let key = [0u8; 32];
    /// let cipher = Aes256GcmCipher::new(&key).unwrap();
    /// ```
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != Self::KEY_LENGTH {
            return Err(CryptoError::InvalidKeyLength {
                expected: Self::KEY_LENGTH,
                actual: key.len(),
            });
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key);

        Ok(Self { key: key_array })
    }

    /// Encrypts plaintext with the given nonce and additional authenticated data.
    ///
    /// # Arguments
    ///
    /// * `nonce` - A 12-byte (96-bit) nonce. Must be unique for each encryption
    ///   with the same key.
    /// * `plaintext` - The data to encrypt.
    /// * `aad` - Additional authenticated data that will be authenticated but
    ///   not encrypted.
    ///
    /// # Returns
    ///
    /// The ciphertext with the authentication tag appended (ciphertext || tag).
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EncryptionFailed` if encryption fails.
    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let nonce = Nonce::from_slice(nonce);

        cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))
    }

    /// Decrypts ciphertext with the given nonce and additional authenticated data.
    ///
    /// # Arguments
    ///
    /// * `nonce` - The same 12-byte nonce used during encryption.
    /// * `ciphertext` - The encrypted data with authentication tag appended.
    /// * `aad` - The same additional authenticated data used during encryption.
    ///
    /// # Returns
    ///
    /// The decrypted plaintext.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::DecryptionFailed` if decryption fails, which can
    /// happen if:
    /// - The ciphertext was tampered with
    /// - The AAD doesn't match
    /// - The nonce doesn't match
    /// - The key doesn't match
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        let nonce = Nonce::from_slice(nonce);

        cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_new_valid_key() {
        let key = [0u8; 32];
        let result = Aes256GcmCipher::new(&key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_new_invalid_key_length() {
        let key = [0u8; 16];
        let result = Aes256GcmCipher::new(&key);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 16
            })
        ));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0u8; 32];
        let cipher = Aes256GcmCipher::new(&key).unwrap();

        let nonce = [0u8; 12];
        let plaintext = b"Hello, World!";
        let aad = b"additional data";

        let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
