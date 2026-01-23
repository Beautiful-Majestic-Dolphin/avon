//! Cryptographic error types for AVON.
//!
//! This module defines the error types used throughout the cryptographic
//! operations in the AVON system.

use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// The provided key has an invalid length.
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected key length in bytes.
        expected: usize,
        /// Actual key length provided.
        actual: usize,
    },

    /// Encryption operation failed.
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption operation failed.
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// Authentication of the message failed.
    #[error("authentication failed")]
    AuthenticationFailed,

    /// Key derivation operation failed.
    #[error("key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Signature verification failed.
    #[error("invalid signature")]
    InvalidSignature,

    /// Random number generation failed.
    #[error("random generation failed: {0}")]
    RandomGenerationFailed(String),
}
