//! AVON Cryptographic Primitives
//!
//! This crate provides cryptographic operations for the AVON network,
//! including:
//!
//! - **AEAD**: Authenticated encryption using AES-256-GCM
//! - **ECDH**: X25519 Diffie-Hellman key exchange
//! - **KDF**: Key derivation using HKDF with SHA-256 and SHA-384
//! - **HMAC**: Message authentication using HMAC-SHA256
//! - **Random**: Cryptographically secure random number generation
//! - **Signature**: Ed25519 digital signatures
//! - **PQC**: Post-quantum cryptography (CRYSTALS-Kyber KEM)
//!
//! # Example
//!
//! ```
//! use avon_crypto::{aead::Aes256GcmCipher, random::random_bytes_fixed};
//!
//! // Generate a random key and nonce
//! let key: [u8; 32] = random_bytes_fixed().unwrap();
//! let nonce: [u8; 12] = random_bytes_fixed().unwrap();
//!
//! // Create cipher and encrypt
//! let cipher = Aes256GcmCipher::new(&key).unwrap();
//! let ciphertext = cipher.encrypt(&nonce, b"secret message", b"").unwrap();
//!
//! // Decrypt
//! let plaintext = cipher.decrypt(&nonce, &ciphertext, b"").unwrap();
//! assert_eq!(plaintext, b"secret message");
//! ```

pub mod aead;
pub mod ecdh;
pub mod error;
pub mod hmac;
pub mod kdf;
pub mod pqc;
pub mod random;
pub mod signature;

pub use error::CryptoError;

/// Initializes the cryptographic subsystem.
///
/// This function performs any necessary initialization for the cryptographic
/// primitives. Currently, this is a no-op but may be extended in the future
/// for hardware acceleration or post-quantum algorithm initialization.
pub fn init() {
    // Placeholder for crypto initialization
}
