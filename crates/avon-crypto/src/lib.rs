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
//! - **PQC**: Post-quantum cryptography (ML-KEM-768, ML-DSA-65)
//! - **Hybrid**: Hybrid classical+PQC cryptography (X25519+ML-KEM-768, Ed25519+ML-DSA-65)
//! - **Token**: Rotating authentication tokens for device identity
//! - **Tunnel**: High-performance tunnel encryption with atomic nonce counter
//! - **Session**: Session key derivation for tunnel establishment
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
pub mod cert;
pub mod ecdh;
pub mod error;
pub mod hmac;
pub mod hybrid;
pub mod kdf;
pub mod pqc;
pub mod random;
pub mod session;
pub mod signature;
pub mod token;
pub mod tunnel;

pub use error::CryptoError;

/// Initializes the cryptographic subsystem.
///
/// This function performs any necessary initialization for the cryptographic
/// primitives. Currently, this is a no-op but may be extended in the future
/// for hardware acceleration or post-quantum algorithm initialization.
pub fn init() {
    // Placeholder for crypto initialization
}
