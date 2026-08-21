//! AVON cryptographic primitives.
//!
//! - **pqc**: ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204) via PQClean.
//! - **ecdh / signature**: X25519 and Ed25519.
//! - **hybrid**: X25519+ML-KEM-768 KEM with a ciphertext- and key-binding
//!   combiner; Ed25519+ML-DSA-65 composite signatures with domain separation.
//! - **aead**: AES-256-GCM and ChaCha20-Poly1305 suites, in-place APIs.
//! - **session**: ATP/2 key schedule, epoch rekey, replay window, session cipher.
//! - **cert**: the AVON certificate format and chain verification.
//! - **kdf / hmac / random**: HKDF-SHA256/384, HMAC-SHA256, OS randomness that fails closed.
//!
//! Security levels: NIST category 3 (ML-KEM-768 / ML-DSA-65) combined with
//! 128-bit classical primitives; see docs/security.md for the profile table.
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
