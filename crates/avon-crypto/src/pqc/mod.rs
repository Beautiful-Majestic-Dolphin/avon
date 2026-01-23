//! Post-Quantum Cryptography (PQC) primitives.
//!
//! This module provides post-quantum cryptographic algorithms that are
//! resistant to attacks by quantum computers. These algorithms are designed
//! to be used alongside classical cryptography in a hybrid approach.
//!
//! # Available Algorithms
//!
//! - **Kyber**: CRYSTALS-Kyber Key Encapsulation Mechanism (KEM)
//! - **Dilithium**: CRYSTALS-Dilithium Digital Signature Algorithm
//!
//! # Example
//!
//! ```
//! use avon_crypto::pqc::kyber::KyberKeyPair;
//!
//! // Generate a keypair
//! let keypair = KyberKeyPair::generate().unwrap();
//!
//! // Encapsulate to create a shared secret
//! let (ciphertext, shared_secret_sender) = keypair.public_key().encapsulate().unwrap();
//!
//! // Decapsulate to recover the shared secret
//! let shared_secret_receiver = keypair.decapsulate(&ciphertext).unwrap();
//!
//! // Both parties now have the same shared secret
//! assert_eq!(shared_secret_sender.as_bytes(), shared_secret_receiver.as_bytes());
//! ```

pub mod dilithium;
pub mod kyber;

pub use dilithium::{
    DilithiumKeyPair, DilithiumSignature, DilithiumSigningKey, DilithiumVerifyingKey,
    DILITHIUM3_PUBLIC_KEY_BYTES, DILITHIUM3_SECRET_KEY_BYTES, DILITHIUM3_SIGNATURE_BYTES,
};
pub use kyber::{
    KyberCiphertext, KyberKeyPair, KyberPublicKey, KyberSecretKey, KyberSharedSecret,
    KYBER768_CIPHERTEXT_BYTES, KYBER768_PUBLIC_KEY_BYTES, KYBER768_SECRET_KEY_BYTES,
    KYBER768_SHARED_SECRET_BYTES,
};
