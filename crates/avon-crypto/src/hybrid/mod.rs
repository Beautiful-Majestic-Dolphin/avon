//! Hybrid Classical + Post-Quantum Cryptography.
//!
//! This module provides hybrid cryptographic algorithms that combine classical
//! and post-quantum cryptography for defense-in-depth security.
//!
//! # Security Properties
//!
//! - **Key Exchange**: Secure if EITHER X25519 OR ML-KEM-768 remains unbroken
//! - **Signatures**: Forgery requires breaking BOTH Ed25519 AND ML-DSA-65
//!
//! # Available Algorithms
//!
//! - **Hybrid Key Exchange**: X25519 + ML-KEM-768
//! - **Hybrid Signatures**: Ed25519 + ML-DSA-65
//!
//! # Example - Key Exchange
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
//!
//! # Example - Signatures
//!
//! ```
//! use avon_crypto::hybrid::signature::HybridSigningKeyPair;
//!
//! // Generate a signing keypair
//! let keypair = HybridSigningKeyPair::generate().unwrap();
//!
//! // Sign a message
//! let message = b"Hello, hybrid world!";
//! let signature = keypair.sign(message);
//!
//! // Verify the signature
//! keypair.verifying_key().verify(message, &signature).unwrap();
//! ```

pub mod key_exchange;
pub mod signature;

pub use key_exchange::{
    hybrid_encapsulate, HybridEncapsulation, HybridKeyPair, HybridPublicKey, HybridSharedSecret,
};
pub use signature::{HybridSignature, HybridSigningKeyPair, HybridVerifyingKey};
