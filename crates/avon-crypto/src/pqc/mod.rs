//! Post-Quantum Cryptography (PQC) primitives.
//!
//! This module provides post-quantum cryptographic algorithms that are
//! resistant to attacks by quantum computers. These algorithms are designed
//! to be used alongside classical cryptography in a hybrid approach.
//!
//! # Available Algorithms
//!
//! - **ML-KEM-768**: FIPS 203 Module-Lattice-Based KEM
//! - **ML-DSA-65**: FIPS 204 Module-Lattice Digital Signature Algorithm

pub mod mldsa;
pub mod mlkem;

pub use mldsa::{
    MlDsaKeyPair, MlDsaSignature, MlDsaSigningKey, MlDsaVerifyingKey, MLDSA65_PUBLIC_KEY_BYTES,
    MLDSA65_SECRET_KEY_BYTES, MLDSA65_SIGNATURE_BYTES,
};
pub use mlkem::{
    MlKemCiphertext, MlKemKeyPair, MlKemPublicKey, MlKemSecretKey, MlKemSharedSecret,
    MLKEM768_CIPHERTEXT_BYTES, MLKEM768_PUBLIC_KEY_BYTES, MLKEM768_SECRET_KEY_BYTES,
    MLKEM768_SHARED_SECRET_BYTES,
};
