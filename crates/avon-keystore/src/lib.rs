//! Key providers for AVON device identities.
//!
//! Every device holds four keys: a hybrid signing key (Ed25519 + ML-DSA-65), a
//! hybrid static KEM key (X25519 + ML-KEM-768) and an Ed25519 TLS key. No
//! shipping TPM or Secure Enclave can hold post-quantum keys, so hardware
//! providers do two things instead of one:
//!
//! 1. they protect the PQ key material at rest (sealed to the TPM, stored in
//!    the Keychain, wrapped with DPAPI-NG), and
//! 2. they sign a *binding statement* over both PQ public keys with a
//!    hardware-resident key, so the control plane can tell a hardware-backed
//!    device from a software one and can refuse a key substitution.
//!
//! The trait deliberately exposes `sign`/`decapsulate` rather than key bytes:
//! only the software provider can serialize its secrets, and only for its own
//! persistence.

pub mod binding;
pub mod provider;
pub mod select;
pub mod software;

#[cfg(all(feature = "cng", target_os = "windows"))]
pub mod cng;
#[cfg(all(feature = "keychain", target_os = "macos"))]
pub mod keychain;
#[cfg(all(feature = "tpm2", any(target_os = "linux", target_os = "windows")))]
pub mod tpm2;

pub use binding::{binding_message, verify_binding, BindingError};
pub use provider::{
    HardwareBinding, KeyError, KeyProvider, ProviderKind, Quote, MAX_BINDING_BYTES,
};
pub use select::{open_existing, open_or_create, ProviderChoice};
pub use software::SoftwareKeyProvider;
