//! Attestation evidence and TPM quote verification.
//!
//! The crate is deliberately small and free of I/O: it takes the bytes a device
//! sent, the nonce the control plane issued, and says whether the two agree.

pub mod evidence;
pub mod policy;
pub mod tpms;
pub mod verify;

pub use evidence::{AttestError, Evidence};
pub use policy::{AttestationState, QuotePolicy};
pub use verify::{verify, Verified};
