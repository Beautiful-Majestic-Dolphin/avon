//! AVON Certificate Authority
//!
//! This crate provides the Certificate Authority service for the AVON network,
//! including:
//!
//! - Root and intermediate CA keypair management
//! - Ephemeral certificate issuance with hybrid signatures (Ed25519 + Dilithium)
//! - Certificate verification and validation
//! - OCSP staple generation and caching
//!
//! # Architecture
//!
//! The CA service consists of:
//! - `CertificateAuthority`: Core CA logic for certificate operations
//! - `OcspResponder`: OCSP response caching and management
//! - `CaServiceImpl`: gRPC service implementation
//!
//! # Security
//!
//! Certificates are signed with hybrid signatures combining classical (Ed25519)
//! and post-quantum (Dilithium3) algorithms. This provides defense-in-depth
//! against both classical and quantum attacks.
//!
//! # Example
//!
//! ```ignore
//! use avon_ca::{CertificateAuthority, CaConfig};
//! use avon_common::device::DeviceId;
//!
//! let config = CaConfig::default();
//! let ca = CertificateAuthority::new(&config).await?;
//!
//! let device_id = DeviceId::new();
//! let cert = ca.issue_ephemeral_cert(
//!     device_id,
//!     &public_key_classical,
//!     &public_key_pqc,
//!     None,
//! ).await?;
//! ```

pub mod ca;
pub mod config;
pub mod ocsp;
pub mod service;

pub use ca::{CaError, CertificateAuthority, CertificateStatus, IssuedCertificate, OcspStaple, VerifiedCert};
pub use config::CaConfig;
pub use ocsp::OcspResponder;
pub use service::CaServiceImpl;

pub fn init() {
    tracing::debug!("AVON CA module initialized");
}
