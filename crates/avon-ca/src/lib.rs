//! avon-ca: key custody, PQ certificate issuance, X.509 TLS sub-CA, CRLs.
//!
//! `clippy::result_large_err` is allowed crate-wide: every gRPC handler returns
//! `Result<_, tonic::Status>`, `Status` is 176 bytes, and tonic's generated
//! trait signatures fix that type, so the lint cannot be satisfied here.
#![allow(clippy::result_large_err)]

pub mod keys;
pub mod pki;
pub mod service;
pub mod store;
