//! avon-control library: service implementations and helpers (binary in main.rs).
//!
//! `clippy::result_large_err` is allowed crate-wide: every gRPC handler returns
//! `Result<_, tonic::Status>`, `Status` is 176 bytes, and tonic's generated
//! trait signatures fix that type, so the lint cannot be satisfied here.
#![allow(clippy::result_large_err)]

pub mod authz;
