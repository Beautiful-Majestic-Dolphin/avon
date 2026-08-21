//! avon-control: enrollment, authentication, pulse, sessions and gateway
//! coordination for the AVON control plane.
//!
//! `clippy::result_large_err` is allowed crate-wide: every gRPC handler returns
//! `Result<_, tonic::Status>`, `Status` is 176 bytes, and tonic's generated
//! trait signatures fix that type, so the lint cannot be satisfied here.
#![allow(clippy::result_large_err)]

pub mod auth;
pub mod authz;
pub mod ca_client;
pub mod config;
pub mod enroll;
pub mod gateway_stream;
pub mod liveness;
pub mod pulse;
pub mod renew;
pub mod service;
pub mod session_token;
pub mod store;
