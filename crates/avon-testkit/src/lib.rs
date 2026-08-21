//! Shared test infrastructure. Everything here is for tests only; the crate
//! is never a dependency of a shipped binary.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod db;
pub mod device;
pub mod gateway;
pub mod net;
pub mod pki;
pub mod redis;
pub mod services;
