//! Shared test infrastructure. Everything here is for tests only; the crate
//! is never a dependency of a shipped binary.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod agent_fixture;
pub mod db;
pub mod device;
pub mod gateway;
pub mod gateway_fixture;
pub mod memtun;
pub mod metrics;
pub mod net;
pub mod packets;
pub mod pki;
pub mod redis;
pub mod services;
