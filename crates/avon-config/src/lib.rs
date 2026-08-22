//! Shared configuration for AVON services.
//!
//! Every service composes these `clap::Args` structs with `#[command(flatten)]`
//! and calls `validate()` on each before doing anything else. Missing or
//! invalid configuration is fatal by design (no localhost fallbacks).

mod database;
mod observability;
mod redis;
mod tls;
mod validate;

pub use database::DatabaseArgs;
pub use observability::{LogFormat, ObservabilityArgs};
pub use redis::{redis_client, RedisArgs};
pub use tls::TlsArgs;
pub use validate::{ConfigError, Validate};
