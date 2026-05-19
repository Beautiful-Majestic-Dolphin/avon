//! AVON Authentication Service Library
//!
//! This crate provides the authentication service for the AVON network,
//! handling device verification, enrollment, token rotation, and state management.
//!
//! # Architecture
//!
//! The authentication service consists of:
//!
//! - **gRPC Service**: Implements the AuthService protocol for device authentication
//! - **Database Layer**: PostgreSQL storage for device records and enrollment tokens
//! - **Cache Layer**: Redis caching for fast authentication lookups
//! - **Configuration**: File and environment-based configuration
//!
//! # Example
//!
//! ```ignore
//! use avon_auth::{AuthConfig, AuthDatabase, AuthCache, AuthServiceImpl};
//! use avon_protocol::v1::auth_service_server::AuthServiceServer;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = AuthConfig::load(None)?;
//!     
//!     let db = Arc::new(AuthDatabase::new(&config.database_url).await?);
//!     let cache = Arc::new(AuthCache::new(&config.redis_url, config.cache_ttl_secs).await?);
//!     
//!     let service = AuthServiceImpl::new(db, cache);
//!     let server = AuthServiceServer::new(service);
//!     
//!     // Start gRPC server...
//!     Ok(())
//! }
//! ```

pub mod cache;
pub mod config;
pub mod db;
pub mod fido2;
pub mod service;

// Re-export main types
pub use cache::{AuthCache, CacheError, CachedDeviceState};
pub use config::AuthConfig;
pub use db::{AuthDatabase, DbDevice, DbError, EnrollmentToken, NewDevice};
pub use service::{AuthMetrics, AuthServiceImpl};

/// Initialize the auth service (placeholder for any global initialization).
pub fn init() {
    // No-op for now, but available for future initialization needs
}
