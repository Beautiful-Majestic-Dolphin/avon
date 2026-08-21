//! Database access for AVON services: pool construction with TLS,
//! embedded migrations (single schema owner) and tenant-scoped transactions.

mod pool;
mod tenant;

pub use pool::{connect, migrate, DbError};
pub use tenant::{begin_tenant, DEFAULT_TENANT_ID};

pub use sqlx;
