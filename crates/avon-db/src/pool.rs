use std::str::FromStr;

use avon_config::DatabaseArgs;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::PgPool;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("database connection failed: {0}")]
    Connect(#[source] sqlx::Error),
    #[error("database migration failed: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("database query failed: {0}")]
    Query(#[source] sqlx::Error),
    #[error("invalid database URL: {0}")]
    Url(#[source] sqlx::Error),
}

/// Build a pool from validated `DatabaseArgs`. When `require_tls` is set the
/// connection uses `sslmode=verify-full`, overriding whatever the URL says.
pub async fn connect(args: &DatabaseArgs) -> Result<PgPool, DbError> {
    let mut options = PgConnectOptions::from_str(&args.url).map_err(DbError::Url)?;
    if args.require_tls {
        options = options.ssl_mode(PgSslMode::VerifyFull);
    }
    if let Some(ca) = &args.tls_ca {
        options = options.ssl_root_cert(ca);
    }
    PgPoolOptions::new()
        .max_connections(args.max_connections)
        .connect_with(options)
        .await
        .map_err(DbError::Connect)
}

/// Apply the migrations from `migrations/` at the repository root. They are
/// embedded at compile time, so this works from any working directory and
/// inside a distroless image that ships only the binary.
pub async fn migrate(pool: &PgPool) -> Result<(), DbError> {
    sqlx::migrate!("../../migrations")
        .run(pool)
        .await
        .map_err(DbError::Migrate)?;
    Ok(())
}
