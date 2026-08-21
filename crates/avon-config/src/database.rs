use std::path::PathBuf;

use clap::{ArgAction, Args};

use crate::validate::{parse_url, require_file, ConfigError, Validate};

/// PostgreSQL connection settings. Shared by every service.
#[derive(Args, Debug, Clone)]
pub struct DatabaseArgs {
    /// PostgreSQL URL, e.g. postgres://user:pass@host:5432/avon
    #[arg(
        long = "database-url",
        id = "database_url",
        env = "AVON_DATABASE_URL",
        hide_env_values = true
    )]
    pub url: String,

    /// Maximum pool size.
    #[arg(
        long = "database-max-connections",
        env = "AVON_DATABASE_MAX_CONNECTIONS",
        default_value_t = 10
    )]
    pub max_connections: u32,

    /// PEM file with the CA that signed the PostgreSQL server certificate.
    #[arg(
        long = "database-tls-ca",
        id = "database_tls_ca",
        env = "AVON_DATABASE_TLS_CA"
    )]
    pub tls_ca: Option<PathBuf>,

    /// Require TLS with full verification (sslmode=verify-full). Disable only for local development.
    #[arg(long = "database-require-tls", id = "database_require_tls", env = "AVON_DATABASE_REQUIRE_TLS", default_value_t = true, action = ArgAction::Set)]
    pub require_tls: bool,
}

impl Validate for DatabaseArgs {
    fn validate(&self) -> Result<(), ConfigError> {
        let url = parse_url("database-url", &self.url)?;
        if url.scheme() != "postgres" && url.scheme() != "postgresql" {
            return Err(ConfigError::Invalid {
                field: "database-url",
                reason: format!("scheme must be postgres://, got {}://", url.scheme()),
            });
        }
        if url.host_str().is_none() {
            return Err(ConfigError::Invalid {
                field: "database-url",
                reason: "missing host".into(),
            });
        }
        if self.max_connections == 0 {
            return Err(ConfigError::Invalid {
                field: "database-max-connections",
                reason: "must be >= 1".into(),
            });
        }
        if let Some(ca) = &self.tls_ca {
            require_file("database-tls-ca", ca)?;
        }
        Ok(())
    }
}
