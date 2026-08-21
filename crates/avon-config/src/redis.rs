use std::path::PathBuf;

use clap::{ArgAction, Args};

use crate::validate::{parse_url, require_file, ConfigError, Validate};

/// Redis connection settings.
#[derive(Args, Debug, Clone)]
pub struct RedisArgs {
    /// Redis URL. Use rediss:// for TLS.
    #[arg(
        long = "redis-url",
        id = "redis_url",
        env = "AVON_REDIS_URL",
        hide_env_values = true
    )]
    pub url: String,

    /// PEM file with the CA that signed the Redis server certificate.
    #[arg(long = "redis-tls-ca", id = "redis_tls_ca", env = "AVON_REDIS_TLS_CA")]
    pub tls_ca: Option<PathBuf>,

    /// Require a rediss:// URL. Disable only for local development.
    #[arg(long = "redis-require-tls", id = "redis_require_tls", env = "AVON_REDIS_REQUIRE_TLS", default_value_t = true, action = ArgAction::Set)]
    pub require_tls: bool,
}

impl Validate for RedisArgs {
    fn validate(&self) -> Result<(), ConfigError> {
        let url = parse_url("redis-url", &self.url)?;
        match (url.scheme(), self.require_tls) {
            ("rediss", _) => {}
            ("redis", false) => {}
            ("redis", true) => {
                return Err(ConfigError::Invalid {
                    field: "redis-url",
                    reason: "TLS is required; use rediss:// or set --redis-require-tls=false"
                        .into(),
                })
            }
            (other, _) => {
                return Err(ConfigError::Invalid {
                    field: "redis-url",
                    reason: format!("scheme must be redis:// or rediss://, got {other}://"),
                })
            }
        }
        if let Some(ca) = &self.tls_ca {
            require_file("redis-tls-ca", ca)?;
        }
        Ok(())
    }
}
