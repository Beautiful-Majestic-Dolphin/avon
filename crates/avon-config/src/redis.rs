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

/// Build a client for `args`.
///
/// `redis::Client::open` trusts only the system roots, so a `rediss://` URL
/// against a privately-issued certificate never verifies and the connection
/// manager retries forever. Every service that talks to Redis must go through
/// here rather than calling `open` itself.
pub fn redis_client(args: &RedisArgs) -> Result<redis::Client, ConfigError> {
    let bad = |e: redis::RedisError| ConfigError::Invalid {
        field: "redis-url",
        reason: e.to_string(),
    };
    let Some(ca_path) = &args.tls_ca else {
        return redis::Client::open(args.url.as_str()).map_err(bad);
    };
    let root_cert = std::fs::read(ca_path).map_err(|e| ConfigError::Invalid {
        field: "redis-tls-ca",
        reason: e.to_string(),
    })?;
    redis::Client::build_with_tls(
        args.url.as_str(),
        redis::TlsCertificates {
            client_tls: None,
            root_cert: Some(root_cert),
        },
    )
    .map_err(bad)
}
