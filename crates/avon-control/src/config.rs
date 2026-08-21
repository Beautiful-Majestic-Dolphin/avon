use std::net::SocketAddr;

use avon_config::{ConfigError, DatabaseArgs, ObservabilityArgs, RedisArgs, TlsArgs, Validate};
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "avon-control", version)]
pub struct ControlConfig {
    #[command(flatten)]
    pub db: DatabaseArgs,
    #[command(flatten)]
    pub redis: RedisArgs,
    #[command(flatten)]
    pub tls: TlsArgs,
    #[command(flatten)]
    pub obs: ObservabilityArgs,
    #[arg(
        long,
        env = "AVON_CONTROL_LISTEN_ADDR",
        default_value = "0.0.0.0:50051"
    )]
    pub listen_addr: SocketAddr,
    /// https://host:port of avon-ca
    #[arg(long, env = "AVON_CONTROL_CA_URL")]
    pub ca_url: String,
    /// Server name expected in the CA's TLS certificate.
    #[arg(long, env = "AVON_CONTROL_CA_SERVER_NAME", default_value = "ca")]
    pub ca_server_name: String,
    #[arg(long, env = "AVON_CONTROL_SESSION_TTL_SECS", default_value_t = 86_400)]
    pub session_ttl_secs: u64,
    #[arg(long, env = "AVON_CONTROL_PULSE_INTERVAL_SECS", default_value_t = 30)]
    pub pulse_interval_secs: u32,
}

impl Validate for ControlConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        self.db.validate()?;
        self.redis.validate()?;
        self.tls.validate()?;
        self.obs.validate()?;
        if !self.ca_url.starts_with("https://") {
            return Err(ConfigError::Invalid {
                field: "ca-url",
                reason: "must start with https://".into(),
            });
        }
        if !(5..=300).contains(&self.pulse_interval_secs) {
            return Err(ConfigError::Invalid {
                field: "pulse-interval-secs",
                reason: "5..=300".into(),
            });
        }
        Ok(())
    }
}
