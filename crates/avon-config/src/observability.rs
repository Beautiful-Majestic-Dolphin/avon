use std::net::SocketAddr;

use clap::{Args, ValueEnum};

use crate::validate::{ConfigError, Validate};

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Text,
}

/// Logging, metrics and health endpoints.
#[derive(Args, Debug, Clone)]
pub struct ObservabilityArgs {
    /// tracing filter, e.g. "info" or "info,avon_gateway=debug".
    #[arg(long = "log-level", env = "AVON_LOG_LEVEL", default_value = "info")]
    pub log_level: String,
    #[arg(long = "log-format", env = "AVON_LOG_FORMAT", value_enum, default_value_t = LogFormat::Json)]
    pub log_format: LogFormat,
    /// Prometheus exporter listen address.
    #[arg(
        long = "metrics-addr",
        env = "AVON_METRICS_ADDR",
        default_value = "0.0.0.0:9090"
    )]
    pub metrics_addr: SocketAddr,
    /// HTTP health/readiness listen address.
    #[arg(
        long = "health-addr",
        env = "AVON_HEALTH_ADDR",
        default_value = "0.0.0.0:8080"
    )]
    pub health_addr: SocketAddr,
}

impl Validate for ObservabilityArgs {
    fn validate(&self) -> Result<(), ConfigError> {
        // Accept exactly what tracing_subscriber::EnvFilter accepts: a comma
        // separated list of `target=level` or bare levels.
        for directive in self.log_level.split(',') {
            let level = directive
                .rsplit('=')
                .next()
                .unwrap_or(directive)
                .trim()
                .to_ascii_lowercase();
            if !matches!(
                level.as_str(),
                "trace" | "debug" | "info" | "warn" | "error" | "off"
            ) {
                return Err(ConfigError::Invalid {
                    field: "log-level",
                    reason: format!("unknown level {level:?} in {:?}", self.log_level),
                });
            }
        }
        if self.metrics_addr == self.health_addr {
            return Err(ConfigError::Invalid {
                field: "health-addr",
                reason: "health and metrics addresses must differ".into(),
            });
        }
        Ok(())
    }
}
