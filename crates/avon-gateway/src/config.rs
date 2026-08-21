//! Configuration for the AVON UDP Gateway.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Gateway configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// UDP listen address.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: SocketAddr,
    /// Health check TCP port.
    #[serde(default = "default_health_port")]
    pub health_port: u16,
    /// Prometheus metrics port.
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
    /// Log level.
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Rate limiting configuration.
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    /// Redis URL for device registry sync.
    #[serde(default = "default_redis_url")]
    pub redis_url: String,
    /// Auth service gRPC address.
    #[serde(default = "default_auth_addr")]
    pub auth_service_addr: String,
    /// Pulse service gRPC address.
    #[serde(default = "default_pulse_addr")]
    pub pulse_service_addr: String,
}

fn default_listen_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4600)
}

fn default_health_port() -> u16 {
    8080
}

fn default_metrics_port() -> u16 {
    9090
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_redis_url() -> String {
    "redis://localhost:6379".to_string()
}

fn default_auth_addr() -> String {
    "http://localhost:50051".to_string()
}

fn default_pulse_addr() -> String {
    "http://localhost:50052".to_string()
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            health_port: default_health_port(),
            metrics_port: default_metrics_port(),
            log_level: default_log_level(),
            rate_limit: RateLimitConfig::default(),
            redis_url: default_redis_url(),
            auth_service_addr: default_auth_addr(),
            pulse_service_addr: default_pulse_addr(),
        }
    }
}

impl GatewayConfig {
    /// Load configuration from file and environment.
    pub fn load(config_path: Option<&str>) -> anyhow::Result<Self> {
        let mut builder = config::Config::builder();

        // Load from file if provided
        if let Some(path) = config_path {
            builder = builder.add_source(config::File::with_name(path).required(false));
        }

        // Override with environment variables (AVON_GATEWAY_ prefix)
        builder = builder.add_source(
            config::Environment::with_prefix("AVON_GATEWAY")
                .separator("_")
                .try_parsing(true),
        );

        let config = builder.build()?;
        let gateway_config: GatewayConfig = config.try_deserialize().unwrap_or_default();

        Ok(gateway_config)
    }

    /// Apply CLI overrides.
    pub fn with_overrides(mut self, port: Option<u16>, log_level: Option<String>) -> Self {
        if let Some(p) = port {
            self.listen_addr.set_port(p);
        }
        if let Some(level) = log_level {
            self.log_level = level;
        }
        self
    }
}

/// Rate limiting configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests per second per IP.
    #[serde(default = "default_requests_per_second")]
    pub requests_per_second: u32,
    /// Burst size for rate limiting.
    #[serde(default = "default_burst_size")]
    pub burst_size: u32,
    /// Cleanup interval for expired rate limiters in seconds.
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval_secs: u64,
}

fn default_requests_per_second() -> u32 {
    100
}

fn default_burst_size() -> u32 {
    200
}

fn default_cleanup_interval() -> u64 {
    60
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: default_requests_per_second(),
            burst_size: default_burst_size(),
            cleanup_interval_secs: default_cleanup_interval(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_default_config() {
        let config = GatewayConfig::default();
        assert_eq!(config.listen_addr.port(), 4600);
        assert_eq!(config.health_port, 8080);
        assert_eq!(config.metrics_port, 9090);
        assert_eq!(config.log_level, "info");
    }

    #[test]
    fn test_rate_limit_defaults() {
        let config = RateLimitConfig::default();
        assert_eq!(config.requests_per_second, 100);
        assert_eq!(config.burst_size, 200);
        assert_eq!(config.cleanup_interval_secs, 60);
    }

    #[test]
    fn test_config_with_overrides() {
        let config = GatewayConfig::default().with_overrides(Some(5000), Some("debug".to_string()));
        assert_eq!(config.listen_addr.port(), 5000);
        assert_eq!(config.log_level, "debug");
    }
}
