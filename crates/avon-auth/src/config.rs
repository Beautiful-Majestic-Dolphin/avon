//! Configuration for the AVON authentication service.
//!
//! This module provides configuration loading from files and environment variables.

use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;
use std::net::SocketAddr;

/// Configuration for the authentication service.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    /// gRPC server listen address.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: SocketAddr,

    /// Health check port.
    #[serde(default = "default_health_port")]
    pub health_port: u16,

    /// Metrics port.
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,

    /// Log level.
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Database URL.
    pub database_url: String,

    /// Redis URL.
    pub redis_url: String,

    /// Cache TTL in seconds.
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,
}

fn default_listen_addr() -> SocketAddr {
    "0.0.0.0:50051".parse().unwrap()
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

fn default_cache_ttl() -> u64 {
    300 // 5 minutes
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            health_port: default_health_port(),
            metrics_port: default_metrics_port(),
            log_level: default_log_level(),
            database_url: "postgres://localhost/avon".to_string(),
            redis_url: "redis://localhost:6379".to_string(),
            cache_ttl_secs: default_cache_ttl(),
        }
    }
}

impl AuthConfig {
    /// Loads configuration from file and environment variables.
    ///
    /// Configuration is loaded in the following order (later sources override earlier):
    /// 1. Default values
    /// 2. Configuration file (if provided)
    /// 3. Environment variables (prefixed with AVON_AUTH_)
    pub fn load(config_path: Option<&str>) -> Result<Self, ConfigError> {
        let mut builder = Config::builder();

        // Add config file if provided
        if let Some(path) = config_path {
            builder = builder.add_source(File::with_name(path).required(false));
        }

        // Add environment variables
        builder = builder.add_source(
            Environment::with_prefix("AVON_AUTH")
                .separator("_")
                .try_parsing(true),
        );

        builder.build()?.try_deserialize()
    }

    /// Applies CLI overrides to the configuration.
    pub fn with_overrides(
        mut self,
        listen_addr: Option<SocketAddr>,
        log_level: Option<String>,
    ) -> Self {
        if let Some(addr) = listen_addr {
            self.listen_addr = addr;
        }
        if let Some(level) = log_level {
            self.log_level = level;
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AuthConfig::default();
        assert_eq!(config.listen_addr.port(), 50051);
        assert_eq!(config.health_port, 8080);
        assert_eq!(config.metrics_port, 9090);
        assert_eq!(config.log_level, "info");
        assert_eq!(config.cache_ttl_secs, 300);
    }

    #[test]
    fn test_config_with_overrides() {
        let config = AuthConfig::default();
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let config = config.with_overrides(Some(addr), Some("debug".to_string()));

        assert_eq!(config.listen_addr.port(), 9999);
        assert_eq!(config.log_level, "debug");
    }

    #[test]
    fn test_default_functions() {
        assert_eq!(default_listen_addr().port(), 50051);
        assert_eq!(default_health_port(), 8080);
        assert_eq!(default_metrics_port(), 9090);
        assert_eq!(default_log_level(), "info");
        assert_eq!(default_cache_ttl(), 300);
    }
}
