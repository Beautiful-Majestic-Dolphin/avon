//! Configuration types for AVON services.
//!
//! This module provides configuration structures for the control plane and agent.

use serde::{Deserialize, Serialize};

/// Configuration for the AVON control plane services.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlPlaneConfig {
    /// Port for the control plane to listen on.
    pub listen_port: u16,
    /// PostgreSQL database connection URL.
    pub database_url: String,
    /// Redis connection URL.
    pub redis_url: String,
    /// Interval between pulse requests in seconds.
    pub pulse_interval_secs: u64,
    /// Lifetime of issued certificates in seconds.
    pub cert_lifetime_secs: u64,
    /// Log level (trace, debug, info, warn, error).
    pub log_level: String,
}

impl Default for ControlPlaneConfig {
    fn default() -> Self {
        Self {
            listen_port: 50051,
            database_url: "postgres://avon:avon@localhost:5432/avon".to_string(),
            redis_url: "redis://localhost:6379".to_string(),
            pulse_interval_secs: 30,
            cert_lifetime_secs: 86400, // 24 hours
            log_level: "info".to_string(),
        }
    }
}

impl ControlPlaneConfig {
    /// Creates a new ControlPlaneConfig from environment variables.
    ///
    /// Environment variables:
    /// - `CONTROL_PLANE_PORT` - Listen port (default: 50051)
    /// - `DATABASE_URL` - PostgreSQL connection URL
    /// - `REDIS_URL` - Redis connection URL
    /// - `PULSE_INTERVAL_SECS` - Pulse interval (default: 30)
    /// - `CERT_LIFETIME_SECS` - Certificate lifetime (default: 86400)
    /// - `LOG_LEVEL` - Log level (default: info)
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            listen_port: std::env::var("CONTROL_PLANE_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(50051),
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://avon:avon@localhost:5432/avon".to_string()),
            redis_url: std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://localhost:6379".to_string()),
            pulse_interval_secs: std::env::var("PULSE_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
            cert_lifetime_secs: std::env::var("CERT_LIFETIME_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(86400),
            log_level: std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
        }
    }
}

/// Configuration for the AVON agent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentConfig {
    /// List of control plane addresses to connect to.
    pub control_plane_addresses: Vec<String>,
    /// Port for the control plane.
    pub control_plane_port: u16,
    /// Log level (trace, debug, info, warn, error).
    pub log_level: String,
    /// Optional port for metrics endpoint.
    pub metrics_port: Option<u16>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            control_plane_addresses: vec!["localhost".to_string()],
            control_plane_port: 50051,
            log_level: "info".to_string(),
            metrics_port: None,
        }
    }
}

impl AgentConfig {
    /// Creates a new AgentConfig from environment variables.
    ///
    /// Environment variables:
    /// - `CONTROL_PLANE_ADDRESSES` - Comma-separated list of addresses
    /// - `CONTROL_PLANE_PORT` - Control plane port (default: 50051)
    /// - `LOG_LEVEL` - Log level (default: info)
    /// - `METRICS_PORT` - Optional metrics port
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            control_plane_addresses: std::env::var("CONTROL_PLANE_ADDRESSES")
                .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_else(|_| vec!["localhost".to_string()]),
            control_plane_port: std::env::var("CONTROL_PLANE_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(50051),
            log_level: std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
            metrics_port: std::env::var("METRICS_PORT")
                .ok()
                .and_then(|s| s.parse().ok()),
        }
    }

    /// Returns the full address for the first control plane.
    #[must_use]
    pub fn primary_address(&self) -> String {
        let addr = self
            .control_plane_addresses
            .first()
            .map(|s| s.as_str())
            .unwrap_or("localhost");
        format!("{}:{}", addr, self.control_plane_port)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_control_plane_config_default() {
        let config = ControlPlaneConfig::default();
        assert_eq!(config.listen_port, 50051);
        assert_eq!(config.pulse_interval_secs, 30);
        assert_eq!(config.cert_lifetime_secs, 86400);
        assert_eq!(config.log_level, "info");
    }

    #[test]
    fn test_agent_config_default() {
        let config = AgentConfig::default();
        assert_eq!(config.control_plane_addresses, vec!["localhost"]);
        assert_eq!(config.control_plane_port, 50051);
        assert_eq!(config.log_level, "info");
        assert!(config.metrics_port.is_none());
    }

    #[test]
    fn test_agent_config_primary_address() {
        let config = AgentConfig::default();
        assert_eq!(config.primary_address(), "localhost:50051");
    }

    #[test]
    fn test_control_plane_config_serialization() {
        let config = ControlPlaneConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let restored: ControlPlaneConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.listen_port, restored.listen_port);
    }

    #[test]
    fn test_agent_config_serialization() {
        let config = AgentConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let restored: AgentConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.control_plane_port, restored.control_plane_port);
    }
}
