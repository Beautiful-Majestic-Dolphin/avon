//! Configuration for the AVON Pulse Manager.
//!
//! This module provides configuration management for the pulse service.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PulseConfig {
    pub listen_addr: String,
    pub database_url: Option<String>,
    pub redis_url: Option<String>,
    pub pulse_interval_secs: Option<u64>,
    pub rotation_interval_secs: Option<u64>,
    pub stale_threshold_secs: Option<u64>,
    pub offline_threshold_secs: Option<u64>,
    pub gateway_channel_size: Option<usize>,
}

impl Default for PulseConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:50053".to_string(),
            database_url: None,
            redis_url: None,
            pulse_interval_secs: Some(30),
            rotation_interval_secs: Some(3600),
            stale_threshold_secs: Some(90),
            offline_threshold_secs: Some(300),
            gateway_channel_size: Some(1000),
        }
    }
}

impl PulseConfig {
    pub fn from_env() -> Self {
        Self {
            listen_addr: std::env::var("PULSE_LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:50053".to_string()),
            database_url: std::env::var("DATABASE_URL").ok(),
            redis_url: std::env::var("REDIS_URL").ok(),
            pulse_interval_secs: std::env::var("PULSE_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse().ok()),
            rotation_interval_secs: std::env::var("ROTATION_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse().ok()),
            stale_threshold_secs: std::env::var("STALE_THRESHOLD_SECS")
                .ok()
                .and_then(|s| s.parse().ok()),
            offline_threshold_secs: std::env::var("OFFLINE_THRESHOLD_SECS")
                .ok()
                .and_then(|s| s.parse().ok()),
            gateway_channel_size: std::env::var("GATEWAY_CHANNEL_SIZE")
                .ok()
                .and_then(|s| s.parse().ok()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PulseConfig::default();
        assert_eq!(config.listen_addr, "0.0.0.0:50053");
        assert_eq!(config.pulse_interval_secs, Some(30));
        assert_eq!(config.rotation_interval_secs, Some(3600));
        assert_eq!(config.stale_threshold_secs, Some(90));
        assert_eq!(config.offline_threshold_secs, Some(300));
    }
}
