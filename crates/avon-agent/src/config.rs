//! Agent configuration management.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub control_plane_addresses: Vec<SocketAddr>,
    pub control_plane_port: u16,
    pub data_dir: PathBuf,
    pub log_level: String,
    pub pulse_timeout_secs: u64,
    pub reconnect_interval_secs: u64,
    pub max_reconnect_attempts: u32,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            control_plane_addresses: vec![],
            control_plane_port: 8443,
            data_dir: Self::default_data_dir(),
            log_level: "info".to_string(),
            pulse_timeout_secs: 30,
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
        }
    }
}

impl AgentConfig {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let config_path = path
            .map(PathBuf::from)
            .or_else(Self::default_config_path);

        let mut builder = config::Config::builder();

        if let Some(ref path) = config_path {
            if path.exists() {
                tracing::info!(path = %path.display(), "Loading configuration file");
                builder = builder.add_source(config::File::from(path.as_path()));
            } else {
                tracing::warn!(path = %path.display(), "Configuration file not found, using defaults");
            }
        }

        builder = builder.add_source(
            config::Environment::with_prefix("AVON_AGENT")
                .separator("__")
                .try_parsing(true),
        );

        let config = builder
            .build()
            .context("Failed to build configuration")?;

        let mut agent_config: AgentConfig = config
            .try_deserialize()
            .unwrap_or_default();

        if agent_config.data_dir == PathBuf::new() {
            agent_config.data_dir = Self::default_data_dir();
        }

        Ok(agent_config)
    }

    pub fn default_data_dir() -> PathBuf {
        if cfg!(target_os = "linux") {
            PathBuf::from("/var/lib/avon")
        } else if cfg!(target_os = "macos") {
            PathBuf::from("/Library/Application Support/AVON")
        } else if cfg!(target_os = "windows") {
            PathBuf::from(r"C:\ProgramData\AVON")
        } else {
            ProjectDirs::from("ai", "avon", "avon-agent")
                .map(|dirs| dirs.data_dir().to_path_buf())
                .unwrap_or_else(|| PathBuf::from(".avon"))
        }
    }

    pub fn default_config_path() -> Option<PathBuf> {
        if cfg!(target_os = "linux") {
            Some(PathBuf::from("/etc/avon/agent.conf"))
        } else if cfg!(target_os = "macos") {
            Some(PathBuf::from("/Library/Application Support/AVON/agent.conf"))
        } else if cfg!(target_os = "windows") {
            Some(PathBuf::from(r"C:\ProgramData\AVON\agent.conf"))
        } else {
            ProjectDirs::from("ai", "avon", "avon-agent")
                .map(|dirs| dirs.config_dir().join("agent.conf"))
        }
    }

    pub fn identity_path(&self) -> PathBuf {
        self.data_dir.join("identity.json")
    }

    pub fn keystore_path(&self) -> PathBuf {
        self.data_dir.join("keystore.enc")
    }

    pub fn token_path(&self) -> PathBuf {
        self.data_dir.join("token.enc")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AgentConfig::default();
        assert_eq!(config.control_plane_port, 8443);
        assert_eq!(config.pulse_timeout_secs, 30);
        assert_eq!(config.log_level, "info");
    }

    #[test]
    fn test_default_data_dir() {
        let data_dir = AgentConfig::default_data_dir();
        assert!(!data_dir.as_os_str().is_empty());
    }
}
