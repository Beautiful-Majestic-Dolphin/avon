//! Agent configuration: a TOML file plus `AVON_AGENT_*` environment overrides.
//! Errors are never swallowed; an unreadable or invalid file stops the agent.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigLoadError {
    #[error("cannot read config file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse config file {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("invalid value for {field}: {reason}")]
    Invalid { field: &'static str, reason: String },
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    /// host:port of the avon-control gRPC endpoint.
    pub control_plane: String,
    /// Directory for identity and state files (0700).
    pub data_dir: PathBuf,
    /// Seconds between pulses (>= 5).
    pub pulse_interval_secs: u64,
    /// tracing filter.
    pub log_level: String,
    /// TUN interface name.
    pub tun_name: String,
    /// Overlay MTU.
    pub overlay_mtu: u16,
    /// CIDRs this device routes for (subnet-router mode).
    pub advertise_routes: Vec<String>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            control_plane: String::new(),
            data_dir: Self::default_data_dir(),
            pulse_interval_secs: 30,
            log_level: "info".to_string(),
            tun_name: "avon0".to_string(),
            overlay_mtu: 1280,
            advertise_routes: Vec::new(),
        }
    }
}

impl AgentConfig {
    /// Load from `path`, or from the platform default path if it exists, then
    /// apply `AVON_AGENT_*` overrides, then validate.
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigLoadError> {
        let mut cfg = match path {
            Some(p) => Self::from_file(p)?,
            None => match Self::default_config_path() {
                Some(p) if p.is_file() => Self::from_file(&p)?,
                _ => Self::default(),
            },
        };
        cfg.apply_env();
        cfg.validate()?;
        Ok(cfg)
    }

    fn from_file(path: &Path) -> Result<Self, ConfigLoadError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigLoadError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        toml::from_str(&text).map_err(|source| ConfigLoadError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("AVON_AGENT_CONTROL_PLANE") {
            self.control_plane = v;
        }
        if let Ok(v) = std::env::var("AVON_AGENT_DATA_DIR") {
            self.data_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("AVON_AGENT_PULSE_INTERVAL_SECS") {
            if let Ok(n) = v.parse() {
                self.pulse_interval_secs = n;
            }
        }
        if let Ok(v) = std::env::var("AVON_AGENT_LOG_LEVEL") {
            self.log_level = v;
        }
        if let Ok(v) = std::env::var("AVON_AGENT_TUN_NAME") {
            self.tun_name = v;
        }
    }

    fn validate(&self) -> Result<(), ConfigLoadError> {
        if self.control_plane.is_empty() || !self.control_plane.contains(':') {
            return Err(ConfigLoadError::Invalid {
                field: "control_plane",
                reason: "must be host:port (set in agent.toml or AVON_AGENT_CONTROL_PLANE)".into(),
            });
        }
        if self.pulse_interval_secs < 5 {
            return Err(ConfigLoadError::Invalid {
                field: "pulse_interval_secs",
                reason: "must be >= 5".into(),
            });
        }
        if !(576..=9000).contains(&self.overlay_mtu) {
            return Err(ConfigLoadError::Invalid {
                field: "overlay_mtu",
                reason: "must be within 576..=9000".into(),
            });
        }
        if self.tun_name.is_empty() || self.tun_name.len() > 15 {
            return Err(ConfigLoadError::Invalid {
                field: "tun_name",
                reason: "1..=15 characters".into(),
            });
        }
        Ok(())
    }

    pub fn default_data_dir() -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            PathBuf::from("/var/lib/avon")
        }
        #[cfg(target_os = "macos")]
        {
            PathBuf::from("/Library/Application Support/AVON")
        }
        #[cfg(target_os = "windows")]
        {
            PathBuf::from(r"C:\ProgramData\AVON")
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            PathBuf::from("./avon-data")
        }
    }

    pub fn default_config_path() -> Option<PathBuf> {
        #[cfg(target_os = "linux")]
        {
            Some(PathBuf::from("/etc/avon/agent.toml"))
        }
        #[cfg(target_os = "macos")]
        {
            Some(PathBuf::from(
                "/Library/Application Support/AVON/agent.toml",
            ))
        }
        #[cfg(target_os = "windows")]
        {
            Some(PathBuf::from(r"C:\ProgramData\AVON\agent.toml"))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            None
        }
    }
}
