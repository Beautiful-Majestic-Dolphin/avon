//! AVON Agent core implementation.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::signal;
use tokio::sync::RwLock;

use crate::config::AgentConfig;
use crate::identity::IdentityManager;

#[derive(Debug, Clone, PartialEq)]
pub enum AgentStatus {
    Starting,
    Connecting,
    Connected,
    Reconnecting,
    Stopping,
    Error(String),
}

impl std::fmt::Display for AgentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentStatus::Starting => write!(f, "Starting"),
            AgentStatus::Connecting => write!(f, "Connecting"),
            AgentStatus::Connected => write!(f, "Connected"),
            AgentStatus::Reconnecting => write!(f, "Reconnecting"),
            AgentStatus::Stopping => write!(f, "Stopping"),
            AgentStatus::Error(msg) => write!(f, "Error: {}", msg),
        }
    }
}

#[derive(Debug)]
pub struct AgentState {
    pub status: AgentStatus,
    pub connected_since: Option<Instant>,
    pub active_tunnels: usize,
    pub last_pulse: Option<Instant>,
    pub reconnect_attempts: u32,
}

impl Default for AgentState {
    fn default() -> Self {
        Self {
            status: AgentStatus::Starting,
            connected_since: None,
            active_tunnels: 0,
            last_pulse: None,
            reconnect_attempts: 0,
        }
    }
}

pub struct AvonAgent {
    config: AgentConfig,
    identity: Arc<IdentityManager>,
    state: Arc<RwLock<AgentState>>,
}

impl AvonAgent {
    pub async fn new(config: AgentConfig) -> Result<Self> {
        tracing::info!(data_dir = %config.data_dir.display(), "Initializing AVON Agent");

        std::fs::create_dir_all(&config.data_dir).context("Failed to create data directory")?;

        let identity = IdentityManager::load(&config.data_dir)
            .await
            .context("Failed to load identity. Is this device enrolled?")?;

        tracing::info!(device_id = %identity.device_id(), "Identity loaded");

        Ok(Self {
            config,
            identity: Arc::new(identity),
            state: Arc::new(RwLock::new(AgentState::default())),
        })
    }

    pub async fn run(&self) -> Result<()> {
        tracing::info!("Starting AVON Agent main loop");

        {
            let mut state = self.state.write().await;
            state.status = AgentStatus::Connecting;
        }

        let shutdown_signal = Self::shutdown_signal();
        tokio::pin!(shutdown_signal);

        let pulse_interval = Duration::from_secs(self.config.pulse_timeout_secs);
        let mut pulse_timer = tokio::time::interval(pulse_interval);

        loop {
            tokio::select! {
                _ = &mut shutdown_signal => {
                    tracing::info!("Shutdown signal received");
                    break;
                }
                _ = pulse_timer.tick() => {
                    self.handle_pulse().await;
                }
            }
        }

        self.shutdown().await;
        Ok(())
    }

    async fn handle_pulse(&self) {
        tracing::debug!("Sending pulse to control plane");

        {
            let mut state = self.state.write().await;
            state.last_pulse = Some(Instant::now());
        }
    }

    async fn connect_to_control_plane(&self) -> Result<()> {
        tracing::info!("Connecting to control plane");

        {
            let mut state = self.state.write().await;
            state.status = AgentStatus::Connecting;
        }

        {
            let mut state = self.state.write().await;
            state.status = AgentStatus::Connected;
            state.connected_since = Some(Instant::now());
            state.reconnect_attempts = 0;
        }

        tracing::info!("Connected to control plane");
        Ok(())
    }

    pub async fn shutdown(&self) {
        tracing::info!("Shutting down AVON Agent");

        {
            let mut state = self.state.write().await;
            state.status = AgentStatus::Stopping;
        }

        tracing::info!("AVON Agent shutdown complete");
    }

    pub async fn status(&self) -> AgentStatus {
        self.state.read().await.status.clone()
    }

    pub async fn active_tunnels(&self) -> usize {
        self.state.read().await.active_tunnels
    }

    pub fn device_id(&self) -> &avon_common::device::DeviceId {
        self.identity.device_id()
    }

    async fn shutdown_signal() {
        let ctrl_c = async {
            signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to install signal handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_status_display() {
        assert_eq!(format!("{}", AgentStatus::Starting), "Starting");
        assert_eq!(format!("{}", AgentStatus::Connected), "Connected");
        assert_eq!(
            format!("{}", AgentStatus::Error("test".to_string())),
            "Error: test"
        );
    }

    #[test]
    fn test_agent_state_default() {
        let state = AgentState::default();
        assert_eq!(state.status, AgentStatus::Starting);
        assert!(state.connected_since.is_none());
        assert_eq!(state.active_tunnels, 0);
    }
}
