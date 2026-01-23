//! Reconnection management for control plane client.
//!
//! Handles automatic reconnection with exponential backoff when the
//! connection to the control plane is lost.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::RwLock;
use tokio::time::sleep;

use super::ControlPlaneClient;

/// Configuration for reconnection behavior.
#[derive(Debug, Clone)]
pub struct ReconnectConfig {
    /// Initial delay before first reconnection attempt.
    pub initial_delay: Duration,
    /// Maximum delay between reconnection attempts.
    pub max_delay: Duration,
    /// Maximum number of reconnection attempts (None for unlimited).
    pub max_attempts: Option<u32>,
    /// Multiplier for exponential backoff.
    pub backoff_multiplier: f64,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            max_attempts: None,
            backoff_multiplier: 2.0,
        }
    }
}

/// State of the reconnection manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconnectState {
    /// Connected and healthy.
    Connected,
    /// Attempting to reconnect.
    Reconnecting,
    /// Stopped (max attempts reached or manually stopped).
    Stopped,
}

/// Manages automatic reconnection to the control plane.
pub struct ReconnectManager {
    client: Arc<ControlPlaneClient>,
    config: ReconnectConfig,
    state: Arc<RwLock<ReconnectState>>,
    current_delay: Arc<RwLock<Duration>>,
    attempt_count: Arc<RwLock<u32>>,
}

impl ReconnectManager {
    /// Creates a new reconnection manager.
    pub fn new(client: Arc<ControlPlaneClient>, config: ReconnectConfig) -> Self {
        Self {
            client,
            config: config.clone(),
            state: Arc::new(RwLock::new(ReconnectState::Connected)),
            current_delay: Arc::new(RwLock::new(config.initial_delay)),
            attempt_count: Arc::new(RwLock::new(0)),
        }
    }

    /// Returns the current reconnection state.
    pub async fn state(&self) -> ReconnectState {
        *self.state.read().await
    }

    /// Returns the current attempt count.
    pub async fn attempt_count(&self) -> u32 {
        *self.attempt_count.read().await
    }

    /// Resets the reconnection state after a successful connection.
    pub async fn reset(&self) {
        let mut state = self.state.write().await;
        let mut delay = self.current_delay.write().await;
        let mut attempts = self.attempt_count.write().await;

        *state = ReconnectState::Connected;
        *delay = self.config.initial_delay;
        *attempts = 0;

        tracing::debug!("Reconnection state reset");
    }

    /// Main reconnection loop.
    ///
    /// Monitors the connection state and attempts reconnection when needed.
    /// This should be spawned as a background task.
    pub async fn run(&self) -> Result<()> {
        loop {
            // Check connection state
            let conn_state = self.client.connection_state().await;

            if conn_state.connected {
                // Connection is healthy, reset state
                if *self.state.read().await != ReconnectState::Connected {
                    self.reset().await;
                }
                sleep(Duration::from_secs(1)).await;
                continue;
            }

            // Connection lost, attempt reconnection
            {
                let mut state = self.state.write().await;
                if *state == ReconnectState::Stopped {
                    tracing::info!("Reconnection manager stopped");
                    return Ok(());
                }
                *state = ReconnectState::Reconnecting;
            }

            // Check if we've exceeded max attempts
            let attempts = {
                let mut attempts = self.attempt_count.write().await;
                *attempts += 1;
                *attempts
            };

            if let Some(max) = self.config.max_attempts {
                if attempts > max {
                    tracing::error!(
                        attempts,
                        max_attempts = max,
                        "Max reconnection attempts exceeded"
                    );
                    *self.state.write().await = ReconnectState::Stopped;
                    return Ok(());
                }
            }

            // Get current delay
            let delay = *self.current_delay.read().await;

            tracing::info!(
                attempt = attempts,
                delay_secs = delay.as_secs_f64(),
                "Attempting reconnection"
            );

            // Wait before attempting
            sleep(delay).await;

            // Try to reconnect by sending a ping/auth request
            match self.attempt_reconnect().await {
                Ok(()) => {
                    tracing::info!(attempt = attempts, "Reconnection successful");
                    self.reset().await;
                }
                Err(e) => {
                    tracing::warn!(
                        attempt = attempts,
                        error = %e,
                        "Reconnection attempt failed"
                    );

                    // Increase delay with exponential backoff
                    let mut current_delay = self.current_delay.write().await;
                    let new_delay = Duration::from_secs_f64(
                        (current_delay.as_secs_f64() * self.config.backoff_multiplier)
                            .min(self.config.max_delay.as_secs_f64()),
                    );
                    *current_delay = new_delay;

                    // Try next address
                    self.client.next_address();
                }
            }
        }
    }

    /// Attempts a single reconnection.
    async fn attempt_reconnect(&self) -> Result<()> {
        // Send a simple request to verify connectivity
        // In a real implementation, this would send an auth request
        // For now, we just check if we can reach the server

        let conn_state = self.client.connection_state().await;
        if conn_state.connected {
            return Ok(());
        }

        // The actual reconnection logic would involve:
        // 1. Re-authenticating with the control plane
        // 2. Re-establishing any active sessions
        // For now, we rely on the next successful response to mark us as connected

        anyhow::bail!("Not yet connected")
    }

    /// Stops the reconnection manager.
    pub async fn stop(&self) {
        *self.state.write().await = ReconnectState::Stopped;
        tracing::info!("Reconnection manager stopped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reconnect_config_default() {
        let config = ReconnectConfig::default();
        assert_eq!(config.initial_delay, Duration::from_secs(1));
        assert_eq!(config.max_delay, Duration::from_secs(60));
        assert!(config.max_attempts.is_none());
        assert_eq!(config.backoff_multiplier, 2.0);
    }

    #[test]
    fn test_reconnect_state_eq() {
        assert_eq!(ReconnectState::Connected, ReconnectState::Connected);
        assert_ne!(ReconnectState::Connected, ReconnectState::Reconnecting);
    }
}
