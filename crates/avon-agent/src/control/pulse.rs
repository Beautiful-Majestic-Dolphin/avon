//! Pulse handling for control plane communication.
//!
//! Handles heartbeat requests from the server, including token rotation
//! and device posture reporting.

use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use avon_crypto::token::TokenRotationInput;
use avon_protocol::v1::{PulseRequest, PulseResponse, Timestamp};
use tokio::sync::RwLock;

use crate::identity::IdentityManager;

use super::posture::PostureCollector;

/// Handles pulse requests from the control plane.
pub struct PulseHandler {
    identity: Arc<IdentityManager>,
    last_pulse: Arc<RwLock<Option<Instant>>>,
    posture_collector: PostureCollector,
}

impl PulseHandler {
    /// Creates a new pulse handler.
    pub fn new(identity: Arc<IdentityManager>) -> Self {
        Self {
            identity,
            last_pulse: Arc::new(RwLock::new(None)),
            posture_collector: PostureCollector::new(),
        }
    }

    /// Returns the time of the last pulse, if any.
    pub async fn last_pulse(&self) -> Option<Instant> {
        *self.last_pulse.read().await
    }

    /// Checks if a pulse is overdue based on the expected interval.
    pub async fn is_pulse_overdue(&self, expected_interval: std::time::Duration) -> bool {
        match *self.last_pulse.read().await {
            Some(last) => last.elapsed() > expected_interval * 2,
            None => false, // No pulse received yet, can't be overdue
        }
    }

    /// Handles a pulse request from the server.
    ///
    /// This method:
    /// 1. Generates a client nonce
    /// 2. Collects current device posture
    /// 3. Rotates the token if requested
    /// 4. Returns the pulse response
    pub async fn handle_pulse_request(&self, request: &PulseRequest) -> Result<PulseResponse> {
        // Update last pulse time
        *self.last_pulse.write().await = Some(Instant::now());

        // Generate client nonce
        let client_nonce: [u8; 32] = rand::random();

        // Collect device posture
        let posture = self.posture_collector.collect();

        // Handle token rotation if requested
        let rotation_ack = if request.request_rotation {
            self.handle_token_rotation(&request.server_nonce, &client_nonce)
                .await?;
            true
        } else {
            false
        };

        // Create timestamp
        let now = chrono::Utc::now();
        let timestamp = Timestamp {
            seconds: now.timestamp(),
            nanos: now.timestamp_subsec_nanos() as i32,
        };

        let response = PulseResponse {
            client_nonce: client_nonce.to_vec(),
            timestamp: Some(timestamp),
            rotation_ack,
            posture: Some(posture),
        };

        tracing::debug!(
            rotation_requested = request.request_rotation,
            rotation_ack,
            "Pulse request handled"
        );

        Ok(response)
    }

    /// Handles token rotation.
    async fn handle_token_rotation(
        &self,
        server_nonce: &[u8],
        client_nonce: &[u8; 32],
    ) -> Result<()> {
        if server_nonce.len() != 32 {
            anyhow::bail!(
                "Invalid server nonce length: expected 32, got {}",
                server_nonce.len()
            );
        }

        let mut server_nonce_arr = [0u8; 32];
        server_nonce_arr.copy_from_slice(server_nonce);

        let now = chrono::Utc::now();
        let input = TokenRotationInput {
            server_nonce: server_nonce_arr,
            client_nonce: *client_nonce,
            timestamp: now.timestamp() as u64,
        };

        self.identity.rotate_token(&input).await;

        tracing::info!("Token rotation completed");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use tempfile::TempDir;

    async fn create_test_identity() -> Arc<IdentityManager> {
        let temp_dir = TempDir::new().unwrap();
        let identity = IdentityManager::enroll("test-token", "gateway.test:8443", temp_dir.path())
            .await
            .unwrap();
        Arc::new(identity)
    }

    #[tokio::test]
    async fn test_pulse_handler_creation() {
        let identity = create_test_identity().await;
        let handler = PulseHandler::new(identity);
        assert!(handler.last_pulse().await.is_none());
    }

    #[tokio::test]
    async fn test_handle_pulse_request_no_rotation() {
        let identity = create_test_identity().await;
        let handler = PulseHandler::new(identity);

        let request = PulseRequest {
            server_nonce: vec![0u8; 32],
            timestamp: Some(Timestamp {
                seconds: 1234567890,
                nanos: 0,
            }),
            request_rotation: false,
        };

        let response = handler.handle_pulse_request(&request).await.unwrap();

        assert_eq!(response.client_nonce.len(), 32);
        assert!(!response.rotation_ack);
        assert!(response.posture.is_some());
        assert!(handler.last_pulse().await.is_some());
    }

    #[tokio::test]
    async fn test_handle_pulse_request_with_rotation() {
        let identity = create_test_identity().await;
        let handler = PulseHandler::new(identity);

        let request = PulseRequest {
            server_nonce: vec![42u8; 32],
            timestamp: Some(Timestamp {
                seconds: 1234567890,
                nanos: 0,
            }),
            request_rotation: true,
        };

        let response = handler.handle_pulse_request(&request).await.unwrap();

        assert!(response.rotation_ack);
    }

    #[tokio::test]
    async fn test_is_pulse_overdue() {
        let identity = create_test_identity().await;
        let handler = PulseHandler::new(identity);

        // No pulse yet, not overdue
        assert!(
            !handler
                .is_pulse_overdue(std::time::Duration::from_secs(30))
                .await
        );

        // Simulate a pulse
        *handler.last_pulse.write().await = Some(Instant::now());

        // Just received, not overdue
        assert!(
            !handler
                .is_pulse_overdue(std::time::Duration::from_secs(30))
                .await
        );
    }
}
