//! Packet handling for the AVON UDP Gateway.
//!
//! Processes incoming control plane packets and routes them to appropriate handlers.

use avon_common::device::DeviceId;
use avon_protocol::codec::encode_with_auth_tag;
use avon_protocol::v1::{
    control_message::Payload, AuthResponse, ConnectRequest, ConnectResponse, ControlMessage,
    PulseRequest, PulseResponse, Timestamp,
};
use prost::Message;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, warn};

use crate::device_registry::DeviceRegistry;

/// Errors that can occur during packet handling.
#[derive(Debug, Error)]
pub enum PacketError {
    /// Failed to decode packet.
    #[error("Decode error: {0}")]
    DecodeError(String),
    /// Authentication failed.
    #[error("Authentication failed")]
    AuthFailed,
    /// Device not found.
    #[error("Device not found: {0}")]
    DeviceNotFound(String),
    /// Invalid message type.
    #[error("Invalid message type")]
    InvalidMessageType,
    /// Internal error.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Handles incoming packets and routes them to appropriate handlers.
pub struct PacketHandler {
    registry: Arc<DeviceRegistry>,
}

impl PacketHandler {
    /// Creates a new packet handler.
    pub fn new(registry: Arc<DeviceRegistry>) -> Self {
        Self { registry }
    }

    /// Handles an incoming packet.
    ///
    /// Returns a response packet if one should be sent, or None for silent drop.
    pub async fn handle_packet(&self, packet: &[u8], source: SocketAddr) -> Option<Vec<u8>> {
        // Try to decode the packet header to get device ID
        let message = match ControlMessage::decode(packet) {
            Ok(msg) => msg,
            Err(e) => {
                debug!(?source, error = %e, "Failed to decode packet");
                return None; // Silent drop
            }
        };

        // Get device ID
        let device_id = match message.device_id.as_ref() {
            Some(id) if id.uuid.len() == 16 => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&id.uuid);
                DeviceId::from_bytes(&bytes)
            }
            _ => {
                debug!(?source, "Invalid or missing device ID");
                return None; // Silent drop
            }
        };

        // Look up device and verify auth tag
        let device_state = match self.registry.lookup(&device_id).await {
            Some(state) => state,
            None => {
                // For auth requests, we allow unknown devices
                if matches!(message.payload, Some(Payload::AuthRequest(_))) {
                    return self.handle_auth_request(&message, source).await;
                }
                debug!(?device_id, ?source, "Unknown device");
                return None; // Silent drop
            }
        };

        // Verify auth tag
        if message.auth_tag.len() != 32 {
            debug!(?device_id, ?source, "Invalid auth tag length");
            return None;
        }

        let mut auth_tag = [0u8; 32];
        auth_tag.copy_from_slice(&message.auth_tag);

        // Verify using device's token
        let mut verify_msg = message.clone();
        verify_msg.auth_tag.clear();
        let payload_bytes = verify_msg.encode_to_vec();

        let token_valid = self.registry.verify_token(&device_id, &auth_tag);
        if !token_valid {
            // Also try verifying with HMAC
            let _computed_tag =
                avon_crypto::hmac::hmac_sha256(&device_state.current_token, &payload_bytes);
            if !avon_crypto::hmac::hmac_sha256_verify(
                &device_state.current_token,
                &payload_bytes,
                &auth_tag,
            ) {
                // Try previous token
                if let Some(prev_token) = device_state.previous_token {
                    if !avon_crypto::hmac::hmac_sha256_verify(
                        &prev_token,
                        &payload_bytes,
                        &auth_tag,
                    ) {
                        warn!(?device_id, ?source, "Auth tag verification failed");
                        return None;
                    }
                } else {
                    warn!(?device_id, ?source, "Auth tag verification failed");
                    return None;
                }
            }
        }

        // Update last seen
        self.registry.update_last_seen(&device_id, source).await;

        // Route to appropriate handler
        match message.payload {
            Some(Payload::PulseRequest(req)) => {
                self.handle_pulse_request(
                    &device_id,
                    &device_state.current_token,
                    req,
                    message.sequence,
                )
                .await
            }
            Some(Payload::AuthRequest(_)) => self.handle_auth_request(&message, source).await,
            Some(Payload::ConnectRequest(req)) => {
                self.handle_connect_request(
                    &device_id,
                    &device_state.current_token,
                    req,
                    message.sequence,
                )
                .await
            }
            _ => {
                debug!(?device_id, "Unhandled message type");
                None
            }
        }
    }

    /// Handles a pulse request.
    async fn handle_pulse_request(
        &self,
        device_id: &DeviceId,
        token: &[u8; 32],
        request: PulseRequest,
        sequence: u64,
    ) -> Option<Vec<u8>> {
        debug!(?device_id, sequence, "Handling pulse request");

        // Generate response
        let client_nonce: [u8; 32] = avon_crypto::random::random_bytes_fixed().unwrap_or([0u8; 32]);

        let response = PulseResponse {
            client_nonce: client_nonce.to_vec(),
            timestamp: Some(Timestamp {
                seconds: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64,
                nanos: 0,
            }),
            rotation_ack: request.request_rotation,
            posture: None, // Device will fill this in
        };

        let mut msg = ControlMessage {
            version: 1,
            sequence: sequence + 1,
            device_id: Some(avon_protocol::v1::DeviceId {
                uuid: device_id.as_bytes().to_vec(),
            }),
            auth_tag: vec![],
            payload: Some(Payload::PulseResponse(response)),
        };

        let bytes = encode_with_auth_tag(&mut msg, token);
        Some(bytes)
    }

    /// Handles an auth request.
    async fn handle_auth_request(
        &self,
        message: &ControlMessage,
        source: SocketAddr,
    ) -> Option<Vec<u8>> {
        debug!(?source, "Handling auth request");

        // In production, this would:
        // 1. Validate the device certificate
        // 2. Verify hardware fingerprint
        // 3. Issue a new token
        // 4. Register the device

        // For now, return a placeholder response
        let response = AuthResponse {
            success: false,
            error_message: "Auth service not connected".to_string(),
            new_token: vec![],
            issued_cert: None,
        };

        // Use a temporary token for the response
        let temp_token = [0u8; 32];
        let mut msg = ControlMessage {
            version: 1,
            sequence: message.sequence + 1,
            device_id: message.device_id.clone(),
            auth_tag: vec![],
            payload: Some(Payload::AuthResponse(response)),
        };

        let bytes = encode_with_auth_tag(&mut msg, &temp_token);
        Some(bytes)
    }

    /// Handles a connect request.
    async fn handle_connect_request(
        &self,
        device_id: &DeviceId,
        token: &[u8; 32],
        request: ConnectRequest,
        sequence: u64,
    ) -> Option<Vec<u8>> {
        debug!(?device_id, target = ?request.target_device, "Handling connect request");

        // In production, this would:
        // 1. Check policy engine for permission
        // 2. Look up target device
        // 3. Generate session ID
        // 4. Return connection info

        let response = ConnectResponse {
            allowed: false,
            deny_reason: "Policy engine not connected".to_string(),
            session_id: vec![],
            target_device: request.target_device,
            target_candidates: vec![],
            target_cert: None,
        };

        let mut msg = ControlMessage {
            version: 1,
            sequence: sequence + 1,
            device_id: Some(avon_protocol::v1::DeviceId {
                uuid: device_id.as_bytes().to_vec(),
            }),
            auth_tag: vec![],
            payload: Some(Payload::ConnectResponse(response)),
        };

        let bytes = encode_with_auth_tag(&mut msg, token);
        Some(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_packet_handler_new() {
        let registry = Arc::new(
            DeviceRegistry::new("redis://localhost:6379".to_string())
                .await
                .unwrap(),
        );
        let _handler = PacketHandler::new(registry);
    }

    #[tokio::test]
    async fn test_handle_invalid_packet() {
        let registry = Arc::new(
            DeviceRegistry::new("redis://localhost:6379".to_string())
                .await
                .unwrap(),
        );
        let handler = PacketHandler::new(registry);

        let invalid_packet = vec![0x00, 0x01, 0x02];
        let source: SocketAddr = "192.168.1.1:12345".parse().unwrap();

        let result = handler.handle_packet(&invalid_packet, source).await;
        assert!(result.is_none()); // Should silently drop
    }
}
