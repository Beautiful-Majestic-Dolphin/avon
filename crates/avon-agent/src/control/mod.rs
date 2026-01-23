//! Control plane client for AVON Agent.
//!
//! This module handles communication with the AVON control plane, including:
//! - Sending authenticated requests
//! - Handling pulse requests and responses
//! - Managing connection state and reconnection
//! - Token rotation

pub mod posture;
pub mod pulse;
pub mod reconnect;
pub mod requests;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use avon_protocol::v1::{
    control_message, ControlMessage, DeviceId as ProtoDeviceId, PulseRequest, PulseResponse,
    Timestamp,
};
use dashmap::DashMap;
use prost::Message;
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, RwLock};
use tokio::time::timeout;

use crate::identity::IdentityManager;

use self::posture::PostureCollector;
use self::pulse::PulseHandler;
use self::requests::ControlResponse;

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PACKET_SIZE: usize = 65536;

/// Pending request awaiting a response.
struct PendingRequest {
    sender: oneshot::Sender<ControlResponse>,
    sent_at: Instant,
}

/// Connection state with the control plane.
#[derive(Debug, Clone)]
pub struct ConnectionState {
    pub connected: bool,
    pub current_address: Option<SocketAddr>,
    pub last_response: Option<Instant>,
    pub consecutive_failures: u32,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self {
            connected: false,
            current_address: None,
            last_response: None,
            consecutive_failures: 0,
        }
    }
}

/// Client for communicating with the AVON control plane.
///
/// Uses UDP for all communication with authenticated messages.
/// Handles request/response matching, pulse handling, and reconnection.
pub struct ControlPlaneClient {
    socket: Arc<UdpSocket>,
    addresses: Vec<SocketAddr>,
    current_addr_idx: AtomicUsize,
    identity: Arc<IdentityManager>,
    pending_requests: DashMap<u64, PendingRequest>,
    state: Arc<RwLock<ConnectionState>>,
    sequence: AtomicU64,
    pulse_handler: Arc<PulseHandler>,
}

impl ControlPlaneClient {
    /// Creates a new control plane client.
    ///
    /// # Arguments
    ///
    /// * `addresses` - List of control plane addresses to connect to
    /// * `identity` - Identity manager for authentication
    pub async fn new(
        addresses: Vec<SocketAddr>,
        identity: Arc<IdentityManager>,
    ) -> Result<Self> {
        if addresses.is_empty() {
            anyhow::bail!("At least one control plane address is required");
        }

        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind UDP socket")?;

        let socket = Arc::new(socket);
        let state = Arc::new(RwLock::new(ConnectionState::default()));

        let pulse_handler = Arc::new(PulseHandler::new(identity.clone()));

        Ok(Self {
            socket,
            addresses,
            current_addr_idx: AtomicUsize::new(0),
            identity,
            pending_requests: DashMap::new(),
            state,
            sequence: AtomicU64::new(1),
            pulse_handler,
        })
    }

    /// Returns the current connection state.
    pub async fn connection_state(&self) -> ConnectionState {
        self.state.read().await.clone()
    }

    /// Returns the pulse handler for external access.
    pub fn pulse_handler(&self) -> Arc<PulseHandler> {
        self.pulse_handler.clone()
    }

    /// Gets the current control plane address.
    fn current_address(&self) -> SocketAddr {
        let idx = self.current_addr_idx.load(Ordering::Relaxed);
        self.addresses[idx % self.addresses.len()]
    }

    /// Switches to the next control plane address.
    fn next_address(&self) -> SocketAddr {
        let idx = self.current_addr_idx.fetch_add(1, Ordering::Relaxed);
        self.addresses[(idx + 1) % self.addresses.len()]
    }

    /// Gets the next sequence number.
    fn next_sequence(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::Relaxed)
    }

    /// Main receive loop for handling incoming packets.
    ///
    /// This should be spawned as a background task.
    pub async fn run(&self) -> Result<()> {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    let packet = &buf[..len];
                    if let Err(e) = self.handle_packet(packet, addr).await {
                        tracing::warn!(error = %e, "Failed to handle packet from {}", addr);
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "Socket receive error");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Handles an incoming packet.
    async fn handle_packet(&self, packet: &[u8], addr: SocketAddr) -> Result<()> {
        let msg = ControlMessage::decode(packet)
            .context("Failed to decode control message")?;

        // Update connection state
        {
            let mut state = self.state.write().await;
            state.connected = true;
            state.current_address = Some(addr);
            state.last_response = Some(Instant::now());
            state.consecutive_failures = 0;
        }

        // Check if this is a response to a pending request
        if let Some((_, pending)) = self.pending_requests.remove(&msg.sequence) {
            let response = ControlResponse::from_message(msg);
            let _ = pending.sender.send(response);
            return Ok(());
        }

        // Handle unsolicited messages (pulse requests from server)
        match msg.payload {
            Some(control_message::Payload::PulseRequest(pulse_req)) => {
                self.handle_pulse_request(pulse_req, msg.sequence).await?;
            }
            Some(payload) => {
                tracing::debug!(?payload, "Received unsolicited message");
            }
            None => {
                tracing::warn!("Received message with no payload");
            }
        }

        Ok(())
    }

    /// Handles a pulse request from the server.
    async fn handle_pulse_request(&self, request: PulseRequest, sequence: u64) -> Result<()> {
        tracing::debug!(sequence, "Handling pulse request");

        let response = self.pulse_handler.handle_pulse_request(&request).await?;

        self.send_pulse_response(response, sequence).await?;

        Ok(())
    }

    /// Sends a pulse response to the server.
    async fn send_pulse_response(&self, response: PulseResponse, sequence: u64) -> Result<()> {
        let payload_bytes = response.encode_to_vec();
        let auth_tag = self.identity.get_auth_tag(&payload_bytes).await;

        let msg = ControlMessage {
            version: avon_protocol::PROTOCOL_VERSION,
            sequence,
            device_id: Some(self.device_id_proto()),
            auth_tag: auth_tag.to_vec(),
            payload: Some(control_message::Payload::PulseResponse(response)),
        };

        let encoded = msg.encode_to_vec();
        let addr = self.current_address();

        self.socket
            .send_to(&encoded, addr)
            .await
            .context("Failed to send pulse response")?;

        tracing::debug!(sequence, "Sent pulse response");

        Ok(())
    }

    /// Sends a request to the control plane and waits for a response.
    ///
    /// # Arguments
    ///
    /// * `payload` - The request payload to send
    /// * `timeout_duration` - Optional timeout (defaults to 5 seconds)
    ///
    /// # Returns
    ///
    /// The response from the control plane, or an error if the request fails.
    pub async fn send_request(
        &self,
        payload: control_message::Payload,
        timeout_duration: Option<Duration>,
    ) -> Result<ControlResponse> {
        let timeout_duration = timeout_duration.unwrap_or(DEFAULT_REQUEST_TIMEOUT);
        let sequence = self.next_sequence();

        // Serialize payload for auth tag computation
        let payload_bytes = self.encode_payload(&payload);
        let auth_tag = self.identity.get_auth_tag(&payload_bytes).await;

        let msg = ControlMessage {
            version: avon_protocol::PROTOCOL_VERSION,
            sequence,
            device_id: Some(self.device_id_proto()),
            auth_tag: auth_tag.to_vec(),
            payload: Some(payload),
        };

        let encoded = msg.encode_to_vec();

        // Create response channel
        let (tx, rx) = oneshot::channel();
        self.pending_requests.insert(
            sequence,
            PendingRequest {
                sender: tx,
                sent_at: Instant::now(),
            },
        );

        // Send the request
        let addr = self.current_address();
        self.socket
            .send_to(&encoded, addr)
            .await
            .context("Failed to send request")?;

        tracing::debug!(sequence, %addr, "Sent request");

        // Wait for response with timeout
        match timeout(timeout_duration, rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => {
                self.pending_requests.remove(&sequence);
                self.record_failure().await;
                anyhow::bail!("Response channel closed unexpectedly")
            }
            Err(_) => {
                self.pending_requests.remove(&sequence);
                self.record_failure().await;
                anyhow::bail!("Request timed out after {:?}", timeout_duration)
            }
        }
    }

    /// Records a request failure and updates connection state.
    async fn record_failure(&self) {
        let mut state = self.state.write().await;
        state.consecutive_failures += 1;

        if state.consecutive_failures >= 3 {
            state.connected = false;
            tracing::warn!(
                failures = state.consecutive_failures,
                "Connection marked as disconnected after consecutive failures"
            );
        }
    }

    /// Encodes a payload for auth tag computation.
    fn encode_payload(&self, payload: &control_message::Payload) -> Vec<u8> {
        match payload {
            control_message::Payload::PulseRequest(p) => p.encode_to_vec(),
            control_message::Payload::PulseResponse(p) => p.encode_to_vec(),
            control_message::Payload::AuthRequest(p) => p.encode_to_vec(),
            control_message::Payload::AuthResponse(p) => p.encode_to_vec(),
            control_message::Payload::ConnectRequest(p) => p.encode_to_vec(),
            control_message::Payload::ConnectResponse(p) => p.encode_to_vec(),
            control_message::Payload::IceCandidates(p) => p.encode_to_vec(),
            control_message::Payload::CertRequest(p) => p.encode_to_vec(),
            control_message::Payload::CertResponse(p) => p.encode_to_vec(),
            control_message::Payload::TunnelEstablished(p) => p.encode_to_vec(),
            control_message::Payload::TunnelClosed(p) => p.encode_to_vec(),
            control_message::Payload::KeyRotation(p) => p.encode_to_vec(),
        }
    }

    /// Converts the device ID to protocol format.
    fn device_id_proto(&self) -> ProtoDeviceId {
        ProtoDeviceId {
            uuid: self.identity.device_id().as_bytes().to_vec(),
        }
    }

    /// Creates a timestamp for the current time.
    pub fn now_timestamp() -> Timestamp {
        let now = chrono::Utc::now();
        Timestamp {
            seconds: now.timestamp(),
            nanos: now.timestamp_subsec_nanos() as i32,
        }
    }

    /// Cleans up expired pending requests.
    pub fn cleanup_expired_requests(&self, max_age: Duration) {
        let now = Instant::now();
        self.pending_requests.retain(|_, req| {
            now.duration_since(req.sent_at) < max_age
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_state_default() {
        let state = ConnectionState::default();
        assert!(!state.connected);
        assert!(state.current_address.is_none());
        assert!(state.last_response.is_none());
        assert_eq!(state.consecutive_failures, 0);
    }

    #[test]
    fn test_now_timestamp() {
        let ts = ControlPlaneClient::now_timestamp();
        assert!(ts.seconds > 0);
    }
}
