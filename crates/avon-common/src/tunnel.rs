//! Tunnel-related types for AVON.
//!
//! This module provides types for tunnel session management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::device::DeviceId;

/// Unique identifier for a tunnel session.
///
/// A SessionId is a 16-byte random identifier for a tunnel session.
///
/// # Example
///
/// ```
/// use avon_common::tunnel::SessionId;
///
/// let id = SessionId::new();
/// let bytes = id.as_bytes();
/// let restored = SessionId::from_bytes(bytes);
/// assert_eq!(id, restored);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub [u8; 16]);

impl SessionId {
    /// Creates a new random SessionId.
    #[must_use]
    pub fn new() -> Self {
        Self(*Uuid::new_v4().as_bytes())
    }

    /// Creates a SessionId from a 16-byte array.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 16]) -> Self {
        Self(*bytes)
    }

    /// Returns the SessionId as a 16-byte array.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// Information about an active tunnel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelInfo {
    /// Unique session identifier.
    pub session_id: SessionId,
    /// Device that initiated the tunnel.
    pub source_device: DeviceId,
    /// Device that accepted the tunnel.
    pub destination_device: DeviceId,
    /// When the tunnel was established.
    pub established_at: DateTime<Utc>,
    /// Last activity on the tunnel.
    pub last_activity: DateTime<Utc>,
    /// Total bytes sent through the tunnel.
    pub bytes_sent: u64,
    /// Total bytes received through the tunnel.
    pub bytes_received: u64,
    /// Current status of the tunnel.
    pub status: TunnelStatus,
}

impl TunnelInfo {
    /// Creates a new TunnelInfo for a newly established tunnel.
    #[must_use]
    pub fn new(source_device: DeviceId, destination_device: DeviceId) -> Self {
        let now = Utc::now();
        Self {
            session_id: SessionId::new(),
            source_device,
            destination_device,
            established_at: now,
            last_activity: now,
            bytes_sent: 0,
            bytes_received: 0,
            status: TunnelStatus::Establishing,
        }
    }

    /// Returns true if the tunnel is currently active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == TunnelStatus::Active
    }

    /// Updates the last activity timestamp.
    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }

    /// Records bytes sent through the tunnel.
    pub fn record_sent(&mut self, bytes: u64) {
        self.bytes_sent = self.bytes_sent.saturating_add(bytes);
        self.touch();
    }

    /// Records bytes received through the tunnel.
    pub fn record_received(&mut self, bytes: u64) {
        self.bytes_received = self.bytes_received.saturating_add(bytes);
        self.touch();
    }
}

/// Status of a tunnel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelStatus {
    /// Tunnel is being established (handshake in progress).
    Establishing,
    /// Tunnel is active and can transfer data.
    Active,
    /// Tunnel is being closed.
    Closing,
    /// Tunnel has been closed.
    Closed,
}

impl TunnelStatus {
    /// Returns true if the tunnel can transfer data.
    #[must_use]
    pub fn can_transfer(&self) -> bool {
        matches!(self, TunnelStatus::Active)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_new() {
        let id1 = SessionId::new();
        let id2 = SessionId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_session_id_from_bytes() {
        let bytes = [1u8; 16];
        let id = SessionId::from_bytes(&bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn test_session_id_roundtrip() {
        let id = SessionId::new();
        let bytes = id.as_bytes();
        let restored = SessionId::from_bytes(bytes);
        assert_eq!(id, restored);
    }

    #[test]
    fn test_tunnel_info_new() {
        let source = DeviceId::new();
        let dest = DeviceId::new();
        let info = TunnelInfo::new(source, dest);
        assert_eq!(info.source_device, source);
        assert_eq!(info.destination_device, dest);
        assert_eq!(info.status, TunnelStatus::Establishing);
        assert_eq!(info.bytes_sent, 0);
        assert_eq!(info.bytes_received, 0);
    }

    #[test]
    fn test_tunnel_status_can_transfer() {
        assert!(TunnelStatus::Active.can_transfer());
        assert!(!TunnelStatus::Establishing.can_transfer());
        assert!(!TunnelStatus::Closing.can_transfer());
        assert!(!TunnelStatus::Closed.can_transfer());
    }

    #[test]
    fn test_tunnel_record_bytes() {
        let source = DeviceId::new();
        let dest = DeviceId::new();
        let mut info = TunnelInfo::new(source, dest);
        
        info.record_sent(100);
        assert_eq!(info.bytes_sent, 100);
        
        info.record_received(200);
        assert_eq!(info.bytes_received, 200);
    }
}
