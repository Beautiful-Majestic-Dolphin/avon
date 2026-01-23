//! Device-related types for AVON.
//!
//! This module provides types for device identification and management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a device in the AVON network.
///
/// A DeviceId is a 16-byte UUID that uniquely identifies a device.
///
/// # Example
///
/// ```
/// use avon_common::device::DeviceId;
///
/// let id = DeviceId::new();
/// let bytes = id.as_bytes();
/// let restored = DeviceId::from_bytes(bytes);
/// assert_eq!(id, restored);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub Uuid);

impl DeviceId {
    /// Creates a new random DeviceId.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Creates a DeviceId from a 16-byte array.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 16]) -> Self {
        Self(Uuid::from_bytes(*bytes))
    }

    /// Creates a DeviceId from a byte slice, returning an error if the slice is not 16 bytes.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 16 {
            return Err("DeviceId must be exactly 16 bytes");
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(bytes);
        Ok(Self::from_bytes(&arr))
    }

    /// Creates a DeviceId from a UUID.
    #[must_use]
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Returns the DeviceId as a 16-byte array.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }

    /// Returns the underlying UUID.
    #[must_use]
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for DeviceId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Information about a device in the AVON network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Unique identifier for the device.
    pub id: DeviceId,
    /// Human-readable name for the device.
    pub name: String,
    /// Current status of the device.
    pub status: DeviceStatus,
    /// Last time the device was seen (sent a pulse).
    pub last_seen: Option<DateTime<Utc>>,
    /// Hardware fingerprint for device binding (32 bytes).
    pub hardware_fingerprint: [u8; 32],
}

impl DeviceInfo {
    /// Creates a new DeviceInfo with the given parameters.
    #[must_use]
    pub fn new(name: String, hardware_fingerprint: [u8; 32]) -> Self {
        Self {
            id: DeviceId::new(),
            name,
            status: DeviceStatus::PendingEnrollment,
            last_seen: None,
            hardware_fingerprint,
        }
    }

    /// Returns true if the device is currently active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == DeviceStatus::Active
    }
}

/// Status of a device in the AVON network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceStatus {
    /// Device is awaiting enrollment approval.
    PendingEnrollment,
    /// Device is active and can establish tunnels.
    Active,
    /// Device is temporarily suspended.
    Suspended,
    /// Device has been permanently revoked.
    Revoked,
}

impl DeviceStatus {
    /// Returns true if the device can establish tunnels.
    #[must_use]
    pub fn can_connect(&self) -> bool {
        matches!(self, DeviceStatus::Active)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_id_new() {
        let id1 = DeviceId::new();
        let id2 = DeviceId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_device_id_from_bytes() {
        let bytes = [1u8; 16];
        let id = DeviceId::from_bytes(&bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn test_device_id_roundtrip() {
        let id = DeviceId::new();
        let bytes = id.as_bytes();
        let restored = DeviceId::from_bytes(bytes);
        assert_eq!(id, restored);
    }

    #[test]
    fn test_device_info_new() {
        let fingerprint = [0x42u8; 32];
        let info = DeviceInfo::new("test-device".to_string(), fingerprint);
        assert_eq!(info.name, "test-device");
        assert_eq!(info.status, DeviceStatus::PendingEnrollment);
        assert!(info.last_seen.is_none());
    }

    #[test]
    fn test_device_status_can_connect() {
        assert!(DeviceStatus::Active.can_connect());
        assert!(!DeviceStatus::PendingEnrollment.can_connect());
        assert!(!DeviceStatus::Suspended.can_connect());
        assert!(!DeviceStatus::Revoked.can_connect());
    }
}
