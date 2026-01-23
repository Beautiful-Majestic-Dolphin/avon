//! Device registry for the AVON UDP Gateway.
//!
//! Provides an in-memory cache of device state, synced from Redis.

use avon_common::device::DeviceId;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::time::interval;
use tracing::{debug, info};

/// Errors that can occur in the device registry.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Failed to connect to Redis.
    #[error("Redis connection failed: {0}")]
    ConnectionFailed(String),
    /// Device not found.
    #[error("Device not found: {0}")]
    DeviceNotFound(DeviceId),
    /// Sync failed.
    #[error("Sync failed: {0}")]
    SyncFailed(String),
}

/// State for a single device.
#[derive(Clone, Debug)]
pub struct DeviceState {
    /// Device identifier.
    pub id: DeviceId,
    /// Current authentication token.
    pub current_token: [u8; 32],
    /// Previous token for grace period.
    pub previous_token: Option<[u8; 32]>,
    /// Token sequence number.
    pub token_sequence: u64,
    /// Last time the device was seen.
    pub last_seen: Instant,
    /// Last known address of the device.
    pub last_addr: SocketAddr,
}

impl DeviceState {
    /// Creates a new device state.
    pub fn new(id: DeviceId, token: [u8; 32], addr: SocketAddr) -> Self {
        Self {
            id,
            current_token: token,
            previous_token: None,
            token_sequence: 0,
            last_seen: Instant::now(),
            last_addr: addr,
        }
    }
}

/// In-memory cache of device state, synced from Redis.
pub struct DeviceRegistry {
    devices: DashMap<DeviceId, DeviceState>,
    redis_url: String,
}

impl DeviceRegistry {
    /// Creates a new device registry.
    pub async fn new(redis_url: String) -> Result<Self, RegistryError> {
        let registry = Self {
            devices: DashMap::new(),
            redis_url,
        };

        // Initial sync would happen here in production
        // For now, we just create an empty registry
        info!("Device registry initialized");

        Ok(registry)
    }

    /// Looks up a device by ID.
    pub async fn lookup(&self, device_id: &DeviceId) -> Option<DeviceState> {
        self.devices.get(device_id).map(|entry| entry.clone())
    }

    /// Updates the last seen time and address for a device.
    pub async fn update_last_seen(&self, device_id: &DeviceId, addr: SocketAddr) {
        if let Some(mut entry) = self.devices.get_mut(device_id) {
            entry.last_seen = Instant::now();
            entry.last_addr = addr;
            debug!(?device_id, ?addr, "Updated device last seen");
        }
    }

    /// Updates the token for a device.
    pub async fn update_token(
        &self,
        device_id: &DeviceId,
        new_token: [u8; 32],
        sequence: u64,
    ) -> Result<(), RegistryError> {
        if let Some(mut entry) = self.devices.get_mut(device_id) {
            // Move current token to previous for grace period
            entry.previous_token = Some(entry.current_token);
            entry.current_token = new_token;
            entry.token_sequence = sequence;
            debug!(?device_id, sequence, "Updated device token");
            Ok(())
        } else {
            Err(RegistryError::DeviceNotFound(*device_id))
        }
    }

    /// Registers a new device.
    pub async fn register_device(&self, state: DeviceState) {
        let device_id = state.id;
        self.devices.insert(device_id, state);
        info!(?device_id, "Registered new device");
    }

    /// Removes a device from the registry.
    pub async fn remove_device(&self, device_id: &DeviceId) -> Option<DeviceState> {
        self.devices.remove(device_id).map(|(_, state)| state)
    }

    /// Returns the number of registered devices.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Periodically syncs device state from the database.
    ///
    /// This should be spawned as a background task.
    pub async fn sync_from_database(self: Arc<Self>, sync_interval_secs: u64) {
        let mut ticker = interval(Duration::from_secs(sync_interval_secs));

        loop {
            ticker.tick().await;

            // In production, this would:
            // 1. Connect to Redis
            // 2. Fetch updated device states
            // 3. Update local cache
            // 4. Remove stale entries

            debug!(
                device_count = self.devices.len(),
                redis_url = %self.redis_url,
                "Database sync tick (not implemented)"
            );
        }
    }

    /// Verifies a token for a device.
    ///
    /// Returns `true` if the token matches either the current or previous token.
    pub fn verify_token(&self, device_id: &DeviceId, token: &[u8; 32]) -> bool {
        if let Some(entry) = self.devices.get(device_id) {
            // Check current token
            if constant_time_eq(&entry.current_token, token) {
                return true;
            }
            // Check previous token (grace period)
            if let Some(ref prev) = entry.previous_token {
                if constant_time_eq(prev, token) {
                    return true;
                }
            }
        }
        false
    }
}

/// Constant-time comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_registry_new() {
        let registry = DeviceRegistry::new("redis://localhost:6379".to_string())
            .await
            .unwrap();
        assert_eq!(registry.device_count(), 0);
    }

    #[tokio::test]
    async fn test_register_and_lookup() {
        let registry = DeviceRegistry::new("redis://localhost:6379".to_string())
            .await
            .unwrap();

        let device_id = DeviceId::new();
        let token = [0x42u8; 32];
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();

        let state = DeviceState::new(device_id, token, addr);
        registry.register_device(state).await;

        let found = registry.lookup(&device_id).await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().current_token, token);
    }

    #[tokio::test]
    async fn test_update_token() {
        let registry = DeviceRegistry::new("redis://localhost:6379".to_string())
            .await
            .unwrap();

        let device_id = DeviceId::new();
        let token1 = [0x42u8; 32];
        let token2 = [0x43u8; 32];
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();

        let state = DeviceState::new(device_id, token1, addr);
        registry.register_device(state).await;

        registry.update_token(&device_id, token2, 1).await.unwrap();

        let found = registry.lookup(&device_id).await.unwrap();
        assert_eq!(found.current_token, token2);
        assert_eq!(found.previous_token, Some(token1));
        assert_eq!(found.token_sequence, 1);
    }

    #[tokio::test]
    async fn test_verify_token() {
        let registry = DeviceRegistry::new("redis://localhost:6379".to_string())
            .await
            .unwrap();

        let device_id = DeviceId::new();
        let token1 = [0x42u8; 32];
        let token2 = [0x43u8; 32];
        let wrong_token = [0x44u8; 32];
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();

        let state = DeviceState::new(device_id, token1, addr);
        registry.register_device(state).await;

        // Current token should verify
        assert!(registry.verify_token(&device_id, &token1));

        // Update token
        registry.update_token(&device_id, token2, 1).await.unwrap();

        // Both current and previous should verify
        assert!(registry.verify_token(&device_id, &token2));
        assert!(registry.verify_token(&device_id, &token1));

        // Wrong token should not verify
        assert!(!registry.verify_token(&device_id, &wrong_token));
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [0x42u8; 32];
        let b = [0x42u8; 32];
        let c = [0x43u8; 32];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }
}
