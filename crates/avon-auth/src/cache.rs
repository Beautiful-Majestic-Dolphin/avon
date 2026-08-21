//! Redis caching for the AVON authentication service.
//!
//! This module provides caching for device state to reduce database load
//! and improve authentication latency. It also handles pub/sub for token
//! rotation notifications across multiple auth service instances.

use avon_common::device::DeviceId;
use futures::StreamExt;
use redis::aio::MultiplexedConnection;
use redis::{AsyncCommands, Client as RedisClient};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, warn};

/// Errors that can occur during cache operations.
#[derive(Debug, Error)]
pub enum CacheError {
    /// Redis connection or command error.
    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Cached device state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedDeviceState {
    /// Current authentication token.
    pub current_token: Vec<u8>,
    /// Previous authentication token (for grace period).
    pub previous_token: Option<Vec<u8>>,
    /// Token sequence number.
    pub token_sequence: u64,
    /// Device status (active, suspended, revoked).
    pub status: String,
}

/// Redis cache for authentication state.
pub struct AuthCache {
    #[allow(dead_code)] // Kept for potential reconnection handling
    client: RedisClient,
    connection: MultiplexedConnection,
    ttl_secs: u64,
}

impl AuthCache {
    /// Creates a new cache connection.
    ///
    /// # Arguments
    ///
    /// * `redis_url` - Redis connection URL
    /// * `ttl_secs` - Time-to-live for cached entries in seconds
    ///
    /// # Returns
    ///
    /// A new `AuthCache` instance.
    pub async fn new(redis_url: &str, ttl_secs: u64) -> Result<Self, CacheError> {
        let client = RedisClient::open(redis_url)?;
        let connection = client.get_multiplexed_async_connection().await?;

        debug!("Connected to Redis cache");
        Ok(Self {
            client,
            connection,
            ttl_secs,
        })
    }

    /// Gets the cache key for a device.
    fn device_key(id: &DeviceId) -> String {
        format!("avon:device:{}", id.as_uuid())
    }

    /// Gets the pub/sub channel for token rotations.
    fn rotation_channel() -> &'static str {
        "avon:token_rotations"
    }

    /// Gets a device's cached state.
    pub async fn get_device_state(
        &self,
        id: &DeviceId,
    ) -> Result<Option<CachedDeviceState>, CacheError> {
        let key = Self::device_key(id);
        let mut conn = self.connection.clone();

        let data: Option<String> = conn.get(&key).await?;

        match data {
            Some(json) => {
                let state: CachedDeviceState = serde_json::from_str(&json)
                    .map_err(|e| CacheError::SerializationError(e.to_string()))?;
                debug!(?id, "Cache hit for device state");
                Ok(Some(state))
            }
            None => {
                debug!(?id, "Cache miss for device state");
                Ok(None)
            }
        }
    }

    /// Sets a device's cached state.
    pub async fn set_device_state(
        &self,
        id: &DeviceId,
        state: &CachedDeviceState,
    ) -> Result<(), CacheError> {
        let key = Self::device_key(id);
        let mut conn = self.connection.clone();

        let json = serde_json::to_string(state)
            .map_err(|e| CacheError::SerializationError(e.to_string()))?;

        conn.set_ex::<_, _, ()>(&key, &json, self.ttl_secs).await?;

        debug!(?id, "Cached device state");
        Ok(())
    }

    /// Invalidates a device's cached state.
    pub async fn invalidate_device(&self, id: &DeviceId) -> Result<(), CacheError> {
        let key = Self::device_key(id);
        let mut conn = self.connection.clone();

        conn.del::<_, ()>(&key).await?;

        debug!(?id, "Invalidated device cache");
        Ok(())
    }

    /// Publishes a token rotation notification.
    ///
    /// This notifies other auth service instances that a device's token
    /// has been rotated so they can invalidate their caches.
    pub async fn publish_token_rotation(
        &self,
        id: &DeviceId,
        new_sequence: u64,
    ) -> Result<(), CacheError> {
        let mut conn = self.connection.clone();
        let channel = Self::rotation_channel();

        let message = format!("{}:{}", id.as_uuid(), new_sequence);
        conn.publish::<_, _, ()>(channel, &message).await?;

        debug!(?id, new_sequence, "Published token rotation");
        Ok(())
    }

    /// Subscribes to token rotation notifications.
    ///
    /// Returns a receiver that yields (DeviceId, sequence) pairs when
    /// other instances rotate tokens.
    ///
    /// Note: This uses a polling approach since the redis crate's async pubsub
    /// API varies between versions. For production, consider using a dedicated
    /// pubsub connection.
    pub async fn subscribe_token_rotations(
        &self,
        redis_url: &str,
    ) -> Result<tokio::sync::mpsc::Receiver<(DeviceId, u64)>, CacheError> {
        let (tx, rx) = tokio::sync::mpsc::channel(100);
        let url = redis_url.to_string();

        tokio::spawn(async move {
            let client = match RedisClient::open(url.as_str()) {
                Ok(c) => c,
                Err(e) => {
                    warn!("Failed to create pubsub client: {}", e);
                    return;
                }
            };

            let mut pubsub = match client.get_async_pubsub().await {
                Ok(pubsub) => pubsub,
                Err(e) => {
                    warn!("Failed to create pubsub connection: {}", e);
                    return;
                }
            };

            if let Err(e) = pubsub.subscribe(Self::rotation_channel()).await {
                warn!("Failed to subscribe to rotation channel: {}", e);
                return;
            }

            let mut stream = pubsub.on_message();
            while let Some(msg) = stream.next().await {
                let payload: String = match msg.get_payload() {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                // Parse "uuid:sequence" format
                let parts: Vec<&str> = payload.split(':').collect();
                if parts.len() != 2 {
                    continue;
                }

                let uuid = match uuid::Uuid::parse_str(parts[0]) {
                    Ok(u) => u,
                    Err(_) => continue,
                };

                let sequence: u64 = match parts[1].parse() {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                let device_id = DeviceId::from_uuid(uuid);
                if tx.send((device_id, sequence)).await.is_err() {
                    break;
                }
            }
        });

        Ok(rx)
    }

    /// Checks if the cache is healthy.
    pub async fn health_check(&self) -> Result<bool, CacheError> {
        let mut conn = self.connection.clone();
        let result: String = redis::cmd("PING").query_async(&mut conn).await?;
        Ok(result == "PONG")
    }

    /// Gets the TTL for cached entries.
    pub fn ttl(&self) -> Duration {
        Duration::from_secs(self.ttl_secs)
    }
}

/// Token rotation message for pub/sub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRotationMessage {
    /// Device ID that rotated.
    pub device_id: String,
    /// New token sequence number.
    pub new_sequence: u64,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_cached_device_state_serialization() {
        let state = CachedDeviceState {
            current_token: vec![0x42; 32],
            previous_token: Some(vec![0x41; 32]),
            token_sequence: 42,
            status: "active".to_string(),
        };

        let json = serde_json::to_string(&state).unwrap();
        let deserialized: CachedDeviceState = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.token_sequence, 42);
        assert_eq!(deserialized.status, "active");
    }

    #[test]
    fn test_device_key_format() {
        let id = DeviceId::new();
        let key = AuthCache::device_key(&id);
        assert!(key.starts_with("avon:device:"));
    }

    #[test]
    fn test_rotation_channel() {
        assert_eq!(AuthCache::rotation_channel(), "avon:token_rotations");
    }

    #[test]
    fn test_token_rotation_message_serialization() {
        let msg = TokenRotationMessage {
            device_id: "test-device".to_string(),
            new_sequence: 100,
        };

        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: TokenRotationMessage = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.device_id, "test-device");
        assert_eq!(deserialized.new_sequence, 100);
    }
}
