//! Token Rotation Manager for the AVON Pulse Manager.
//!
//! This module handles the secure rotation of device authentication tokens,
//! ensuring synchronized token updates between client and server.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use avon_common::device::DeviceId;
use avon_crypto::kdf::hkdf_sha256;
use avon_crypto::random::random_bytes_fixed;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use thiserror::Error;
use tracing::info;

use crate::db::PulseDatabase;

#[derive(Error, Debug)]
pub enum RotationError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Redis error: {0}")]
    RedisError(String),

    #[error("Device not found: {0}")]
    DeviceNotFound(DeviceId),

    #[error("No pending rotation for device")]
    NoPendingRotation,

    #[error("Rotation context mismatch")]
    ContextMismatch,

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Rotation already in progress")]
    RotationInProgress,
}

pub type Result<T> = std::result::Result<T, RotationError>;

#[derive(Clone, Debug)]
pub struct RotationContext {
    pub rotation_id: u64,
    pub server_nonce: [u8; 32],
    pub initiated_at: DateTime<Utc>,
    pub device_id: DeviceId,
}

struct PendingRotation {
    context: RotationContext,
    old_token: [u8; 32],
}

struct DeviceTokenState {
    current_token: [u8; 32],
    previous_token: Option<[u8; 32]>,
    token_sequence: u64,
    last_rotation: Option<DateTime<Utc>>,
}

pub struct TokenRotationManager {
    db: Arc<PulseDatabase>,
    rotation_interval: Duration,
    rotation_counter: AtomicU64,
    pending_rotations: DashMap<DeviceId, PendingRotation>,
    device_tokens: DashMap<DeviceId, DeviceTokenState>,
}

impl TokenRotationManager {
    pub fn new(db: Arc<PulseDatabase>, rotation_interval: Duration) -> Self {
        Self {
            db,
            rotation_interval,
            rotation_counter: AtomicU64::new(1),
            pending_rotations: DashMap::new(),
            device_tokens: DashMap::new(),
        }
    }

    pub async fn initiate_rotation(&self, device_id: DeviceId) -> Result<RotationContext> {
        if self.pending_rotations.contains_key(&device_id) {
            return Err(RotationError::RotationInProgress);
        }

        let rotation_id = self.rotation_counter.fetch_add(1, Ordering::SeqCst);
        let server_nonce: [u8; 32] =
            random_bytes_fixed().map_err(|e| RotationError::CryptoError(e.to_string()))?;

        let context = RotationContext {
            rotation_id,
            server_nonce,
            initiated_at: Utc::now(),
            device_id,
        };

        let old_token = self
            .device_tokens
            .get(&device_id)
            .map(|state| state.current_token)
            .unwrap_or([0u8; 32]);

        self.pending_rotations.insert(
            device_id,
            PendingRotation {
                context: context.clone(),
                old_token,
            },
        );

        info!(?device_id, rotation_id, "Token rotation initiated");

        Ok(context)
    }

    pub async fn complete_rotation(
        &self,
        device_id: DeviceId,
        client_nonce: &[u8; 32],
        server_nonce: &[u8; 32],
    ) -> Result<[u8; 32]> {
        let pending = self
            .pending_rotations
            .remove(&device_id)
            .map(|(_, v)| v)
            .ok_or(RotationError::NoPendingRotation)?;

        if &pending.context.server_nonce != server_nonce {
            self.pending_rotations.insert(device_id, pending);
            return Err(RotationError::ContextMismatch);
        }

        let new_token = self.compute_new_token(&pending.old_token, server_nonce, client_nonce)?;

        let new_sequence = self
            .device_tokens
            .get(&device_id)
            .map(|state| state.token_sequence + 1)
            .unwrap_or(1);

        self.db
            .update_device_token(device_id, &new_token, new_sequence)
            .await
            .map_err(|e| RotationError::DatabaseError(e.to_string()))?;

        self.db
            .invalidate_device_cache(device_id)
            .await
            .map_err(|e| RotationError::RedisError(e.to_string()))?;

        let now = Utc::now();
        self.device_tokens
            .entry(device_id)
            .and_modify(|state| {
                state.previous_token = Some(state.current_token);
                state.current_token = new_token;
                state.token_sequence = new_sequence;
                state.last_rotation = Some(now);
            })
            .or_insert(DeviceTokenState {
                current_token: new_token,
                previous_token: Some(pending.old_token),
                token_sequence: new_sequence,
                last_rotation: Some(now),
            });

        self.db
            .publish_rotation_event(device_id, new_sequence)
            .await
            .map_err(|e| RotationError::RedisError(e.to_string()))?;

        info!(
            ?device_id,
            rotation_id = pending.context.rotation_id,
            new_sequence,
            "Token rotation completed"
        );

        metrics::counter!("avon_token_rotations_total").increment(1);

        Ok(new_token)
    }

    fn compute_new_token(
        &self,
        old_token: &[u8; 32],
        server_nonce: &[u8; 32],
        client_nonce: &[u8; 32],
    ) -> Result<[u8; 32]> {
        let mut ikm = Vec::with_capacity(96);
        ikm.extend_from_slice(old_token);
        ikm.extend_from_slice(server_nonce);
        ikm.extend_from_slice(client_nonce);

        let derived = hkdf_sha256(&ikm, Some(b"avon-token-rotation"), b"token", 32)
            .map_err(|e| RotationError::CryptoError(e.to_string()))?;

        let mut new_token = [0u8; 32];
        new_token.copy_from_slice(&derived);

        Ok(new_token)
    }

    pub async fn should_rotate(&self, device_id: &DeviceId) -> bool {
        if self.pending_rotations.contains_key(device_id) {
            return false;
        }

        if let Some(state) = self.device_tokens.get(device_id) {
            if let Some(last_rotation) = state.last_rotation {
                let elapsed = Utc::now() - last_rotation;
                return elapsed >= chrono::Duration::from_std(self.rotation_interval).unwrap();
            }
        }

        true
    }

    pub async fn get_current_token(&self, device_id: &DeviceId) -> Option<[u8; 32]> {
        self.device_tokens
            .get(device_id)
            .map(|state| state.current_token)
    }

    pub fn register_device(&self, device_id: DeviceId, token: [u8; 32], sequence: u64) {
        self.device_tokens.insert(
            device_id,
            DeviceTokenState {
                current_token: token,
                previous_token: None,
                token_sequence: sequence,
                last_rotation: None,
            },
        );
    }

    pub fn cancel_pending_rotation(&self, device_id: &DeviceId) -> bool {
        self.pending_rotations.remove(device_id).is_some()
    }

    pub fn has_pending_rotation(&self, device_id: &DeviceId) -> bool {
        self.pending_rotations.contains_key(device_id)
    }

    pub fn get_pending_rotation(&self, device_id: &DeviceId) -> Option<RotationContext> {
        self.pending_rotations
            .get(device_id)
            .map(|r| r.context.clone())
    }

    pub fn pending_rotation_count(&self) -> usize {
        self.pending_rotations.len()
    }

    pub fn tracked_device_count(&self) -> usize {
        self.device_tokens.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotation_context_creation() {
        let device_id = DeviceId::new();
        let context = RotationContext {
            rotation_id: 1,
            server_nonce: [1u8; 32],
            initiated_at: Utc::now(),
            device_id,
        };

        assert_eq!(context.rotation_id, 1);
        assert_eq!(context.server_nonce, [1u8; 32]);
    }

    #[test]
    fn test_compute_new_token() {
        let old_token = [1u8; 32];
        let server_nonce = [2u8; 32];
        let client_nonce = [3u8; 32];

        let mut ikm = Vec::with_capacity(96);
        ikm.extend_from_slice(&old_token);
        ikm.extend_from_slice(&server_nonce);
        ikm.extend_from_slice(&client_nonce);

        let derived = hkdf_sha256(&ikm, Some(b"avon-token-rotation"), b"token", 32).unwrap();

        assert_eq!(derived.len(), 32);
        assert_ne!(&derived[..], &old_token[..]);
    }
}
