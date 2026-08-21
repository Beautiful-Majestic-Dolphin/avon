//! Pulse Scheduler for the AVON Pulse Manager.
//!
//! This module provides the core scheduling functionality for device pulses,
//! including tracking expected responses and detecting missed pulses.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use avon_common::device::DeviceId;
use avon_crypto::hmac::hmac_sha256_verify;
use avon_crypto::random::random_bytes_fixed;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::config::PulseConfig;
use crate::db::PulseDatabase;
use crate::rotation::TokenRotationManager;

#[derive(Error, Debug)]
pub enum SchedulerError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Redis error: {0}")]
    RedisError(String),

    #[error("Device not found: {0}")]
    DeviceNotFound(DeviceId),

    #[error("Invalid pulse response")]
    InvalidPulseResponse,

    #[error("Pulse timeout")]
    PulseTimeout,

    #[error("Channel send error: {0}")]
    ChannelError(String),
}

pub type Result<T> = std::result::Result<T, SchedulerError>;

#[derive(Clone, Debug)]
pub struct OutboundPulse {
    pub device_id: DeviceId,
    pub server_nonce: [u8; 32],
    pub pulse_id: u64,
    pub timestamp: DateTime<Utc>,
    pub rotation_requested: bool,
}

#[derive(Clone, Debug)]
pub struct PulseResponse {
    pub device_id: DeviceId,
    pub pulse_id: u64,
    pub client_nonce: [u8; 32],
    pub auth_tag: [u8; 32],
    pub posture: DevicePosture,
}

#[derive(Clone, Debug, Default)]
pub struct DevicePosture {
    pub os_version: String,
    pub agent_version: String,
    pub firewall_enabled: bool,
    pub disk_encrypted: bool,
    pub last_update_check: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LivenessStatus {
    Online { last_seen: DateTime<Utc> },
    Stale { last_seen: DateTime<Utc> },
    Offline,
}

struct PendingPulse {
    server_nonce: [u8; 32],
    sent_at: DateTime<Utc>,
    rotation_requested: bool,
}

struct DevicePulseState {
    last_seen: DateTime<Utc>,
    last_pulse_at: Option<DateTime<Utc>>,
    missed_pulses: u32,
    current_token: [u8; 32],
}

pub struct PulseScheduler {
    db: Arc<PulseDatabase>,
    rotation_manager: Arc<TokenRotationManager>,
    gateway_sender: mpsc::Sender<OutboundPulse>,
    pulse_interval: Duration,
    stale_threshold: Duration,
    offline_threshold: Duration,
    pulse_counter: AtomicU64,
    pending_pulses: DashMap<(DeviceId, u64), PendingPulse>,
    device_states: DashMap<DeviceId, DevicePulseState>,
}

impl PulseScheduler {
    pub fn new(
        db: Arc<PulseDatabase>,
        rotation_manager: Arc<TokenRotationManager>,
        gateway_sender: mpsc::Sender<OutboundPulse>,
        config: &PulseConfig,
    ) -> Self {
        Self {
            db,
            rotation_manager,
            gateway_sender,
            pulse_interval: Duration::from_secs(config.pulse_interval_secs.unwrap_or(30)),
            stale_threshold: Duration::from_secs(config.stale_threshold_secs.unwrap_or(90)),
            offline_threshold: Duration::from_secs(config.offline_threshold_secs.unwrap_or(300)),
            pulse_counter: AtomicU64::new(1),
            pending_pulses: DashMap::new(),
            device_states: DashMap::new(),
        }
    }

    pub async fn run(&self) -> Result<()> {
        info!(
            pulse_interval_secs = self.pulse_interval.as_secs(),
            "Starting pulse scheduler"
        );

        let mut interval = tokio::time::interval(self.pulse_interval);

        loop {
            interval.tick().await;

            if let Err(e) = self.schedule_pulses().await {
                error!(error = %e, "Failed to schedule pulses");
            }

            self.check_missed_pulses().await;
        }
    }

    async fn schedule_pulses(&self) -> Result<()> {
        let devices = self
            .db
            .get_devices_due_for_pulse(self.pulse_interval)
            .await
            .map_err(|e| SchedulerError::DatabaseError(e.to_string()))?;

        debug!(
            device_count = devices.len(),
            "Scheduling pulses for devices"
        );

        for device in devices {
            if let Err(e) = self.send_pulse(device.id).await {
                warn!(device_id = ?device.id, error = %e, "Failed to send pulse");
            }
        }

        Ok(())
    }

    async fn send_pulse(&self, device_id: DeviceId) -> Result<()> {
        let pulse_id = self.pulse_counter.fetch_add(1, Ordering::SeqCst);
        let server_nonce: [u8; 32] =
            random_bytes_fixed().map_err(|e| SchedulerError::ChannelError(e.to_string()))?;

        let rotation_requested = self.rotation_manager.should_rotate(&device_id).await;

        let pulse = OutboundPulse {
            device_id,
            server_nonce,
            pulse_id,
            timestamp: Utc::now(),
            rotation_requested,
        };

        self.gateway_sender
            .send(pulse.clone())
            .await
            .map_err(|e| SchedulerError::ChannelError(e.to_string()))?;

        self.pending_pulses.insert(
            (device_id, pulse_id),
            PendingPulse {
                server_nonce,
                sent_at: pulse.timestamp,
                rotation_requested,
            },
        );

        debug!(?device_id, pulse_id, "Pulse sent");

        Ok(())
    }

    pub async fn handle_pulse_response(&self, response: PulseResponse) -> Result<()> {
        let key = (response.device_id, response.pulse_id);

        let pending = self
            .pending_pulses
            .remove(&key)
            .map(|(_, v)| v)
            .ok_or(SchedulerError::InvalidPulseResponse)?;

        let device_state = self.device_states.get(&response.device_id);
        let current_token = device_state
            .as_ref()
            .map(|s| s.current_token)
            .unwrap_or([0u8; 32]);

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&pending.server_nonce);
        auth_data.extend_from_slice(&response.client_nonce);
        auth_data.extend_from_slice(&response.pulse_id.to_be_bytes());

        if !hmac_sha256_verify(&current_token, &auth_data, &response.auth_tag) {
            warn!(
                device_id = ?response.device_id,
                pulse_id = response.pulse_id,
                "Invalid auth tag in pulse response"
            );
            return Err(SchedulerError::InvalidPulseResponse);
        }

        let now = Utc::now();

        self.device_states
            .entry(response.device_id)
            .and_modify(|state| {
                state.last_seen = now;
                state.last_pulse_at = Some(now);
                state.missed_pulses = 0;
            })
            .or_insert(DevicePulseState {
                last_seen: now,
                last_pulse_at: Some(now),
                missed_pulses: 0,
                current_token,
            });

        self.db
            .update_device_last_seen(response.device_id, now)
            .await
            .map_err(|e| SchedulerError::DatabaseError(e.to_string()))?;

        self.db
            .update_device_posture(response.device_id, &response.posture)
            .await
            .map_err(|e| SchedulerError::DatabaseError(e.to_string()))?;

        if pending.rotation_requested {
            if let Err(e) = self
                .rotation_manager
                .complete_rotation(
                    response.device_id,
                    &response.client_nonce,
                    &pending.server_nonce,
                )
                .await
            {
                warn!(
                    device_id = ?response.device_id,
                    error = %e,
                    "Failed to complete token rotation"
                );
            } else {
                if let Some(mut state) = self.device_states.get_mut(&response.device_id) {
                    let new_token = self
                        .rotation_manager
                        .get_current_token(&response.device_id)
                        .await
                        .unwrap_or(state.current_token);
                    state.current_token = new_token;
                }
                info!(device_id = ?response.device_id, "Token rotation completed");
            }
        }

        debug!(
            device_id = ?response.device_id,
            pulse_id = response.pulse_id,
            "Pulse response processed"
        );

        Ok(())
    }

    async fn check_missed_pulses(&self) {
        let now = Utc::now();
        let timeout =
            chrono::Duration::from_std(self.pulse_interval * 2).unwrap_or(chrono::Duration::MAX);

        let mut expired_keys = Vec::new();

        for entry in self.pending_pulses.iter() {
            let ((device_id, pulse_id), pending) = entry.pair();
            if now - pending.sent_at > timeout {
                expired_keys.push((*device_id, *pulse_id));
            }
        }

        for key in expired_keys {
            if let Some((_, pending)) = self.pending_pulses.remove(&key) {
                let (device_id, pulse_id) = key;

                self.device_states
                    .entry(device_id)
                    .and_modify(|state| {
                        state.missed_pulses += 1;
                    })
                    .or_insert(DevicePulseState {
                        last_seen: pending.sent_at,
                        last_pulse_at: None,
                        missed_pulses: 1,
                        current_token: [0u8; 32],
                    });

                warn!(
                    ?device_id,
                    pulse_id,
                    sent_at = ?pending.sent_at,
                    "Pulse response timeout - missed pulse"
                );

                metrics::counter!("avon_pulse_missed_total").increment(1);
            }
        }
    }

    pub fn check_device_liveness(&self, device_id: &DeviceId) -> LivenessStatus {
        let now = Utc::now();

        if let Some(state) = self.device_states.get(device_id) {
            let elapsed = now - state.last_seen;

            if elapsed
                < chrono::Duration::from_std(self.stale_threshold).unwrap_or(chrono::Duration::MAX)
            {
                LivenessStatus::Online {
                    last_seen: state.last_seen,
                }
            } else if elapsed
                < chrono::Duration::from_std(self.offline_threshold)
                    .unwrap_or(chrono::Duration::MAX)
            {
                LivenessStatus::Stale {
                    last_seen: state.last_seen,
                }
            } else {
                LivenessStatus::Offline
            }
        } else {
            LivenessStatus::Offline
        }
    }

    pub fn get_device_pulse_info(
        &self,
        device_id: &DeviceId,
    ) -> Option<(DateTime<Utc>, Option<DateTime<Utc>>, u32)> {
        self.device_states
            .get(device_id)
            .map(|state| (state.last_seen, state.last_pulse_at, state.missed_pulses))
    }

    pub fn register_device(&self, device_id: DeviceId, token: [u8; 32]) {
        let now = Utc::now();
        self.device_states.insert(
            device_id,
            DevicePulseState {
                last_seen: now,
                last_pulse_at: None,
                missed_pulses: 0,
                current_token: token,
            },
        );
    }

    pub fn pending_pulse_count(&self) -> usize {
        self.pending_pulses.len()
    }

    pub fn tracked_device_count(&self) -> usize {
        self.device_states.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[allow(dead_code)]
    fn create_test_posture() -> DevicePosture {
        DevicePosture {
            os_version: "Linux 5.15".to_string(),
            agent_version: "0.1.0".to_string(),
            firewall_enabled: true,
            disk_encrypted: true,
            last_update_check: Some(Utc::now()),
        }
    }

    #[test]
    fn test_liveness_status() {
        let now = Utc::now();

        let online = LivenessStatus::Online { last_seen: now };
        let stale = LivenessStatus::Stale { last_seen: now };
        let offline = LivenessStatus::Offline;

        assert!(matches!(online, LivenessStatus::Online { .. }));
        assert!(matches!(stale, LivenessStatus::Stale { .. }));
        assert!(matches!(offline, LivenessStatus::Offline));
    }

    #[test]
    fn test_device_posture_default() {
        let posture = DevicePosture::default();
        assert!(posture.os_version.is_empty());
        assert!(!posture.firewall_enabled);
    }

    #[test]
    fn test_outbound_pulse_creation() {
        let device_id = DeviceId::new();
        let pulse = OutboundPulse {
            device_id,
            server_nonce: [1u8; 32],
            pulse_id: 1,
            timestamp: Utc::now(),
            rotation_requested: false,
        };

        assert_eq!(pulse.pulse_id, 1);
        assert!(!pulse.rotation_requested);
    }
}
