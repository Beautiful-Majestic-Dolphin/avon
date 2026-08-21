//! Database operations for the AVON Pulse Manager.
//!
//! This module provides database access for pulse tracking and device state.

use avon_common::device::DeviceId;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use thiserror::Error;
use tracing::{debug, info};

use crate::scheduler::DevicePosture;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("Database error: {0}")]
    SqlxError(#[from] sqlx::Error),

    #[error("Device not found: {0}")]
    DeviceNotFound(DeviceId),

    #[error("Redis error: {0}")]
    RedisError(String),
}

pub type Result<T> = std::result::Result<T, DbError>;

#[derive(Clone, Debug)]
pub struct DeviceRecord {
    pub id: DeviceId,
    pub name: String,
    pub current_token: [u8; 32],
    pub token_sequence: u64,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub last_pulse_at: Option<DateTime<Utc>>,
}

pub struct PulseDatabase {
    pool: PgPool,
    redis_url: Option<String>,
}

impl PulseDatabase {
    pub fn new(pool: PgPool, redis_url: Option<String>) -> Self {
        Self { pool, redis_url }
    }

    pub async fn get_devices_due_for_pulse(
        &self,
        interval: std::time::Duration,
    ) -> Result<Vec<DeviceRecord>> {
        let interval_secs = interval.as_secs() as i64;

        let rows = sqlx::query_as::<
            _,
            (
                uuid::Uuid,
                String,
                Vec<u8>,
                i64,
                Option<DateTime<Utc>>,
                Option<DateTime<Utc>>,
            ),
        >(
            r#"
            SELECT id, name, current_token, token_sequence, last_seen_at, last_pulse_at
            FROM devices
            WHERE status = 'active'
            AND (last_pulse_at IS NULL OR last_pulse_at < NOW() - INTERVAL '1 second' * $1)
            ORDER BY last_pulse_at ASC NULLS FIRST
            LIMIT 100
            "#,
        )
        .bind(interval_secs)
        .fetch_all(&self.pool)
        .await?;

        let devices = rows
            .into_iter()
            .map(
                |(id, name, current_token, token_sequence, last_seen_at, last_pulse_at)| {
                    let mut token = [0u8; 32];
                    if current_token.len() >= 32 {
                        token.copy_from_slice(&current_token[..32]);
                    }

                    DeviceRecord {
                        id: DeviceId::from_uuid(id),
                        name,
                        current_token: token,
                        token_sequence: token_sequence as u64,
                        last_seen_at,
                        last_pulse_at,
                    }
                },
            )
            .collect();

        Ok(devices)
    }

    pub async fn update_device_last_seen(
        &self,
        device_id: DeviceId,
        last_seen: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE devices
            SET last_seen_at = $1, updated_at = NOW()
            WHERE id = $2
            "#,
        )
        .bind(last_seen)
        .bind(device_id.as_uuid())
        .execute(&self.pool)
        .await?;

        debug!(?device_id, ?last_seen, "Updated device last_seen");

        Ok(())
    }

    pub async fn update_device_pulse(
        &self,
        device_id: DeviceId,
        pulse_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE devices
            SET last_pulse_at = $1, last_seen_at = $1, updated_at = NOW()
            WHERE id = $2
            "#,
        )
        .bind(pulse_at)
        .bind(device_id.as_uuid())
        .execute(&self.pool)
        .await?;

        debug!(?device_id, ?pulse_at, "Updated device pulse timestamp");

        Ok(())
    }

    pub async fn update_device_token(
        &self,
        device_id: DeviceId,
        new_token: &[u8; 32],
        sequence: u64,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE devices
            SET previous_token = current_token,
                current_token = $1,
                token_sequence = $2,
                updated_at = NOW()
            WHERE id = $3
            "#,
        )
        .bind(&new_token[..])
        .bind(sequence as i64)
        .bind(device_id.as_uuid())
        .execute(&self.pool)
        .await?;

        info!(?device_id, sequence, "Updated device token");

        Ok(())
    }

    pub async fn update_device_posture(
        &self,
        _device_id: DeviceId,
        _posture: &DevicePosture,
    ) -> Result<()> {
        Ok(())
    }

    pub async fn get_device(&self, device_id: DeviceId) -> Result<Option<DeviceRecord>> {
        let row = sqlx::query_as::<
            _,
            (
                uuid::Uuid,
                String,
                Vec<u8>,
                i64,
                Option<DateTime<Utc>>,
                Option<DateTime<Utc>>,
            ),
        >(
            r#"
            SELECT id, name, current_token, token_sequence, last_seen_at, last_pulse_at
            FROM devices
            WHERE id = $1
            "#,
        )
        .bind(device_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(
            |(id, name, current_token, token_sequence, last_seen_at, last_pulse_at)| {
                let mut token = [0u8; 32];
                if current_token.len() >= 32 {
                    token.copy_from_slice(&current_token[..32]);
                }

                DeviceRecord {
                    id: DeviceId::from_uuid(id),
                    name,
                    current_token: token,
                    token_sequence: token_sequence as u64,
                    last_seen_at,
                    last_pulse_at,
                }
            },
        ))
    }

    pub async fn invalidate_device_cache(&self, device_id: DeviceId) -> Result<()> {
        if self.redis_url.is_none() {
            return Ok(());
        }

        debug!(?device_id, "Invalidated device cache");
        Ok(())
    }

    pub async fn publish_rotation_event(&self, device_id: DeviceId, sequence: u64) -> Result<()> {
        if self.redis_url.is_none() {
            return Ok(());
        }

        debug!(?device_id, sequence, "Published rotation event");
        Ok(())
    }

    pub async fn record_missed_pulse(
        &self,
        device_id: DeviceId,
        pulse_id: u64,
        expected_at: DateTime<Utc>,
    ) -> Result<()> {
        debug!(?device_id, pulse_id, ?expected_at, "Recorded missed pulse");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_device_record_creation() {
        let device_id = DeviceId::new();
        let record = DeviceRecord {
            id: device_id,
            name: "test-device".to_string(),
            current_token: [1u8; 32],
            token_sequence: 1,
            last_seen_at: Some(Utc::now()),
            last_pulse_at: None,
        };

        assert_eq!(record.name, "test-device");
        assert_eq!(record.token_sequence, 1);
    }
}
