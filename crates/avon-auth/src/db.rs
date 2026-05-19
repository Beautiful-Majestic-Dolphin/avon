//! Database operations for the AVON authentication service.

use avon_common::device::DeviceId;
use chrono::{DateTime, Utc};
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use sqlx::Row;
use std::net::IpAddr;
use std::str::FromStr;
use thiserror::Error;
use tracing::{debug, info};

#[derive(Debug, Error)]
pub enum DbError {
    #[error("Database error: {0}")]
    SqlxError(#[from] sqlx::Error),
    #[error("Device not found: {0}")]
    DeviceNotFound(DeviceId),
    #[error("Enrollment token not found or already used")]
    EnrollmentTokenNotFound,
    #[error("Invalid data: {0}")]
    InvalidData(String),
}

#[derive(Debug, Clone)]
pub struct DbDevice {
    pub id: DeviceId,
    pub name: String,
    pub hardware_fingerprint: Vec<u8>,
    pub current_token: Vec<u8>,
    pub previous_token: Option<Vec<u8>>,
    pub token_sequence: i64,
    pub status: String,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub last_known_ip: Option<IpAddr>,
}

#[derive(Debug, Clone)]
pub struct NewDevice {
    pub id: DeviceId,
    pub name: String,
    pub hardware_fingerprint: Vec<u8>,
    pub initial_token: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EnrollmentToken {
    pub token: String,
    pub expected_fingerprint: Option<Vec<u8>>,
    pub pod_id: Option<uuid::Uuid>,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
    pub max_uses: i32,
    pub use_count: i32,
}

pub struct AuthDatabase {
    pool: PgPool,
}

impl AuthDatabase {
    pub async fn new(database_url: &str) -> Result<Self, DbError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;
        info!("Connected to database");
        Ok(Self { pool })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn get_device(&self, id: DeviceId) -> Result<Option<DbDevice>, DbError> {
        let uuid = id.as_uuid();
        let row: Option<PgRow> = sqlx::query(
            "SELECT id, name, hardware_fingerprint, current_token, previous_token, token_sequence, status, last_seen_at, last_known_ip FROM devices WHERE id = $1",
        )
        .bind(uuid)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                let db_id: uuid::Uuid = r.get("id");
                let name: String = r.get("name");
                let hardware_fingerprint: Vec<u8> = r.get("hardware_fingerprint");
                let current_token: Vec<u8> = r.get("current_token");
                let previous_token: Option<Vec<u8>> = r.get("previous_token");
                let token_sequence: i64 = r.get("token_sequence");
                let status: String = r.get("status");
                let last_seen_at: Option<DateTime<Utc>> = r.get("last_seen_at");
                let last_known_ip_str: Option<String> = r.get("last_known_ip");
                let last_known_ip = last_known_ip_str
                    .as_ref()
                    .and_then(|ip| IpAddr::from_str(ip).ok());
                Ok(Some(DbDevice {
                    id: DeviceId::from_uuid(db_id),
                    name,
                    hardware_fingerprint,
                    current_token,
                    previous_token,
                    token_sequence,
                    status,
                    last_seen_at,
                    last_known_ip,
                }))
            }
            None => Ok(None),
        }
    }

    pub async fn get_device_by_fingerprint(
        &self,
        fingerprint: &[u8],
    ) -> Result<Option<DbDevice>, DbError> {
        let row: Option<PgRow> = sqlx::query(
            "SELECT id, name, hardware_fingerprint, current_token, previous_token, token_sequence, status, last_seen_at, last_known_ip FROM devices WHERE hardware_fingerprint = $1",
        )
        .bind(fingerprint)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                let db_id: uuid::Uuid = r.get("id");
                let name: String = r.get("name");
                let hardware_fingerprint: Vec<u8> = r.get("hardware_fingerprint");
                let current_token: Vec<u8> = r.get("current_token");
                let previous_token: Option<Vec<u8>> = r.get("previous_token");
                let token_sequence: i64 = r.get("token_sequence");
                let status: String = r.get("status");
                let last_seen_at: Option<DateTime<Utc>> = r.get("last_seen_at");
                let last_known_ip_str: Option<String> = r.get("last_known_ip");
                let last_known_ip = last_known_ip_str
                    .as_ref()
                    .and_then(|ip| IpAddr::from_str(ip).ok());
                Ok(Some(DbDevice {
                    id: DeviceId::from_uuid(db_id),
                    name,
                    hardware_fingerprint,
                    current_token,
                    previous_token,
                    token_sequence,
                    status,
                    last_seen_at,
                    last_known_ip,
                }))
            }
            None => Ok(None),
        }
    }

    pub async fn create_device(&self, device: NewDevice) -> Result<DbDevice, DbError> {
        let uuid = device.id.as_uuid();
        sqlx::query("INSERT INTO devices (id, name, hardware_fingerprint, current_token, token_sequence, status) VALUES ($1, $2, $3, $4, 0, 'active')")
            .bind(uuid)
            .bind(&device.name)
            .bind(&device.hardware_fingerprint)
            .bind(&device.initial_token)
            .execute(&self.pool)
            .await?;
        debug!(?device.id, "Created new device");
        Ok(DbDevice {
            id: device.id,
            name: device.name,
            hardware_fingerprint: device.hardware_fingerprint,
            current_token: device.initial_token,
            previous_token: None,
            token_sequence: 0,
            status: "active".to_string(),
            last_seen_at: None,
            last_known_ip: None,
        })
    }

    pub async fn update_device_token(
        &self,
        id: DeviceId,
        new_token: &[u8],
        new_sequence: u64,
    ) -> Result<(), DbError> {
        let uuid = id.as_uuid();
        let sequence = new_sequence as i64;
        let result = sqlx::query("UPDATE devices SET previous_token = current_token, current_token = $2, token_sequence = $3 WHERE id = $1")
            .bind(uuid).bind(new_token).bind(sequence)
            .execute(&self.pool).await?;
        if result.rows_affected() == 0 {
            return Err(DbError::DeviceNotFound(id));
        }
        debug!(?id, new_sequence, "Updated device token");
        Ok(())
    }

    pub async fn update_device_last_seen(&self, id: DeviceId, addr: IpAddr) -> Result<(), DbError> {
        let uuid = id.as_uuid();
        let ip_str = addr.to_string();
        let result = sqlx::query(
            "UPDATE devices SET last_seen_at = NOW(), last_known_ip = $2 WHERE id = $1",
        )
        .bind(uuid)
        .bind(&ip_str)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::DeviceNotFound(id));
        }
        Ok(())
    }

    pub async fn update_device_status(&self, id: DeviceId, status: &str) -> Result<(), DbError> {
        let uuid = id.as_uuid();
        let result = sqlx::query("UPDATE devices SET status = $2 WHERE id = $1")
            .bind(uuid)
            .bind(status)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::DeviceNotFound(id));
        }
        debug!(?id, status, "Updated device status");
        Ok(())
    }

    pub async fn get_enrollment_token(
        &self,
        token: &str,
    ) -> Result<Option<EnrollmentToken>, DbError> {
        let row: Option<PgRow> = sqlx::query("SELECT token, expected_fingerprint, pod_id, expires_at, used, max_uses, use_count FROM enrollment_tokens WHERE token = $1 AND NOT used AND expires_at > NOW()")
            .bind(token)
            .fetch_optional(&self.pool).await?;
        match row {
            Some(r) => Ok(Some(EnrollmentToken {
                token: r.get("token"),
                expected_fingerprint: r.get("expected_fingerprint"),
                pod_id: r.get("pod_id"),
                expires_at: r.get("expires_at"),
                used: r.get("used"),
                max_uses: r.get("max_uses"),
                use_count: r.get("use_count"),
            })),
            None => Ok(None),
        }
    }

    pub async fn consume_enrollment_token(&self, token: &str) -> Result<(), DbError> {
        let result = sqlx::query("UPDATE enrollment_tokens SET used = true, use_count = use_count + 1 WHERE token = $1 AND NOT used AND expires_at > NOW()")
            .bind(token).execute(&self.pool).await?;
        if result.rows_affected() == 0 {
            return Err(DbError::EnrollmentTokenNotFound);
        }
        debug!(token, "Consumed enrollment token");
        Ok(())
    }

    pub async fn create_enrollment_token(
        &self,
        token: &str,
        expected_fingerprint: Option<&[u8]>,
        pod_id: Option<uuid::Uuid>,
        expires_at: DateTime<Utc>,
        max_uses: i32,
    ) -> Result<(), DbError> {
        sqlx::query("INSERT INTO enrollment_tokens (token, expected_fingerprint, pod_id, expires_at, max_uses) VALUES ($1, $2, $3, $4, $5)")
            .bind(token).bind(expected_fingerprint).bind(pod_id).bind(expires_at).bind(max_uses)
            .execute(&self.pool).await?;
        debug!(token, "Created enrollment token");
        Ok(())
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Runs database migrations from the migrations directory.
    pub async fn run_migrations(&self) -> Result<(), DbError> {
        // Note: In production, migrations should be run separately
        // This is a convenience method for development
        info!("Running database migrations...");

        // Execute migration SQL files manually since sqlx::migrate! requires compile-time path
        let migrations = [
            include_str!("../migrations/001_create_devices.sql"),
            include_str!("../migrations/002_create_enrollment_tokens.sql"),
        ];

        for (i, migration) in migrations.iter().enumerate() {
            debug!("Running migration {}", i + 1);
            sqlx::query(migration)
                .execute(&self.pool)
                .await
                .map_err(|e| DbError::InvalidData(format!("Migration {} failed: {}", i + 1, e)))?;
        }

        info!("Database migrations completed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_device_creation() {
        let device = DbDevice {
            id: DeviceId::new(),
            name: "Test Device".to_string(),
            hardware_fingerprint: vec![0x01, 0x02, 0x03],
            current_token: vec![0x42; 32],
            previous_token: None,
            token_sequence: 0,
            status: "active".to_string(),
            last_seen_at: None,
            last_known_ip: None,
        };
        assert_eq!(device.name, "Test Device");
        assert_eq!(device.status, "active");
    }

    #[test]
    fn test_new_device_creation() {
        let device = NewDevice {
            id: DeviceId::new(),
            name: "New Device".to_string(),
            hardware_fingerprint: vec![0x01, 0x02, 0x03],
            initial_token: vec![0x42; 32],
        };
        assert_eq!(device.name, "New Device");
        assert_eq!(device.initial_token.len(), 32);
    }

    #[test]
    fn test_enrollment_token_creation() {
        let token = EnrollmentToken {
            token: "test-token".to_string(),
            expected_fingerprint: Some(vec![0x01, 0x02, 0x03]),
            pod_id: None,
            expires_at: Utc::now(),
            used: false,
            max_uses: 1,
            use_count: 0,
        };
        assert!(!token.used);
        assert_eq!(token.max_uses, 1);
    }
}
