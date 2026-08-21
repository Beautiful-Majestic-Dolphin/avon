use avon_common::ids::TenantId;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    #[error("invalid token")]
    InvalidToken,
    #[error("token expired")]
    Expired,
    #[error("token exhausted")]
    Exhausted,
    #[error("fingerprint mismatch")]
    FingerprintMismatch,
    #[error("attestation required")]
    AttestationRequired,
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
}

pub fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

#[derive(sqlx::FromRow, Debug)]
pub struct EnrollmentToken {
    pub id: Uuid,
    pub tenant_id: TenantId,
    pub device_name: Option<String>,
    pub device_kind: String,
    pub pod_ids: Vec<Uuid>,
    pub device_class_id: Option<Uuid>,
    pub require_attestation: bool,
    pub require_approval: bool,
    pub expected_fingerprint: Option<Vec<u8>>,
    pub max_uses: i32,
    pub use_count: i32,
    pub expires_at: DateTime<Utc>,
}

/// Lock the token row, validate it, and count this use — all inside `tx`.
pub async fn consume_token(
    tx: &mut Transaction<'_, Postgres>,
    token_hash: &[u8; 32],
) -> Result<EnrollmentToken, EnrollError> {
    let token: Option<EnrollmentToken> = sqlx::query_as(
        "SELECT id, tenant_id, device_name, device_kind::text AS device_kind, pod_ids, \
                device_class_id, require_attestation, require_approval, expected_fingerprint, \
                max_uses, use_count, expires_at \
         FROM enrollment_tokens WHERE token_hash = $1 FOR UPDATE",
    )
    .bind(token_hash.as_slice())
    .fetch_optional(&mut **tx)
    .await?;
    let token = token.ok_or(EnrollError::InvalidToken)?;
    if token.expires_at < Utc::now() {
        return Err(EnrollError::Expired);
    }
    if token.use_count >= token.max_uses {
        return Err(EnrollError::Exhausted);
    }
    sqlx::query(
        "UPDATE enrollment_tokens SET use_count = use_count + 1, last_used_at = now() WHERE id = $1",
    )
    .bind(token.id)
    .execute(&mut **tx)
    .await?;
    Ok(token)
}

#[allow(clippy::too_many_arguments)]
pub async fn create_device(
    tx: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    device_id: Uuid,
    name: &str,
    kind: &str,
    status: &str,
    device_class_id: Option<Uuid>,
    fingerprint: Option<&[u8]>,
    key_provider: &str,
) -> Result<(), EnrollError> {
    sqlx::query(
        "INSERT INTO devices (id, tenant_id, name, kind, status, device_class_id, fingerprint, \
         key_provider) \
         VALUES ($1, $2, $3, $4::device_kind, $5::device_status, $6, $7, $8)",
    )
    .bind(device_id)
    .bind(tenant)
    .bind(name)
    .bind(kind)
    .bind(status)
    .bind(device_class_id)
    .bind(fingerprint)
    .bind(key_provider)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn add_device_pods(
    tx: &mut Transaction<'_, Postgres>,
    device_id: Uuid,
    pod_ids: &[Uuid],
) -> Result<(), EnrollError> {
    for pod in pod_ids {
        sqlx::query(
            "INSERT INTO device_pods (device_id, pod_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(device_id)
        .bind(pod)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

pub async fn record_enrollment(
    tx: &mut Transaction<'_, Postgres>,
    token_id: Uuid,
    device_id: Uuid,
    client_ip: Option<std::net::IpAddr>,
) -> Result<(), EnrollError> {
    sqlx::query("INSERT INTO enrollments (token_id, device_id, client_ip) VALUES ($1, $2, $3)")
        .bind(token_id)
        .bind(device_id)
        .bind(client_ip.map(sqlx::types::ipnetwork::IpNetwork::from))
        .execute(&mut **tx)
        .await?;
    Ok(())
}
