use avon_common::ids::TenantId;
use sqlx::PgPool;
use uuid::Uuid;

use crate::pki::{Issued, PkiError};

pub async fn store_issued(
    pool: &PgPool,
    issued: &Issued,
    tenant: Option<TenantId>,
    subject: Uuid,
    kind: &str,
    issuer_key_id: &[u8; 32],
) -> Result<(), PkiError> {
    sqlx::query(
        "INSERT INTO certificates (serial, tenant_id, subject_id, kind, certificate, \
         tls_certificate_der, not_before, not_after, issuer_key_id) \
         VALUES ($1, $2, $3, $4::cert_kind, $5, $6, to_timestamp($7), to_timestamp($8), $9)",
    )
    .bind(issued.serial.as_slice())
    .bind(tenant.map(|t| t.as_uuid()))
    .bind(subject)
    .bind(kind)
    .bind(issued.certificate.encode())
    .bind(&issued.tls_cert_der)
    .bind(issued.certificate.tbs.not_before as f64)
    .bind(issued.not_after as f64)
    .bind(issuer_key_id.as_slice())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn is_revoked(pool: &PgPool, serial: &[u8; 16]) -> Result<bool, PkiError> {
    let row: Option<(Option<chrono::DateTime<chrono::Utc>>,)> =
        sqlx::query_as("SELECT revoked_at FROM certificates WHERE serial = $1")
            .bind(serial.as_slice())
            .fetch_optional(pool)
            .await?;
    Ok(matches!(row, Some((Some(_),))))
}
