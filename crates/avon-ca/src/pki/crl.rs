use avon_crypto::cert::crl::Crl;
use sqlx::PgPool;

use super::PkiError;
use crate::keys::CaKeys;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

async fn build_and_store(pool: &PgPool, keys: &CaKeys) -> Result<avon_protocol::v2::Crl, PkiError> {
    let mut tx = pool.begin().await?;
    let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
        "SELECT serial FROM certificates WHERE revoked_at IS NOT NULL AND not_after > now() \
         ORDER BY serial",
    )
    .fetch_all(&mut *tx)
    .await?;
    let serials = rows
        .into_iter()
        .filter_map(|(s,)| s.try_into().ok())
        .collect();
    let (next,): (i64,) = sqlx::query_as("SELECT COALESCE(MAX(version), 0) + 1 FROM crl_versions")
        .fetch_one(&mut *tx)
        .await?;
    let crl = Crl {
        version: next as u64,
        issued_at: now(),
        serials,
    };
    let tbs = crl.encode_tbs();
    let signature = crl.sign(&keys.issuing)?;
    let mut encoded = (tbs.len() as u32).to_be_bytes().to_vec();
    encoded.extend_from_slice(&tbs);
    encoded.extend_from_slice(&signature);
    sqlx::query("INSERT INTO crl_versions (version, crl) VALUES ($1, $2)")
        .bind(next)
        .bind(&encoded)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(avon_protocol::v2::Crl { tbs, signature })
}

fn split(encoded: &[u8]) -> Option<avon_protocol::v2::Crl> {
    if encoded.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes(encoded[..4].try_into().ok()?) as usize;
    if encoded.len() < 4 + len {
        return None;
    }
    Some(avon_protocol::v2::Crl {
        tbs: encoded[4..4 + len].to_vec(),
        signature: encoded[4 + len..].to_vec(),
    })
}

pub async fn current_crl(pool: &PgPool, keys: &CaKeys) -> Result<avon_protocol::v2::Crl, PkiError> {
    let latest: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT crl FROM crl_versions ORDER BY version DESC LIMIT 1")
            .fetch_optional(pool)
            .await?;
    match latest.and_then(|(e,)| split(&e)) {
        Some(crl) => Ok(crl),
        None => build_and_store(pool, keys).await,
    }
}

pub async fn revoke(
    pool: &PgPool,
    keys: &CaKeys,
    serial: &[u8; 16],
    reason: &str,
) -> Result<avon_protocol::v2::Crl, PkiError> {
    let updated = sqlx::query(
        "UPDATE certificates SET revoked_at = COALESCE(revoked_at, now()), \
         revocation_reason = $2 WHERE serial = $1",
    )
    .bind(serial.as_slice())
    .bind(reason)
    .execute(pool)
    .await?
    .rows_affected();
    if updated == 0 {
        return Err(PkiError::X509("unknown serial".into()));
    }
    build_and_store(pool, keys).await
}
