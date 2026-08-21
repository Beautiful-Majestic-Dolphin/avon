//! Marking devices stale and then offline when their pulse stops.

use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;

use crate::service::AppState;

/// One pass: online→stale after `stale`, anything→offline after `offline`.
/// Returns the ids that transitioned to offline so callers can close sessions.
pub async fn sweep_once(
    pool: &PgPool,
    stale: Duration,
    offline: Duration,
) -> Result<Vec<uuid::Uuid>, sqlx::Error> {
    sqlx::query(
        "UPDATE devices SET liveness = 'stale' \
         WHERE liveness = 'online' AND last_seen_at < now() - $1::interval",
    )
    .bind(format!("{} seconds", stale.as_secs()))
    .execute(pool)
    .await?;
    let rows: Vec<(uuid::Uuid,)> = sqlx::query_as(
        "UPDATE devices SET liveness = 'offline' \
         WHERE liveness IN ('online','stale') AND last_seen_at < now() - $1::interval RETURNING id",
    )
    .bind(format!("{} seconds", offline.as_secs()))
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

pub async fn liveness_sweeper(
    state: Arc<AppState>,
    stale: Duration,
    offline: Duration,
    every: Duration,
) {
    let mut tick = tokio::time::interval(every);
    loop {
        tick.tick().await;
        match sweep_once(&state.pool, stale, offline).await {
            Ok(offline_ids) => {
                for id in offline_ids {
                    crate::gateway_stream::close_device_sessions(
                        &state,
                        id.into(),
                        "device offline",
                    )
                    .await;
                }
            }
            Err(e) => tracing::warn!(error = %e, "liveness sweep failed"),
        }
    }
}
