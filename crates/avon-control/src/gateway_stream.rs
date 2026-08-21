//! Gateway registry and fan-out. Registration, the event stream and revocation
//! fan-out land in task 2.11.

use std::sync::Arc;

use avon_common::ids::GatewayId;
use avon_protocol::v2::GatewayDown;
use dashmap::DashMap;
use sqlx::PgPool;
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct GatewayHandle {
    pub tx: mpsc::Sender<GatewayDown>,
    pub endpoint: String,
    pub region: String,
}

#[derive(Default, Clone)]
pub struct GatewayRegistry(Arc<DashMap<GatewayId, GatewayHandle>>);

impl GatewayRegistry {
    pub fn insert(&self, id: GatewayId, h: GatewayHandle) {
        self.0.insert(id, h);
    }
    pub fn remove(&self, id: GatewayId) {
        self.0.remove(&id);
    }
    pub fn get(&self, id: GatewayId) -> Option<GatewayHandle> {
        self.0.get(&id).map(|h| h.clone())
    }
    pub fn pick(&self, region: Option<&str>) -> Option<(GatewayId, GatewayHandle)> {
        let mut candidates: Vec<_> = self
            .0
            .iter()
            .filter(|e| region.map(|r| e.value().region == r).unwrap_or(true))
            .map(|e| (*e.key(), e.value().clone()))
            .collect();
        candidates.sort_by_key(|(id, _)| *id.as_bytes());
        candidates.into_iter().next()
    }
    pub fn broadcast(&self, msg: GatewayDown) {
        for h in self.0.iter() {
            let _ = h.value().tx.try_send(msg.clone());
        }
    }
}

/// Gateway certificates a device may be offered a session on.
pub async fn gateway_certificates(pool: &PgPool) -> Result<Vec<Vec<u8>>, sqlx::Error> {
    let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
        "SELECT certificate FROM certificates \
         WHERE kind = 'gateway' AND revoked_at IS NULL AND not_after > now()",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}
