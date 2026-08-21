//! Gateway registry, session close fan-out and device revocation.

use std::sync::Arc;

use avon_common::ids::{DeviceId, GatewayId};
use avon_protocol::v2::{gateway_down, pulse_down, GatewayDown, PulseDown, SessionClose};
use dashmap::DashMap;
use sqlx::PgPool;
use tokio::sync::mpsc;
use tonic::Status;

use crate::service::AppState;

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

/// Close every open session of a device, telling both the serving gateway and
/// the device itself.
pub async fn close_device_sessions(state: &AppState, device: DeviceId, reason: &str) {
    let rows: Vec<(Vec<u8>, Option<uuid::Uuid>)> = sqlx::query_as(
        "UPDATE sessions SET state = 'closed', closed_at = now(), close_reason = $2 \
         WHERE device_id = $1 AND state <> 'closed' RETURNING id, gateway_id",
    )
    .bind(device)
    .bind(reason)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    for (session_id, gateway_id) in rows {
        if let Some(gw) = gateway_id.and_then(|g| state.gateways.get(g.into())) {
            let _ = gw.tx.try_send(GatewayDown {
                msg: Some(gateway_down::Msg::Close(SessionClose {
                    session_id: session_id.clone(),
                    reason: reason.into(),
                })),
            });
        }
        state.devices.send(
            device,
            PulseDown {
                msg: Some(pulse_down::Msg::Close(SessionClose {
                    session_id,
                    reason: reason.into(),
                })),
            },
        );
    }
}

/// Revoke a device everywhere at once: database status, every certificate it
/// holds, the cached CRL, all connected gateways, its own pulse stream and its
/// session token.
pub async fn revoke_device(state: &AppState, device: DeviceId, reason: &str) -> Result<(), Status> {
    sqlx::query("UPDATE devices SET status = 'revoked' WHERE id = $1")
        .bind(device)
        .execute(&state.pool)
        .await
        .map_err(|_| Status::unavailable("database"))?;
    let serials: Vec<(Vec<u8>,)> = sqlx::query_as(
        "SELECT serial FROM certificates WHERE subject_id = $1 AND revoked_at IS NULL",
    )
    .bind(device)
    .fetch_all(&state.pool)
    .await
    .map_err(|_| Status::unavailable("database"))?;
    let mut latest = None;
    for (serial,) in serials {
        latest = Some(state.ca.revoke(serial, reason).await?);
    }
    if let Some(crl_pb) = latest {
        {
            let mut chain = state.chain.write().await;
            if let Ok(crl) = avon_crypto::cert::crl::Crl::verify(
                &crl_pb.tbs,
                &crl_pb.signature,
                &chain.issuing.tbs.signing_key,
            ) {
                chain.crl = crl;
                chain.crl_raw = crl_pb.clone();
            }
        }
        state.gateways.broadcast(GatewayDown {
            msg: Some(gateway_down::Msg::Crl(crl_pb)),
        });
    }
    state.sessions.revoke_device(device).await?;
    close_device_sessions(state, device, reason).await;
    metrics::counter!("avon_control_devices_revoked_total").increment(1);
    Ok(())
}

/// The admin API publishes {"device_id": "...", "reason": "..."} on
/// `avon:control:revoke`; every control replica acts on it.
pub async fn admin_event_listener(state: Arc<AppState>, redis_url: String) {
    loop {
        let result: anyhow::Result<()> = async {
            let client = redis::Client::open(redis_url.clone())?;
            let mut pubsub = client.get_async_pubsub().await?;
            pubsub.subscribe("avon:control:revoke").await?;
            use tokio_stream::StreamExt;
            let mut stream = pubsub.on_message();
            while let Some(msg) = stream.next().await {
                let payload: String = msg.get_payload()?;
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&payload) {
                    if let (Some(id), Some(reason)) = (
                        v["device_id"]
                            .as_str()
                            .and_then(|s| s.parse::<uuid::Uuid>().ok()),
                        v["reason"].as_str(),
                    ) {
                        if let Err(e) = revoke_device(&state, id.into(), reason).await {
                            tracing::warn!(error = %e, "revocation via admin event failed");
                        }
                    }
                }
            }
            Ok(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!(error = %e, "admin event listener reconnecting");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }
}
