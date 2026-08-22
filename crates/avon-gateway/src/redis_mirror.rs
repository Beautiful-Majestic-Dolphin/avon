//! A best-effort mirror of session metadata in Redis, so admin views can list
//! live tunnels without asking every gateway. Never authoritative, never on the
//! forwarding path, and every failure is logged rather than propagated —
//! forwarding must not depend on Redis being up.

use std::net::SocketAddr;

use avon_common::ids::SessionId;
use redis::AsyncCommands;
use serde::Serialize;

use crate::state::{GatewayState, SessionMeta};

/// Long enough to survive a control blip, short enough that a gateway which
/// dies without cleaning up disappears on its own.
const TTL_SECS: u64 = 300;

#[derive(Serialize)]
struct MirroredSession {
    gateway: String,
    session: String,
    device: String,
    tenant: String,
    overlay_v4: Option<String>,
    overlay_v6: Option<String>,
    advertised: Vec<String>,
    endpoint: Option<String>,
}

fn key(state: &GatewayState, id: &SessionId) -> String {
    format!("avon:gw:{}:session:{}", state.id, id)
}

fn render(
    state: &GatewayState,
    id: &SessionId,
    meta: &SessionMeta,
    endpoint: Option<SocketAddr>,
) -> MirroredSession {
    MirroredSession {
        gateway: state.id.to_string(),
        session: id.to_string(),
        device: meta.device_id.to_string(),
        tenant: meta.tenant.to_string(),
        overlay_v4: meta.overlay_v4.map(|n| n.to_string()),
        overlay_v6: meta.overlay_v6.map(|n| n.to_string()),
        advertised: meta.advertised.iter().map(|n| n.to_string()).collect(),
        endpoint: endpoint.map(|e| e.to_string()),
    }
}

pub async fn mirror_session(state: &GatewayState, id: &SessionId, meta: &SessionMeta) {
    write(state, id, render(state, id, meta, None)).await;
}

pub async fn mirror_endpoint(state: &GatewayState, id: &SessionId, endpoint: SocketAddr) {
    let Some(meta) = state.sessions_meta.get(id).map(|m| m.clone()) else {
        return;
    };
    write(state, id, render(state, id, &meta, Some(endpoint))).await;
}

pub async fn unmirror(state: &GatewayState, id: &SessionId) {
    let Some(mut conn) = state.redis.read().await.clone() else {
        return;
    };
    if let Err(e) = conn.del::<_, ()>(key(state, id)).await {
        tracing::debug!(error = %e, "session mirror delete failed");
    }
}

async fn write(state: &GatewayState, id: &SessionId, value: MirroredSession) {
    let Some(mut conn) = state.redis.read().await.clone() else {
        return;
    };
    let Ok(json) = serde_json::to_string(&value) else {
        return;
    };
    if let Err(e) = conn
        .set_ex::<_, _, ()>(key(state, id), json, TTL_SECS)
        .await
    {
        tracing::debug!(error = %e, "session mirror write failed");
    }
}
