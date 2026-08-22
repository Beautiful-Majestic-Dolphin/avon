//! Device pulse streams: the registry of open downstreams plus heartbeat
//! handling (posture, liveness and per-session counters).

use std::sync::Arc;

use avon_common::ids::DeviceId;
use avon_protocol::v2::{PulseAck, PulseDown, PulseHeartbeat};
use dashmap::DashMap;
use tokio::sync::mpsc;
use tonic::Status;

use crate::service::AppState;
use crate::session_token::SessionInfo;

#[derive(Default, Clone)]
pub struct DeviceStreams(Arc<DashMap<DeviceId, mpsc::Sender<PulseDown>>>);

impl DeviceStreams {
    pub fn insert(&self, device: DeviceId, tx: mpsc::Sender<PulseDown>) {
        self.0.insert(device, tx);
    }
    pub fn remove(&self, device: DeviceId) {
        self.0.remove(&device);
    }
    pub fn is_connected(&self, device: DeviceId) -> bool {
        self.0.contains_key(&device)
    }
    pub fn send(&self, device: DeviceId, msg: PulseDown) -> bool {
        match self.0.get(&device) {
            Some(tx) => tx.try_send(msg).is_ok(),
            None => false,
        }
    }
}

pub async fn handle_heartbeat(
    state: &AppState,
    info: &SessionInfo,
    hb: PulseHeartbeat,
) -> Result<PulseAck, Status> {
    if let Some(p) = hb.posture {
        let posture = serde_json::json!({
            "os_name": p.os_name,
            "os_version": p.os_version,
            "agent_version": p.agent_version,
            "firewall_enabled": p.firewall_enabled,
            "disk_encrypted": p.disk_encrypted,
            "screen_lock_enabled": p.screen_lock_enabled,
            "last_update_unix": p.last_update_unix,
            "key_provider": p.key_provider,
            "collected_at_unix": p.collected_at_unix,
        });
        sqlx::query(
            "UPDATE devices SET posture = $2, posture_updated_at = now(), last_seen_at = now(), \
             liveness = 'online' WHERE id = $1",
        )
        .bind(info.device)
        .bind(posture)
        .execute(&state.pool)
        .await
        .map_err(|_| Status::unavailable("database"))?;
    } else {
        sqlx::query("UPDATE devices SET last_seen_at = now(), liveness = 'online' WHERE id = $1")
            .bind(info.device)
            .execute(&state.pool)
            .await
            .map_err(|_| Status::unavailable("database"))?;
    }
    for s in hb.sessions {
        sqlx::query(
            "UPDATE sessions SET bytes_tx = $2, bytes_rx = $3 WHERE id = $1 AND device_id = $4",
        )
        .bind(&s.session_id)
        .bind(s.bytes_tx as i64)
        .bind(s.bytes_rx as i64)
        .bind(info.device)
        .execute(&state.pool)
        .await
        .ok();
    }
    metrics::counter!("avon_control_pulses_total").increment(1);
    // Patch device attributes into engines/gateways (debounced).
    crate::policy_push::patch_device_attrs(state, info.tenant, info.device).await;
    Ok(PulseAck {
        server_time_unix: chrono::Utc::now().timestamp(),
        next_interval_secs: state.pulse_interval_secs,
    })
}
