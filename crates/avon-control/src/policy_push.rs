//! Policy distribution.
//!
//! Postgres notifies on every change that can affect a decision (the triggers
//! in migration 0001); this module turns those notifications into compiled
//! snapshots and pushes them to gateways. Two shapes of update exist because
//! their rates differ by orders of magnitude: whole snapshots when policy or
//! membership changes (rare, seconds apart at worst) and single-device attribute
//! patches when posture or attestation changes (one per device per pulse).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use avon_common::ids::{DeviceId, GatewayId, TenantId};
use avon_policy::engine::Engine;
use avon_policy::entities::{DeviceAttrs, SnapshotData};
use avon_protocol::v2::{
    gateway_down, DecisionRecord, DeviceUpdate, GatewayDown, PolicySnapshot, Uuid as PbUuid,
};
use sqlx::postgres::PgListener;
use tokio::sync::Mutex;

use crate::service::AppState;

const DEBOUNCE: Duration = Duration::from_millis(250);
const DEVICE_DEBOUNCE: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum PushError {
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("policy compilation: {0}")]
    Compile(#[from] avon_policy::compile::CompileError),
}

pub fn snapshot_message(tenant: TenantId, data: &SnapshotData) -> PolicySnapshot {
    let _ = tenant;
    PolicySnapshot {
        version: data.version,
        encoded: avon_policy::snapshot::encode(data),
    }
}

/// Load, compile, swap in and broadcast one tenant's policy.
pub async fn refresh_tenant(state: &AppState, tenant: TenantId) -> Result<u64, PushError> {
    let data = avon_policy::db::load_snapshot(&state.pool, tenant.as_uuid()).await?;
    let now = chrono::Utc::now().timestamp();
    let engine = state
        .engines
        .entry(tenant)
        .or_insert_with(|| Arc::new(Engine::empty(tenant.as_uuid())))
        .clone();
    engine.load(data.clone(), now)?;
    let msg = GatewayDown {
        msg: Some(gateway_down::Msg::Policy(snapshot_message(tenant, &data))),
    };
    state.gateways.broadcast(msg);
    metrics::counter!("avon_control_policy_snapshots_pushed_total").increment(1);
    tracing::info!(%tenant, version = data.version, policies = data.policies.len(), "policy snapshot pushed");
    Ok(data.version)
}

/// Every tenant's current snapshot, for a gateway that has just registered.
pub async fn snapshots_for_registration(
    state: &AppState,
) -> Result<Vec<PolicySnapshot>, PushError> {
    let tenants: Vec<(uuid::Uuid,)> = sqlx::query_as("SELECT id FROM tenants")
        .fetch_all(&state.pool)
        .await?;
    let mut out = Vec::with_capacity(tenants.len());
    for (id,) in tenants {
        let tenant = TenantId::new(id);
        let data = avon_policy::db::load_snapshot(&state.pool, id).await?;
        let engine = state
            .engines
            .entry(tenant)
            .or_insert_with(|| Arc::new(Engine::empty(id)))
            .clone();
        engine.load(data.clone(), chrono::Utc::now().timestamp())?;
        out.push(snapshot_message(tenant, &data));
    }
    Ok(out)
}

/// `LISTEN avon_policy_changed` with a short debounce: a bulk edit in the admin
/// API fires one notification per row, and recompiling ten times in a second
/// would be pure waste.
pub async fn policy_listener(state: Arc<AppState>, database_url: String) {
    loop {
        let result: Result<(), anyhow::Error> = async {
            let mut listener = PgListener::connect(&database_url).await?;
            listener.listen("avon_policy_changed").await?;
            let pending: Arc<Mutex<HashMap<TenantId, Instant>>> =
                Arc::new(Mutex::new(HashMap::new()));

            // Drain the debounce map on a fixed tick.
            let drain_state = state.clone();
            let drain_pending = pending.clone();
            let _drainer = tokio::spawn(async move {
                let mut tick = tokio::time::interval(DEBOUNCE);
                loop {
                    tick.tick().await;
                    let due: Vec<TenantId> = {
                        let mut map = drain_pending.lock().await;
                        let now = Instant::now();
                        let due: Vec<TenantId> = map
                            .iter()
                            .filter(|(_, at)| now.duration_since(**at) >= DEBOUNCE)
                            .map(|(t, _)| *t)
                            .collect();
                        for t in &due {
                            map.remove(t);
                        }
                        due
                    };
                    for tenant in due {
                        if let Err(e) = refresh_tenant(&drain_state, tenant).await {
                            tracing::warn!(%tenant, error = %e, "policy refresh failed");
                        }
                    }
                }
            });

            loop {
                let notification = listener.recv().await?;
                if let Ok(id) = notification.payload().parse::<uuid::Uuid>() {
                    pending
                        .lock()
                        .await
                        .insert(TenantId::new(id), Instant::now());
                }
            }
            #[allow(unreachable_code)]
            {
                _drainer.abort();
                Ok(())
            }
        }
        .await;
        if let Err(e) = result {
            tracing::warn!(error = %e, "policy listener reconnecting");
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
}

/// Patch one device's attributes into every engine and gateway. Debounced so a
/// chatty agent cannot make control recompile continuously.
pub async fn patch_device_attrs(state: &AppState, tenant: TenantId, device: DeviceId) {
    {
        let mut last = state.device_patch_at.lock().await;
        if let Some(at) = last.get(&device) {
            if at.elapsed() < DEVICE_DEBOUNCE {
                return;
            }
        }
        last.insert(device, Instant::now());
    }
    #[allow(clippy::type_complexity)]
    let row: Option<(Option<serde_json::Value>, String, i16, String, Option<uuid::Uuid>)> = sqlx::query_as(
        "SELECT posture, attestation_state::text, risk_score, status::text, device_class_id FROM devices WHERE id = $1")
        .bind(device.as_uuid())
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);
    let Some((posture, attestation, risk, status, class)) = row else {
        return;
    };
    let p = posture.unwrap_or_else(|| serde_json::json!({}));
    let attrs = DeviceAttrs {
        status,
        class,
        firewall_enabled: p["firewall_enabled"].as_bool(),
        disk_encrypted: p["disk_encrypted"].as_bool(),
        screen_lock_enabled: p["screen_lock_enabled"].as_bool(),
        os_version: p["os_version"].as_str().map(str::to_string),
        last_update_unix: p["last_update_unix"].as_i64(),
        attestation,
        risk_score: risk.clamp(0, 100) as u8,
        ..Default::default()
    };
    if let Some(engine) = state.engines.get(&tenant) {
        let _ = engine.patch_device(
            device.as_uuid(),
            attrs.clone(),
            chrono::Utc::now().timestamp(),
        );
    }
    let attrs_json = serde_json::to_string(&attrs).unwrap_or_else(|_| "{}".into());
    state.gateways.broadcast(GatewayDown {
        msg: Some(gateway_down::Msg::DeviceUpdate(DeviceUpdate {
            tenant_id: Some(PbUuid {
                value: tenant.as_uuid().as_bytes().to_vec(),
            }),
            device_id: Some(PbUuid {
                value: device.as_uuid().as_bytes().to_vec(),
            }),
            attrs_json,
        })),
    });
}

/// Time-window policies become active or inactive without any database change,
/// so engines are re-checked on a slow tick.
pub async fn window_ticker(state: Arc<AppState>) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        let now = chrono::Utc::now().timestamp();
        let tenants: Vec<TenantId> = state.engines.iter().map(|e| *e.key()).collect();
        for tenant in tenants {
            let needs = state
                .engines
                .get(&tenant)
                .is_some_and(|e| e.needs_recompile(now));
            if needs {
                if let Err(e) = refresh_tenant(&state, tenant).await {
                    tracing::warn!(%tenant, error = %e, "time-window recompile failed");
                }
            }
        }
    }
}

pub async fn record_decisions(
    state: &AppState,
    gateway: GatewayId,
    records: Vec<DecisionRecord>,
) -> Result<(), sqlx::Error> {
    let _ = gateway;
    if records.is_empty() {
        return Ok(());
    }
    let mut tx = state.pool.begin().await?;
    for r in records.into_iter().take(1000) {
        let (Some(tenant), Some(device)) = (r.tenant_id.as_ref(), r.device_id.as_ref()) else {
            continue;
        };
        let policy_ids: Vec<uuid::Uuid> =
            r.policy_ids.iter().filter_map(|s| s.parse().ok()).collect();
        sqlx::query(
            "INSERT INTO policy_decisions (tenant_id, device_id, session_id, destination, effect, policy_ids, reason, decided_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, to_timestamp($8))")
            .bind(avon_protocol::bytes_to_uuid(&tenant.value).unwrap_or_default())
            .bind(avon_protocol::bytes_to_uuid(&device.value).unwrap_or_default())
            .bind(if r.session_id.is_empty() { None } else { Some(r.session_id) })
            .bind(&r.destination)
            .bind(if r.allow { "allow" } else { "deny" })
            .bind(&policy_ids)
            .bind(&r.reason)
            .bind(r.decided_at_unix as f64)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await
}
