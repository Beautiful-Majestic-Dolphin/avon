use sqlx::types::ipnetwork::IpNetwork;
use sqlx::PgPool;
use uuid::Uuid;

use crate::entities::{DeviceAttrs, DeviceEntity, PodEntity, PolicyEntry, SnapshotData};
use crate::spec::PolicySpec;

#[allow(clippy::type_complexity)]
pub async fn load_snapshot(pool: &PgPool, tenant: Uuid) -> Result<SnapshotData, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await?;

    let row: Option<(i64,)> =
        sqlx::query_as("SELECT version FROM policy_snapshots WHERE tenant_id = $1")
            .bind(tenant)
            .fetch_optional(&mut *tx)
            .await?;
    let version = row.map(|(v,)| v as u64).unwrap_or(1);

    let pods: Vec<(Uuid, Option<Uuid>)> =
        sqlx::query_as("SELECT id, parent_id FROM pods WHERE tenant_id = $1")
            .bind(tenant)
            .fetch_all(&mut *tx)
            .await?;
    let pods = pods
        .into_iter()
        .map(|(id, parent)| PodEntity { id, parent })
        .collect::<Vec<_>>();

    let device_classes: Vec<(Uuid,)> =
        sqlx::query_as("SELECT id FROM device_classes WHERE tenant_id = $1")
            .bind(tenant)
            .fetch_all(&mut *tx)
            .await?;
    let device_classes = device_classes.into_iter().map(|(id,)| id).collect();

    let device_rows: Vec<(
        Uuid,
        String,
        Option<Uuid>,
        Option<serde_json::Value>,
        String,
        i16,
        Option<IpNetwork>,
        Option<IpNetwork>,
    )> = sqlx::query_as(
        "SELECT id, status::text, device_class_id, posture, attestation_state::text, risk_score, overlay_ipv4, overlay_ipv6 FROM devices WHERE tenant_id = $1",
    )
    .bind(tenant)
    .fetch_all(&mut *tx)
    .await?;

    let mut devices: Vec<DeviceEntity> = Vec::new();
    for (id, status, class, posture, attestation, risk, v4, v6) in device_rows {
        let p: serde_json::Value = posture.unwrap_or_else(|| serde_json::json!({}));
        let attrs = DeviceAttrs {
            status,
            class,
            firewall_enabled: p
                .get("firewall_enabled")
                .and_then(serde_json::Value::as_bool),
            disk_encrypted: p.get("disk_encrypted").and_then(serde_json::Value::as_bool),
            screen_lock_enabled: p
                .get("screen_lock_enabled")
                .and_then(serde_json::Value::as_bool),
            os_version: p
                .get("os_version")
                .and_then(serde_json::Value::as_str)
                .map(|s| s.to_string()),
            last_update_unix: p
                .get("last_update_unix")
                .and_then(serde_json::Value::as_i64),
            attestation,
            risk_score: risk.clamp(0, 100) as u8,
            overlay_v4: v4.and_then(|n: IpNetwork| match n.ip() {
                std::net::IpAddr::V4(v4a) => Some(v4a),
                _ => None,
            }),
            overlay_v6: v6.and_then(|n: IpNetwork| match n.ip() {
                std::net::IpAddr::V6(v6a) => Some(v6a),
                _ => None,
            }),
        };
        devices.push(DeviceEntity {
            id,
            pods: Vec::new(),
            attrs,
        });
    }

    if !devices.is_empty() {
        let device_ids: Vec<Uuid> = devices.iter().map(|d| d.id).collect();
        let memberships: Vec<(Uuid, Uuid)> =
            sqlx::query_as("SELECT device_id, pod_id FROM device_pods WHERE device_id = ANY($1)")
                .bind(&device_ids)
                .fetch_all(&mut *tx)
                .await?;
        let mut map: std::collections::HashMap<Uuid, Vec<Uuid>> = std::collections::HashMap::new();
        for (did, pid) in memberships {
            map.entry(did).or_default().push(pid);
        }
        for d in &mut devices {
            if let Some(pods) = map.get(&d.id) {
                d.pods = pods.clone();
            }
        }
    }

    // Policies - only enabled
    let policy_rows: Vec<(Uuid, String, serde_json::Value)> = sqlx::query_as(
        "SELECT id, name, spec FROM policies WHERE tenant_id = $1 AND enabled = true",
    )
    .bind(tenant)
    .fetch_all(&mut *tx)
    .await?;

    let mut policies = Vec::new();
    for (id, name, spec_val) in policy_rows {
        let spec: Result<PolicySpec, _> = serde_json::from_value(spec_val.clone());
        match spec {
            Ok(s) => {
                if let Err(e) = s.validate() {
                    tracing::warn!(policy_id = %id, error = %e, "skipping invalid policy spec");
                    metrics::counter!("avon_policy_invalid_policies_total").increment(1);
                    continue;
                }
                policies.push(PolicyEntry { id, name, spec: s });
            }
            Err(e) => {
                tracing::warn!(policy_id = %id, error = %e, "skipping policy with invalid JSON");
                metrics::counter!("avon_policy_invalid_policies_total").increment(1);
                continue;
            }
        }
    }

    tx.commit().await?;

    Ok(SnapshotData {
        tenant_id: tenant,
        version: version as u64,
        generated_at: chrono::Utc::now().timestamp(),
        pods,
        device_classes,
        devices,
        policies,
    })
}
