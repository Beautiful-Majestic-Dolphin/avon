#![allow(clippy::unwrap_used, clippy::panic)]
use avon_policy::db::load_snapshot;
use avon_testkit::db::TestDb;

#[tokio::test]
async fn loads_pods_devices_memberships_and_valid_policies() {
    let db = TestDb::new().await;
    let t = avon_db::DEFAULT_TENANT_ID;
    let (pod,): (uuid::Uuid,) =
        sqlx::query_as("INSERT INTO pods (tenant_id, name) VALUES ($1, 'eng') RETURNING id")
            .bind(t)
            .fetch_one(db.pool())
            .await
            .unwrap();
    let dev = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO devices (id, tenant_id, name, posture, risk_score, overlay_ipv4) VALUES ($1, $2, 'd', '{\"firewall_enabled\": true, \"os_version\": \"14.2\"}', 10, '100.64.0.9/32')")
        .bind(dev)
        .bind(t)
        .execute(db.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO device_pods (device_id, pod_id) VALUES ($1, $2)")
        .bind(dev)
        .bind(pod)
        .execute(db.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO policies (tenant_id, name, spec) VALUES ($1, 'ok', $2), ($1, 'bad', '{\"version\": 9}')")
        .bind(t)
        .bind(serde_json::json!({"version":2,"effect":"allow","source":{"pods":[pod]},"destination":{"any":true}}))
        .execute(db.pool())
        .await
        .unwrap();
    let snap = load_snapshot(db.pool(), t).await.unwrap();
    assert_eq!(snap.pods.len(), 1);
    assert_eq!(snap.devices.len(), 1);
    assert_eq!(snap.devices[0].pods, vec![pod]);
    assert_eq!(snap.devices[0].attrs.firewall_enabled, Some(true));
    assert_eq!(snap.devices[0].attrs.os_version.as_deref(), Some("14.2"));
    assert_eq!(
        snap.devices[0].attrs.overlay_v4.unwrap().to_string(),
        "100.64.0.9"
    );
    assert_eq!(snap.policies.len(), 1, "invalid policy rows are skipped");
    assert!(
        snap.version >= 3,
        "triggers bumped the version for pod, membership and policies"
    );
}
