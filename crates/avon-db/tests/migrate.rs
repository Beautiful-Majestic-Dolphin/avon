#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use avon_db::{begin_tenant, DEFAULT_TENANT_ID};
use avon_testkit::db::TestDb;
use uuid::Uuid;

#[tokio::test]
async fn migrations_apply_and_default_tenant_exists() {
    let db = TestDb::new().await;
    let (name,): (String,) = sqlx::query_as("SELECT name FROM tenants WHERE id = $1")
        .bind(DEFAULT_TENANT_ID)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(name, "default");
}

#[tokio::test]
async fn policy_snapshot_version_bumps_on_policy_insert() {
    let db = TestDb::new().await;
    let before: (i64,) =
        sqlx::query_as("SELECT version FROM policy_snapshots WHERE tenant_id = $1")
            .bind(DEFAULT_TENANT_ID)
            .fetch_one(db.pool())
            .await
            .unwrap();
    sqlx::query(
        "INSERT INTO policies (tenant_id, name, spec) VALUES ($1, 'p1', '{\"version\":2}')",
    )
    .bind(DEFAULT_TENANT_ID)
    .execute(db.pool())
    .await
    .unwrap();
    let after: (i64,) = sqlx::query_as("SELECT version FROM policy_snapshots WHERE tenant_id = $1")
        .bind(DEFAULT_TENANT_ID)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(after.0, before.0 + 1);
}

#[tokio::test]
async fn row_level_security_isolates_tenants() {
    let db = TestDb::new().await;
    // A non-superuser role subject to RLS.
    let role = format!("rls_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE ROLE {role} LOGIN PASSWORD 'pw'"))
        .execute(db.pool())
        .await
        .unwrap();
    sqlx::query(&format!(
        "GRANT ALL ON ALL TABLES IN SCHEMA public TO {role}"
    ))
    .execute(db.pool())
    .await
    .unwrap();
    sqlx::query(&format!(
        "GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {role}"
    ))
    .execute(db.pool())
    .await
    .unwrap();

    let other_tenant = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, 'other')")
        .bind(other_tenant)
        .execute(db.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO pods (tenant_id, name) VALUES ($1, 'default-pod'), ($2, 'other-pod')")
        .bind(DEFAULT_TENANT_ID)
        .bind(other_tenant)
        .execute(db.pool())
        .await
        .unwrap();

    let scoped = db.pool_as(&role, "pw").await;
    let mut tx = begin_tenant(&scoped, DEFAULT_TENANT_ID).await.unwrap();
    let names: Vec<(String,)> = sqlx::query_as("SELECT name FROM pods ORDER BY name")
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    assert_eq!(names, vec![("default-pod".to_string(),)]);

    // Writing into another tenant is rejected by the WITH CHECK clause.
    let err = sqlx::query("INSERT INTO pods (tenant_id, name) VALUES ($1, 'smuggled')")
        .bind(other_tenant)
        .execute(&mut *tx)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("row-level security"), "{err}");
    tx.rollback().await.unwrap();
}
