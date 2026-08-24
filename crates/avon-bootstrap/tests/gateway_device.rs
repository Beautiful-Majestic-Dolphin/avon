#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Regression test for the `devices` row `issue_service_certs()` creates for
//! the gateway service (see `src/lib.rs`), added after fix round 1 of
//! Task 9 shipped that insert with no test coverage at all.
//!
//! Covers exactly the three invariants that are cheap to break silently in a
//! refactor and expensive to get wrong in a zero-trust product:
//!   1. the row lands in the tenant that was passed in, not a hardcoded
//!      default (fix round 2's own regression: `bootstrap certs` briefly did
//!      exactly this);
//!   2. re-inserting the same gateway id does not fail and does not
//!      duplicate the row;
//!   3. only the gateway service gets a device row — `control` does not.
//!
//! Needs a real Postgres (`AVON_TEST_DATABASE_URL`, see
//! `avon_testkit::db::TestDb`); like the rest of this workspace's DB-backed
//! tests, it does not run on a developer machine without one and is expected
//! to run in CI.

use avon_bootstrap::{issue_service_certs, upsert_gateway_device};
use avon_ca::keys::{load_or_init, CaKeys, SealedFileProvider};
use avon_testkit::db::TestDb;
use uuid::Uuid;

async fn keys(db: &TestDb) -> CaKeys {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("m.key");
    SealedFileProvider::generate_master_key(&path).unwrap();
    let provider = SealedFileProvider::from_file(&path).unwrap();
    let keys = load_or_init(db.pool(), &provider, true).await.unwrap();
    std::mem::forget(dir); // keep the temp dir alive for keys' lifetime
    keys
}

/// A tenant other than the seeded `default` one (`avon_db::DEFAULT_TENANT_ID`).
/// Using a *different* tenant, rather than asserting against `default`, is
/// what makes the tenant-scoping assertion below discriminating: a
/// regression back to a hardcoded `DEFAULT_TENANT_ID` would still pass a
/// test that only ever exercised the default tenant.
async fn other_tenant(db: &TestDb) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, 'acme')")
        .bind(id)
        .execute(db.pool())
        .await
        .unwrap();
    id
}

#[tokio::test]
async fn gateway_device_row_is_tenant_scoped_idempotent_and_gateway_only() {
    let db = TestDb::new().await;
    let keys = keys(&db).await;
    let out = tempfile::tempdir().unwrap();
    let tenant_id = other_tenant(&db).await;

    // --- (1) tenant scoping + (3) gateway-only, in one pass -------------
    // Two services, only one of which should ever get a devices row.
    issue_service_certs(
        db.pool(),
        &keys,
        out.path(),
        &["control".to_string(), "gateway".to_string()],
        &[],
        tenant_id,
    )
    .await
    .expect("issue_service_certs");

    let rows: Vec<(Uuid, String, Uuid)> =
        sqlx::query_as("SELECT id, kind::text, tenant_id FROM devices")
            .fetch_all(db.pool())
            .await
            .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "only the gateway service should get a devices row, control should not: {rows:?}"
    );
    let (gateway_device_id, kind, row_tenant) = rows[0].clone();
    assert_eq!(kind, "gateway");
    assert_eq!(
        row_tenant, tenant_id,
        "the gateway's devices row must land in the tenant that was passed in \
         (mutation check: reverting the insert to a hardcoded DEFAULT_TENANT_ID \
         must fail this assertion)"
    );

    // --- (2) idempotent: re-inserting the same id must not fail or duplicate
    upsert_gateway_device(db.pool(), gateway_device_id, tenant_id, "gateway")
        .await
        .expect("re-inserting the same gateway device id must not fail");

    let count: (i64,) = sqlx::query_as("SELECT count(*) FROM devices WHERE kind = 'gateway'")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(
        count.0, 1,
        "re-inserting the same gateway device id must not create a second row"
    );
}
