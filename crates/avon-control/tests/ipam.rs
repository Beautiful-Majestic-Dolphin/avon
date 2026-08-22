#![allow(clippy::unwrap_used)]
use avon_control::ipam::allocate;
use avon_testkit::db::TestDb;
use uuid::Uuid;

#[tokio::test(flavor = "multi_thread")]
async fn allocations_are_unique_stable_and_skip_the_gateway_address() {
    let db = TestDb::new().await;
    let tenant = avon_db::DEFAULT_TENANT_ID.into();
    let mut ids = Vec::new();
    for i in 0..20 {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO devices (id, tenant_id, name) VALUES ($1, $2, $3)")
            .bind(id)
            .bind(avon_db::DEFAULT_TENANT_ID)
            .bind(format!("d{i}"))
            .execute(db.pool())
            .await
            .unwrap();
        ids.push(id);
    }
    let mut handles = Vec::new();
    for id in ids.clone() {
        let pool = db.pool().clone();
        handles.push(tokio::spawn(async move {
            let mut tx = pool.begin().await.unwrap();
            let (v4, _v6) = allocate(&mut tx, tenant, id.into()).await.unwrap();
            tx.commit().await.unwrap();
            v4
        }));
    }
    let mut addrs: Vec<_> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();
    addrs.sort();
    addrs.dedup();
    assert_eq!(
        addrs.len(),
        20,
        "every device gets a distinct address even under concurrency"
    );
    assert!(
        addrs
            .iter()
            .all(|a| a.addr() != "100.64.0.1".parse::<std::net::Ipv4Addr>().unwrap()),
        ".1 is reserved for the gateway"
    );
    assert!(addrs.iter().all(|a| a.prefix_len() == 10));
    // Re-allocating for an existing device returns the same address.
    let mut tx = db.pool().begin().await.unwrap();
    let (again, _) = allocate(&mut tx, tenant, ids[0].into()).await.unwrap();
    let (first,): (sqlx::types::ipnetwork::IpNetwork,) =
        sqlx::query_as("SELECT overlay_ipv4 FROM devices WHERE id = $1")
            .bind(ids[0])
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(again.addr().to_string(), first.ip().to_string());
}
