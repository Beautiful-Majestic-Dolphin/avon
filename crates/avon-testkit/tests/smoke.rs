#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use avon_testkit::{db::TestDb, net::free_udp_addr, redis::TestRedis};

#[tokio::test]
async fn each_test_db_is_isolated() {
    let a = TestDb::new().await;
    let b = TestDb::new().await;
    assert_ne!(a.url(), b.url());
    sqlx::query("INSERT INTO pods (tenant_id, name) VALUES ('00000000-0000-0000-0000-000000000001', 'only-in-a')")
        .execute(a.pool()).await.unwrap();
    let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM pods")
        .fetch_one(b.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn redis_is_flushed_per_test() {
    let r = TestRedis::new().await;
    let mut c = r.client().await;
    let _: () = redis::cmd("SET")
        .arg("k")
        .arg("v")
        .query_async(&mut c)
        .await
        .unwrap();
    let r2 = TestRedis::new().await;
    let mut c2 = r2.client().await;
    let v: Option<String> = redis::cmd("GET")
        .arg("k")
        .query_async(&mut c2)
        .await
        .unwrap();
    assert_eq!(v, None);
}

#[test]
fn free_ports_are_distinct() {
    let a = free_udp_addr();
    let b = free_udp_addr();
    assert_ne!(a.port(), 0);
    assert_ne!(a, b);
}
