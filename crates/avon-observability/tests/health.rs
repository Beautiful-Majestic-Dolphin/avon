#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::time::Duration;

use avon_observability::{serve_health, Readiness};
use avon_testkit::net::free_tcp_addr;

#[tokio::test]
async fn ready_is_503_until_all_flags_set() {
    let addr = free_tcp_addr();
    let readiness = Readiness::new();
    let db = readiness.register("database");
    let redis = readiness.register("redis");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve_health(addr, readiness.clone(), async {
        let _ = rx.await;
    }));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let health = client
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);

    let ready = client
        .get(format!("http://{addr}/ready"))
        .send()
        .await
        .unwrap();
    assert_eq!(ready.status(), 503);
    let body: serde_json::Value = ready.json().await.unwrap();
    assert_eq!(body["checks"]["database"], false);

    db.set(true);
    redis.set(true);
    let ready = client
        .get(format!("http://{addr}/ready"))
        .send()
        .await
        .unwrap();
    assert_eq!(ready.status(), 200);

    redis.set(false);
    let ready = client
        .get(format!("http://{addr}/ready"))
        .send()
        .await
        .unwrap();
    assert_eq!(ready.status(), 503);

    tx.send(()).unwrap();
    server.await.unwrap().unwrap();
}
