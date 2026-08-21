use redis::aio::ConnectionManager;
use std::sync::atomic::{AtomicU8, Ordering};

static NEXT_DB: AtomicU8 = AtomicU8::new(1);

/// A Redis logical database (1..=15) that is flushed on creation. Tests that
/// need more than 15 concurrent Redis users should serialize themselves.
pub struct TestRedis {
    url: String,
}

impl TestRedis {
    pub async fn new() -> Self {
        let base = std::env::var("AVON_TEST_REDIS_URL")
            .unwrap_or_else(|_| "redis://localhost:6379".to_string());
        let db = (NEXT_DB.fetch_add(1, Ordering::SeqCst) % 15) + 1;
        let url = format!("{}/{db}", base.trim_end_matches('/'));
        let client = redis::Client::open(url.clone()).expect("redis url");
        let mut conn = ConnectionManager::new(client).await.expect("redis connect");
        let _: () = redis::cmd("FLUSHDB")
            .query_async(&mut conn)
            .await
            .expect("flushdb");
        Self { url }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub async fn client(&self) -> ConnectionManager {
        let client = redis::Client::open(self.url.clone()).expect("redis url");
        ConnectionManager::new(client).await.expect("redis connect")
    }
}
