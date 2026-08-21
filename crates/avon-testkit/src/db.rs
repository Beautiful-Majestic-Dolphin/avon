use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool};
use uuid::Uuid;

/// A freshly created, fully migrated database that is dropped when the
/// handle is dropped.
pub struct TestDb {
    admin_url: String,
    name: String,
    url: String,
    pool: PgPool,
}

fn admin_url() -> String {
    std::env::var("AVON_TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://avon:test@localhost:5432/postgres".to_string())
}

impl TestDb {
    pub async fn new() -> Self {
        let admin_url = admin_url();
        let name = format!("avon_test_{}", Uuid::new_v4().simple());
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await
            .expect("connect to AVON_TEST_DATABASE_URL");
        admin
            .execute(format!("CREATE DATABASE {name}").as_str())
            .await
            .expect("create test db");
        let mut url = url::Url::parse(&admin_url).expect("valid admin url");
        url.set_path(&format!("/{name}"));
        let url = url.to_string();
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("connect test db");
        avon_db::migrate(&pool).await.expect("migrate test db");
        Self {
            admin_url,
            name,
            url,
            pool,
        }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Connect to the same database as a different role (for RLS tests).
    pub async fn pool_as(&self, user: &str, password: &str) -> PgPool {
        let mut url = url::Url::parse(&self.url).unwrap();
        url.set_username(user).unwrap();
        url.set_password(Some(password)).unwrap();
        PgPoolOptions::new()
            .max_connections(2)
            .connect(url.as_str())
            .await
            .expect("connect as role")
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let admin_url = self.admin_url.clone();
        let name = self.name.clone();
        self.pool.close_event();
        let handle = tokio::runtime::Handle::try_current();
        if let Ok(handle) = handle {
            handle.spawn(async move {
                if let Ok(admin) = PgPoolOptions::new()
                    .max_connections(1)
                    .connect(&admin_url)
                    .await
                {
                    let _ = admin
                        .execute(format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)").as_str())
                        .await;
                }
            });
        }
    }
}
