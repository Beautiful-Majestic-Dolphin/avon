use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use serde_json::json;

use crate::ObservabilityError;

/// Aggregates named readiness flags. Clone is cheap (Arc).
#[derive(Clone, Default)]
pub struct Readiness {
    flags: Arc<Mutex<BTreeMap<&'static str, Arc<AtomicBool>>>>,
}

#[derive(Clone)]
pub struct ReadyFlag(Arc<AtomicBool>);

impl ReadyFlag {
    pub fn set(&self, ready: bool) {
        self.0.store(ready, Ordering::SeqCst);
    }
}

impl Readiness {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, name: &'static str) -> ReadyFlag {
        let flag = Arc::new(AtomicBool::new(false));
        if let Ok(mut flags) = self.flags.lock() {
            flags.insert(name, flag.clone());
        }
        ReadyFlag(flag)
    }

    pub fn report(&self) -> Vec<(&'static str, bool)> {
        match self.flags.lock() {
            Ok(flags) => flags
                .iter()
                .map(|(k, v)| (*k, v.load(Ordering::SeqCst)))
                .collect(),
            Err(_) => vec![("readiness-lock", false)],
        }
    }

    pub fn is_ready(&self) -> bool {
        let report = self.report();
        !report.is_empty() && report.iter().all(|(_, ok)| *ok)
    }
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

async fn ready(State(readiness): State<Readiness>) -> (StatusCode, Json<serde_json::Value>) {
    let checks: serde_json::Map<String, serde_json::Value> = readiness
        .report()
        .into_iter()
        .map(|(k, v)| (k.to_string(), json!(v)))
        .collect();
    let ok = readiness.is_ready();
    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(json!({ "ready": ok, "checks": checks })))
}

/// Serve `/health` and `/ready` until `shutdown` resolves.
pub async fn serve_health(
    addr: SocketAddr,
    readiness: Readiness,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), ObservabilityError> {
    let app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .with_state(readiness);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

/// gRPC health service (grpc.health.v1) for Kubernetes gRPC probes.
pub struct GrpcHealth {
    pub reporter: tonic_health::server::HealthReporter,
    pub service: tonic_health::pb::health_server::HealthServer<tonic_health::server::HealthService>,
}

pub fn grpc_health() -> GrpcHealth {
    let (reporter, _) = tonic_health::server::health_reporter();
    let service_impl = tonic_health::server::HealthService::from_health_reporter(reporter.clone());
    let service = tonic_health::pb::health_server::HealthServer::new(service_impl);
    GrpcHealth { reporter, service }
}
