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

/// Probe a locally running AVON service's `/health` endpoint by speaking raw
/// HTTP/1.1 over `std::net`, with no shell and no HTTP client crate involved.
///
/// `ca`, `control` and `gateway` ship on
/// `gcr.io/distroless/cc-debian12:nonroot`, which has no shell and no
/// `wget`/`curl` — the only executable Docker's `HEALTHCHECK` can invoke
/// inside those containers is the service binary itself. This is that
/// self-probe: it is meant to be called from each binary's `main` when
/// invoked as `avon health-check`.
///
/// Reads `AVON_HEALTH_ADDR` (the same variable `serve_health` binds to,
/// falling back to `0.0.0.0:8080` if unset) only to discover the port; it
/// always dials `127.0.0.1`, since a healthcheck always runs inside the same
/// container/network-namespace as the service it is checking.
pub fn health_probe_from_env() -> std::process::ExitCode {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::process::ExitCode;
    use std::time::Duration;

    let addr_var = std::env::var("AVON_HEALTH_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let port: u16 = addr_var
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let target = SocketAddr::from(([127, 0, 0, 1], port));
    let timeout = Duration::from_secs(2);

    let mut stream = match TcpStream::connect_timeout(&target, timeout) {
        Ok(s) => s,
        Err(_) => return ExitCode::FAILURE,
    };
    if stream.set_read_timeout(Some(timeout)).is_err()
        || stream.set_write_timeout(Some(timeout)).is_err()
    {
        return ExitCode::FAILURE;
    }

    // `/health` (not `/healthz`) is what `serve_health` above actually
    // routes; see its `Router::new().route("/health", ...)`.
    let request = b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    if stream.write_all(request).is_err() {
        return ExitCode::FAILURE;
    }

    let mut response = Vec::new();
    let read_result = stream.read_to_end(&mut response);
    if read_result.is_err() && response.is_empty() {
        return ExitCode::FAILURE;
    }

    let status_line = response
        .split(|&b| b == b'\n')
        .next()
        .map(|line| String::from_utf8_lossy(line).into_owned())
        .unwrap_or_default();
    let is_2xx = status_line
        .split_whitespace()
        .nth(1)
        .map(|code| code.starts_with('2'))
        .unwrap_or(false);

    if is_2xx {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod probe_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::process::ExitCode;
    use std::sync::{Mutex, OnceLock};

    /// `AVON_HEALTH_ADDR` is process-wide state; serialize the tests that
    /// set it so they cannot race each other.
    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn probe_reports_success_for_2xx_response() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        std::env::set_var("AVON_HEALTH_ADDR", format!("0.0.0.0:{port}"));

        let server = std::thread::spawn(move || {
            if let Ok((mut socket, _)) = listener.accept() {
                let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            }
        });

        let code = health_probe_from_env();
        server.join().expect("server thread panicked");
        std::env::remove_var("AVON_HEALTH_ADDR");

        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn probe_reports_failure_when_nothing_is_listening() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        // Bind then drop, so we have a port we know nothing is listening on.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);
        std::env::set_var("AVON_HEALTH_ADDR", format!("0.0.0.0:{port}"));

        let code = health_probe_from_env();
        std::env::remove_var("AVON_HEALTH_ADDR");

        assert_eq!(code, ExitCode::FAILURE);
    }
}
