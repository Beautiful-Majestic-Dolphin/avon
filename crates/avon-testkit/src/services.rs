//! In-process launchers for AVON services, wired to the test PKI.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use avon_protocol::v2::ca_service_client::CaServiceClient;
use tonic::transport::{Channel, Endpoint};

use crate::db::TestDb;
use crate::net::free_tcp_addr;
use crate::pki::TestPki;

pub struct SpawnedService {
    pub addr: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl SpawnedService {
    pub fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

pub async fn spawn_ca(db: &TestDb, pki: &TestPki, dir: &Path) -> SpawnedService {
    use avon_ca::keys::{load_or_init, SealedFileProvider};
    use avon_ca::service::CaService;
    use avon_protocol::v2::ca_service_server::CaServiceServer;

    let master = dir.join("ca-master.key");
    if !master.exists() {
        SealedFileProvider::generate_master_key(&master).expect("master key");
    }
    let provider = SealedFileProvider::from_file(&master).expect("provider");
    let keys = Arc::new(
        load_or_init(db.pool(), &provider, true)
            .await
            .expect("ca keys"),
    );
    let tls = pki.write_to(dir, "ca", "spiffe://avon/service/ca", &["localhost"]);
    let addr = free_tcp_addr();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let svc = CaService {
        pool: db.pool().clone(),
        keys,
        device_lifetime_secs: 86_400,
    };
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .tls_config(avon_tls::server_tls_config(&tls).expect("tls"))
            .expect("tls cfg")
            .add_service(CaServiceServer::new(svc))
            .serve_with_shutdown(addr, async {
                let _ = rx.await;
            })
            .await
            .expect("ca server");
    });
    wait_for_port(addr).await;
    SpawnedService {
        addr,
        shutdown: Some(tx),
    }
}

pub async fn ca_client(
    pki: &TestPki,
    dir: &Path,
    addr: SocketAddr,
    as_spiffe: &str,
) -> CaServiceClient<Channel> {
    let name = as_spiffe.replace(['/', ':'], "_");
    let tls = pki.write_to(dir, &name, as_spiffe, &[]);
    let channel = Endpoint::from_shared(format!("https://localhost:{}", addr.port()))
        .expect("endpoint")
        .tls_config(avon_tls::client_tls_config(&tls, "localhost").expect("client tls"))
        .expect("tls")
        .connect()
        .await
        .expect("connect");
    CaServiceClient::new(channel)
}

pub async fn wait_for_port(addr: SocketAddr) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("service at {addr} did not start");
}

// ---------------------------------------------------------------- control

/// Captures tracing output so tests can assert on what was (not) logged.
pub struct LogCapture {
    buf: std::sync::Mutex<Vec<u8>>,
}

impl LogCapture {
    pub fn contents(&self) -> String {
        String::from_utf8_lossy(&self.buf.lock().expect("log lock")).into_owned()
    }
}

/// `MakeWriter` needs an owned `io::Write`; `Arc<LogCapture>` cannot implement
/// it directly (orphan rule), so writes go through this handle.
#[derive(Clone)]
pub struct LogWriter(std::sync::Arc<LogCapture>);

impl std::io::Write for LogWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.buf.lock().expect("log lock").extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct ControlFixture {
    pub db: TestDb,
    pub pki: TestPki,
    pub dir: tempfile::TempDir,
    pub ca: SpawnedService,
    pub control: SpawnedService,
    pub redis: crate::redis::TestRedis,
    state: std::sync::Arc<avon_control::service::AppState>,
    logs: std::sync::Arc<LogCapture>,
}

impl ControlFixture {
    pub fn capture_logs(&self) -> std::sync::Arc<LogCapture> {
        self.logs.clone()
    }
    pub fn state(&self) -> std::sync::Arc<avon_control::service::AppState> {
        self.state.clone()
    }
    pub fn issuing_cert(&self) -> avon_crypto::cert::Certificate {
        // Cheap enough for tests; avoids holding the read guard across awaits.
        futures_lite_block(async {
            let chain = self.state.chain.read().await;
            chain.issuing.clone()
        })
    }
    /// The PEM bundle a client should trust to reach control.
    pub fn trust_bundle(&self) -> std::path::PathBuf {
        self.dir.path().join("client-trust.crt")
    }
}

fn futures_lite_block<F: std::future::Future>(f: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
}

pub async fn spawn_control(
    db: TestDb,
    pki: TestPki,
    dir: tempfile::TempDir,
    ca: SpawnedService,
) -> ControlFixture {
    use avon_control::service::agent::AgentServiceImpl;
    use avon_control::service::gateway::GatewayServiceImpl;
    use avon_control::service::AppState;
    use avon_protocol::v2::agent_service_server::AgentServiceServer;
    use avon_protocol::v2::gateway_service_server::GatewayServiceServer;

    static LOGS: std::sync::OnceLock<std::sync::Arc<LogCapture>> = std::sync::OnceLock::new();
    let logs = LOGS
        .get_or_init(|| {
            let cap = std::sync::Arc::new(LogCapture {
                buf: std::sync::Mutex::new(Vec::new()),
            });
            let writer = cap.clone();
            let _ = tracing_subscriber::fmt()
                .with_writer(move || LogWriter(writer.clone()))
                .with_max_level(tracing::Level::DEBUG)
                .try_init();
            cap
        })
        .clone();

    let redis = crate::redis::TestRedis::new().await;
    let control_tls = pki.write_to(
        dir.path(),
        "control",
        "spiffe://avon/service/control",
        &["localhost"],
    );
    let ca_client = avon_control::ca_client::CaClient::connect(
        &format!("https://localhost:{}", ca.addr.port()),
        "localhost",
        &control_tls,
    )
    .await
    .expect("ca client");

    // Devices present certificates signed by the CA's TLS sub-CA; services
    // present certificates signed by the test PKI. Control must trust both.
    let chain = ca_client.chain().await.expect("chain");
    let bundle_path = dir.path().join("client-trust.crt");
    std::fs::write(
        &bundle_path,
        format!("{}{}", pki.tls_ca_pem, chain.tls_ca_pem),
    )
    .expect("write bundle");
    let server_tls_args = avon_config::TlsArgs {
        cert: control_tls.cert.clone(),
        key: control_tls.key.clone(),
        ca: bundle_path,
    };

    let state = AppState::new(
        db.pool().clone(),
        redis.client().await,
        ca_client,
        control_tls.clone(),
        86_400,
        30,
    )
    .await
    .expect("state");
    let addr = free_tcp_addr();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let server_tls = avon_tls::server_tls_config_optional_client(&server_tls_args).expect("tls");
    let agent_state = state.clone();
    let gateway_state = state.clone();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .tls_config(server_tls)
            .expect("tls cfg")
            .add_service(AgentServiceServer::new(AgentServiceImpl::new(agent_state)))
            .add_service(GatewayServiceServer::new(GatewayServiceImpl::new(
                gateway_state,
            )))
            .serve_with_shutdown(addr, async {
                let _ = rx.await;
            })
            .await
            .expect("control server");
    });
    wait_for_port(addr).await;
    ControlFixture {
        db,
        pki,
        dir,
        ca,
        control: SpawnedService {
            addr,
            shutdown: Some(tx),
        },
        redis,
        state,
        logs,
    }
}

fn control_endpoint(f: &ControlFixture) -> Endpoint {
    Endpoint::from_shared(format!("https://localhost:{}", f.control.addr.port())).expect("endpoint")
}

pub async fn agent_client_anonymous(
    f: &ControlFixture,
) -> avon_protocol::v2::agent_service_client::AgentServiceClient<Channel> {
    let ca = std::fs::read(f.trust_bundle()).expect("ca");
    let channel = control_endpoint(f)
        .tls_config(
            tonic::transport::ClientTlsConfig::new()
                .domain_name("localhost")
                .ca_certificate(tonic::transport::Certificate::from_pem(ca)),
        )
        .expect("tls")
        .connect()
        .await
        .expect("connect");
    avon_protocol::v2::agent_service_client::AgentServiceClient::new(channel)
}

pub async fn agent_client_as_device(
    f: &ControlFixture,
    cert_pem: &str,
    key_pem: &str,
) -> avon_protocol::v2::agent_service_client::AgentServiceClient<Channel> {
    avon_protocol::v2::agent_service_client::AgentServiceClient::new(
        device_channel(f, cert_pem, key_pem).await,
    )
}

pub async fn device_channel(f: &ControlFixture, cert_pem: &str, key_pem: &str) -> Channel {
    let ca = std::fs::read(f.trust_bundle()).expect("ca");
    control_endpoint(f)
        .tls_config(
            tonic::transport::ClientTlsConfig::new()
                .domain_name("localhost")
                .ca_certificate(tonic::transport::Certificate::from_pem(ca))
                .identity(tonic::transport::Identity::from_pem(cert_pem, key_pem)),
        )
        .expect("tls")
        .connect()
        .await
        .expect("connect")
}
