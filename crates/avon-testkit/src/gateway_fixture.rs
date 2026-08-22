//! A gateway running in-process against a `ControlFixture`, with an in-memory
//! TUN instead of a kernel device. It goes through the same
//! [`avon_gateway::GatewayState::bootstrap`] the binary does, so the tests
//! exercise the shipped startup path.

use std::sync::Arc;

use avon_gateway::config::GatewayConfig;
use avon_gateway::state::GatewayState;
use avon_gateway::{control_link, dataplane, AllowAll};
use avon_tunnel::{PacketSink, PacketSource};
use ipnet::IpNet;

use crate::gateway::TestGateway;
use crate::memtun::MemoryTun;
use crate::net::free_udp_addr;
use crate::services::ControlFixture;

pub struct GatewayFixture {
    pub gateway: TestGateway,
    pub state: Arc<GatewayState>,
    pub udp_addr: std::net::SocketAddr,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
    _dir: tempfile::TempDir,
}

impl GatewayFixture {
    pub fn sessions(&self) -> usize {
        self.state.table.len()
    }

    /// A counter's value, for asserting *why* a packet was dropped.
    pub fn metric(&self, name: &str, labels: &[(&str, &str)]) -> u64 {
        crate::metrics::counter(name, labels)
    }

    /// Wait until the gateway has `n` sessions, or give up after ~2 s.
    pub async fn wait_for_sessions(&self, n: usize) -> bool {
        for _ in 0..200 {
            if self.state.table.len() >= n {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        false
    }
}

/// Enrol a gateway identity, wire it to `f`, and run its control link and data
/// plane against `tun`.
pub async fn spawn_gateway(
    f: &ControlFixture,
    tun: Arc<MemoryTun>,
    protected: Vec<IpNet>,
) -> GatewayFixture {
    crate::metrics::install();
    let gateway = TestGateway::enroll(f).await;
    let dir = tempfile::tempdir().expect("gateway dir");

    // The identity `avon-bootstrap` would have written.
    std::fs::write(
        dir.path().join("gateway.avon.crt"),
        gateway.certificate.encode(),
    )
    .expect("write cert");
    std::fs::write(
        dir.path().join("gateway.avon.key"),
        gateway.signing.to_secret_bytes(),
    )
    .expect("write signing key");
    let tls_cert = dir.path().join("gateway.tls.crt");
    let tls_key = dir.path().join("gateway.tls.key");
    std::fs::write(&tls_cert, &gateway.tls_cert_pem).expect("write tls cert");
    std::fs::write(&tls_key, &gateway.tls_key_pem).expect("write tls key");

    let udp_addr = free_udp_addr();
    let cfg = GatewayConfig {
        tls: avon_config::TlsArgs {
            cert: tls_cert,
            key: tls_key,
            ca: f.trust_bundle(),
        },
        observability: observability_args(),
        control_url: format!("https://localhost:{}", f.control.addr.port()),
        control_server_name: "localhost".into(),
        listen_udp: udp_addr,
        public_endpoint: udp_addr.to_string(),
        region: "default".into(),
        capacity: 100,
        protected_cidrs: protected,
        overlay_prefixes: ["100.64.0.0/10", "fd00:a70::/48"]
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect(),
        tun_name: "memtun".into(),
        overlay_mtu: 1380,
        identity_dir: dir.path().to_path_buf(),
        redis_url: None,
        redis_tls_ca: None,
        keepalive_secs: 15,
        rekey_secs: 3600,
        idle_timeout_secs: 300,
    };

    let (state, events) = GatewayState::bootstrap(&cfg, Arc::new(AllowAll))
        .await
        .expect("gateway bootstrap");

    let sink: Arc<dyn PacketSink> = tun.clone();
    let source: Arc<dyn PacketSource> = tun;
    let dp_state = state.clone();
    let data = tokio::spawn(async move {
        let _ = dataplane::run_dataplane(dp_state, events, sink, source).await;
    });
    let link_state = state.clone();
    let link_cfg = cfg.clone();
    let link = tokio::spawn(async move {
        let _ = control_link::run_control_link(link_state, link_cfg).await;
    });

    // The link must be registered before a test opens a session, or control
    // answers `unavailable`.
    for _ in 0..200 {
        if state.up.read().await.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    GatewayFixture {
        gateway,
        state,
        udp_addr,
        _tasks: vec![data, link],
        _dir: dir,
    }
}

fn observability_args() -> avon_config::ObservabilityArgs {
    // Health and metrics listeners are not started by the fixture; the
    // addresses are only here because the config type requires them.
    avon_config::ObservabilityArgs {
        log_level: "debug".into(),
        log_format: avon_config::LogFormat::Text,
        health_addr: "127.0.0.1:0".parse().expect("health addr"),
        metrics_addr: "127.0.0.1:0".parse().expect("metrics addr"),
    }
}
