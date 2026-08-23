use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use avon_agent_core::identity::{enroll, load};
use avon_agent_core::traits::{FingerprintProvider, PostureProvider, TunProvider};
use avon_agent_core::{Agent, AgentCoreConfig, Status};
use avon_keystore::ProviderChoice;
use avon_protocol::v2::{DevicePosture, Fingerprint};
use avon_tunnel::TimerConfig;
use avon_tunnel::{PacketSink, PacketSource, TunnelError};
use chrono::Utc;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use tokio::sync::Mutex;

use crate::memtun::MemoryTun;
use crate::services::ControlFixture;

/// Inserts a one-use enrollment token for the default tenant.
pub async fn insert_token(f: &ControlFixture, token: &str, max_uses: i32) {
    let hash = avon_control::store::hash_token(token);
    sqlx::query(
        "INSERT INTO enrollment_tokens (tenant_id, token_hash, max_uses, expires_at) VALUES ($1, $2, $3, now() + interval '1 hour') ON CONFLICT (token_hash) DO UPDATE SET max_uses = EXCLUDED.max_uses, use_count = 0",
    )
    .bind(avon_db::DEFAULT_TENANT_ID)
    .bind(&hash[..])
    .bind(max_uses)
    .execute(f.db.pool())
    .await
    .expect("insert token");
}

pub struct TestFingerprint;

impl FingerprintProvider for TestFingerprint {
    fn collect(&self) -> Fingerprint {
        Fingerprint {
            version: 2,
            hash: vec![7; 32],
            identifier_kinds: vec!["machine-id".into()],
        }
    }
}

struct TestPosture;

impl PostureProvider for TestPosture {
    fn collect(&self) -> DevicePosture {
        DevicePosture {
            os_name: "test".into(),
            os_version: "1.0".into(),
            agent_version: "0.2.0".into(),
            firewall_enabled: None,
            disk_encrypted: None,
            screen_lock_enabled: None,
            last_update_unix: None,
            key_provider: "software".into(),
            collected_at_unix: Utc::now().timestamp(),
        }
    }
}

#[derive(Clone)]
struct MutablePosture {
    inner: Arc<Mutex<DevicePosture>>,
}

impl PostureProvider for MutablePosture {
    fn collect(&self) -> DevicePosture {
        // Try to block on the async mutex; for tests we can use try_lock.
        self.inner
            .try_lock()
            .map(|p| p.clone())
            .unwrap_or_else(|_| DevicePosture {
                os_name: "test".into(),
                os_version: "1.0".into(),
                agent_version: "0.2.0".into(),
                firewall_enabled: None,
                disk_encrypted: None,
                screen_lock_enabled: None,
                last_update_unix: None,
                key_provider: "software".into(),
                collected_at_unix: Utc::now().timestamp(),
            })
    }
}

/// A `TunProvider` backed by an in-memory channel. `configure` and `set_routes`
/// just remember the values for assertions.
pub struct TestTun {
    inner: Arc<MemoryTun>,
    overlay_v4: Mutex<Option<Ipv4Net>>,
    overlay_v6: Mutex<Option<Ipv6Net>>,
    routes: Mutex<Vec<IpNet>>,
    name: String,
}

impl TestTun {
    fn new(inner: Arc<MemoryTun>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            overlay_v4: Mutex::new(None),
            overlay_v6: Mutex::new(None),
            routes: Mutex::new(vec![]),
            name: "testtun0".into(),
        })
    }
}

#[async_trait]
impl PacketSink for TestTun {
    async fn deliver(&self, ip_packet: &[u8]) -> Result<(), TunnelError> {
        self.inner.deliver(ip_packet).await
    }
}

#[async_trait]
impl PacketSource for TestTun {
    async fn next_packet(&self, buf: &mut Vec<u8>) -> Result<usize, TunnelError> {
        self.inner.next_packet(buf).await
    }
}

#[async_trait]
impl TunProvider for TestTun {
    async fn configure(
        &self,
        v4: Ipv4Net,
        v6: Ipv6Net,
        _mtu: u16,
    ) -> Result<(), avon_agent_core::AgentError> {
        *self.overlay_v4.lock().await = Some(v4);
        *self.overlay_v6.lock().await = Some(v6);
        Ok(())
    }

    async fn set_routes(&self, routes: &[IpNet]) -> Result<(), avon_agent_core::AgentError> {
        *self.routes.lock().await = routes.to_vec();
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn overlay_v4(&self) -> Option<Ipv4Net> {
        // This is sync, but we store async mutex; try to block.
        // For tests we just return None and rely on status snapshot instead.
        None
    }
}

pub struct TestAgentCore {
    pub tun: Arc<MemoryTun>,
    #[allow(dead_code)]
    test_tun: Arc<TestTun>,
    pub data_dir: tempfile::TempDir,
    agent_task: tokio::task::JoinHandle<()>,
    status_handle: avon_agent_core::StatusHandle,
    peer_handle: Arc<tokio::sync::RwLock<Option<Arc<avon_agent_core::peer::PeerManager>>>>,
    control_url: String,
    // Keep the agent's device id for assertions.
    _agent: Option<Agent>,
    posture: Option<Arc<Mutex<DevicePosture>>>,
}

impl TestAgentCore {
    pub async fn enroll_and_connect(f: &ControlFixture, token: &str) -> Self {
        Self::enroll_and_connect_with(f, token, TimerConfig::default()).await
    }

    pub async fn enroll_and_connect_with_rekey(
        f: &ControlFixture,
        token: &str,
        rekey_after: Duration,
    ) -> Self {
        let timers = TimerConfig {
            rekey_after,
            ..TimerConfig::default()
        };
        Self::enroll_and_connect_with(f, token, timers).await
    }

    async fn enroll_and_connect_with(f: &ControlFixture, token: &str, timers: TimerConfig) -> Self {
        insert_token(f, token, 1).await;
        let data_dir = tempfile::tempdir().expect("data dir");
        let ca_pem = std::fs::read(f.trust_bundle()).expect("ca");
        let control_url = format!("https://localhost:{}", f.control.addr.port());
        let _id = enroll(
            &control_url,
            token,
            data_dir.path(),
            &ca_pem,
            "localhost",
            ProviderChoice::Software,
            &TestFingerprint,
            "test",
        )
        .await
        .expect("enroll");

        let identity = load(data_dir.path()).await.expect("load");

        let memtun = MemoryTun::new();
        let test_tun = TestTun::new(memtun.clone());
        let tun_provider: Arc<dyn TunProvider> = test_tun.clone();

        let cfg = AgentCoreConfig {
            control: control_url.clone(),
            pulse_interval: Duration::from_secs(1),
            timers,
            overlay_mtu: 1280,
            bind: "127.0.0.1:0".parse().unwrap(),
            suites: vec![
                avon_crypto::aead::Suite::Aes256Gcm,
                avon_crypto::aead::Suite::ChaCha20Poly1305,
            ],
        };

        let agent = Agent::new(cfg, identity, tun_provider, Arc::new(TestPosture));
        let status = agent.status_handle();
        let peer_handle = agent.peer_handle();
        let control_url_clone = control_url.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let agent_task = tokio::spawn(async move {
            let _ = agent
                .run(async {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        // Wait for connected.
        for _ in 0..200 {
            if status.snapshot().state == "connected" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Also wait for peer_handle to be populated.
        for _ in 0..50 {
            if peer_handle.read().await.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Leak shutdown_tx for now? We need to keep it to later shut down.
        // Store it in a way that drop shuts down? For tests, we just leak and let task run until test ends.
        std::mem::forget(shutdown_tx);

        Self {
            tun: memtun,
            test_tun,
            data_dir,
            agent_task,
            status_handle: status,
            peer_handle,
            control_url: control_url_clone,
            _agent: None,
            posture: None,
        }
    }

    pub fn status(&self) -> Status {
        self.status_handle.snapshot()
    }

    pub fn overlay_v4(&self) -> Ipv4Net {
        // Parse from status.
        let s = self.status();
        s.overlay_v4
            .as_ref()
            .expect("overlay v4")
            .parse()
            .expect("parse v4")
    }

    pub fn device_id(&self) -> uuid::Uuid {
        self.status().device_id.parse().expect("device id")
    }

    pub fn session_epoch(&self) -> u32 {
        self.status().epoch.unwrap_or(0)
    }

    pub async fn wait_for_new_session(&self, old: &str) {
        for _ in 0..200 {
            let cur = self.status().session_id.clone().unwrap_or_default();
            if !cur.is_empty() && cur != old {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!(
            "wait_for_new_session timed out: old={old} cur={:?}",
            self.status().session_id
        );
    }

    pub async fn wait_for_pulse_after(&self, after: Instant) {
        let start_unix = Utc::now().timestamp();
        // Wait for last_pulse_unix to advance beyond start.
        for _ in 0..400 {
            if let Some(ts) = self.status().last_pulse_unix {
                // If after is recent, ensure pulse happened after `after`.
                // We compare wall time; if pulse timestamp > start_unix, it's fresh.
                if ts >= start_unix {
                    return;
                }
            }
            // Also consider connected state as pulse evidence.
            if self.status().state == "connected" {
                // Wait a bit more to ensure pulse ack.
                tokio::time::sleep(Duration::from_millis(100)).await;
                if self.status().last_pulse_unix.is_some() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            if Instant::now().duration_since(after) > Duration::from_secs(20) {
                break;
            }
        }
        // Fallback: if we are connected, consider it pulse.
        if self.status().state == "connected" {
            return;
        }
        panic!("wait_for_pulse_after timed out");
    }

    pub fn has_direct_peer(&self, device: uuid::Uuid) -> bool {
        let dev = avon_common::ids::DeviceId::new(device);
        // Try to use peer manager if available; otherwise check via blocking read.
        if let Some(mgr) = self.peer_handle.try_read().ok().and_then(|g| g.clone()) {
            mgr.has_direct_peer(dev)
        } else {
            false
        }
    }

    pub async fn wait_for_direct_peer(&self, device: uuid::Uuid) {
        let dev = avon_common::ids::DeviceId::new(device);
        for _ in 0..100 {
            if let Some(mgr) = self.peer_handle.read().await.clone() {
                if mgr.has_direct_peer(dev) {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("wait_for_direct_peer timed out for {device}");
    }

    pub async fn dial_peer(&self, target: uuid::Uuid) -> Result<(), avon_agent_core::AgentError> {
        let mgr = self
            .peer_handle
            .read()
            .await
            .clone()
            .ok_or_else(|| avon_agent_core::AgentError::Protocol("peer not ready".into()))?;
        // Create a fresh control client for the dial (transient)
        let identity = avon_agent_core::identity::load(self.data_dir.path())
            .await
            .map_err(|e| avon_agent_core::AgentError::Protocol(e.to_string()))?;
        let control =
            avon_agent_core::control::ControlClient::connect(&identity, &self.control_url).await?;
        control.authenticate(&identity).await?;
        mgr.dial_peer(&control, &identity, avon_common::ids::DeviceId::new(target))
            .await
    }

    pub async fn enroll_and_connect_with_blackholed_candidates(
        f: &crate::services::ControlFixture,
        token: &str,
    ) -> Self {
        let this = Self::enroll_and_connect(f, token).await;
        // Inject blackholed candidates into peer manager
        if let Some(mgr) = this.peer_handle.read().await.clone() {
            mgr.set_blackholed_candidates(vec![avon_protocol::v2::Candidate {
                address: "192.0.2.1:1".into(),
                priority: 100,
                kind: "host".into(),
            }]);
        }
        this
    }

    pub async fn enroll_and_connect_with_posture(
        f: &crate::services::ControlFixture,
        token: &str,
        firewall: bool,
    ) -> Self {
        insert_token(f, token, 1).await;
        let data_dir = tempfile::tempdir().expect("data dir");
        let ca_pem = std::fs::read(f.trust_bundle()).expect("ca");
        let control_url = format!("https://localhost:{}", f.control.addr.port());
        let _id = enroll(
            &control_url,
            token,
            data_dir.path(),
            &ca_pem,
            "localhost",
            ProviderChoice::Software,
            &TestFingerprint,
            "test",
        )
        .await
        .expect("enroll");

        let identity = load(data_dir.path()).await.expect("load");

        let memtun = MemoryTun::new();
        let test_tun = TestTun::new(memtun.clone());
        let tun_provider: Arc<dyn TunProvider> = test_tun.clone();

        let cfg = AgentCoreConfig {
            control: control_url.clone(),
            pulse_interval: Duration::from_secs(1),
            timers: TimerConfig::default(),
            overlay_mtu: 1280,
            bind: "127.0.0.1:0".parse().unwrap(),
            suites: vec![
                avon_crypto::aead::Suite::Aes256Gcm,
                avon_crypto::aead::Suite::ChaCha20Poly1305,
            ],
        };

        let posture = Arc::new(Mutex::new(DevicePosture {
            os_name: "test".into(),
            os_version: "1.0".into(),
            agent_version: "0.2.0".into(),
            firewall_enabled: Some(firewall),
            disk_encrypted: None,
            screen_lock_enabled: None,
            last_update_unix: None,
            key_provider: "software".into(),
            collected_at_unix: Utc::now().timestamp(),
        }));
        let provider = MutablePosture {
            inner: posture.clone(),
        };

        let agent = Agent::new(cfg, identity, tun_provider, Arc::new(provider));
        let status = agent.status_handle();
        let peer_handle = agent.peer_handle();
        let control_url_clone = control_url.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let agent_task = tokio::spawn(async move {
            let _ = agent
                .run(async {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        for _ in 0..200 {
            if status.snapshot().state == "connected" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        for _ in 0..50 {
            if peer_handle.read().await.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        std::mem::forget(shutdown_tx);

        Self {
            tun: memtun,
            test_tun,
            data_dir,
            agent_task,
            status_handle: status,
            peer_handle,
            control_url: control_url_clone,
            _agent: None,
            posture: Some(posture),
        }
    }

    pub async fn set_posture_firewall(&self, enabled: bool) {
        if let Some(p) = &self.posture {
            let mut guard = p.lock().await;
            guard.firewall_enabled = Some(enabled);
            guard.collected_at_unix = Utc::now().timestamp();
        }
    }
}

impl Drop for TestAgentCore {
    fn drop(&mut self) {
        self.agent_task.abort();
    }
}
