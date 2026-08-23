use async_trait::async_trait;
use avon_protocol::v2::{DevicePosture, Fingerprint};
use avon_tunnel::{PacketSink, PacketSource};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

pub use avon_keystore::{HardwareBinding, KeyError, KeyProvider, ProviderKind};

/// The tunnel's interface to the local stack. The real TUN implements this with
/// kernel ioctls/netlink; tests use an in-memory channel pair.
#[async_trait]
pub trait TunProvider: PacketSink + PacketSource {
    async fn configure(&self, v4: Ipv4Net, v6: Ipv6Net, mtu: u16) -> Result<(), crate::AgentError>;
    async fn set_routes(&self, routes: &[IpNet]) -> Result<(), crate::AgentError>;
    fn name(&self) -> &str;
    fn overlay_v4(&self) -> Option<Ipv4Net> {
        None
    }
}

/// Local enforcement that follows the tunnel's state.
///
/// The agent core knows when a session comes up and what it carries; what to do
/// about it — install nftables rules, pf anchors, Windows filters — is the
/// platform's business, so it lives behind this trait.
#[async_trait]
pub trait Enforcement: Send + Sync {
    /// A session is up and carrying `protected`.
    async fn on_session_up(
        &self,
        tun_name: &str,
        protected: &[IpNet],
    ) -> Result<(), crate::AgentError>;
    /// The session is gone. A fail-closed implementation leaves its rules in
    /// place; that is the point of it.
    async fn on_session_down(&self) -> Result<(), crate::AgentError>;
}

/// Snapshot of the device's health, sent on every pulse.
pub trait PostureProvider: Send + Sync {
    fn collect(&self) -> DevicePosture;
}

/// Stable hardware fingerprint, sent at enrollment and refreshed on pulse.
pub trait FingerprintProvider: Send + Sync {
    fn collect(&self) -> Fingerprint;
}

/// No-op posture: phase 5 replaces it with real collectors.
pub struct NoopPosture;

impl PostureProvider for NoopPosture {
    fn collect(&self) -> DevicePosture {
        DevicePosture {
            os_name: std::env::consts::OS.to_string(),
            os_version: "unknown".into(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            firewall_enabled: None,
            disk_encrypted: None,
            screen_lock_enabled: None,
            last_update_unix: None,
            key_provider: "software".into(),
            collected_at_unix: chrono::Utc::now().timestamp(),
        }
    }
}

/// Returns a deterministic test fingerprint.
pub struct TestFingerprintProvider;

impl FingerprintProvider for TestFingerprintProvider {
    fn collect(&self) -> Fingerprint {
        Fingerprint {
            version: 2,
            hash: vec![7; 32],
            identifier_kinds: vec!["machine-id".into()],
        }
    }
}

// (no blanket From impl to avoid conflict with lib.rs Tunnel variant)
