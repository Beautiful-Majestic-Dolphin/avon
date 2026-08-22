//! Gateway configuration. Everything is a flag with an `AVON_*` environment
//! fallback, so a container needs no config file.

use std::net::SocketAddr;
use std::path::PathBuf;

use avon_config::{ObservabilityArgs, TlsArgs};
use clap::Parser;
use ipnet::IpNet;

#[derive(Clone, Debug, Parser)]
pub struct GatewayConfig {
    #[command(flatten)]
    pub tls: TlsArgs,
    #[command(flatten)]
    pub observability: ObservabilityArgs,

    /// Control plane gRPC endpoint.
    #[arg(long, env = "AVON_CONTROL_URL", default_value = "https://control:8443")]
    pub control_url: String,
    /// TLS server name to verify control against.
    #[arg(long, env = "AVON_CONTROL_SERVER_NAME", default_value = "control")]
    pub control_server_name: String,

    /// UDP address the tunnel listens on.
    #[arg(long, env = "AVON_LISTEN_UDP", default_value = "0.0.0.0:4600")]
    pub listen_udp: SocketAddr,
    /// host:port devices should send to. Must be reachable from the internet.
    #[arg(long, env = "AVON_PUBLIC_ENDPOINT")]
    pub public_endpoint: String,
    #[arg(long, env = "AVON_REGION", default_value = "default")]
    pub region: String,
    /// Sessions this gateway advertises room for.
    #[arg(long, env = "AVON_CAPACITY", default_value_t = 1000)]
    pub capacity: u32,

    /// Networks this gateway routes into on behalf of its sessions. Control
    /// hands these to devices as routes.
    #[arg(long, env = "AVON_PROTECTED_CIDRS", value_delimiter = ',')]
    pub protected_cidrs: Vec<IpNet>,
    /// The tenant overlay pools. Must match `ipam_pools`: a destination inside
    /// them belongs to a session, one outside goes out the TUN.
    #[arg(
        long,
        env = "AVON_OVERLAY_PREFIXES",
        value_delimiter = ',',
        default_values_t = default_overlay_prefixes()
    )]
    pub overlay_prefixes: Vec<IpNet>,

    #[arg(long, env = "AVON_TUN_NAME", default_value = "avon0")]
    pub tun_name: String,
    #[arg(long, env = "AVON_OVERLAY_MTU", default_value_t = 1380)]
    pub overlay_mtu: u16,

    /// Where `avon-bootstrap` wrote `gateway.avon.crt`, `gateway.avon.key` and
    /// `gateway.kem.key`.
    #[arg(long, env = "AVON_IDENTITY_DIR", default_value = "/var/lib/avon")]
    pub identity_dir: PathBuf,

    /// Optional: mirror session metadata here for admin views. The mirror is
    /// never on the forwarding path, so a gateway runs fine without it.
    #[arg(long = "redis-url", env = "AVON_REDIS_URL", hide_env_values = true)]
    pub redis_url: Option<String>,
    /// PEM CA for a `rediss://` mirror URL.
    #[arg(long = "redis-tls-ca", env = "AVON_REDIS_TLS_CA")]
    pub redis_tls_ca: Option<std::path::PathBuf>,

    #[arg(long, env = "AVON_KEEPALIVE_SECS", default_value_t = 15)]
    pub keepalive_secs: u64,
    #[arg(long, env = "AVON_REKEY_SECS", default_value_t = 3600)]
    pub rekey_secs: u64,
    #[arg(long, env = "AVON_IDLE_TIMEOUT_SECS", default_value_t = 300)]
    pub idle_timeout_secs: u64,
}

fn default_overlay_prefixes() -> Vec<IpNet> {
    ["100.64.0.0/10", "fd00:a70::/48"]
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect()
}

impl GatewayConfig {
    pub fn timers(&self) -> avon_tunnel::TimerConfig {
        avon_tunnel::TimerConfig {
            keepalive: std::time::Duration::from_secs(self.keepalive_secs),
            rekey_after: std::time::Duration::from_secs(self.rekey_secs),
            idle_timeout: std::time::Duration::from_secs(self.idle_timeout_secs),
            ..Default::default()
        }
    }
}

impl GatewayConfig {
    /// The mirror client, if one is configured. Goes through
    /// [`avon_config::redis_client`] so a privately-issued `rediss://`
    /// certificate verifies.
    pub fn redis_client(&self) -> Option<redis::Client> {
        let url = self.redis_url.clone()?;
        let args = avon_config::RedisArgs {
            url,
            tls_ca: self.redis_tls_ca.clone(),
            require_tls: false,
        };
        avon_config::redis_client(&args)
            .map_err(|e| tracing::warn!(error = %e, "session mirroring disabled"))
            .ok()
    }
}
