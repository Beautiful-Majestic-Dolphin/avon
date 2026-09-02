//! The agent's run loop, factored out of `main` so the Windows service entry
//! point and the CLI drive exactly the same code.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
#[cfg(unix)]
use ipnet::IpNet;

use crate::config::AgentConfig;
use crate::enforcement::FirewallEnforcement;
#[cfg(unix)]
use crate::helper::{HelperClient, HelperTun};

#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    pub config: Option<PathBuf>,
    /// Create the TUN directly instead of asking the helper. Requires the agent
    /// to be privileged; the e2e containers run this way.
    pub no_helper: bool,
    /// Leave protected prefixes reachable off-tunnel when the session drops.
    pub fail_open: bool,
}

/// Where the helper's socket lives, in order of precedence: the environment
/// (set by the service units), then the data directory.
#[cfg(unix)]
fn helper_socket(cfg: &AgentConfig) -> PathBuf {
    std::env::var_os("AVON_HELPER_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::helper::socket_path(&cfg.data_dir))
}

pub async fn run_agent(
    opts: RunOptions,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let cfg = AgentConfig::load(opts.config.as_deref())?;
    let control = if cfg.control_plane.starts_with("https://") {
        cfg.control_plane.clone()
    } else {
        format!("https://{}", cfg.control_plane)
    };
    let data_dir = cfg.data_dir.clone();
    let identity = avon_agent_core::identity::load(&data_dir).await?;

    // The overlay prefixes the helper will accept routes inside. Anything the
    // control plane sends outside this set is refused by the privileged half.
    #[cfg(unix)]
    let allowed: Vec<IpNet> = cfg
        .allowed_routes
        .iter()
        .filter_map(|r| r.parse::<IpNet>().ok())
        .collect();

    #[cfg(unix)]
    let (tun, helper_tun): (
        Arc<dyn avon_agent_core::traits::TunProvider>,
        Option<Arc<HelperTun>>,
    ) = if opts.no_helper {
        let tun = avon_tun::Tun::create(&cfg.tun_name, cfg.overlay_mtu)
            .await
            .context("create tun")?;
        (Arc::new(tun), None)
    } else {
        let socket = helper_socket(&cfg);
        let client = HelperClient::connect(&socket)
            .await
            .with_context(|| format!("connect to the helper at {}", socket.display()))?;
        let tun = Arc::new(
            HelperTun::create(client, &cfg.tun_name, cfg.overlay_mtu, allowed)
                .await
                .context("ask the helper for a tun")?,
        );
        (tun.clone(), Some(tun))
    };

    // Windows has no helper: a WinTun session cannot be handed to another
    // process, so the service owns the adapter itself.
    #[cfg(not(unix))]
    let tun: Arc<dyn avon_agent_core::traits::TunProvider> = Arc::new(
        avon_tun::Tun::create(&cfg.tun_name, cfg.overlay_mtu)
            .await
            .context("create tun")?,
    );

    let posture = Arc::new(crate::platform::posture::PostureCollector::new(
        std::time::Duration::from_secs(60),
    ));
    let agent_cfg = avon_agent_core::AgentCoreConfig {
        control,
        pulse_interval: std::time::Duration::from_secs(cfg.pulse_interval_secs),
        timers: avon_tunnel::TimerConfig {
            rekey_after: std::time::Duration::from_secs(cfg.rekey_secs),
            ..avon_tunnel::TimerConfig::default()
        },
        overlay_mtu: cfg.overlay_mtu,
        bind: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
        suites: vec![
            avon_crypto::aead::Suite::Aes256Gcm,
            avon_crypto::aead::Suite::ChaCha20Poly1305,
        ],
    };
    #[cfg(unix)]
    let enforcement = Arc::new(FirewallEnforcement::new(helper_tun, opts.fail_open));
    #[cfg(not(unix))]
    let enforcement = Arc::new(FirewallEnforcement::new(opts.fail_open));
    let agent = avon_agent_core::Agent::new(agent_cfg, identity, tun, posture)
        .with_enforcement(enforcement);

    let status_handle = agent.status_handle();
    let status_dir = data_dir.clone();
    tokio::spawn(async move {
        let _ = avon_agent_core::status::serve_status(status_handle, status_dir).await;
    });

    agent.run(shutdown).await?;
    Ok(())
}
