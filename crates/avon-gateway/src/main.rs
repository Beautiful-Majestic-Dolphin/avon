use std::sync::Arc;

use avon_config::Validate;
use avon_gateway::config::GatewayConfig;
use avon_gateway::state::GatewayState;
use avon_gateway::{control_link, dataplane, tun, AllowAll};
use avon_observability::{init_tracing, install_metrics, serve_health, Readiness};
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Before anything builds a rustls config; rustls will not guess a provider.
    avon_tls::install_default_provider();
    let cfg = GatewayConfig::parse();
    cfg.tls.validate()?;
    cfg.observability.validate()?;
    init_tracing(&cfg.observability)?;
    install_metrics(cfg.observability.metrics_addr)?;

    let readiness = Readiness::new();
    let control_ready = readiness.register("control");
    let udp_ready = readiness.register("udp");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut health_rx = shutdown_rx.clone();
    tokio::spawn(serve_health(
        cfg.observability.health_addr,
        readiness.clone(),
        async move {
            let _ = health_rx.wait_for(|v| *v).await;
        },
    ));

    let (state, events) = GatewayState::bootstrap(&cfg, Arc::new(AllowAll)).await?;
    udp_ready.set(true);

    let tun = tun::open(&cfg.tun_name, cfg.overlay_mtu)?;
    if !tun.is_real {
        tracing::warn!("relay-only: packets for protected networks will be dropped");
    }
    tokio::spawn(dataplane::run_dataplane(
        state.clone(),
        events,
        tun.sink,
        tun.source,
    ));

    let link = tokio::spawn(control_link::run_control_link(state.clone(), cfg.clone()));
    control_ready.set(true);
    tracing::info!(gateway = %state.id, "avon-gateway running");

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down; closing sessions");
    let _ = shutdown_tx.send(true);
    for session in state.table.iter() {
        state.close_session(&session.id(), "shutdown").await;
    }
    link.abort();
    Ok(())
}
