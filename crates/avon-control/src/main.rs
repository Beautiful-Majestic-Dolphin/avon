use std::time::Duration;

use avon_config::Validate;
use avon_control::config::ControlConfig;
use avon_control::service::{
    admin::AdminServiceImpl, agent::AgentServiceImpl, gateway::GatewayServiceImpl, AppState,
};
use avon_observability::{grpc_health, init_tracing, install_metrics, serve_health, Readiness};
use avon_protocol::v2::admin_service_server::AdminServiceServer;
use avon_protocol::v2::agent_service_server::AgentServiceServer;
use avon_protocol::v2::gateway_service_server::GatewayServiceServer;
use clap::Parser;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Distroless images have no shell and no wget/curl, so Docker's
    // HEALTHCHECK invokes this binary itself: `avon health-check`. Handle
    // that before clap ever sees argv.
    if std::env::args().nth(1).as_deref() == Some("health-check") {
        let ok = avon_observability::health_probe_from_env() == std::process::ExitCode::SUCCESS;
        std::process::exit(i32::from(!ok));
    }
    // Before anything builds a rustls config: redis (rediss://) and sqlx each
    // construct their own, and rustls will not guess a provider.
    avon_tls::install_default_provider();
    let cfg = ControlConfig::parse();
    cfg.validate()?;
    init_tracing(&cfg.obs)?;
    install_metrics(cfg.obs.metrics_addr)?;
    let readiness = Readiness::new();
    let db_ready = readiness.register("database");
    let redis_ready = readiness.register("redis");
    let ca_ready = readiness.register("ca");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut health_rx = shutdown_rx.clone();
    tokio::spawn(serve_health(
        cfg.obs.health_addr,
        readiness.clone(),
        async move {
            let _ = health_rx.wait_for(|v| *v).await;
        },
    ));

    let pool = avon_db::connect(&cfg.db).await?;
    db_ready.set(true);
    let redis = avon_config::redis_client(&cfg.redis)?;
    let redis_conn = redis::aio::ConnectionManager::new(redis).await?;
    redis_ready.set(true);
    let ca = avon_control::ca_client::CaClient::connect(&cfg.ca_url, &cfg.ca_server_name, &cfg.tls)
        .await?;
    let state = AppState::new(
        pool,
        redis_conn,
        ca,
        cfg.tls.clone(),
        cfg.session_ttl_secs,
        cfg.pulse_interval_secs,
    )
    .await?;
    ca_ready.set(true);

    tokio::spawn(avon_control::liveness::liveness_sweeper(
        state.clone(),
        Duration::from_secs(90),
        Duration::from_secs(300),
        Duration::from_secs(15),
    ));
    tokio::spawn(avon_control::gateway_stream::admin_event_listener(
        state.clone(),
        cfg.redis.clone(),
    ));
    tokio::spawn(avon_control::policy_push::policy_listener(
        state.clone(),
        cfg.db.url.clone(),
    ));
    tokio::spawn(avon_control::policy_push::window_ticker(state.clone()));

    let health = grpc_health();
    health
        .reporter
        .set_serving::<AgentServiceServer<AgentServiceImpl>>()
        .await;
    health
        .reporter
        .set_serving::<AdminServiceServer<AdminServiceImpl>>()
        .await;
    tracing::info!(addr = %cfg.listen_addr, "avon-control serving");
    Server::builder()
        .tls_config(avon_tls::server_tls_config_optional_client(&cfg.tls)?)?
        .add_service(health.service)
        .add_service(AgentServiceServer::new(AgentServiceImpl::new(
            state.clone(),
        )))
        .add_service(AdminServiceServer::new(AdminServiceImpl::new(
            state.clone(),
        )))
        .add_service(GatewayServiceServer::new(GatewayServiceImpl::new(state)))
        .serve_with_shutdown(cfg.listen_addr, async {
            let _ = tokio::signal::ctrl_c().await;
            let _ = shutdown_tx.send(true);
        })
        .await?;
    Ok(())
}
