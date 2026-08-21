use std::time::Duration;

use avon_config::Validate;
use avon_control::config::ControlConfig;
use avon_control::service::{agent::AgentServiceImpl, gateway::GatewayServiceImpl, AppState};
use avon_observability::{grpc_health, init_tracing, install_metrics, serve_health, Readiness};
use avon_protocol::v2::agent_service_server::AgentServiceServer;
use avon_protocol::v2::gateway_service_server::GatewayServiceServer;
use clap::Parser;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
    let redis = avon_control::config::redis_client(&cfg.redis)?;
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

    let health = grpc_health();
    health
        .reporter
        .set_serving::<AgentServiceServer<AgentServiceImpl>>()
        .await;
    tracing::info!(addr = %cfg.listen_addr, "avon-control serving");
    Server::builder()
        .tls_config(avon_tls::server_tls_config_optional_client(&cfg.tls)?)?
        .add_service(health.service)
        .add_service(AgentServiceServer::new(AgentServiceImpl::new(
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
