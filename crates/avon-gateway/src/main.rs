//! AVON UDP Gateway Service
//!
//! Handles UDP traffic routing for the AVON network.

use avon_gateway::{
    config::GatewayConfig,
    device_registry::DeviceRegistry,
    gateway::{HealthServer, UdpGateway},
    packet_handler::PacketHandler,
    rate_limiter::RateLimiter,
};
use clap::Parser;
use metrics_exporter_prometheus::PrometheusBuilder;
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// AVON UDP Gateway Service
#[derive(Parser, Debug)]
#[command(name = "avon-gateway")]
#[command(about = "AVON UDP Gateway - handles control plane traffic")]
struct Args {
    /// Path to configuration file
    #[arg(short, long)]
    config: Option<String>,

    /// Override listen port
    #[arg(short, long)]
    port: Option<u16>,

    /// Override log level
    #[arg(long)]
    log_level: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Load configuration
    let config = GatewayConfig::load(args.config.as_deref())?
        .with_overrides(args.port, args.log_level);

    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(&config.log_level))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("AVON Gateway starting...");
    info!(listen_addr = %config.listen_addr, "Configuration loaded");

    // Initialize Prometheus metrics
    let metrics_addr = format!("0.0.0.0:{}", config.metrics_port);
    PrometheusBuilder::new()
        .with_http_listener(metrics_addr.parse::<std::net::SocketAddr>()?)
        .install()?;
    info!(metrics_port = config.metrics_port, "Prometheus metrics enabled");

    // Initialize device registry
    let registry = Arc::new(DeviceRegistry::new(config.redis_url.clone()).await?);
    info!("Device registry initialized");

    // Initialize rate limiter
    let rate_limiter = Arc::new(RateLimiter::new(config.rate_limit.clone()));
    info!(
        requests_per_second = config.rate_limit.requests_per_second,
        burst_size = config.rate_limit.burst_size,
        "Rate limiter initialized"
    );

    // Start rate limiter cleanup task
    let cleanup_limiter = rate_limiter.clone();
    tokio::spawn(async move {
        cleanup_limiter.cleanup_expired().await;
    });

    // Start device registry sync task
    let sync_registry = registry.clone();
    tokio::spawn(async move {
        sync_registry.sync_from_database(60).await;
    });

    // Initialize packet handler
    let packet_handler = Arc::new(PacketHandler::new(registry));
    info!("Packet handler initialized");

    // Start health server
    let health_server = HealthServer::bind(config.health_port).await?;
    tokio::spawn(async move {
        if let Err(e) = health_server.run().await {
            error!(error = %e, "Health server error");
        }
    });
    info!(health_port = config.health_port, "Health server started");

    // Start UDP gateway
    let gateway = UdpGateway::bind(config.listen_addr, rate_limiter, packet_handler).await?;
    info!("UDP gateway started, entering receive loop");

    gateway.run().await
}
