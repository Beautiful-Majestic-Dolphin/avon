//! AVON Authentication Service
//!
//! Handles device authentication, enrollment, and token rotation for the AVON network.

use avon_auth::{AuthCache, AuthConfig, AuthDatabase, AuthServiceImpl};
use avon_protocol::v1::auth_service_server::AuthServiceServer;
use clap::Parser;
use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tonic::transport::Server;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// AVON Authentication Service
#[derive(Parser, Debug)]
#[command(name = "avon-auth")]
#[command(about = "AVON Authentication Service - handles device authentication and enrollment")]
struct Args {
    /// Path to configuration file
    #[arg(short, long)]
    config: Option<String>,

    /// gRPC listen address (overrides config)
    #[arg(short, long)]
    listen: Option<SocketAddr>,

    /// Log level (overrides config)
    #[arg(short = 'L', long)]
    log_level: Option<String>,
}

/// Health check server for Kubernetes probes.
struct HealthServer {
    listener: TcpListener,
}

impl HealthServer {
    async fn bind(port: u16) -> anyhow::Result<Self> {
        let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
        let listener = TcpListener::bind(addr).await?;
        info!(?addr, "Health server bound");
        Ok(Self { listener })
    }

    async fn run(self) {
        loop {
            match self.listener.accept().await {
                Ok((mut stream, _)) => {
                    tokio::spawn(async move {
                        use tokio::io::AsyncWriteExt;
                        let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                        let _ = stream.write_all(response.as_bytes()).await;
                    });
                }
                Err(e) => {
                    warn!("Health server accept error: {}", e);
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse CLI arguments
    let args = Args::parse();

    // Load configuration
    let config = AuthConfig::load(args.config.as_deref())
        .unwrap_or_else(|e| {
            eprintln!("Warning: Failed to load config: {}. Using defaults.", e);
            AuthConfig::default()
        })
        .with_overrides(args.listen, args.log_level);

    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| config.log_level.clone()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("AVON Auth Service starting...");
    info!(listen_addr = %config.listen_addr, "Configuration loaded");

    // Initialize Prometheus metrics
    let metrics_addr: SocketAddr = format!("0.0.0.0:{}", config.metrics_port).parse()?;
    PrometheusBuilder::new()
        .with_http_listener(metrics_addr)
        .install()
        .expect("Failed to install Prometheus exporter");
    info!(?metrics_addr, "Prometheus metrics server started");

    // Connect to database
    info!("Connecting to database...");
    let db = Arc::new(
        AuthDatabase::new(&config.database_url)
            .await
            .expect("Failed to connect to database"),
    );

    // Run migrations (optional, can be disabled in production)
    if std::env::var("AVON_RUN_MIGRATIONS").unwrap_or_default() == "true" {
        info!("Running database migrations...");
        db.run_migrations().await?;
    }

    // Connect to Redis
    info!("Connecting to Redis...");
    let cache = Arc::new(
        AuthCache::new(&config.redis_url, config.cache_ttl_secs)
            .await
            .expect("Failed to connect to Redis"),
    );

    // Create gRPC service
    let auth_service = AuthServiceImpl::new(db.clone(), cache.clone());
    let grpc_service = AuthServiceServer::new(auth_service);

    // Start health server
    let health_server = HealthServer::bind(config.health_port).await?;
    tokio::spawn(async move {
        health_server.run().await;
    });

    // Start gRPC server with graceful shutdown
    info!(addr = %config.listen_addr, "Starting gRPC server");

    Server::builder()
        .add_service(grpc_service)
        .serve_with_shutdown(config.listen_addr, async {
            signal::ctrl_c().await.ok();
            info!("Received shutdown signal");
        })
        .await?;

    info!("AVON Auth Service stopped");
    Ok(())
}
