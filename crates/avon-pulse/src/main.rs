//! AVON Pulse Manager
//!
//! Manages device pulse scheduling and token rotation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use avon_protocol::v1::pulse_service_server::PulseServiceServer;
use clap::Parser;
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tokio::signal;
use tonic::transport::Server;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use avon_pulse::{
    PulseConfig, PulseDatabase, PulseScheduler, PulseServiceImpl, TokenRotationManager,
};

#[derive(Parser, Debug)]
#[command(name = "avon-pulse")]
#[command(about = "AVON Pulse Manager Service")]
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:50053")]
    listen_addr: String,

    #[arg(long, env = "DATABASE_URL")]
    database_url: Option<String>,

    #[arg(long, env = "REDIS_URL")]
    redis_url: Option<String>,

    #[arg(long, default_value = "30", env = "PULSE_INTERVAL_SECS")]
    pulse_interval_secs: u64,

    #[arg(long, default_value = "3600", env = "ROTATION_INTERVAL_SECS")]
    rotation_interval_secs: u64,

    #[arg(long, default_value = "90", env = "STALE_THRESHOLD_SECS")]
    stale_threshold_secs: u64,

    #[arg(long, default_value = "300", env = "OFFLINE_THRESHOLD_SECS")]
    offline_threshold_secs: u64,
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
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("AVON Pulse Manager starting...");

    let args = Args::parse();

    let config = PulseConfig {
        listen_addr: args.listen_addr.clone(),
        database_url: args.database_url.clone(),
        redis_url: args.redis_url.clone(),
        pulse_interval_secs: Some(args.pulse_interval_secs),
        rotation_interval_secs: Some(args.rotation_interval_secs),
        stale_threshold_secs: Some(args.stale_threshold_secs),
        offline_threshold_secs: Some(args.offline_threshold_secs),
        gateway_channel_size: Some(1000),
    };

    let pool = if let Some(ref db_url) = args.database_url {
        info!("Connecting to database...");
        Some(
            PgPoolOptions::new()
                .max_connections(10)
                .connect(db_url)
                .await?,
        )
    } else {
        info!("No database URL provided, running without persistence");
        None
    };

    let db = Arc::new(PulseDatabase::new(
        pool.unwrap_or_else(|| panic!("Database URL is required for pulse manager")),
        args.redis_url.clone(),
    ));

    let rotation_manager = Arc::new(TokenRotationManager::new(
        db.clone(),
        Duration::from_secs(args.rotation_interval_secs),
    ));

    let (gateway_tx, mut gateway_rx) =
        tokio::sync::mpsc::channel(config.gateway_channel_size.unwrap_or(1000));

    let scheduler = Arc::new(PulseScheduler::new(
        db.clone(),
        rotation_manager.clone(),
        gateway_tx,
        &config,
    ));

    let service = PulseServiceImpl::new(scheduler.clone(), rotation_manager.clone());

    let addr = args.listen_addr.parse().expect("Invalid listen address");

    // Start health server
    let health_port: u16 = std::env::var("AVON_HEALTH_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let health_server = HealthServer::bind(health_port).await?;
    tokio::spawn(async move {
        health_server.run().await;
    });

    info!("Starting gRPC server on {}", addr);

    let scheduler_handle = scheduler.clone();
    tokio::spawn(async move {
        if let Err(e) = scheduler_handle.run().await {
            tracing::error!(error = %e, "Pulse scheduler error");
        }
    });

    tokio::spawn(async move {
        while let Some(pulse) = gateway_rx.recv().await {
            tracing::debug!(
                device_id = ?pulse.device_id,
                pulse_id = pulse.pulse_id,
                "Outbound pulse ready for gateway"
            );
        }
    });

    Server::builder()
        .add_service(PulseServiceServer::new(service))
        .serve_with_shutdown(addr, async {
            signal::ctrl_c().await.ok();
            info!("Received shutdown signal");
        })
        .await?;

    info!("AVON Pulse Manager stopped");
    Ok(())
}
