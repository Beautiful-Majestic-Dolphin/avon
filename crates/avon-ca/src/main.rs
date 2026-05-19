//! AVON Certificate Authority
//!
//! Manages certificates for the AVON network.

use std::net::SocketAddr;
use std::sync::Arc;

use avon_ca::{CaConfig, CaServiceImpl, CertificateAuthority, OcspResponder};
use avon_protocol::v1::ca_service_server::CaServiceServer;
use clap::Parser;
use tokio::net::TcpListener;
use tokio::signal;
use tonic::transport::Server;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(name = "avon-ca")]
#[command(about = "AVON Certificate Authority Service")]
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:50052")]
    listen_addr: String,

    #[arg(long, env = "CA_ROOT_KEY_PATH")]
    root_key_path: Option<String>,

    #[arg(long, env = "CA_INTERMEDIATE_KEY_PATH")]
    intermediate_key_path: Option<String>,

    #[arg(long, default_value = "3600", env = "CA_CERT_LIFETIME_SECS")]
    cert_lifetime_secs: u64,

    #[arg(long, default_value = "3600", env = "CA_OCSP_LIFETIME_SECS")]
    ocsp_lifetime_secs: u64,

    #[arg(long, default_value = "1", env = "CA_INITIAL_SERIAL")]
    initial_serial: u64,
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

    info!("AVON CA starting...");

    let args = Args::parse();

    let config = CaConfig {
        listen_addr: args.listen_addr.clone(),
        root_key_path: args.root_key_path,
        intermediate_key_path: args.intermediate_key_path,
        cert_lifetime_secs: Some(args.cert_lifetime_secs),
        ocsp_lifetime_secs: Some(args.ocsp_lifetime_secs),
        initial_serial: Some(args.initial_serial),
        database_url: std::env::var("DATABASE_URL").ok(),
    };

    info!("Initializing Certificate Authority...");
    let ca = Arc::new(
        CertificateAuthority::new(&config)
            .await
            .expect("Failed to initialize CA"),
    );

    let ocsp = Arc::new(OcspResponder::new(ca.clone()));

    let service = CaServiceImpl::new(ca.clone(), ocsp.clone());

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

    let ocsp_refresh = ocsp.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            ocsp_refresh.refresh_all().await;
        }
    });

    Server::builder()
        .add_service(CaServiceServer::new(service))
        .serve_with_shutdown(addr, async {
            signal::ctrl_c().await.ok();
            info!("Received shutdown signal");
        })
        .await?;

    info!("AVON CA stopped");
    Ok(())
}
