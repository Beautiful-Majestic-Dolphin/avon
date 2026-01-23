//! AVON Pulse Manager Service
//!
//! Manages heartbeat and health monitoring for the AVON network.

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("AVON Pulse Manager starting...");

    // Initialize components
    avon_crypto::init();
    avon_protocol::init();
    avon_common::init();

    tracing::info!("AVON Pulse Manager initialized successfully");

    Ok(())
}
