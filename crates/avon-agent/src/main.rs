//! AVON Endpoint Agent
//!
//! Cross-platform client installed on devices for secure network access.

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("AVON Agent starting...");

    // Initialize components
    avon_crypto::init();
    avon_protocol::init();
    avon_common::init();

    tracing::info!("AVON Agent initialized successfully");

    Ok(())
}
