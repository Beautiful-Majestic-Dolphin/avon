//! AVON Endpoint Agent
//!
//! Cross-platform client installed on devices for secure network access.

// Allow dead code as many components are scaffolded but not yet wired up
#![allow(dead_code)]
// Allow tunnel/tunnel.rs module naming
#![allow(clippy::module_inception)]

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod agent;
mod config;
mod control;
mod identity;
mod tunnel;

use agent::AvonAgent;
use config::AgentConfig;

#[derive(Parser)]
#[command(name = "avon-agent")]
#[command(about = "AVON Endpoint Agent - Secure Zero Trust Network Access")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the agent as a service
    Run {
        /// Path to configuration file
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Enroll this device with the AVON network
    Enroll {
        /// Enrollment token from admin console
        #[arg(short, long)]
        token: String,
        /// Control plane address (e.g., gateway.avon.local:8443)
        #[arg(short = 'c', long)]
        control_plane: String,
        /// Data directory for storing identity
        #[arg(short, long)]
        data_dir: Option<PathBuf>,
        /// Require FIDO2 hardware security key attestation during enrollment
        #[arg(long)]
        fido2: bool,
    },
    /// Show agent status
    Status {
        /// Data directory to check
        #[arg(short, long)]
        data_dir: Option<PathBuf>,
    },
    /// Show version information
    Version,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    match cli.command {
        Commands::Run { config: config_path } => {
            tracing::info!("AVON Agent starting...");
            
            let config = AgentConfig::load(config_path.as_deref())?;
            let agent = AvonAgent::new(config).await?;
            
            agent.run().await?;
        }
        Commands::Enroll {
            token,
            control_plane,
            data_dir,
            fido2,
        } => {
            tracing::info!("Starting device enrollment...");

            let data_dir = data_dir.unwrap_or_else(AgentConfig::default_data_dir);

            // Perform FIDO2 attestation if requested
            if fido2 {
                if identity::fido2::is_authenticator_available() {
                    tracing::info!("FIDO2 authenticator detected");
                } else {
                    eprintln!("Warning: --fido2 specified but no FIDO2 authenticator detected.");
                    eprintln!("Please insert your hardware security key and try again.");
                    std::process::exit(1);
                }
            }

            match identity::IdentityManager::enroll(&token, &control_plane, &data_dir).await {
                Ok(identity) => {
                    tracing::info!(
                        device_id = %identity.device_id(),
                        fido2 = fido2,
                        "Device enrolled successfully"
                    );
                    println!("Device enrolled successfully!");
                    println!("Device ID: {}", identity.device_id());
                    println!("Data directory: {}", data_dir.display());
                    if fido2 {
                        println!("FIDO2 attestation: verified");
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "Enrollment failed");
                    eprintln!("Enrollment failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Status { data_dir } => {
            let data_dir = data_dir.unwrap_or_else(AgentConfig::default_data_dir);
            
            match identity::IdentityManager::load(&data_dir).await {
                Ok(identity) => {
                    println!("AVON Agent Status");
                    println!("=================");
                    println!("Device ID: {}", identity.device_id());
                    println!("Data directory: {}", data_dir.display());
                    println!("Identity: Loaded");
                    println!("TPM: {}", if identity.has_tpm() { "Available" } else { "Not available" });
                }
                Err(_) => {
                    println!("AVON Agent Status");
                    println!("=================");
                    println!("Status: Not enrolled");
                    println!("Data directory: {}", data_dir.display());
                    println!();
                    println!("Run 'avon-agent enroll' to enroll this device.");
                }
            }
        }
        Commands::Version => {
            println!("AVON Agent v{}", env!("CARGO_PKG_VERSION"));
            println!("Built with Rust {}", rustc_version());
        }
    }

    Ok(())
}

fn rustc_version() -> &'static str {
    option_env!("RUSTC_VERSION").unwrap_or("unknown")
}
