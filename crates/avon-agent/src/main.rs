use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use avon_agent::config::AgentConfig;
use avon_agent::platform;

#[derive(Parser)]
#[command(name = "avon-agent")]
#[command(about = "AVON Endpoint Agent")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the agent
    Run {
        /// Path to configuration file
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Create the TUN directly instead of asking the privileged helper.
        /// Requires root; the e2e containers run this way.
        #[arg(long)]
        no_helper: bool,
        /// Leave protected prefixes reachable off-tunnel when the session drops.
        #[arg(long)]
        fail_open: bool,
        /// Run under the Windows service control manager.
        #[arg(long)]
        service: bool,
    },
    /// Register the Windows services (Windows only; elevation required)
    InstallService,
    /// Remove the Windows services (Windows only; elevation required)
    UninstallService,
    /// Enroll this device with the AVON network
    Enroll {
        /// Control plane address (e.g., https://control:8443)
        #[arg(long, env = "AVON_CONTROL_URL")]
        control: String,
        /// Enrollment token
        #[arg(long, env = "AVON_AGENT_ENROLL_TOKEN")]
        token: Option<String>,
        /// Token file (alternative to --token)
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// PEM CA bundle to trust for control
        #[arg(long)]
        ca_file: Option<PathBuf>,
        /// SHA256 fingerprint of the control server's certificate (hex)
        #[arg(long)]
        ca_fingerprint: Option<String>,
        /// Data directory for storing identity
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Key provider: auto|software|tpm2|keychain|cng
        #[arg(long, default_value = "auto")]
        key_provider: String,
    },
    /// Show agent status
    Status {
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Data directory to check
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Show version information
    Version,
}

fn default_data_dir() -> PathBuf {
    AgentConfig::default_data_dir()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    avon_tls::install_default_provider();

    let cli = Cli::parse();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    match cli.command {
        Commands::Run {
            config,
            no_helper,
            fail_open,
            service,
        } => {
            if service {
                #[cfg(target_os = "windows")]
                {
                    avon_agent::platform::service::windows::run_as_service()?;
                    return Ok(());
                }
                #[cfg(not(target_os = "windows"))]
                anyhow::bail!("--service is only meaningful on Windows");
            }
            let opts = avon_agent::run::RunOptions {
                config,
                no_helper,
                fail_open,
            };
            // Graceful shutdown on SIGTERM/SIGINT.
            let shutdown = async {
                let _ = tokio::signal::ctrl_c().await;
                tracing::info!("shutdown signal received");
            };
            avon_agent::run::run_agent(opts, shutdown).await?;
        }
        Commands::InstallService => {
            #[cfg(target_os = "windows")]
            {
                let exe = std::env::current_exe()?;
                avon_agent::platform::service::windows::install(&exe)?;
                println!("registered avon-agent (not started: enrol first)");
            }
            #[cfg(not(target_os = "windows"))]
            anyhow::bail!("install-service is Windows only; use the systemd or launchd units");
        }
        Commands::UninstallService => {
            #[cfg(target_os = "windows")]
            {
                avon_agent::platform::service::windows::uninstall()?;
                println!("removed avon-agent");
            }
            #[cfg(not(target_os = "windows"))]
            anyhow::bail!("uninstall-service is Windows only; use the systemd or launchd units");
        }
        Commands::Enroll {
            control,
            token,
            token_file,
            ca_file,
            ca_fingerprint,
            data_dir,
            key_provider,
        } => {
            let data_dir = data_dir.unwrap_or_else(default_data_dir);
            // Resolve token.
            let token = if let Some(t) = token {
                t
            } else if let Some(path) = token_file {
                std::fs::read_to_string(&path)?.trim().to_string()
            } else if let Ok(t) = std::env::var("AVON_AGENT_ENROLL_TOKEN") {
                t
            } else {
                anyhow::bail!("token required: --token, --token-file, or AVON_AGENT_ENROLL_TOKEN");
            };
            // Resolve CA.
            let ca_pem: Vec<u8> = if let Some(path) = ca_file {
                std::fs::read(&path)?
            } else if let Some(fp) = ca_fingerprint {
                // Fetch server cert and verify fingerprint.
                let fp = fp.trim().to_lowercase().replace(':', "");
                let url = if control.starts_with("https://") {
                    control.clone()
                } else {
                    format!("https://{}", control)
                };
                // Connect without verification to get cert, then verify fingerprint.
                // For now, error if fingerprint provided without ca_file (not fully implemented).
                anyhow::bail!(
                    "ca-fingerprint verification not yet implemented; please use --ca-file (fingerprint was {}) for {}",
                    fp,
                    url
                );
            } else {
                // Try to read from data_dir/ca.pem if exists, otherwise error.
                anyhow::bail!("--ca-file or --ca-fingerprint required");
            };
            let control_url = if control.starts_with("https://") {
                control.clone()
            } else {
                format!("https://{}", control)
            };
            let fp = platform::fingerprint::PlatformFingerprint;
            let choice: avon_keystore::ProviderChoice = key_provider
                .parse()
                .unwrap_or(avon_keystore::ProviderChoice::Auto);
            let id = avon_agent_core::identity::enroll(
                &control_url,
                &token,
                &data_dir,
                &ca_pem,
                // Derive server name from control URL.
                &url_server_name(&control_url),
                choice,
                &fp,
                env!("CARGO_PKG_VERSION"),
            )
            .await?;
            println!("Device enrolled successfully!");
            println!("Device ID: {}", id.device_id);
            println!("Data directory: {}", data_dir.display());
        }
        Commands::Status { json, data_dir } => {
            let data_dir = data_dir.unwrap_or_else(|| {
                // Try to load from config or default.
                AgentConfig::default_data_dir()
            });
            // Try to fetch from status socket, fallback to reading identity.
            match avon_agent_core::status::fetch_status(&data_dir).await {
                Ok(st) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&st)?);
                    } else {
                        println!("AVON Agent Status");
                        println!("=================");
                        println!("State: {}", st.state);
                        println!("Device ID: {}", st.device_id);
                        println!(
                            "Overlay v4: {}",
                            st.overlay_v4.unwrap_or_else(|| "—".into())
                        );
                        println!("Session: {}", st.session_id.unwrap_or_else(|| "—".into()));
                        println!("Gateway: {}", st.gateway.unwrap_or_else(|| "—".into()));
                    }
                }
                Err(_) => {
                    // Fallback: try to load identity.
                    match avon_agent_core::identity::load(&data_dir).await {
                        Ok(id) => {
                            if json {
                                let st = serde_json::json!({
                                    "state": "enrolled",
                                    "device_id": id.device_id.to_string(),
                                    "overlay_v4": null,
                                });
                                println!("{}", serde_json::to_string_pretty(&st)?);
                            } else {
                                println!("AVON Agent Status");
                                println!("=================");
                                println!("Device ID: {}", id.device_id);
                                println!("Data directory: {}", data_dir.display());
                                println!("Identity: Loaded");
                                println!("State: enrolled (agent not running)");
                            }
                        }
                        Err(_) => {
                            if json {
                                println!("{}", serde_json::json!({"state": "not-enrolled"}));
                            } else {
                                println!("AVON Agent Status");
                                println!("=================");
                                println!("State: not-enrolled");
                                println!("Data directory: {}", data_dir.display());
                            }
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
        Commands::Version => {
            println!("avon-agent {}", env!("CARGO_PKG_VERSION"));
        }
    }

    Ok(())
}

fn url_server_name(url: &str) -> String {
    if let Ok(parsed) = url::Url::parse(url) {
        if let Some(host) = parsed.host_str() {
            return host.to_string();
        }
    }
    "localhost".to_string()
}
