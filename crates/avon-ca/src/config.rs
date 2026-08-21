use std::net::SocketAddr;
use std::path::PathBuf;

use avon_config::{DatabaseArgs, ObservabilityArgs, TlsArgs, Validate};
use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "avon-ca", version)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Create root/issuing/TLS keys if none exist (idempotent).
    Init(CommonArgs),
    /// Serve the CA gRPC API.
    Serve(Box<ServeArgs>),
    /// Generate a new sealed-file master key at --master-key-file.
    GenerateMasterKey(CommonArgs),
}

#[derive(Args, Debug, Clone)]
pub struct CommonArgs {
    #[command(flatten)]
    pub db: DatabaseArgs,
    /// 0600 file holding the 32-byte master key for the sealed-file provider.
    #[arg(long, env = "AVON_CA_MASTER_KEY_FILE")]
    pub master_key_file: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub struct ServeArgs {
    #[command(flatten)]
    pub common: CommonArgs,
    #[command(flatten)]
    pub tls: TlsArgs,
    #[command(flatten)]
    pub obs: ObservabilityArgs,
    #[arg(long, env = "AVON_CA_LISTEN_ADDR", default_value = "0.0.0.0:50052")]
    pub listen_addr: SocketAddr,
    /// Lifetime of device credentials in seconds (max 7 days).
    #[arg(long, env = "AVON_CA_DEVICE_LIFETIME_SECS", default_value_t = 86_400)]
    pub device_lifetime_secs: i64,
}

impl ServeArgs {
    pub fn validate(&self) -> Result<(), avon_config::ConfigError> {
        self.common.db.validate()?;
        self.tls.validate()?;
        self.obs.validate()?;
        if !(300..=7 * 86_400).contains(&self.device_lifetime_secs) {
            return Err(avon_config::ConfigError::Invalid {
                field: "device-lifetime-secs",
                reason: "must be within 300..=604800".into(),
            });
        }
        Ok(())
    }
}
