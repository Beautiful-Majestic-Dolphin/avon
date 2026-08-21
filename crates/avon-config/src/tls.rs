use std::path::PathBuf;

use clap::Args;

use crate::validate::{require_file, ConfigError, Validate};

/// Service TLS identity (server certificate + key) and the CA used to verify peers.
#[derive(Args, Debug, Clone)]
pub struct TlsArgs {
    /// PEM certificate chain presented by this service.
    #[arg(long = "tls-cert", env = "AVON_TLS_CERT")]
    pub cert: PathBuf,
    /// PEM private key for --tls-cert.
    #[arg(long = "tls-key", env = "AVON_TLS_KEY")]
    pub key: PathBuf,
    /// PEM CA bundle used to verify client and server certificates.
    #[arg(long = "tls-ca", env = "AVON_TLS_CA")]
    pub ca: PathBuf,
}

impl Validate for TlsArgs {
    fn validate(&self) -> Result<(), ConfigError> {
        require_file("tls-cert", &self.cert)?;
        require_file("tls-key", &self.key)?;
        require_file("tls-ca", &self.ca)?;
        Ok(())
    }
}
