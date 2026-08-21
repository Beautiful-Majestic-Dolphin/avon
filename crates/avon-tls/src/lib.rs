//! TLS for AVON services: TLS 1.3 only, X25519MLKEM768 preferred, mutual
//! authentication against the AVON TLS CA, and SPIFFE identity extraction.

mod client;
mod peer;
mod server;

pub use client::{client_tls_config, rustls_client_config};
pub use peer::{cert_sha256_from_pem, peer_identity, spiffe_from_cert_der, PeerIdentity};
pub use server::{rustls_server_config, server_tls_config, server_tls_config_optional_client};

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("pem: {0}")]
    Pem(String),
    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("no peer certificate on this connection")]
    NoPeerCertificate,
    #[error("x509: {0}")]
    X509(String),
}

pub(crate) fn ensure_provider() {
    // Installing twice returns Err; that is fine.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}
