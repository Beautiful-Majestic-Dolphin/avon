use std::sync::Arc;

use avon_config::TlsArgs;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tonic::transport::{Certificate, Identity, ServerTlsConfig};

use crate::{ensure_provider, TlsError};

pub(crate) fn parse_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    rustls_pemfile::certs(&mut &*pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::Pem(e.to_string()))
}

pub(crate) fn parse_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, TlsError> {
    rustls_pemfile::private_key(&mut &*pem)
        .map_err(|e| TlsError::Pem(e.to_string()))?
        .ok_or_else(|| TlsError::Pem("no private key in pem".into()))
}

pub(crate) fn root_store(ca_pem: &[u8]) -> Result<RootCertStore, TlsError> {
    let mut store = RootCertStore::empty();
    for cert in parse_certs(ca_pem)? {
        store.add(cert)?;
    }
    Ok(store)
}

/// rustls server config: TLS 1.3 only, hybrid group first, client certs
/// required when `require_client_cert`.
pub fn rustls_server_config(
    cert_pem: &[u8],
    key_pem: &[u8],
    ca_pem: &[u8],
    require_client_cert: bool,
) -> Result<Arc<ServerConfig>, TlsError> {
    ensure_provider();
    let certs = parse_certs(cert_pem)?;
    let key = parse_key(key_pem)?;
    let roots = Arc::new(root_store(ca_pem)?);
    let verifier = if require_client_cert {
        WebPkiClientVerifier::builder(roots)
            .build()
            .map_err(|e| TlsError::Pem(e.to_string()))?
    } else {
        WebPkiClientVerifier::builder(roots)
            .allow_unauthenticated()
            .build()
            .map_err(|e| TlsError::Pem(e.to_string()))?
    };
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(config))
}

/// tonic server TLS config requiring client certificates signed by `args.ca`.
pub fn server_tls_config(args: &TlsArgs) -> Result<ServerTlsConfig, TlsError> {
    ensure_provider();
    let cert = std::fs::read(&args.cert)?;
    let key = std::fs::read(&args.key)?;
    let ca = std::fs::read(&args.ca)?;
    Ok(ServerTlsConfig::new()
        .identity(Identity::from_pem(cert, key))
        .client_ca_root(Certificate::from_pem(ca)))
}
