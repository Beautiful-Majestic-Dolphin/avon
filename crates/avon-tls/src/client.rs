use std::sync::Arc;

use avon_config::TlsArgs;
use rustls::ClientConfig;
use tonic::transport::{Certificate, ClientTlsConfig, Identity};

use crate::server::{parse_certs, parse_key, root_store};
use crate::{ensure_provider, TlsError};

pub fn rustls_client_config(
    identity: Option<(&[u8], &[u8])>,
    ca_pem: &[u8],
) -> Result<Arc<ClientConfig>, TlsError> {
    ensure_provider();
    let roots = root_store(ca_pem)?;
    let builder = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots);
    let mut config = match identity {
        Some((cert_pem, key_pem)) => {
            builder.with_client_auth_cert(parse_certs(cert_pem)?, parse_key(key_pem)?)?
        }
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(config))
}

/// tonic client TLS config presenting `args.cert` and verifying the server against `args.ca`.
pub fn client_tls_config(args: &TlsArgs, server_name: &str) -> Result<ClientTlsConfig, TlsError> {
    ensure_provider();
    let cert = std::fs::read(&args.cert)?;
    let key = std::fs::read(&args.key)?;
    let ca = std::fs::read(&args.ca)?;
    Ok(ClientTlsConfig::new()
        .domain_name(server_name)
        .ca_certificate(Certificate::from_pem(ca))
        .identity(Identity::from_pem(cert, key)))
}
