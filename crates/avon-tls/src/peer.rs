use avon_common::ids::SpiffeId;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use crate::TlsError;

#[derive(Clone, Debug)]
pub struct PeerIdentity {
    pub spiffe: Option<SpiffeId>,
    pub cert_sha256: [u8; 32],
}

/// First URI SAN that parses as an AVON SPIFFE id.
pub fn spiffe_from_cert_der(der: &[u8]) -> Result<Option<SpiffeId>, TlsError> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| TlsError::X509(e.to_string()))?;
    let Some(san) = cert
        .subject_alternative_name()
        .map_err(|e| TlsError::X509(e.to_string()))?
    else {
        return Ok(None);
    };
    for name in &san.value.general_names {
        if let GeneralName::URI(uri) = name {
            if let Ok(id) = SpiffeId::parse(uri) {
                return Ok(Some(id));
            }
        }
    }
    Ok(None)
}

pub fn cert_sha256_from_pem(pem: &[u8]) -> Result<[u8; 32], TlsError> {
    let certs = crate::server::parse_certs(pem)?;
    let leaf = certs
        .first()
        .ok_or_else(|| TlsError::Pem("empty pem".into()))?;
    Ok(Sha256::digest(leaf.as_ref()).into())
}

/// Identity of the TLS peer of a tonic request (leaf certificate).
pub fn peer_identity<T>(req: &tonic::Request<T>) -> Result<PeerIdentity, TlsError> {
    let certs = req.peer_certs().ok_or(TlsError::NoPeerCertificate)?;
    let leaf = certs.first().ok_or(TlsError::NoPeerCertificate)?;
    let der: &[u8] = leaf.as_ref();
    Ok(PeerIdentity {
        spiffe: spiffe_from_cert_der(der)?,
        cert_sha256: Sha256::digest(der).into(),
    })
}
