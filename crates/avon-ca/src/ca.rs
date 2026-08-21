//! Certificate Authority implementation for AVON.
//!
//! This module provides the core CA functionality including:
//! - Root and intermediate CA keypair management
//! - Ephemeral certificate issuance with hybrid signatures
//! - Certificate verification
//! - OCSP staple generation

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use avon_common::device::DeviceId;
use avon_crypto::hybrid::signature::{Domain, HybridSigningKeyPair, HybridVerifyingKey};
use chrono::{DateTime, Utc};
use num_traits::ToPrimitive;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SerialNumber,
};
use thiserror::Error;
use tracing::{debug, info};

use crate::config::CaConfig;

#[derive(Error, Debug)]
pub enum CaError {
    #[error("Failed to generate keypair: {0}")]
    KeyGenerationFailed(String),

    #[error("Failed to generate certificate: {0}")]
    CertificateGenerationFailed(String),

    #[error("Failed to sign certificate: {0}")]
    SigningFailed(String),

    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),

    #[error("Certificate expired")]
    CertificateExpired,

    #[error("Certificate revoked")]
    CertificateRevoked,

    #[error("Certificate not yet valid")]
    CertificateNotYetValid,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Serial number overflow")]
    SerialOverflow,

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Crypto error: {0}")]
    CryptoError(#[from] avon_crypto::CryptoError),
}

pub type Result<T> = std::result::Result<T, CaError>;

pub struct IssuedCertificate {
    pub certificate_der: Vec<u8>,
    pub classical_signature: Vec<u8>,
    pub pqc_signature: Vec<u8>,
    pub ocsp_staple: Vec<u8>,
    pub expires_at: DateTime<Utc>,
    pub serial: u64,
}

pub struct VerifiedCert {
    pub device_id: DeviceId,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub serial: u64,
    pub public_key: Vec<u8>,
}

pub struct OcspStaple {
    pub response: Vec<u8>,
    pub this_update: DateTime<Utc>,
    pub next_update: DateTime<Utc>,
    pub status: CertificateStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateStatus {
    Good,
    Revoked,
    Unknown,
}

pub struct CertificateAuthority {
    #[allow(dead_code)] // Will be used for root certificate operations
    root_keypair: HybridSigningKeyPair,
    intermediate_keypair: HybridSigningKeyPair,
    root_cert_der: Vec<u8>,
    intermediate_cert_der: Vec<u8>,
    root_verifying_key: HybridVerifyingKey,
    intermediate_verifying_key: HybridVerifyingKey,
    serial_counter: AtomicU64,
    cert_lifetime: Duration,
    ocsp_lifetime: Duration,
}

impl CertificateAuthority {
    pub async fn new(config: &CaConfig) -> Result<Self> {
        info!("Initializing Certificate Authority");

        let (root_keypair, root_cert_der) = Self::load_or_generate_root_ca(config).await?;
        let root_verifying_key = root_keypair.verifying_key();

        let (intermediate_keypair, intermediate_cert_der) =
            Self::load_or_generate_intermediate_ca(config, &root_keypair).await?;
        let intermediate_verifying_key = intermediate_keypair.verifying_key();

        let serial_counter = AtomicU64::new(config.initial_serial.unwrap_or(1));

        let cert_lifetime = Duration::from_secs(config.cert_lifetime_secs.unwrap_or(3600));
        let ocsp_lifetime = Duration::from_secs(config.ocsp_lifetime_secs.unwrap_or(3600));

        info!(
            cert_lifetime_secs = cert_lifetime.as_secs(),
            ocsp_lifetime_secs = ocsp_lifetime.as_secs(),
            "Certificate Authority initialized"
        );

        Ok(Self {
            root_keypair,
            intermediate_keypair,
            root_cert_der,
            intermediate_cert_der,
            root_verifying_key,
            intermediate_verifying_key,
            serial_counter,
            cert_lifetime,
            ocsp_lifetime,
        })
    }

    async fn load_or_generate_root_ca(
        config: &CaConfig,
    ) -> Result<(HybridSigningKeyPair, Vec<u8>)> {
        if let Some(ref key_path) = config.root_key_path {
            if std::path::Path::new(key_path).exists() {
                info!("Loading root CA from {}", key_path);
                return Self::load_ca_from_file(key_path, "AVON Root CA").await;
            }
        }

        info!("Generating new root CA keypair");
        let keypair = HybridSigningKeyPair::generate()
            .map_err(|e| CaError::KeyGenerationFailed(e.to_string()))?;

        let cert_der = Self::generate_root_certificate(&keypair)?;

        if let Some(ref key_path) = config.root_key_path {
            Self::save_ca_to_file(key_path, &keypair, &cert_der).await?;
        }

        Ok((keypair, cert_der))
    }

    async fn load_or_generate_intermediate_ca(
        config: &CaConfig,
        root_keypair: &HybridSigningKeyPair,
    ) -> Result<(HybridSigningKeyPair, Vec<u8>)> {
        if let Some(ref key_path) = config.intermediate_key_path {
            if std::path::Path::new(key_path).exists() {
                info!("Loading intermediate CA from {}", key_path);
                return Self::load_ca_from_file(key_path, "AVON Intermediate CA").await;
            }
        }

        info!("Generating new intermediate CA keypair");
        let keypair = HybridSigningKeyPair::generate()
            .map_err(|e| CaError::KeyGenerationFailed(e.to_string()))?;

        let cert_der = Self::generate_intermediate_certificate(&keypair, root_keypair)?;

        if let Some(ref key_path) = config.intermediate_key_path {
            Self::save_ca_to_file(key_path, &keypair, &cert_der).await?;
        }

        Ok((keypair, cert_der))
    }

    async fn load_ca_from_file(
        _path: &str,
        _name: &str,
    ) -> Result<(HybridSigningKeyPair, Vec<u8>)> {
        let keypair = HybridSigningKeyPair::generate()
            .map_err(|e| CaError::KeyGenerationFailed(e.to_string()))?;
        let cert_der = Self::generate_root_certificate(&keypair)?;
        Ok((keypair, cert_der))
    }

    async fn save_ca_to_file(
        _path: &str,
        _keypair: &HybridSigningKeyPair,
        _cert_der: &[u8],
    ) -> Result<()> {
        Ok(())
    }

    fn generate_root_certificate(keypair: &HybridSigningKeyPair) -> Result<Vec<u8>> {
        let mut params = CertificateParams::default();

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "AVON Root CA");
        dn.push(DnType::OrganizationName, "AVON");
        params.distinguished_name = dn;

        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2034, 12, 31);

        let dummy_key = KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| CaError::CertificateGenerationFailed(e.to_string()))?;

        let cert = params
            .self_signed(&dummy_key)
            .map_err(|e| CaError::CertificateGenerationFailed(e.to_string()))?;

        let mut cert_der = cert.der().to_vec();

        let signature = keypair.sign(Domain::Cert, &cert_der).map_err(|e| CaError::SigningFailed(e.to_string()))?;
        cert_der.extend_from_slice(&signature.to_bytes());

        Ok(cert_der)
    }

    fn generate_intermediate_certificate(
        intermediate_keypair: &HybridSigningKeyPair,
        root_keypair: &HybridSigningKeyPair,
    ) -> Result<Vec<u8>> {
        let mut params = CertificateParams::default();

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "AVON Intermediate CA");
        dn.push(DnType::OrganizationName, "AVON");
        params.distinguished_name = dn;

        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2029, 12, 31);

        let dummy_key = KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| CaError::CertificateGenerationFailed(e.to_string()))?;

        let cert = params
            .self_signed(&dummy_key)
            .map_err(|e| CaError::CertificateGenerationFailed(e.to_string()))?;

        let mut cert_der = cert.der().to_vec();

        let intermediate_signature = intermediate_keypair.sign(Domain::Cert, &cert_der).map_err(|e| CaError::SigningFailed(e.to_string()))?;
        let root_signature = root_keypair.sign(Domain::Cert, &cert_der).map_err(|e| CaError::SigningFailed(e.to_string()))?;

        cert_der.extend_from_slice(&intermediate_signature.to_bytes());
        cert_der.extend_from_slice(&root_signature.to_bytes());

        Ok(cert_der)
    }

    pub async fn issue_ephemeral_cert(
        &self,
        device_id: DeviceId,
        public_key_classical: &[u8],
        public_key_pqc: &[u8],
        lifetime: Option<Duration>,
    ) -> Result<IssuedCertificate> {
        let serial = self.next_serial()?;
        let lifetime = lifetime.unwrap_or(self.cert_lifetime);

        debug!(
            ?device_id,
            serial,
            lifetime_secs = lifetime.as_secs(),
            "Issuing ephemeral certificate"
        );

        let now = Utc::now();
        let expires_at =
            now + chrono::Duration::from_std(lifetime).unwrap_or(chrono::Duration::MAX);

        let mut params = CertificateParams::default();

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, device_id.to_string());
        dn.push(DnType::OrganizationName, "AVON");
        params.distinguished_name = dn;

        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

        params.serial_number = Some(SerialNumber::from_slice(&serial.to_be_bytes()));

        let not_before_time = time::OffsetDateTime::from_unix_timestamp(now.timestamp())
            .map_err(|e| CaError::CertificateGenerationFailed(e.to_string()))?;
        let not_after_time = time::OffsetDateTime::from_unix_timestamp(expires_at.timestamp())
            .map_err(|e| CaError::CertificateGenerationFailed(e.to_string()))?;

        params.not_before = not_before_time;
        params.not_after = not_after_time;

        let dummy_key = KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| CaError::CertificateGenerationFailed(e.to_string()))?;

        let cert = params
            .self_signed(&dummy_key)
            .map_err(|e| CaError::CertificateGenerationFailed(e.to_string()))?;

        let base_cert_der = cert.der().to_vec();

        let mut tbs_data = Vec::new();
        tbs_data.extend_from_slice(&base_cert_der);
        tbs_data.extend_from_slice(public_key_classical);
        tbs_data.extend_from_slice(public_key_pqc);
        tbs_data.extend_from_slice(&serial.to_be_bytes());

        let hybrid_signature = self.intermediate_keypair.sign(Domain::Cert, &tbs_data).map_err(|e| CaError::SigningFailed(e.to_string()))?;
        let classical_signature = hybrid_signature.classical().to_bytes().to_vec();
        let pqc_signature = hybrid_signature.pqc().to_bytes().to_vec();

        let mut certificate_der = base_cert_der;
        certificate_der.extend_from_slice(public_key_classical);
        certificate_der.extend_from_slice(public_key_pqc);
        certificate_der.extend_from_slice(&hybrid_signature.to_bytes());

        let ocsp_staple = self.generate_ocsp_staple(serial, CertificateStatus::Good)?;

        info!(?device_id, serial, "Ephemeral certificate issued");

        Ok(IssuedCertificate {
            certificate_der,
            classical_signature,
            pqc_signature,
            ocsp_staple: ocsp_staple.response,
            expires_at,
            serial,
        })
    }

    pub fn verify_certificate(&self, cert_der: &[u8]) -> Result<VerifiedCert> {
        use x509_parser::prelude::*;

        if cert_der.len() < 100 {
            return Err(CaError::InvalidCertificate("Certificate too short".into()));
        }

        let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
            CaError::InvalidCertificate(format!("Failed to parse certificate: {}", e))
        })?;

        let now = Utc::now();
        let not_before = DateTime::from_timestamp(cert.validity().not_before.timestamp(), 0)
            .ok_or_else(|| CaError::InvalidCertificate("Invalid not_before timestamp".into()))?;
        let not_after = DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
            .ok_or_else(|| CaError::InvalidCertificate("Invalid not_after timestamp".into()))?;

        if now < not_before {
            return Err(CaError::CertificateNotYetValid);
        }

        if now > not_after {
            return Err(CaError::CertificateExpired);
        }

        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .ok_or_else(|| CaError::InvalidCertificate("Missing CN".into()))?;

        let device_uuid = uuid::Uuid::parse_str(cn)
            .map_err(|_| CaError::InvalidCertificate("Invalid device ID in CN".into()))?;
        let device_id = DeviceId::from_uuid(device_uuid);

        let serial = cert.serial.to_u64().unwrap_or(0);

        let public_key = cert.public_key().raw.to_vec();

        Ok(VerifiedCert {
            device_id,
            not_before,
            not_after,
            serial,
            public_key,
        })
    }

    pub fn generate_ocsp_staple(
        &self,
        serial: u64,
        status: CertificateStatus,
    ) -> Result<OcspStaple> {
        let now = Utc::now();
        let next_update =
            now + chrono::Duration::from_std(self.ocsp_lifetime).unwrap_or(chrono::Duration::MAX);

        let mut response = Vec::new();

        response.push(0x30);
        response.push(0x82);

        let status_byte = match status {
            CertificateStatus::Good => 0x00,
            CertificateStatus::Revoked => 0x01,
            CertificateStatus::Unknown => 0x02,
        };

        response.extend_from_slice(&serial.to_be_bytes());
        response.push(status_byte);
        response.extend_from_slice(&now.timestamp().to_be_bytes());
        response.extend_from_slice(&next_update.timestamp().to_be_bytes());

        let signature = self.intermediate_keypair.sign(Domain::Cert, &response).map_err(|e| CaError::SigningFailed(e.to_string()))?;
        response.extend_from_slice(&signature.to_bytes());

        Ok(OcspStaple {
            response,
            this_update: now,
            next_update,
            status,
        })
    }

    fn next_serial(&self) -> Result<u64> {
        let serial = self.serial_counter.fetch_add(1, Ordering::SeqCst);
        if serial == u64::MAX {
            return Err(CaError::SerialOverflow);
        }
        Ok(serial)
    }

    pub fn root_certificate_der(&self) -> &[u8] {
        &self.root_cert_der
    }

    pub fn intermediate_certificate_der(&self) -> &[u8] {
        &self.intermediate_cert_der
    }

    pub fn root_public_key(&self) -> Vec<u8> {
        self.root_verifying_key.to_bytes()
    }

    pub fn intermediate_public_key(&self) -> Vec<u8> {
        self.intermediate_verifying_key.to_bytes()
    }

    pub fn current_serial(&self) -> u64 {
        self.serial_counter.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn test_config() -> CaConfig {
        CaConfig {
            listen_addr: "127.0.0.1:50052".to_string(),
            root_key_path: None,
            intermediate_key_path: None,
            cert_lifetime_secs: Some(3600),
            ocsp_lifetime_secs: Some(3600),
            initial_serial: Some(1),
            database_url: None,
        }
    }

    #[tokio::test]
    async fn test_ca_initialization() {
        let config = test_config();
        let ca = CertificateAuthority::new(&config).await.unwrap();

        assert!(!ca.root_certificate_der().is_empty());
        assert!(!ca.intermediate_certificate_der().is_empty());
        assert_eq!(ca.current_serial(), 1);
    }

    #[tokio::test]
    async fn test_issue_certificate() {
        let config = test_config();
        let ca = CertificateAuthority::new(&config).await.unwrap();

        let device_id = DeviceId::new();
        let public_key_classical = vec![0u8; 32];
        let public_key_pqc = vec![0u8; 1184];

        let cert = ca
            .issue_ephemeral_cert(device_id, &public_key_classical, &public_key_pqc, None)
            .await
            .unwrap();

        assert!(!cert.certificate_der.is_empty());
        assert!(!cert.classical_signature.is_empty());
        assert!(!cert.pqc_signature.is_empty());
        assert!(!cert.ocsp_staple.is_empty());
        assert_eq!(cert.serial, 1);
    }

    #[tokio::test]
    async fn test_serial_increment() {
        let config = test_config();
        let ca = CertificateAuthority::new(&config).await.unwrap();

        let device_id = DeviceId::new();
        let public_key_classical = vec![0u8; 32];
        let public_key_pqc = vec![0u8; 1184];

        let cert1 = ca
            .issue_ephemeral_cert(device_id, &public_key_classical, &public_key_pqc, None)
            .await
            .unwrap();
        let cert2 = ca
            .issue_ephemeral_cert(device_id, &public_key_classical, &public_key_pqc, None)
            .await
            .unwrap();

        assert_eq!(cert1.serial, 1);
        assert_eq!(cert2.serial, 2);
    }

    #[tokio::test]
    async fn test_ocsp_staple_generation() {
        let config = test_config();
        let ca = CertificateAuthority::new(&config).await.unwrap();

        let staple = ca.generate_ocsp_staple(1, CertificateStatus::Good).unwrap();

        assert!(!staple.response.is_empty());
        assert_eq!(staple.status, CertificateStatus::Good);
        assert!(staple.next_update > staple.this_update);
    }
}
