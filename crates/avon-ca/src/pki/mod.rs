mod hybrid;
mod x509;

pub use hybrid::{
    verify_csr, CsrData, Issued, Issuer, DEVICE_LIFETIME_SECS, SERVICE_LIFETIME_SECS,
};

#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    #[error("csr proof of possession failed")]
    CsrProof,
    #[error("csr template invalid: {0}")]
    CsrTemplate(String),
    #[error("x509: {0}")]
    X509(String),
    #[error("crypto: {0}")]
    Crypto(#[from] avon_crypto::CryptoError),
    #[error("cert: {0}")]
    Cert(#[from] avon_crypto::cert::CertError),
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("randomness unavailable")]
    Random,
}

pub use crate::store::store_issued;
