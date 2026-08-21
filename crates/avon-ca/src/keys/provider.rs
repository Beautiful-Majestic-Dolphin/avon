use async_trait::async_trait;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("key material could not be unsealed")]
    Unseal,
    #[error("key provider io: {0}")]
    Io(#[from] std::io::Error),
    #[error("database: {0}")]
    Db(#[source] sqlx::Error),
    #[error("CA is not initialized; run `avon-ca init`")]
    NotInitialized,
    #[error("missing CA key: {0}")]
    Missing(String),
    #[error("x509: {0}")]
    X509(String),
    #[error("randomness unavailable")]
    Random,
    #[error("master key file has insecure permissions: {0}")]
    Permissions(String),
}

/// Seals and unseals CA private keys. Implementations: sealed file (this
/// phase), KMS and PKCS#11 (phase 6).
#[async_trait]
pub trait SealProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn seal(&self, key_id: &[u8; 32], secret: &[u8]) -> Result<Vec<u8>, KeyError>;
    async fn unseal(
        &self,
        key_id: &[u8; 32],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyError>;
}
