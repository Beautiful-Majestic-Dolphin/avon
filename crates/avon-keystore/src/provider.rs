use std::path::Path;

use avon_crypto::hybrid::kem::{HybridKemCiphertext, HybridKemPublicKey, HybridSharedSecret};
use avon_crypto::hybrid::signature::{Domain, HybridSignature, HybridVerifyingKey};

pub use avon_crypto::cert::{HardwareBinding, ProviderKind, MAX_BINDING_BYTES};

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto: {0}")]
    Crypto(#[from] avon_crypto::CryptoError),
    #[error("{provider:?} provider unavailable: {reason}")]
    Unavailable {
        provider: ProviderKind,
        reason: String,
    },
    #[error("{provider:?} provider error: {message}")]
    Provider {
        provider: ProviderKind,
        message: String,
    },
    #[error("corrupt keystore state: {0}")]
    Corrupt(&'static str),
    #[error("an identity already exists in this directory")]
    Exists,
    #[error("tls key: {0}")]
    Tls(String),
}

/// The device's key custody. Implementations must never return private key
/// bytes for hardware-resident keys.
pub trait KeyProvider: Send + Sync {
    fn kind(&self) -> ProviderKind;
    fn signing_public(&self) -> HybridVerifyingKey;
    fn kem_public(&self) -> HybridKemPublicKey;
    fn sign(&self, domain: Domain, msg: &[u8]) -> Result<HybridSignature, KeyError>;
    fn decapsulate(&self, ct: &HybridKemCiphertext) -> Result<HybridSharedSecret, KeyError>;
    fn tls_key_pem(&self) -> &str;
    fn rotate_tls_key(&mut self) -> Result<String, KeyError>;
    /// `None` for the software provider; a signed statement for hardware ones.
    fn hardware_binding(&self, device_hint: &[u8]) -> Result<Option<HardwareBinding>, KeyError>;
    /// A fresh attestation quote over `nonce`, when the provider is backed by
    /// hardware that can produce one.
    ///
    /// Returning `None` is the honest answer for everything that cannot: the
    /// control plane records "no evidence" rather than treating a
    /// software-signed statement as proof of a measured boot.
    fn attestation_quote(&self, _nonce: &[u8]) -> Result<Option<Quote>, KeyError> {
        Ok(None)
    }
    fn persist(&self) -> Result<(), KeyError>;
}

/// What a TPM returns from `TPM2_Quote`, carried verbatim so the verifier
/// checks the bytes the TPM signed rather than a re-encoding of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Quote {
    /// The `TPMS_ATTEST` structure.
    pub attest: Vec<u8>,
    /// DER-encoded ECDSA signature over `attest`, made by the attestation key.
    pub signature: Vec<u8>,
    /// SPKI DER of the attestation key's public half.
    pub ak_public: Vec<u8>,
    /// The PCR values the quote covers, so the verifier can recompute the
    /// digest the TPM signed.
    pub pcrs: Vec<(u32, Vec<u8>)>,
}

pub(crate) fn write_private(path: &Path, data: &[u8]) -> Result<(), KeyError> {
    let tmp = path.with_extension("tmp");
    {
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?
        };
        #[cfg(not(unix))]
        let mut f = std::fs::File::create(&tmp)?;
        use std::io::Write;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub(crate) fn write_provider_record(dir: &Path, kind: ProviderKind) -> Result<(), KeyError> {
    let data = serde_json::to_vec(&serde_json::json!({"kind": kind.as_str()}))
        .map_err(|_| KeyError::Corrupt("provider.json"))?;
    write_private(&dir.join("provider.json"), &data)
}

pub(crate) fn read_provider_record(dir: &Path) -> Result<ProviderKind, KeyError> {
    let data = std::fs::read(dir.join("provider.json"))?;
    let v: serde_json::Value =
        serde_json::from_slice(&data).map_err(|_| KeyError::Corrupt("provider.json"))?;
    let s = v
        .get("kind")
        .and_then(|k| k.as_str())
        .ok_or(KeyError::Corrupt("provider.json"))?;
    s.parse::<ProviderKind>()
        .map_err(|_| KeyError::Corrupt("provider.json"))
}
