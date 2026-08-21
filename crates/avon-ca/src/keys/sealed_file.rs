use std::path::Path;

use async_trait::async_trait;
use avon_crypto::aead::{AeadKey, Suite};
use zeroize::Zeroizing;

use super::provider::{KeyError, SealProvider};

/// AES-256-GCM under a 32-byte master key stored in a 0600 file.
/// Blob layout: nonce(12) || ciphertext || tag(16); AAD = key_id.
pub struct SealedFileProvider {
    key: AeadKey,
}

impl SealedFileProvider {
    pub fn generate_master_key(path: &Path) -> Result<(), KeyError> {
        let key = avon_crypto::random::random_bytes_fixed::<32>().map_err(|_| KeyError::Random)?;
        write_private(path, &key)?;
        Ok(())
    }

    pub fn from_file(path: &Path) -> Result<Self, KeyError> {
        check_permissions(path)?;
        let bytes = Zeroizing::new(std::fs::read(path)?);
        let key: &[u8; 32] = bytes.as_slice().try_into().map_err(|_| KeyError::Unseal)?;
        Ok(Self {
            key: AeadKey::new(Suite::Aes256Gcm, key),
        })
    }
}

#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> Result<(), KeyError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> Result<(), KeyError> {
    std::fs::write(path, data)?;
    Ok(())
}

#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<(), KeyError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(KeyError::Permissions(format!(
            "{} is mode {mode:o}; expected 0600",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<(), KeyError> {
    Ok(())
}

#[async_trait]
impl SealProvider for SealedFileProvider {
    fn name(&self) -> &'static str {
        "sealed-file"
    }

    async fn seal(&self, key_id: &[u8; 32], secret: &[u8]) -> Result<Vec<u8>, KeyError> {
        let nonce =
            avon_crypto::random::random_bytes_fixed::<12>().map_err(|_| KeyError::Random)?;
        let mut buf = secret.to_vec();
        self.key
            .seal_in_place(&nonce, key_id, &mut buf)
            .map_err(|_| KeyError::Unseal)?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&buf);
        Ok(out)
    }

    async fn unseal(
        &self,
        key_id: &[u8; 32],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        if sealed.len() < 12 + 16 {
            return Err(KeyError::Unseal);
        }
        let nonce: [u8; 12] = sealed[..12].try_into().map_err(|_| KeyError::Unseal)?;
        let mut buf = Zeroizing::new(sealed[12..].to_vec());
        self.key
            .open_in_place(&nonce, key_id, &mut buf)
            .map_err(|_| KeyError::Unseal)?;
        Ok(buf)
    }
}
