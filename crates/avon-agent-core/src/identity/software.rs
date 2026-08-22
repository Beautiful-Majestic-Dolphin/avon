use std::path::{Path, PathBuf};

use avon_crypto::aead::{AeadKey, Suite};
use avon_crypto::hybrid::kem::HybridKemKeyPair;
use avon_crypto::hybrid::signature::HybridSigningKeyPair;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::IdentityError;
use crate::traits::KeyProvider;

/// Keys at rest: `identity.bin` = nonce || AES-256-GCM(serialized keys) under
/// the 32-byte key in `identity.key`. Both files 0600 in a 0700 directory.
/// This provider protects against other users on the machine, not against a
/// root-level compromise; hardware-backed providers (phase 5) do.
pub struct SoftwareKeyProvider {
    signing: HybridSigningKeyPair,
    kem: HybridKemKeyPair,
    tls_key_pem: String,
    dir: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct Stored {
    signing: Vec<u8>,
    kem: Vec<u8>,
    tls_key_pem: String,
}

fn write_private(path: &Path, data: &[u8]) -> Result<(), IdentityError> {
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

impl SoftwareKeyProvider {
    pub fn generate(dir: &Path) -> Result<Self, IdentityError> {
        let tls_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| IdentityError::Tls(e.to_string()))?;
        Ok(Self {
            signing: HybridSigningKeyPair::generate()?,
            kem: HybridKemKeyPair::generate()?,
            tls_key_pem: tls_key.serialize_pem(),
            dir: dir.to_path_buf(),
        })
    }

    pub fn save(&self) -> Result<(), IdentityError> {
        std::fs::create_dir_all(&self.dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let key_path = self.dir.join("identity.key");
        let key: [u8; 32] = if key_path.exists() {
            let data = Zeroizing::new(std::fs::read(&key_path)?);
            data.as_slice()
                .try_into()
                .map_err(|_| IdentityError::Corrupt("identity.key"))?
        } else {
            let k = avon_crypto::random::random_bytes_fixed::<32>()?;
            write_private(&key_path, &k)?;
            k
        };
        let stored = Stored {
            signing: self.signing.to_secret_bytes().to_vec(),
            kem: self.kem.to_secret_bytes().to_vec(),
            tls_key_pem: self.tls_key_pem.clone(),
        };
        let mut buf = Zeroizing::new(
            serde_json::to_vec(&stored).map_err(|_| IdentityError::Corrupt("encode"))?,
        );
        let nonce = avon_crypto::random::random_bytes_fixed::<12>()?;
        AeadKey::new(Suite::Aes256Gcm, &key).seal_in_place(
            &nonce,
            b"avon-identity-v2",
            &mut buf,
        )?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&buf);
        write_private(&self.dir.join("identity.bin"), &out)
    }

    pub fn load(dir: &Path) -> Result<Self, IdentityError> {
        let key: [u8; 32] = {
            let data = Zeroizing::new(std::fs::read(dir.join("identity.key"))?);
            data.as_slice()
                .try_into()
                .map_err(|_| IdentityError::Corrupt("identity.key"))?
        };
        let blob = std::fs::read(dir.join("identity.bin"))?;
        if blob.len() < 28 {
            return Err(IdentityError::Corrupt("identity.bin"));
        }
        let nonce: [u8; 12] = blob[..12]
            .try_into()
            .map_err(|_| IdentityError::Corrupt("nonce"))?;
        let mut buf = Zeroizing::new(blob[12..].to_vec());
        AeadKey::new(Suite::Aes256Gcm, &key).open_in_place(
            &nonce,
            b"avon-identity-v2",
            &mut buf,
        )?;
        let stored: Stored =
            serde_json::from_slice(&buf).map_err(|_| IdentityError::Corrupt("decode"))?;
        Ok(Self {
            signing: HybridSigningKeyPair::from_secret_bytes(&stored.signing)?,
            kem: HybridKemKeyPair::from_secret_bytes(&stored.kem)?,
            tls_key_pem: stored.tls_key_pem,
            dir: dir.to_path_buf(),
        })
    }
}

impl KeyProvider for SoftwareKeyProvider {
    fn name(&self) -> &'static str {
        "software"
    }
    fn signing(&self) -> &HybridSigningKeyPair {
        &self.signing
    }
    fn kem(&self) -> &HybridKemKeyPair {
        &self.kem
    }
    fn tls_key_pem(&self) -> &str {
        &self.tls_key_pem
    }
    fn rotate_tls_key(&mut self) -> Result<String, IdentityError> {
        let k = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| IdentityError::Tls(e.to_string()))?;
        self.tls_key_pem = k.serialize_pem();
        self.save()?;
        Ok(self.tls_key_pem.clone())
    }
}
