use std::path::{Path, PathBuf};

use avon_crypto::aead::{AeadKey, Suite};
use avon_crypto::hybrid::kem::{
    HybridKemCiphertext, HybridKemKeyPair, HybridKemPublicKey, HybridSharedSecret,
};
use avon_crypto::hybrid::signature::{
    Domain, HybridSignature, HybridSigningKeyPair, HybridVerifyingKey,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::provider::{
    write_private, write_provider_record, HardwareBinding, KeyError, KeyProvider, ProviderKind,
};

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

impl SoftwareKeyProvider {
    pub fn create(dir: &Path) -> Result<Self, KeyError> {
        if dir.join("identity.bin").exists() {
            return Err(KeyError::Exists);
        }
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let tls_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| KeyError::Tls(e.to_string()))?;
        let me = Self {
            signing: HybridSigningKeyPair::generate()?,
            kem: HybridKemKeyPair::generate()?,
            tls_key_pem: tls_key.serialize_pem(),
            dir: dir.to_path_buf(),
        };
        me.persist()?;
        Ok(me)
    }

    pub fn open(dir: &Path) -> Result<Self, KeyError> {
        let key: [u8; 32] = {
            let data = Zeroizing::new(std::fs::read(dir.join("identity.key"))?);
            data.as_slice()
                .try_into()
                .map_err(|_| KeyError::Corrupt("identity.key"))?
        };
        let blob = std::fs::read(dir.join("identity.bin"))?;
        if blob.len() < 28 {
            return Err(KeyError::Corrupt("identity.bin"));
        }
        let nonce: [u8; 12] = blob[..12]
            .try_into()
            .map_err(|_| KeyError::Corrupt("nonce"))?;
        let mut buf = Zeroizing::new(blob[12..].to_vec());
        AeadKey::new(Suite::Aes256Gcm, &key)
            .open_in_place(&nonce, b"avon-identity-v2", &mut buf)
            .map_err(|_| KeyError::Corrupt("identity.bin"))?;
        let stored: Stored =
            serde_json::from_slice(&buf).map_err(|_| KeyError::Corrupt("decode"))?;
        Ok(Self {
            signing: HybridSigningKeyPair::from_secret_bytes(&stored.signing)?,
            kem: HybridKemKeyPair::from_secret_bytes(&stored.kem)?,
            tls_key_pem: stored.tls_key_pem,
            dir: dir.to_path_buf(),
        })
    }

    fn save_inner(&self) -> Result<(), KeyError> {
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
                .map_err(|_| KeyError::Corrupt("identity.key"))?
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
        let mut buf =
            Zeroizing::new(serde_json::to_vec(&stored).map_err(|_| KeyError::Corrupt("encode"))?);
        let nonce = avon_crypto::random::random_bytes_fixed::<12>()?;
        AeadKey::new(Suite::Aes256Gcm, &key).seal_in_place(
            &nonce,
            b"avon-identity-v2",
            &mut buf,
        )?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&buf);
        write_private(&self.dir.join("identity.bin"), &out)?;
        write_provider_record(&self.dir, ProviderKind::Software)?;
        Ok(())
    }
}

impl KeyProvider for SoftwareKeyProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Software
    }

    fn signing_public(&self) -> HybridVerifyingKey {
        self.signing.verifying_key()
    }

    fn kem_public(&self) -> HybridKemPublicKey {
        self.kem.public_key()
    }

    fn sign(&self, domain: Domain, msg: &[u8]) -> Result<HybridSignature, KeyError> {
        Ok(self.signing.sign(domain, msg)?)
    }

    fn decapsulate(&self, ct: &HybridKemCiphertext) -> Result<HybridSharedSecret, KeyError> {
        Ok(self.kem.decapsulate(ct)?)
    }

    fn tls_key_pem(&self) -> &str {
        &self.tls_key_pem
    }

    fn rotate_tls_key(&mut self) -> Result<String, KeyError> {
        let k = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| KeyError::Tls(e.to_string()))?;
        self.tls_key_pem = k.serialize_pem();
        self.persist()?;
        Ok(self.tls_key_pem.clone())
    }

    fn hardware_binding(&self, _device_hint: &[u8]) -> Result<Option<HardwareBinding>, KeyError> {
        Ok(None)
    }

    fn persist(&self) -> Result<(), KeyError> {
        self.save_inner()
    }
}
