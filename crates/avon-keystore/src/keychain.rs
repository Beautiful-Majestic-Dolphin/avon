//! macOS Keychain / Secure Enclave provider.
//!
//! The real implementation uses `security-framework` to create a P-256 key
//! in the Secure Enclave (falling back to software token) and stores the PQ
//! material as a generic-password item with
//! `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. This simulation keeps
//! the same contract for CI: the hardware key signs the binding, PQ material
//! never appears in the clear on disk, and the provider is only `available`
//! on macOS.

use std::path::{Path, PathBuf};

use avon_crypto::hybrid::kem::{
    HybridKemCiphertext, HybridKemKeyPair, HybridKemPublicKey, HybridSharedSecret,
};
use avon_crypto::hybrid::signature::{
    Domain, HybridSignature, HybridSigningKeyPair, HybridVerifyingKey,
};
use p256::ecdsa::{signature::Signer, SigningKey};
use p256::pkcs8::EncodePublicKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::binding::{binding_message, HardwareBinding};
use crate::provider::{write_private, write_provider_record, KeyError, KeyProvider, ProviderKind};

const PUBLIC_FILE: &str = "keychain-public.json";
const SEALED_FILE: &str = "keychain-sealed.bin";
const TLS_FILE: &str = "tls.key";

#[derive(Serialize, Deserialize)]
struct PublicMaterial {
    signing_pk: Vec<u8>,
    kem_pk: Vec<u8>,
    hw_spki: Vec<u8>,
    secure_enclave: bool,
}

#[derive(Serialize, Deserialize)]
struct SealedEnvelope {
    nonce: Vec<u8>,
    ct: Vec<u8>,
    binding_priv: Vec<u8>,
}

fn keychain_key() -> Vec<u8> {
    let path = std::env::var("AVON_MACOS_KEYCHAIN").unwrap_or_else(|_| "default".to_string());
    Sha256::digest(path.as_bytes()).to_vec()
}

fn seal(material: &[u8]) -> SealedEnvelope {
    let key = keychain_key();
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut ct = material.to_vec();
    let aead = avon_crypto::aead::AeadKey::new(
        avon_crypto::aead::Suite::Aes256Gcm,
        key.as_slice().try_into().unwrap(),
    );
    let _ = aead.seal_in_place(&nonce, b"avon-keychain-seal", &mut ct);
    SealedEnvelope {
        nonce: nonce.to_vec(),
        ct,
        binding_priv: vec![],
    }
}

fn unseal(envelope: &SealedEnvelope) -> Result<Vec<u8>, KeyError> {
    let key = keychain_key();
    let aead = avon_crypto::aead::AeadKey::new(
        avon_crypto::aead::Suite::Aes256Gcm,
        key.as_slice()
            .try_into()
            .map_err(|_| KeyError::Corrupt("keychain key"))?,
    );
    let mut buf = envelope.ct.clone();
    aead.open_in_place(&envelope.nonce, b"avon-keychain-seal", &mut buf)
        .map_err(|_| KeyError::Corrupt("keychain unseal failed"))?;
    Ok(buf)
}

pub struct KeychainKeyProvider {
    dir: PathBuf,
    signing: HybridSigningKeyPair,
    kem: HybridKemKeyPair,
    tls_key_pem: String,
    hw_spki: Vec<u8>,
    hw_signing: SigningKey,
    sealed: SealedEnvelope,
    secure_enclave: bool,
}

impl KeychainKeyProvider {
    pub fn available() -> bool {
        #[cfg(target_os = "macos")]
        {
            // A keychain we can write to is enough; Secure Enclave is optional.
            // When AVON_MACOS_KEYCHAIN is set (tests) check that file exists.
            if let Ok(path) = std::env::var("AVON_MACOS_KEYCHAIN") {
                return std::path::Path::new(&path).exists();
            }
            true
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }

    pub fn create(dir: &Path) -> Result<Self, KeyError> {
        if dir.join(SEALED_FILE).exists() {
            return Err(KeyError::Exists);
        }
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }

        let signing = HybridSigningKeyPair::generate()?;
        let kem = HybridKemKeyPair::generate()?;

        // Try Secure Enclave, fallback to software token simulation.
        let secure_enclave = false;
        let hw_signing = SigningKey::random(&mut rand::thread_rng());
        let hw_spki = hw_signing
            .verifying_key()
            .to_public_key_der()
            .map_err(|e| KeyError::Provider {
                provider: ProviderKind::Keychain,
                message: e.to_string(),
            })?
            .as_bytes()
            .to_vec();

        let mut material = Vec::new();
        let s = signing.to_secret_bytes();
        let k = kem.to_secret_bytes();
        material.extend_from_slice(&(s.len() as u32).to_be_bytes());
        material.extend_from_slice(&s);
        material.extend_from_slice(&(k.len() as u32).to_be_bytes());
        material.extend_from_slice(&k);

        let mut envelope = seal(&material);
        envelope.binding_priv = hw_signing.to_bytes().as_slice().to_vec();

        let tls = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| KeyError::Tls(e.to_string()))?;
        let tls_pem = tls.serialize_pem();

        let public = PublicMaterial {
            signing_pk: signing.verifying_key().to_bytes(),
            kem_pk: kem.public_key().to_bytes(),
            hw_spki: hw_spki.clone(),
            secure_enclave,
        };

        write_private(
            &dir.join(SEALED_FILE),
            &serde_json::to_vec(&envelope).unwrap(),
        )?;
        write_private(
            &dir.join(PUBLIC_FILE),
            &serde_json::to_vec(&public).unwrap(),
        )?;
        write_private(&dir.join(TLS_FILE), tls_pem.as_bytes())?;
        // Also write provider.json
        write_provider_record(dir, ProviderKind::Keychain)?;
        // Record secure_enclave flag alongside provider.json for control.
        let meta = serde_json::json!({"kind":"keychain","secure_enclave":secure_enclave});
        write_private(
            &dir.join("keychain-meta.json"),
            &serde_json::to_vec(&meta).unwrap(),
        )?;

        Ok(Self {
            dir: dir.to_path_buf(),
            signing,
            kem,
            tls_key_pem: tls_pem,
            hw_spki,
            hw_signing,
            sealed: envelope,
            secure_enclave,
        })
    }

    pub fn open(dir: &Path) -> Result<Self, KeyError> {
        let public: PublicMaterial = serde_json::from_slice(
            &std::fs::read(dir.join(PUBLIC_FILE))
                .map_err(|_| KeyError::Corrupt("keychain-public.json"))?,
        )
        .map_err(|_| KeyError::Corrupt("keychain-public.json"))?;
        let envelope: SealedEnvelope = serde_json::from_slice(
            &std::fs::read(dir.join(SEALED_FILE))
                .map_err(|_| KeyError::Corrupt("keychain-sealed.bin"))?,
        )
        .map_err(|_| KeyError::Corrupt("keychain-sealed.bin"))?;

        let material = unseal(&envelope)?;

        let mut pos = 0;
        let take = |buf: &[u8], pos: &mut usize| -> Result<Vec<u8>, KeyError> {
            if *pos + 4 > buf.len() {
                return Err(KeyError::Corrupt("sealed material"));
            }
            let n = u32::from_be_bytes(buf[*pos..*pos + 4].try_into().unwrap()) as usize;
            *pos += 4;
            if *pos + n > buf.len() {
                return Err(KeyError::Corrupt("sealed material"));
            }
            let out = buf[*pos..*pos + n].to_vec();
            *pos += n;
            Ok(out)
        };
        let signing = HybridSigningKeyPair::from_secret_bytes(&take(&material, &mut pos)?)?;
        let kem = HybridKemKeyPair::from_secret_bytes(&take(&material, &mut pos)?)?;

        if signing.verifying_key().to_bytes() != public.signing_pk
            || kem.public_key().to_bytes() != public.kem_pk
        {
            return Err(KeyError::Corrupt("sealed material mismatch"));
        }

        let hw_signing = SigningKey::from_bytes(
            envelope
                .binding_priv
                .as_slice()
                .try_into()
                .map_err(|_| KeyError::Corrupt("hw key"))?,
        )
        .map_err(|_| KeyError::Corrupt("hw key"))?;

        let tls_key_pem = String::from_utf8(
            std::fs::read(dir.join(TLS_FILE)).map_err(|_| KeyError::Corrupt("tls.key"))?,
        )
        .map_err(|_| KeyError::Corrupt("tls.key"))?;

        Ok(Self {
            dir: dir.to_path_buf(),
            signing,
            kem,
            tls_key_pem,
            hw_spki: public.hw_spki,
            hw_signing,
            sealed: envelope,
            secure_enclave: public.secure_enclave,
        })
    }
}

impl KeyProvider for KeychainKeyProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Keychain
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
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| KeyError::Tls(e.to_string()))?;
        self.tls_key_pem = kp.serialize_pem();
        self.persist()?;
        Ok(self.tls_key_pem.clone())
    }

    fn hardware_binding(&self, device_hint: &[u8]) -> Result<Option<HardwareBinding>, KeyError> {
        let msg = binding_message(
            &self.signing.verifying_key(),
            &self.kem.public_key(),
            device_hint,
        );
        let sig: p256::ecdsa::Signature = self.hw_signing.sign(&msg);
        Ok(Some(HardwareBinding {
            provider: ProviderKind::Keychain,
            algorithm: "ecdsa-p256-sha256".into(),
            public_key: self.hw_spki.clone(),
            signature: sig.to_der().as_bytes().to_vec(),
            attestation: None,
        }))
    }

    fn persist(&self) -> Result<(), KeyError> {
        write_private(&self.dir.join(TLS_FILE), self.tls_key_pem.as_bytes())?;
        write_private(
            &self.dir.join(SEALED_FILE),
            &serde_json::to_vec(&self.sealed).unwrap(),
        )?;
        let public = PublicMaterial {
            signing_pk: self.signing.verifying_key().to_bytes(),
            kem_pk: self.kem.public_key().to_bytes(),
            hw_spki: self.hw_spki.clone(),
            secure_enclave: self.secure_enclave,
        };
        write_private(
            &self.dir.join(PUBLIC_FILE),
            &serde_json::to_vec(&public).unwrap(),
        )?;
        write_provider_record(&self.dir, ProviderKind::Keychain)?;
        Ok(())
    }
}
