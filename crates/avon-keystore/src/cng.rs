//! Windows CNG / DPAPI-NG provider (simulation for non-Windows CI).
//!
//! The real provider uses `NCryptCreatePersistedKey` with
//! `MS_PLATFORM_CRYPTO_PROVIDER` (TPM-backed) or `MS_KEY_STORAGE_PROVIDER`
//! and wraps PQ material with `NCryptProtectSecret` (`LOCAL=machine`).
//! This file simulates the same on-disk contract: PQ material is DPAPI-NG-
//! wrapped, 0600/ACL-restricted, and the binding is signed by a P-256 key.

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

const PUBLIC_FILE: &str = "cng-public.json";
const SEALED_FILE: &str = "cng-sealed.bin";
const TLS_FILE: &str = "tls.key";

#[derive(Serialize, Deserialize)]
struct PublicMaterial {
    signing_pk: Vec<u8>,
    kem_pk: Vec<u8>,
    hw_spki: Vec<u8>,
    platform_crypto: bool,
}

#[derive(Serialize, Deserialize)]
struct SealedEnvelope {
    nonce: Vec<u8>,
    ct: Vec<u8>,
    binding_priv: Vec<u8>,
}

fn machine_key() -> Vec<u8> {
    // DPAPI-NG descriptor is LOCAL=machine — machine-bound.
    // Simulate with a key derived from machine-id or a fixed fallback.
    let id = std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .unwrap_or_else(|_| "avon-cng-sim".to_string());
    Sha256::digest(id.trim().as_bytes()).to_vec()
}

fn seal(material: &[u8]) -> SealedEnvelope {
    let key = machine_key();
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut ct = material.to_vec();
    let aead = avon_crypto::aead::AeadKey::new(
        avon_crypto::aead::Suite::Aes256Gcm,
        key.as_slice().try_into().unwrap(),
    );
    let _ = aead.seal_in_place(&nonce, b"avon-cng-seal", &mut ct);
    SealedEnvelope {
        nonce: nonce.to_vec(),
        ct,
        binding_priv: vec![],
    }
}

fn unseal(envelope: &SealedEnvelope) -> Result<Vec<u8>, KeyError> {
    let key = machine_key();
    let aead = avon_crypto::aead::AeadKey::new(
        avon_crypto::aead::Suite::Aes256Gcm,
        key.as_slice()
            .try_into()
            .map_err(|_| KeyError::Corrupt("cng key"))?,
    );
    let mut buf = envelope.ct.clone();
    aead.open_in_place(&envelope.nonce, b"avon-cng-seal", &mut buf)
        .map_err(|_| KeyError::Corrupt("cng unseal failed"))?;
    Ok(buf)
}

pub struct CngKeyProvider {
    dir: PathBuf,
    signing: HybridSigningKeyPair,
    kem: HybridKemKeyPair,
    tls_key_pem: String,
    hw_spki: Vec<u8>,
    hw_signing: SigningKey,
    sealed: SealedEnvelope,
    platform_crypto: bool,
}

impl CngKeyProvider {
    pub fn available() -> bool {
        #[cfg(target_os = "windows")]
        {
            true
        }
        #[cfg(not(target_os = "windows"))]
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
        let hw_signing = SigningKey::random(&mut rand::thread_rng());
        let hw_spki = hw_signing
            .verifying_key()
            .to_public_key_der()
            .map_err(|e| KeyError::Provider {
                provider: ProviderKind::Cng,
                message: e.to_string(),
            })?
            .as_bytes()
            .to_vec();
        let platform_crypto = false;

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
            platform_crypto,
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
        write_provider_record(dir, ProviderKind::Cng)?;
        let meta = serde_json::json!({"kind":"cng","platform_crypto":platform_crypto});
        write_private(
            &dir.join("cng-meta.json"),
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
            platform_crypto,
        })
    }

    pub fn open(dir: &Path) -> Result<Self, KeyError> {
        let public: PublicMaterial = serde_json::from_slice(
            &std::fs::read(dir.join(PUBLIC_FILE))
                .map_err(|_| KeyError::Corrupt("cng-public.json"))?,
        )
        .map_err(|_| KeyError::Corrupt("cng-public.json"))?;
        let envelope: SealedEnvelope = serde_json::from_slice(
            &std::fs::read(dir.join(SEALED_FILE))
                .map_err(|_| KeyError::Corrupt("cng-sealed.bin"))?,
        )
        .map_err(|_| KeyError::Corrupt("cng-sealed.bin"))?;

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
            platform_crypto: public.platform_crypto,
        })
    }
}

impl KeyProvider for CngKeyProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Cng
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
            provider: ProviderKind::Cng,
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
            platform_crypto: self.platform_crypto,
        };
        write_private(
            &self.dir.join(PUBLIC_FILE),
            &serde_json::to_vec(&public).unwrap(),
        )?;
        write_provider_record(&self.dir, ProviderKind::Cng)?;
        Ok(())
    }
}
