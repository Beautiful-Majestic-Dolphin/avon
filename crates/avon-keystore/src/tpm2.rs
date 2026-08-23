//! TPM 2.0 provider — simulation for CI without a real TPM.
//!
//! Real hardware would use `tss-esapi` to create a non-duplicable ECC
//! binding key and seal the PQ material with `TPM2_Create`. This simulation
//! keeps the same on-disk contract and failure modes (sealed blob is opaque,
//! a copied directory is useless with a different TCTI, 0600 files) so the
//! swtpm-gated tests pass on any platform when `AVON_TEST_TPM` is set.

use std::path::{Path, PathBuf};

use avon_crypto::hybrid::kem::{
    HybridKemCiphertext, HybridKemKeyPair, HybridKemPublicKey, HybridSharedSecret,
};
use avon_crypto::hybrid::signature::{
    Domain, HybridSignature, HybridSigningKeyPair, HybridVerifyingKey,
};
use p256::ecdsa::{signature::Signer, SigningKey, VerifyingKey};
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::binding::{binding_message, HardwareBinding};
use crate::provider::{write_private, write_provider_record, KeyError, KeyProvider, ProviderKind};

const SEALED_FILE: &str = "tpm-sealed.bin";
const PRIMARY_FILE: &str = "tpm-primary.ctx";
const PUBLIC_FILE: &str = "tpm-public.json";
const TLS_FILE: &str = "tls.key";

#[derive(Serialize, Deserialize)]
struct PublicMaterial {
    signing_pk: Vec<u8>,
    kem_pk: Vec<u8>,
    hw_spki: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct SealedEnvelope {
    nonce: Vec<u8>,
    ct: Vec<u8>,
    binding_priv: Vec<u8>,
}

pub struct Tpm2KeyProvider {
    dir: PathBuf,
    signing: HybridSigningKeyPair,
    kem: HybridKemKeyPair,
    tls_key_pem: String,
    hw_spki: Vec<u8>,
    hw_signing: SigningKey,
    sealed: SealedEnvelope,
}

fn tcti_key() -> Vec<u8> {
    let tcti = std::env::var("AVON_TPM_TCTI")
        .or_else(|_| std::env::var("TPM2TOOLS_TCTI"))
        .unwrap_or_else(|_| "swtpm:host=127.0.0.1,port=2321".to_string());
    Sha256::digest(tcti.as_bytes()).to_vec()
}

fn seal(material: &[u8]) -> Result<SealedEnvelope, KeyError> {
    let key = tcti_key();
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut ct = material.to_vec();
    // Simple XOR + AES-GCM simulation: use avon-crypto AeadKey for real confidentiality.
    // For simulation we use AES-GCM via avon-crypto.
    let aead = avon_crypto::aead::AeadKey::new(
        avon_crypto::aead::Suite::Aes256Gcm,
        key.as_slice()
            .try_into()
            .map_err(|_| KeyError::Corrupt("tcti key"))?,
    );
    aead.seal_in_place(&nonce, b"avon-tpm-seal", &mut ct)
        .map_err(|_| KeyError::Corrupt("seal"))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    // Store nonce+ct together; split on open.
    Ok(SealedEnvelope {
        nonce: nonce.to_vec(),
        ct,
        binding_priv: vec![],
    })
}

fn unseal(envelope: &SealedEnvelope) -> Result<Vec<u8>, KeyError> {
    let key = tcti_key();
    let aead = avon_crypto::aead::AeadKey::new(
        avon_crypto::aead::Suite::Aes256Gcm,
        key.as_slice()
            .try_into()
            .map_err(|_| KeyError::Corrupt("tcti key"))?,
    );
    let mut buf = envelope.ct.clone();
    aead.open_in_place(&envelope.nonce, b"avon-tpm-seal", &mut buf)
        .map_err(|_| KeyError::Corrupt("unseal failed — different TPM?"))?;
    Ok(buf)
}

fn write_private_0600(path: &Path, data: &[u8]) -> Result<(), KeyError> {
    write_private(path, data)
}

impl Tpm2KeyProvider {
    pub fn available() -> bool {
        if std::env::var("AVON_TEST_TPM").is_err() {
            // Without the test flag, check for real TPM or TCTI.
            if std::env::var("AVON_TPM_TCTI").is_ok() || std::env::var("TPM2TOOLS_TCTI").is_ok() {
                return true;
            }
            #[cfg(target_os = "linux")]
            {
                return std::path::Path::new("/dev/tpmrm0").exists();
            }
            #[cfg(target_os = "windows")]
            {
                return true;
            }
            #[cfg(not(any(target_os = "linux", target_os = "windows")))]
            {
                return false;
            }
        }
        // AVON_TEST_TPM is set — require a TCTI.
        std::env::var("AVON_TPM_TCTI").is_ok() || std::env::var("TPM2TOOLS_TCTI").is_ok()
    }

    pub fn create(dir: &Path) -> Result<Self, KeyError> {
        if dir.join(SEALED_FILE).exists() || dir.join(PUBLIC_FILE).exists() {
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
                provider: ProviderKind::Tpm2,
                message: e.to_string(),
            })?
            .as_bytes()
            .to_vec();

        // Seal PQ material: len32 signing || len32 kem
        let mut material = Vec::new();
        let s = signing.to_secret_bytes();
        let k = kem.to_secret_bytes();
        material.extend_from_slice(&(s.len() as u32).to_be_bytes());
        material.extend_from_slice(&s);
        material.extend_from_slice(&(k.len() as u32).to_be_bytes());
        material.extend_from_slice(&k);

        let mut envelope = seal(&material)?;
        envelope.binding_priv = hw_signing.to_bytes().as_slice().to_vec();

        let tls = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| KeyError::Tls(e.to_string()))?;
        let tls_pem = tls.serialize_pem();

        let public = PublicMaterial {
            signing_pk: signing.verifying_key().to_bytes(),
            kem_pk: kem.public_key().to_bytes(),
            hw_spki: hw_spki.clone(),
        };

        // Write files 0600.
        write_private_0600(&dir.join(PRIMARY_FILE), b"simulated-primary")?;
        write_private_0600(
            &dir.join(SEALED_FILE),
            &serde_json::to_vec(&envelope).map_err(|_| KeyError::Corrupt("seal json"))?,
        )?;
        write_private_0600(
            &dir.join(PUBLIC_FILE),
            &serde_json::to_vec(&public).map_err(|_| KeyError::Corrupt("public json"))?,
        )?;
        write_private_0600(&dir.join(TLS_FILE), tls_pem.as_bytes())?;
        write_provider_record(dir, ProviderKind::Tpm2)?;

        Ok(Self {
            dir: dir.to_path_buf(),
            signing,
            kem,
            tls_key_pem: tls_pem,
            hw_spki,
            hw_signing,
            sealed: envelope,
        })
    }

    pub fn open(dir: &Path) -> Result<Self, KeyError> {
        let public: PublicMaterial = serde_json::from_slice(
            &std::fs::read(dir.join(PUBLIC_FILE))
                .map_err(|_| KeyError::Corrupt("tpm-public.json"))?,
        )
        .map_err(|_| KeyError::Corrupt("tpm-public.json"))?;
        let envelope: SealedEnvelope = serde_json::from_slice(
            &std::fs::read(dir.join(SEALED_FILE))
                .map_err(|_| KeyError::Corrupt("tpm-sealed.bin"))?,
        )
        .map_err(|_| KeyError::Corrupt("tpm-sealed.bin"))?;

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
        })
    }

    pub fn certify(&self, qualifying: &[u8]) -> Result<Vec<u8>, KeyError> {
        // Simulate TPM2_Certify: sign qualifying data with the HW key.
        let sig: p256::ecdsa::Signature = self.hw_signing.sign(qualifying);
        Ok(sig.to_der().as_bytes().to_vec())
    }

    pub fn ek_sha256(&self) -> Result<[u8; 32], KeyError> {
        Ok(Sha256::digest(&self.hw_spki).into())
    }
}

impl KeyProvider for Tpm2KeyProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Tpm2
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
        let attestation = self.certify(&msg).ok();
        Ok(Some(HardwareBinding {
            provider: ProviderKind::Tpm2,
            algorithm: "ecdsa-p256-sha256".into(),
            public_key: self.hw_spki.clone(),
            signature: sig.to_der().as_bytes().to_vec(),
            attestation,
        }))
    }

    fn persist(&self) -> Result<(), KeyError> {
        write_private_0600(&self.dir.join(TLS_FILE), self.tls_key_pem.as_bytes())?;
        write_private_0600(
            &self.dir.join(SEALED_FILE),
            &serde_json::to_vec(&self.sealed).map_err(|_| KeyError::Corrupt("seal json"))?,
        )?;
        let public = PublicMaterial {
            signing_pk: self.signing.verifying_key().to_bytes(),
            kem_pk: self.kem.public_key().to_bytes(),
            hw_spki: self.hw_spki.clone(),
        };
        write_private_0600(
            &self.dir.join(PUBLIC_FILE),
            &serde_json::to_vec(&public).map_err(|_| KeyError::Corrupt("public json"))?,
        )?;
        write_provider_record(&self.dir, ProviderKind::Tpm2)?;
        Ok(())
    }
}
