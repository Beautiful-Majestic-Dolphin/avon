//! Software-based keystore for identity management.
//!
//! Provides encrypted key storage when TPM is not available.
//! Keys are encrypted using a key derived from the hardware fingerprint.

use std::path::Path;

use anyhow::{Context, Result};
use avon_crypto::aead::Aes256GcmCipher;
use avon_crypto::kdf::hkdf_sha256;
use avon_crypto::signature::{Ed25519KeyPair, Ed25519VerifyingKey};
use avon_crypto::token::RotatingToken;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::hardware::HardwareFingerprint;

const KEYSTORE_VERSION: u8 = 1;
const ENCRYPTION_SALT: &[u8] = b"avon-keystore-encryption-v1";
const TOKEN_ENCRYPTION_SALT: &[u8] = b"avon-token-encryption-v1";

#[derive(Serialize, Deserialize)]
struct KeystoreData {
    version: u8,
    nonce: [u8; 12],
    encrypted_seed: Vec<u8>,
    public_key: Vec<u8>,
}

pub struct SoftwareKeystore {
    keypair: Ed25519KeyPair,
    seed: [u8; 32],
    encryption_key: Zeroizing<[u8; 32]>,
}

impl SoftwareKeystore {
    pub fn create(path: &Path, fingerprint: &HardwareFingerprint) -> Result<Self> {
        let encryption_key = Self::derive_encryption_key(fingerprint)?;

        let seed: [u8; 32] = rand::random();
        let keypair = Ed25519KeyPair::from_seed(&seed)
            .context("Failed to generate signing keypair")?;

        let keystore = Self {
            keypair,
            seed,
            encryption_key,
        };

        keystore.save(path)?;

        tracing::info!(path = %path.display(), "Software keystore created");

        Ok(keystore)
    }

    pub fn load(path: &Path, fingerprint: &HardwareFingerprint) -> Result<Self> {
        let encryption_key = Self::derive_encryption_key(fingerprint)?;

        let data = std::fs::read(path)
            .context("Failed to read keystore file")?;

        let keystore_data: KeystoreData = serde_json::from_slice(&data)
            .context("Failed to parse keystore data")?;

        if keystore_data.version != KEYSTORE_VERSION {
            anyhow::bail!(
                "Unsupported keystore version: {} (expected {})",
                keystore_data.version,
                KEYSTORE_VERSION
            );
        }

        let cipher = Aes256GcmCipher::new(encryption_key.as_ref())
            .context("Failed to create AEAD cipher")?;

        let decrypted = cipher.decrypt(&keystore_data.nonce, &keystore_data.encrypted_seed, &[])
            .context("Failed to decrypt keystore (hardware fingerprint may have changed)")?;

        if decrypted.len() != 32 {
            anyhow::bail!("Invalid seed length in keystore");
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&decrypted);

        let keypair = Ed25519KeyPair::from_seed(&seed)
            .context("Failed to restore keypair from seed")?;

        tracing::info!(path = %path.display(), "Software keystore loaded");

        Ok(Self {
            keypair,
            seed,
            encryption_key,
        })
    }

    fn save(&self, path: &Path) -> Result<()> {
        let nonce_bytes: [u8; 12] = rand::random();
        let cipher = Aes256GcmCipher::new(self.encryption_key.as_ref())
            .context("Failed to create AEAD cipher")?;

        let encrypted = cipher.encrypt(&nonce_bytes, &self.seed, &[])
            .context("Failed to encrypt seed")?;

        let keystore_data = KeystoreData {
            version: KEYSTORE_VERSION,
            nonce: nonce_bytes,
            encrypted_seed: encrypted,
            public_key: self.keypair.verifying_key().to_bytes().to_vec(),
        };

        let json = serde_json::to_vec_pretty(&keystore_data)
            .context("Failed to serialize keystore")?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create keystore directory")?;
        }

        std::fs::write(path, &json)
            .context("Failed to write keystore file")?;

        Ok(())
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let signature = self.keypair.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    pub fn verifying_key(&self) -> &Ed25519VerifyingKey {
        self.keypair.verifying_key()
    }

    pub fn encrypt_token(&self, token: &RotatingToken) -> Result<Vec<u8>> {
        let token_bytes = token.current();

        let token_key = Self::derive_token_key(&self.encryption_key)?;
        let nonce_bytes: [u8; 12] = rand::random();

        let cipher = Aes256GcmCipher::new(&token_key)
            .context("Failed to create AEAD cipher for token")?;

        let encrypted = cipher.encrypt(&nonce_bytes, token_bytes, &[])
            .context("Failed to encrypt token")?;

        let mut result = Vec::with_capacity(12 + encrypted.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&encrypted);

        Ok(result)
    }

    pub fn decrypt_token(&self, encrypted_data: &[u8]) -> Result<RotatingToken> {
        if encrypted_data.len() < 12 {
            anyhow::bail!("Encrypted token data too short");
        }

        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce_array: [u8; 12] = nonce_bytes.try_into()
            .context("Invalid nonce length")?;

        let token_key = Self::derive_token_key(&self.encryption_key)?;

        let cipher = Aes256GcmCipher::new(&token_key)
            .context("Failed to create AEAD cipher for token")?;

        let decrypted = cipher.decrypt(&nonce_array, ciphertext, &[])
            .context("Failed to decrypt token")?;

        if decrypted.len() != 32 {
            anyhow::bail!("Invalid token length");
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&decrypted);

        Ok(RotatingToken::new(seed))
    }

    fn derive_encryption_key(fingerprint: &HardwareFingerprint) -> Result<Zeroizing<[u8; 32]>> {
        let fingerprint_hash = fingerprint.to_hash();
        let key_vec = hkdf_sha256(&fingerprint_hash, Some(ENCRYPTION_SALT), b"keystore-encryption", 32)
            .context("Failed to derive encryption key")?;
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_vec);
        Ok(Zeroizing::new(key))
    }

    fn derive_token_key(base_key: &[u8; 32]) -> Result<[u8; 32]> {
        let key_vec = hkdf_sha256(base_key, Some(TOKEN_ENCRYPTION_SALT), b"token-encryption", 32)
            .context("Failed to derive token key")?;
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_vec);
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_fingerprint() -> HardwareFingerprint {
        HardwareFingerprint {
            cpu_id: Some("test-cpu".to_string()),
            motherboard_uuid: Some("test-uuid".to_string()),
            disk_serials: vec!["disk1".to_string()],
            mac_addresses: vec!["00:11:22:33:44:55".to_string()],
            tpm_ek_hash: None,
            hostname: Some("test-host".to_string()),
            os_name: Some("test-os".to_string()),
        }
    }

    #[test]
    fn test_keystore_create_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let keystore_path = temp_dir.path().join("keystore.enc");
        let fingerprint = test_fingerprint();

        let keystore1 = SoftwareKeystore::create(&keystore_path, &fingerprint).unwrap();
        let keystore2 = SoftwareKeystore::load(&keystore_path, &fingerprint).unwrap();

        assert_eq!(
            keystore1.verifying_key().to_bytes(),
            keystore2.verifying_key().to_bytes()
        );
    }

    #[test]
    fn test_keystore_sign_verify() {
        let temp_dir = TempDir::new().unwrap();
        let keystore_path = temp_dir.path().join("keystore.enc");
        let fingerprint = test_fingerprint();

        let keystore = SoftwareKeystore::create(&keystore_path, &fingerprint).unwrap();

        let data = b"test data to sign";
        let signature = keystore.sign(data).unwrap();

        assert!(!signature.is_empty());
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn test_token_encrypt_decrypt() {
        let temp_dir = TempDir::new().unwrap();
        let keystore_path = temp_dir.path().join("keystore.enc");
        let fingerprint = test_fingerprint();

        let keystore = SoftwareKeystore::create(&keystore_path, &fingerprint).unwrap();

        let seed = [42u8; 32];
        let token = RotatingToken::new(seed);

        let encrypted = keystore.encrypt_token(&token).unwrap();
        let decrypted = keystore.decrypt_token(&encrypted).unwrap();

        assert_eq!(token.sequence(), decrypted.sequence());
    }

    #[test]
    fn test_keystore_wrong_fingerprint_fails() {
        let temp_dir = TempDir::new().unwrap();
        let keystore_path = temp_dir.path().join("keystore.enc");
        let fingerprint1 = test_fingerprint();

        SoftwareKeystore::create(&keystore_path, &fingerprint1).unwrap();

        let fingerprint2 = HardwareFingerprint {
            cpu_id: Some("different-cpu".to_string()),
            motherboard_uuid: Some("different-uuid".to_string()),
            disk_serials: vec![],
            mac_addresses: vec![],
            tpm_ek_hash: None,
            hostname: None,
            os_name: None,
        };

        let result = SoftwareKeystore::load(&keystore_path, &fingerprint2);
        assert!(result.is_err());
    }
}
