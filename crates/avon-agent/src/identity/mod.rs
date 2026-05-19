//! Identity management for AVON Agent.
//!
//! Handles device identity, authentication tokens, and cryptographic operations.
//! Supports both TPM-backed and software-based keystores.

pub mod fido2;
pub mod hardware;
pub mod software;
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub mod tpm;

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use avon_common::device::DeviceId;
use avon_crypto::token::{RotatingToken, TokenRotationInput};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use hardware::HardwareFingerprint;
use software::SoftwareKeystore;

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityData {
    pub device_id: DeviceId,
    pub enrolled_at: chrono::DateTime<chrono::Utc>,
    pub control_plane: String,
    pub has_tpm: bool,
}

pub struct IdentityManager {
    data: IdentityData,
    keystore: SoftwareKeystore,
    token: Arc<RwLock<RotatingToken>>,
    #[allow(dead_code)]
    fingerprint: HardwareFingerprint,
}

impl IdentityManager {
    pub async fn load(data_dir: &Path) -> Result<Self> {
        let identity_path = data_dir.join("identity.json");
        let keystore_path = data_dir.join("keystore.enc");
        let token_path = data_dir.join("token.enc");

        let identity_data =
            std::fs::read_to_string(&identity_path).context("Failed to read identity file")?;
        let data: IdentityData =
            serde_json::from_str(&identity_data).context("Failed to parse identity data")?;

        let fingerprint = HardwareFingerprint::collect();

        let keystore = SoftwareKeystore::load(&keystore_path, &fingerprint)
            .context("Failed to load keystore")?;

        let token_data = std::fs::read(&token_path).context("Failed to read token file")?;
        let token = keystore
            .decrypt_token(&token_data)
            .context("Failed to decrypt token")?;

        tracing::info!(device_id = %data.device_id, "Identity loaded successfully");

        Ok(Self {
            data,
            keystore,
            token: Arc::new(RwLock::new(token)),
            fingerprint,
        })
    }

    pub async fn enroll(
        enrollment_token: &str,
        control_plane: &str,
        data_dir: &Path,
    ) -> Result<Self> {
        tracing::info!(control_plane = %control_plane, "Starting enrollment");

        std::fs::create_dir_all(data_dir).context("Failed to create data directory")?;

        let fingerprint = HardwareFingerprint::collect();
        tracing::debug!(fingerprint_hash = %hex::encode(fingerprint.to_hash()), "Hardware fingerprint collected");

        let device_id = DeviceId::new();

        let has_tpm = Self::check_tpm_available();
        tracing::info!(has_tpm = has_tpm, "TPM availability checked");

        let keystore_path = data_dir.join("keystore.enc");
        let keystore = SoftwareKeystore::create(&keystore_path, &fingerprint)
            .context("Failed to create keystore")?;

        let initial_token = Self::create_initial_token(enrollment_token, &fingerprint);

        let token_path = data_dir.join("token.enc");
        let encrypted_token = keystore.encrypt_token(&initial_token)?;
        std::fs::write(&token_path, &encrypted_token).context("Failed to write token file")?;

        let data = IdentityData {
            device_id,
            enrolled_at: chrono::Utc::now(),
            control_plane: control_plane.to_string(),
            has_tpm,
        };

        let identity_path = data_dir.join("identity.json");
        let identity_json =
            serde_json::to_string_pretty(&data).context("Failed to serialize identity")?;
        std::fs::write(&identity_path, &identity_json).context("Failed to write identity file")?;

        tracing::info!(device_id = %device_id, "Enrollment complete");

        Ok(Self {
            data,
            keystore,
            token: Arc::new(RwLock::new(initial_token)),
            fingerprint,
        })
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.data.device_id
    }

    pub fn has_tpm(&self) -> bool {
        self.data.has_tpm
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.keystore.sign(data)
    }

    pub async fn get_auth_tag(&self, data: &[u8]) -> [u8; 32] {
        let token = self.token.read().await;
        token.compute_auth_tag(data)
    }

    pub async fn rotate_token(&self, input: &TokenRotationInput) -> [u8; 32] {
        let mut token = self.token.write().await;
        let new_token = token.rotate(input);

        tracing::debug!("Token rotated successfully");
        new_token
    }

    pub async fn current_token_sequence(&self) -> u64 {
        self.token.read().await.sequence()
    }

    fn check_tpm_available() -> bool {
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            tpm::TpmContext::try_open().is_some()
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            false
        }
    }

    fn create_initial_token(
        enrollment_token: &str,
        fingerprint: &HardwareFingerprint,
    ) -> RotatingToken {
        let mut seed = [0u8; 32];
        let enrollment_bytes = enrollment_token.as_bytes();
        let fingerprint_hash = fingerprint.to_hash();

        for (i, byte) in enrollment_bytes.iter().take(32).enumerate() {
            seed[i] = *byte;
        }
        for (i, byte) in fingerprint_hash.iter().enumerate() {
            seed[i] ^= byte;
        }

        RotatingToken::new(seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_enrollment_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path();

        let identity =
            IdentityManager::enroll("test-enrollment-token", "gateway.avon.local:8443", data_dir)
                .await
                .unwrap();

        assert!(!identity.device_id().to_string().is_empty());

        let loaded = IdentityManager::load(data_dir).await.unwrap();
        assert_eq!(loaded.device_id(), identity.device_id());
    }

    #[tokio::test]
    async fn test_auth_tag_generation() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path();

        let identity = IdentityManager::enroll("test-token", "gateway.avon.local:8443", data_dir)
            .await
            .unwrap();

        let data = b"test data";
        let tag1 = identity.get_auth_tag(data).await;
        let tag2 = identity.get_auth_tag(data).await;

        assert_eq!(tag1, tag2);
        assert_ne!(tag1, [0u8; 32]);
    }
}
