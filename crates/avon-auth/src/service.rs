//! gRPC service implementation for the AVON authentication service.
//!
//! This module implements the AuthService gRPC interface, handling device
//! verification, enrollment, token rotation, and state queries.

use avon_common::device::DeviceId;
use avon_protocol::v1::auth_service_server::AuthService;
use avon_protocol::v1::{
    EnrollDeviceRequest, EnrollDeviceResponse, GetDeviceStateRequest, GetDeviceStateResponse,
    RevokeDeviceRequest, RevokeDeviceResponse, RotateTokenRequest, RotateTokenResponse,
    Timestamp, VerifyDeviceRequest, VerifyDeviceResponse,
};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

use crate::cache::{AuthCache, CachedDeviceState};
use crate::db::{AuthDatabase, NewDevice};

/// Metrics for the auth service.
pub struct AuthMetrics;

impl AuthMetrics {
    /// Records a verification attempt.
    pub fn record_verification(success: bool) {
        let label = if success { "success" } else { "failure" };
        metrics::counter!("avon_auth_verifications_total", "result" => label).increment(1);
    }

    /// Records an enrollment attempt.
    pub fn record_enrollment(success: bool) {
        let label = if success { "success" } else { "failure" };
        metrics::counter!("avon_auth_enrollments_total", "result" => label).increment(1);
    }

    /// Records a token rotation.
    pub fn record_rotation(success: bool) {
        let label = if success { "success" } else { "failure" };
        metrics::counter!("avon_auth_rotations_total", "result" => label).increment(1);
    }

    /// Records a device revocation.
    pub fn record_revocation(success: bool) {
        let label = if success { "success" } else { "failure" };
        metrics::counter!("avon_auth_revocations_total", "result" => label).increment(1);
    }
}

/// Implementation of the AuthService gRPC service.
pub struct AuthServiceImpl {
    db: Arc<AuthDatabase>,
    cache: Arc<AuthCache>,
}

impl AuthServiceImpl {
    /// Creates a new auth service instance.
    pub fn new(db: Arc<AuthDatabase>, cache: Arc<AuthCache>) -> Self {
        Self { db, cache }
    }

    /// Gets device state from cache or database.
    async fn get_device_state_cached(
        &self,
        id: &DeviceId,
    ) -> Result<Option<CachedDeviceState>, Status> {
        // Try cache first
        if let Ok(Some(state)) = self.cache.get_device_state(id).await {
            return Ok(Some(state));
        }

        // Fall back to database
        let device = self
            .db
            .get_device(*id)
            .await
            .map_err(|e| Status::internal(format!("Database error: {}", e)))?;

        match device {
            Some(d) => {
                let state = CachedDeviceState {
                    current_token: d.current_token,
                    previous_token: d.previous_token,
                    token_sequence: d.token_sequence as u64,
                    status: d.status,
                };

                // Update cache
                if let Err(e) = self.cache.set_device_state(id, &state).await {
                    warn!(?id, "Failed to update cache: {}", e);
                }

                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    /// Verifies an authentication tag against device tokens.
    fn verify_auth_tag(
        state: &CachedDeviceState,
        auth_tag: &[u8],
        authenticated_data: &[u8],
    ) -> bool {
        // Verify against current token
        if state.current_token.len() == 32 {
            let mut token = [0u8; 32];
            token.copy_from_slice(&state.current_token);
            if avon_crypto::hmac::hmac_sha256_verify(&token, authenticated_data, auth_tag) {
                return true;
            }
        }

        // Try previous token (grace period)
        if let Some(prev) = &state.previous_token {
            if prev.len() == 32 {
                let mut token = [0u8; 32];
                token.copy_from_slice(prev);
                if avon_crypto::hmac::hmac_sha256_verify(&token, authenticated_data, auth_tag) {
                    return true;
                }
            }
        }

        false
    }
}

#[tonic::async_trait]
impl AuthService for AuthServiceImpl {
    async fn verify_device(
        &self,
        request: Request<VerifyDeviceRequest>,
    ) -> Result<Response<VerifyDeviceResponse>, Status> {
        let req = request.into_inner();

        // Parse device ID
        let device_id = DeviceId::try_from_slice(&req.device_id)
            .map_err(|_| Status::invalid_argument("Invalid device ID"))?;

        debug!(?device_id, "Verifying device");

        // Get device state
        let state = match self.get_device_state_cached(&device_id).await? {
            Some(s) => s,
            None => {
                AuthMetrics::record_verification(false);
                return Ok(Response::new(VerifyDeviceResponse {
                    valid: false,
                    device_id: req.device_id,
                    token_sequence: 0,
                    error_message: "Device not found".to_string(),
                }));
            }
        };

        // Check device status
        if state.status != "active" {
            AuthMetrics::record_verification(false);
            return Ok(Response::new(VerifyDeviceResponse {
                valid: false,
                device_id: req.device_id,
                token_sequence: state.token_sequence,
                error_message: format!("Device is {}", state.status),
            }));
        }

        // Verify auth tag
        let auth_tag: [u8; 32] = req
            .auth_tag
            .try_into()
            .map_err(|_| Status::invalid_argument("Auth tag must be 32 bytes"))?;

        let valid = Self::verify_auth_tag(&state, &auth_tag, &req.authenticated_data);

        AuthMetrics::record_verification(valid);

        if valid {
            debug!(?device_id, "Device verification successful");
        } else {
            warn!(?device_id, "Device verification failed");
        }

        Ok(Response::new(VerifyDeviceResponse {
            valid,
            device_id: req.device_id,
            token_sequence: state.token_sequence,
            error_message: if valid {
                String::new()
            } else {
                "Invalid authentication tag".to_string()
            },
        }))
    }

    async fn enroll_device(
        &self,
        request: Request<EnrollDeviceRequest>,
    ) -> Result<Response<EnrollDeviceResponse>, Status> {
        let req = request.into_inner();

        debug!(enrollment_token = %req.enrollment_token, "Processing device enrollment");

        // Validate enrollment token
        let token = self
            .db
            .get_enrollment_token(&req.enrollment_token)
            .await
            .map_err(|e| Status::internal(format!("Database error: {}", e)))?
            .ok_or_else(|| {
                AuthMetrics::record_enrollment(false);
                Status::unauthenticated("Invalid or expired enrollment token")
            })?;

        // Verify hardware fingerprint if expected
        if let Some(expected) = &token.expected_fingerprint {
            if expected != &req.hardware_fingerprint {
                AuthMetrics::record_enrollment(false);
                return Ok(Response::new(EnrollDeviceResponse {
                    success: false,
                    device_id: vec![],
                    initial_token: vec![],
                    server_public_key: None,
                    error_message: "Hardware fingerprint mismatch".to_string(),
                    fido2_attested: false,
                }));
            }
        }

        // Check if device already exists with this fingerprint
        if let Some(existing) = self
            .db
            .get_device_by_fingerprint(&req.hardware_fingerprint)
            .await
            .map_err(|e| Status::internal(format!("Database error: {}", e)))?
        {
            AuthMetrics::record_enrollment(false);
            return Ok(Response::new(EnrollDeviceResponse {
                success: false,
                device_id: existing.id.as_bytes().to_vec(),
                initial_token: vec![],
                server_public_key: None,
                error_message: "Device already enrolled".to_string(),
                fido2_attested: false,
            }));
        }

        // Generate initial token
        let initial_token: [u8; 32] = avon_crypto::random::random_bytes_fixed()
            .map_err(|e| Status::internal(format!("Failed to generate token: {}", e)))?;

        // Create device
        let device_id = DeviceId::new();
        let new_device = NewDevice {
            id: device_id,
            name: req.device_name.clone(),
            hardware_fingerprint: req.hardware_fingerprint,
            initial_token: initial_token.to_vec(),
        };

        self.db
            .create_device(new_device)
            .await
            .map_err(|e| Status::internal(format!("Failed to create device: {}", e)))?;

        // Consume enrollment token
        self.db
            .consume_enrollment_token(&req.enrollment_token)
            .await
            .map_err(|e| Status::internal(format!("Failed to consume token: {}", e)))?;

        AuthMetrics::record_enrollment(true);
        info!(?device_id, name = %req.device_name, "Device enrolled successfully");

        Ok(Response::new(EnrollDeviceResponse {
            success: true,
            device_id: device_id.as_bytes().to_vec(),
            initial_token: initial_token.to_vec(),
            server_public_key: None, // TODO: Generate hybrid key pair
            error_message: String::new(),
            fido2_attested: false,
        }))
    }

    async fn rotate_token(
        &self,
        request: Request<RotateTokenRequest>,
    ) -> Result<Response<RotateTokenResponse>, Status> {
        let req = request.into_inner();

        // Parse device ID
        let device_id = DeviceId::try_from_slice(&req.device_id)
            .map_err(|_| Status::invalid_argument("Invalid device ID"))?;

        debug!(?device_id, "Processing token rotation");

        // Get current device state
        let state = match self.get_device_state_cached(&device_id).await? {
            Some(s) => s,
            None => {
                AuthMetrics::record_rotation(false);
                return Ok(Response::new(RotateTokenResponse {
                    success: false,
                    new_sequence: 0,
                    acknowledgment: vec![],
                    error_message: "Device not found".to_string(),
                }));
            }
        };

        // Verify current auth tag
        let auth_tag: [u8; 32] = req
            .current_auth_tag
            .try_into()
            .map_err(|_| Status::invalid_argument("Auth tag must be 32 bytes"))?;

        // Build authenticated data for verification (device_id + server_nonce + client_nonce)
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&req.device_id);
        auth_data.extend_from_slice(&req.server_nonce);
        auth_data.extend_from_slice(&req.client_nonce);

        if !Self::verify_auth_tag(&state, &auth_tag, &auth_data) {
            AuthMetrics::record_rotation(false);
            return Ok(Response::new(RotateTokenResponse {
                success: false,
                new_sequence: state.token_sequence,
                acknowledgment: vec![],
                error_message: "Invalid authentication".to_string(),
            }));
        }

        // Derive new token using HKDF
        let current_token: [u8; 32] = state
            .current_token
            .try_into()
            .map_err(|_| Status::internal("Invalid token state"))?;

        let mut ikm = Vec::new();
        ikm.extend_from_slice(&current_token);
        ikm.extend_from_slice(&req.server_nonce);
        ikm.extend_from_slice(&req.client_nonce);

        let new_token = avon_crypto::kdf::hkdf_sha256(&ikm, None, b"avon-token-rotation", 32)
            .map_err(|e| Status::internal(format!("Failed to derive token: {}", e)))?;

        let new_sequence = state.token_sequence + 1;

        // Update database
        self.db
            .update_device_token(device_id, &new_token, new_sequence)
            .await
            .map_err(|e| Status::internal(format!("Failed to update token: {}", e)))?;

        // Invalidate cache and publish rotation
        let _ = self.cache.invalidate_device(&device_id).await;
        let _ = self
            .cache
            .publish_token_rotation(&device_id, new_sequence)
            .await;

        // Generate acknowledgment (HMAC of new sequence with new token)
        let mut new_token_arr = [0u8; 32];
        new_token_arr.copy_from_slice(&new_token);
        let ack = avon_crypto::hmac::hmac_sha256(&new_token_arr, &new_sequence.to_be_bytes());

        AuthMetrics::record_rotation(true);
        info!(?device_id, new_sequence, "Token rotated successfully");

        Ok(Response::new(RotateTokenResponse {
            success: true,
            new_sequence,
            acknowledgment: ack.to_vec(),
            error_message: String::new(),
        }))
    }

    async fn get_device_state(
        &self,
        request: Request<GetDeviceStateRequest>,
    ) -> Result<Response<GetDeviceStateResponse>, Status> {
        let req = request.into_inner();

        // Parse device ID
        let device_id = DeviceId::try_from_slice(&req.device_id)
            .map_err(|_| Status::invalid_argument("Invalid device ID"))?;

        debug!(?device_id, "Getting device state");

        // Get device from database (not cache, for full state)
        let device = self
            .db
            .get_device(device_id)
            .await
            .map_err(|e| Status::internal(format!("Database error: {}", e)))?;

        match device {
            Some(d) => {
                let last_seen = d.last_seen_at.map(|dt| Timestamp {
                    seconds: dt.timestamp(),
                    nanos: dt.timestamp_subsec_nanos() as i32,
                });

                Ok(Response::new(GetDeviceStateResponse {
                    found: true,
                    device_id: req.device_id,
                    device_name: d.name,
                    token_sequence: d.token_sequence as u64,
                    status: d.status,
                    last_seen,
                    last_known_ip: d.last_known_ip.map(|ip| ip.to_string()).unwrap_or_default(),
                }))
            }
            None => Ok(Response::new(GetDeviceStateResponse {
                found: false,
                device_id: req.device_id,
                device_name: String::new(),
                token_sequence: 0,
                status: String::new(),
                last_seen: None,
                last_known_ip: String::new(),
            })),
        }
    }

    async fn revoke_device(
        &self,
        request: Request<RevokeDeviceRequest>,
    ) -> Result<Response<RevokeDeviceResponse>, Status> {
        let req = request.into_inner();

        // Parse device ID
        let device_id = DeviceId::try_from_slice(&req.device_id)
            .map_err(|_| Status::invalid_argument("Invalid device ID"))?;

        info!(?device_id, reason = %req.reason, "Revoking device");

        // Update device status
        match self.db.update_device_status(device_id, "revoked").await {
            Ok(()) => {
                // Invalidate cache
                let _ = self.cache.invalidate_device(&device_id).await;

                AuthMetrics::record_revocation(true);
                Ok(Response::new(RevokeDeviceResponse {
                    success: true,
                    error_message: String::new(),
                }))
            }
            Err(e) => {
                AuthMetrics::record_revocation(false);
                Ok(Response::new(RevokeDeviceResponse {
                    success: false,
                    error_message: format!("Failed to revoke device: {}", e),
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_auth_tag_with_current_token() {
        let token = [0x42u8; 32];
        let data = b"test data";
        let tag = avon_crypto::hmac::hmac_sha256(&token, data);

        let state = CachedDeviceState {
            current_token: token.to_vec(),
            previous_token: None,
            token_sequence: 1,
            status: "active".to_string(),
        };

        assert!(AuthServiceImpl::verify_auth_tag(&state, &tag, data));
    }

    #[test]
    fn test_verify_auth_tag_with_previous_token() {
        let current_token = [0x42u8; 32];
        let previous_token = [0x41u8; 32];
        let data = b"test data";
        let tag = avon_crypto::hmac::hmac_sha256(&previous_token, data);

        let state = CachedDeviceState {
            current_token: current_token.to_vec(),
            previous_token: Some(previous_token.to_vec()),
            token_sequence: 2,
            status: "active".to_string(),
        };

        assert!(AuthServiceImpl::verify_auth_tag(&state, &tag, data));
    }

    #[test]
    fn test_verify_auth_tag_fails_with_wrong_token() {
        let token = [0x42u8; 32];
        let wrong_token = [0x43u8; 32];
        let data = b"test data";
        let tag = avon_crypto::hmac::hmac_sha256(&wrong_token, data);

        let state = CachedDeviceState {
            current_token: token.to_vec(),
            previous_token: None,
            token_sequence: 1,
            status: "active".to_string(),
        };

        assert!(!AuthServiceImpl::verify_auth_tag(&state, &tag, data));
    }
}
