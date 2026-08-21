//! FIDO2 hardware security key interaction for device enrollment.
//!
//! Uses CTAP2 over USB HID to perform makeCredential during device
//! enrollment, providing hardware attestation of the enrolling device.
//!
//! TODO: This module does not currently compile with the pinned
//! `ctap-hid-fido2 = "3.5"` dependency. The code was written against an
//! older API: `FidoKeyHidFactory::create` returns a single `FidoKeyHid`
//! (not a `Vec`), and `MakeCredentialArgsBuilder` in v3.5 has no
//! `user_id`/`user_name` setters. The feature is opt-in (off by default)
//! and CI does not exercise it. Rewrite required before this can ship.

/// Result of FIDO2 enrollment attestation.
#[derive(Debug, Clone)]
pub struct Fido2Enrollment {
    /// CBOR-encoded attestation object from makeCredential.
    pub attestation_object: Vec<u8>,
    /// Client data JSON for the attestation.
    pub client_data_json: Vec<u8>,
}

/// Check if any FIDO2 authenticator is connected via USB.
pub fn is_authenticator_available() -> bool {
    #[cfg(feature = "fido2")]
    {
        ctap_hid_fido2::FidoKeyHidFactory::create(&ctap_hid_fido2::Cfg::init())
            .map(|devices| !devices.is_empty())
            .unwrap_or(false)
    }
    #[cfg(not(feature = "fido2"))]
    {
        false
    }
}

/// Perform FIDO2 makeCredential for device enrollment attestation.
///
/// The challenge is deterministically derived from the enrollment token
/// using HMAC-SHA256, so both the agent and server compute it independently
/// without an extra round-trip.
///
/// # Arguments
/// * `enrollment_token` - The enrollment token string
/// * `rp_id` - Relying party ID (e.g., "enroll.avon.local")
/// * `device_id` - The device UUID bytes (used as user ID)
/// * `device_name` - Human-readable device name (used as user name)
pub fn perform_enrollment_attestation(
    enrollment_token: &str,
    rp_id: &str,
    device_id: &[u8],
    device_name: &str,
) -> anyhow::Result<Fido2Enrollment> {
    // Derive challenge deterministically from enrollment token
    let challenge =
        avon_crypto::hmac::hmac_sha256(b"avon-fido2-enrollment-v1", enrollment_token.as_bytes());

    #[cfg(feature = "fido2")]
    {
        use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};

        // Discover FIDO2 authenticator
        let devices = FidoKeyHidFactory::create(&Cfg::init())
            .map_err(|e| anyhow::anyhow!("Failed to enumerate FIDO2 devices: {:?}", e))?;

        if devices.is_empty() {
            anyhow::bail!(
                "No FIDO2 authenticator found. Please insert your hardware security key."
            );
        }

        let device = &devices[0];
        eprintln!("FIDO2 authenticator detected. Please tap your security key...");

        // Build makeCredential arguments
        let make_credential_args =
            ctap_hid_fido2::fidokey::MakeCredentialArgsBuilder::new(rp_id, &challenge)
                .user_id(device_id)
                .user_name(device_name)
                .build();

        let attestation = device
            .make_credential_with_args(&make_credential_args)
            .map_err(|e| anyhow::anyhow!("FIDO2 makeCredential failed: {:?}", e))?;

        // Build client data JSON (matches WebAuthn spec format)
        let challenge_b64 = base64url_encode(&challenge);
        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": challenge_b64,
            "origin": "avon-agent://enroll",
            "crossOrigin": false,
        });
        let client_data_json = serde_json::to_vec(&client_data)?;

        eprintln!("FIDO2 attestation successful.");

        Ok(Fido2Enrollment {
            attestation_object: attestation.attestation_object,
            client_data_json,
        })
    }

    #[cfg(not(feature = "fido2"))]
    {
        let _ = (rp_id, device_id, device_name, challenge);
        anyhow::bail!("FIDO2 support not compiled. Rebuild with: cargo build --features fido2")
    }
}

/// Base64url encode without padding.
fn base64url_encode(data: &[u8]) -> String {
    use base64ct::{Base64Url, Encoding};
    let encoded = Base64Url::encode_string(data);
    encoded.trim_end_matches('=').to_string()
}

// Re-export base64ct for the encoding
use base64ct;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_base64url_encode() {
        let data = b"hello";
        let encoded = base64url_encode(data);
        assert_eq!(encoded, "aGVsbG8");
    }

    #[test]
    fn test_challenge_derivation_deterministic() {
        let token = "test-enrollment-token-123";
        let challenge1 =
            avon_crypto::hmac::hmac_sha256(b"avon-fido2-enrollment-v1", token.as_bytes());
        let challenge2 =
            avon_crypto::hmac::hmac_sha256(b"avon-fido2-enrollment-v1", token.as_bytes());
        assert_eq!(challenge1, challenge2);
        assert_ne!(challenge1, [0u8; 32]);
    }

    #[test]
    fn test_authenticator_available_without_feature() {
        // Without a physical key connected, this should return false
        // (or false when fido2 feature is not enabled)
        let _available = is_authenticator_available();
        // Just verify it doesn't panic
    }
}
