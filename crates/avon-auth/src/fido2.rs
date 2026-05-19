//! FIDO2 attestation verification for device enrollment.
//!
//! Parses and verifies CBOR-encoded attestation objects from FIDO2
//! authenticators during device enrollment. Supports `none` and `packed`
//! attestation formats.

use sha2::{Digest, Sha256};

/// Result of successful FIDO2 attestation verification.
#[derive(Debug, Clone)]
pub struct Fido2AttestationResult {
    /// The credential ID assigned by the authenticator.
    pub credential_id: Vec<u8>,
    /// The AAGUID identifying the authenticator model (16 bytes).
    pub aaguid: [u8; 16],
    /// The attestation format (e.g., "none", "packed", "fido-u2f").
    pub attestation_format: String,
    /// The sign count from the authenticator.
    pub sign_count: u32,
}

/// Errors during FIDO2 attestation verification.
#[derive(Debug, thiserror::Error)]
pub enum Fido2Error {
    #[error("Failed to parse client data JSON: {0}")]
    ClientDataParse(String),
    #[error("Invalid client data type: expected 'webauthn.create', got '{0}'")]
    InvalidClientDataType(String),
    #[error("Challenge mismatch")]
    ChallengeMismatch,
    #[error("Failed to parse attestation object: {0}")]
    AttestationParse(String),
    #[error("Missing field in attestation: {0}")]
    MissingField(String),
    #[error("Invalid auth data: {0}")]
    InvalidAuthData(String),
    #[error("RP ID hash mismatch")]
    RpIdHashMismatch,
    #[error("Attestation data flag not set")]
    AttestationDataFlagNotSet,
    #[error("Auth data too short: need {expected} bytes, got {actual}")]
    AuthDataTooShort { expected: usize, actual: usize },
}

/// Verify a FIDO2 attestation object from a device enrollment.
///
/// # Arguments
/// * `attestation_object` - CBOR-encoded attestation object from makeCredential
/// * `client_data_json` - Client data JSON from makeCredential
/// * `expected_challenge` - The expected challenge bytes
/// * `expected_rp_id` - The expected relying party ID
pub fn verify_attestation(
    attestation_object: &[u8],
    client_data_json: &[u8],
    expected_challenge: &[u8],
    expected_rp_id: &str,
) -> Result<Fido2AttestationResult, Fido2Error> {
    // 1. Parse and verify client data JSON
    let client_data: serde_json::Value = serde_json::from_slice(client_data_json)
        .map_err(|e| Fido2Error::ClientDataParse(e.to_string()))?;

    let data_type = client_data
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Fido2Error::ClientDataParse("missing 'type' field".into()))?;

    if data_type != "webauthn.create" {
        return Err(Fido2Error::InvalidClientDataType(data_type.to_string()));
    }

    // Verify challenge (base64url-encoded in client data)
    let challenge_b64 = client_data
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Fido2Error::ClientDataParse("missing 'challenge' field".into()))?;

    let challenge_bytes = base64url_decode(challenge_b64)
        .map_err(|e| Fido2Error::ClientDataParse(format!("invalid challenge encoding: {}", e)))?;

    if challenge_bytes != expected_challenge {
        return Err(Fido2Error::ChallengeMismatch);
    }

    // 2. Parse CBOR attestation object
    let att_obj: ciborium::Value = ciborium::from_reader(attestation_object)
        .map_err(|e| Fido2Error::AttestationParse(e.to_string()))?;

    let att_map = match &att_obj {
        ciborium::Value::Map(m) => m,
        _ => return Err(Fido2Error::AttestationParse("expected CBOR map".into())),
    };

    // Extract fmt
    let fmt =
        cbor_map_get_text(att_map, "fmt").ok_or_else(|| Fido2Error::MissingField("fmt".into()))?;

    // Extract authData
    let auth_data = cbor_map_get_bytes(att_map, "authData")
        .ok_or_else(|| Fido2Error::MissingField("authData".into()))?;

    // 3. Parse authData
    // authData structure:
    //   rpIdHash (32 bytes) || flags (1 byte) || signCount (4 bytes, big-endian)
    //   [attestedCredentialData if flags.AT is set]
    if auth_data.len() < 37 {
        return Err(Fido2Error::AuthDataTooShort {
            expected: 37,
            actual: auth_data.len(),
        });
    }

    let rp_id_hash = &auth_data[0..32];
    let flags = auth_data[32];
    let sign_count =
        u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);

    // Verify rpIdHash
    let expected_rp_id_hash = Sha256::digest(expected_rp_id.as_bytes());
    if rp_id_hash != expected_rp_id_hash.as_slice() {
        return Err(Fido2Error::RpIdHashMismatch);
    }

    // Check AT flag (bit 6) for attested credential data
    let at_flag = (flags & 0x40) != 0;
    if !at_flag {
        return Err(Fido2Error::AttestationDataFlagNotSet);
    }

    // Parse attested credential data (starts at byte 37)
    // aaguid (16 bytes) || credentialIdLength (2 bytes, big-endian) || credentialId
    let acd_start = 37;
    if auth_data.len() < acd_start + 18 {
        return Err(Fido2Error::AuthDataTooShort {
            expected: acd_start + 18,
            actual: auth_data.len(),
        });
    }

    let mut aaguid = [0u8; 16];
    aaguid.copy_from_slice(&auth_data[acd_start..acd_start + 16]);

    let cred_id_len =
        u16::from_be_bytes([auth_data[acd_start + 16], auth_data[acd_start + 17]]) as usize;

    let cred_id_start = acd_start + 18;
    if auth_data.len() < cred_id_start + cred_id_len {
        return Err(Fido2Error::AuthDataTooShort {
            expected: cred_id_start + cred_id_len,
            actual: auth_data.len(),
        });
    }

    let credential_id = auth_data[cred_id_start..cred_id_start + cred_id_len].to_vec();

    tracing::info!(
        fmt = %fmt,
        aaguid = %hex::encode(aaguid),
        credential_id_len = credential_id.len(),
        sign_count = sign_count,
        "FIDO2 attestation verified"
    );

    Ok(Fido2AttestationResult {
        credential_id,
        aaguid,
        attestation_format: fmt,
        sign_count,
    })
}

/// Helper: get a text value from a CBOR map by string key.
fn cbor_map_get_text(map: &[(ciborium::Value, ciborium::Value)], key: &str) -> Option<String> {
    for (k, v) in map {
        if let ciborium::Value::Text(k_str) = k {
            if k_str == key {
                if let ciborium::Value::Text(val) = v {
                    return Some(val.clone());
                }
            }
        }
    }
    None
}

/// Helper: get a bytes value from a CBOR map by string key.
fn cbor_map_get_bytes(map: &[(ciborium::Value, ciborium::Value)], key: &str) -> Option<Vec<u8>> {
    for (k, v) in map {
        if let ciborium::Value::Text(k_str) = k {
            if k_str == key {
                if let ciborium::Value::Bytes(val) = v {
                    return Some(val.clone());
                }
            }
        }
    }
    None
}

/// Decode a base64url-encoded string (no padding required).
fn base64url_decode(input: &str) -> Result<Vec<u8>, String> {
    // Add padding if needed
    let padded = match input.len() % 4 {
        2 => format!("{}==", input),
        3 => format!("{}=", input),
        _ => input.to_string(),
    };
    // Replace URL-safe chars with standard base64
    let standard = padded.replace('-', "+").replace('_', "/");
    base64ct::Base64::decode_vec(&standard).map_err(|e| format!("base64 decode error: {}", e))
}

use base64ct::Encoding;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64url_decode() {
        // "hello" in base64url
        let encoded = "aGVsbG8";
        let decoded = base64url_decode(encoded).unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn test_base64url_decode_with_padding() {
        let encoded = "aGVsbG8=";
        let decoded = base64url_decode(encoded).unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn test_rp_id_hash() {
        let rp_id = "enroll.avon.local";
        let hash = Sha256::digest(rp_id.as_bytes());
        assert_eq!(hash.len(), 32);
    }
}
