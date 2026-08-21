//! Encoding and decoding utilities for AVON protocol messages.
//!
//! This module provides functions for serializing and deserializing protocol
//! messages, computing and verifying authentication tags, and length-prefixed
//! framing for UDP transport.
//!
//! # Authentication
//!
//! Control plane messages include an `auth_tag` field that provides message
//! authentication using HMAC-SHA256. The tag is computed over the serialized
//! payload (excluding the auth_tag field itself).
//!
//! # Framing
//!
//! Messages are framed with a 4-byte length prefix (big-endian) for reliable
//! parsing over UDP:
//!
//! ```text
//! +----------------+------------------+
//! | Length (4 bytes) | Message (N bytes) |
//! +----------------+------------------+
//! ```
//!
//! # Example
//!
//! ```
//! use avon_protocol::v1::{ControlMessage, PulseRequest, Timestamp, DeviceId};
//! use avon_protocol::codec::{encode_with_auth_tag, decode_and_verify};
//!
//! let token = [0x42u8; 32];
//! let pulse = PulseRequest {
//!     server_nonce: vec![0u8; 32],
//!     timestamp: Some(Timestamp { seconds: 1234567890, nanos: 0 }),
//!     request_rotation: false,
//! };
//!
//! let mut msg = ControlMessage {
//!     version: 1,
//!     sequence: 1,
//!     device_id: Some(DeviceId { uuid: vec![0u8; 16] }),
//!     auth_tag: vec![],
//!     payload: Some(avon_protocol::v1::control_message::Payload::PulseRequest(pulse)),
//! };
//!
//! // Encode with authentication
//! let bytes = encode_with_auth_tag(&mut msg, &token);
//!
//! // Decode and verify
//! let decoded = decode_and_verify(&bytes, &token).unwrap();
//! assert_eq!(decoded.sequence, 1);
//! ```

use avon_crypto::hmac::{hmac_sha256, hmac_sha256_verify};
use prost::Message;
use thiserror::Error;

use crate::v1::ControlMessage;
use crate::{AUTH_TAG_SIZE, MAX_MESSAGE_SIZE};

/// Errors that can occur during encoding/decoding.
#[derive(Debug, Error)]
pub enum CodecError {
    /// Message exceeds maximum allowed size.
    #[error("Message too large: {0} bytes (max {MAX_MESSAGE_SIZE})")]
    MessageTooLarge(usize),

    /// Message is too short to contain required fields.
    #[error("Message too short: {0} bytes")]
    MessageTooShort(usize),

    /// Failed to decode protobuf message.
    #[error("Decode error: {0}")]
    DecodeError(#[from] prost::DecodeError),

    /// Authentication tag verification failed.
    #[error("Authentication failed: invalid auth tag")]
    AuthenticationFailed,

    /// Invalid length prefix.
    #[error("Invalid length prefix: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
}

/// Encodes a control message and computes its authentication tag.
///
/// The auth_tag field is computed as HMAC-SHA256 over the serialized message
/// (with auth_tag set to empty), then the message is re-serialized with the
/// computed tag.
///
/// # Arguments
///
/// * `message` - The control message to encode (auth_tag will be set)
/// * `token` - The 32-byte authentication token
///
/// # Returns
///
/// The serialized message bytes with authentication tag.
pub fn encode_with_auth_tag(message: &mut ControlMessage, token: &[u8; 32]) -> Vec<u8> {
    // Clear auth_tag and serialize to compute tag
    message.auth_tag.clear();
    let payload_bytes = message.encode_to_vec();

    // Compute HMAC-SHA256 over the payload
    let tag = hmac_sha256(token, &payload_bytes);

    // Set the auth_tag and re-serialize
    message.auth_tag = tag.to_vec();
    message.encode_to_vec()
}

/// Decodes a control message and verifies its authentication tag.
///
/// # Arguments
///
/// * `bytes` - The serialized message bytes
/// * `token` - The 32-byte authentication token
///
/// # Returns
///
/// The decoded control message if authentication succeeds.
///
/// # Errors
///
/// Returns `CodecError::AuthenticationFailed` if the auth tag is invalid.
pub fn decode_and_verify(bytes: &[u8], token: &[u8; 32]) -> Result<ControlMessage, CodecError> {
    // Decode the message
    let message = ControlMessage::decode(bytes)?;

    // Extract and verify the auth tag
    if message.auth_tag.len() != AUTH_TAG_SIZE {
        return Err(CodecError::AuthenticationFailed);
    }

    // Reconstruct the payload without auth_tag to verify
    let mut verify_msg = message.clone();
    verify_msg.auth_tag.clear();
    let payload_bytes = verify_msg.encode_to_vec();

    // Verify the tag
    let mut expected_tag = [0u8; 32];
    expected_tag.copy_from_slice(&message.auth_tag);

    if !hmac_sha256_verify(token, &payload_bytes, &expected_tag) {
        return Err(CodecError::AuthenticationFailed);
    }

    Ok(message)
}

/// Encodes a message with length-prefixed framing.
///
/// Format: 4-byte big-endian length || message bytes
///
/// # Arguments
///
/// * `bytes` - The message bytes to frame
///
/// # Returns
///
/// The framed message bytes.
///
/// # Errors
///
/// Returns `CodecError::MessageTooLarge` if the message exceeds MAX_MESSAGE_SIZE.
pub fn encode_framed(bytes: &[u8]) -> Result<Vec<u8>, CodecError> {
    if bytes.len() > MAX_MESSAGE_SIZE {
        return Err(CodecError::MessageTooLarge(bytes.len()));
    }

    let len = bytes.len() as u32;
    let mut framed = Vec::with_capacity(4 + bytes.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(bytes);

    Ok(framed)
}

/// Decodes a length-prefixed framed message.
///
/// # Arguments
///
/// * `bytes` - The framed message bytes
///
/// # Returns
///
/// The message bytes without the length prefix.
///
/// # Errors
///
/// Returns an error if the frame is invalid or the length doesn't match.
pub fn decode_framed(bytes: &[u8]) -> Result<&[u8], CodecError> {
    if bytes.len() < 4 {
        return Err(CodecError::MessageTooShort(bytes.len()));
    }

    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;

    if len > MAX_MESSAGE_SIZE {
        return Err(CodecError::MessageTooLarge(len));
    }

    let expected_total = 4 + len;
    if bytes.len() < expected_total {
        return Err(CodecError::InvalidLength {
            expected: expected_total,
            actual: bytes.len(),
        });
    }

    Ok(&bytes[4..4 + len])
}

/// Computes an authentication tag for arbitrary data.
///
/// # Arguments
///
/// * `token` - The 32-byte authentication token
/// * `data` - The data to authenticate
///
/// # Returns
///
/// The 32-byte HMAC-SHA256 tag.
pub fn compute_auth_tag(token: &[u8; 32], data: &[u8]) -> [u8; 32] {
    hmac_sha256(token, data)
}

/// Verifies an authentication tag for arbitrary data.
///
/// # Arguments
///
/// * `token` - The 32-byte authentication token
/// * `data` - The data that was authenticated
/// * `tag` - The authentication tag to verify
///
/// # Returns
///
/// `true` if the tag is valid, `false` otherwise.
pub fn verify_auth_tag(token: &[u8; 32], data: &[u8], tag: &[u8; 32]) -> bool {
    hmac_sha256_verify(token, data, tag)
}

/// Encodes a control message with auth tag and length-prefixed framing.
///
/// This is a convenience function that combines `encode_with_auth_tag` and
/// `encode_framed`.
///
/// # Arguments
///
/// * `message` - The control message to encode
/// * `token` - The 32-byte authentication token
///
/// # Returns
///
/// The framed message bytes with authentication tag.
pub fn encode_control_message(
    message: &mut ControlMessage,
    token: &[u8; 32],
) -> Result<Vec<u8>, CodecError> {
    let bytes = encode_with_auth_tag(message, token);
    encode_framed(&bytes)
}

/// Decodes a length-prefixed control message and verifies its auth tag.
///
/// This is a convenience function that combines `decode_framed` and
/// `decode_and_verify`.
///
/// # Arguments
///
/// * `bytes` - The framed message bytes
/// * `token` - The 32-byte authentication token
///
/// # Returns
///
/// The decoded control message if authentication succeeds.
pub fn decode_control_message(
    bytes: &[u8],
    token: &[u8; 32],
) -> Result<ControlMessage, CodecError> {
    let message_bytes = decode_framed(bytes)?;
    decode_and_verify(message_bytes, token)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::v1::{control_message::Payload, DeviceId, PulseRequest, Timestamp};

    fn create_test_message() -> ControlMessage {
        let pulse = PulseRequest {
            server_nonce: vec![0u8; 32],
            timestamp: Some(Timestamp {
                seconds: 1234567890,
                nanos: 0,
            }),
            request_rotation: false,
        };

        ControlMessage {
            version: 1,
            sequence: 42,
            device_id: Some(DeviceId {
                uuid: vec![0x01u8; 16],
            }),
            auth_tag: vec![],
            payload: Some(Payload::PulseRequest(pulse)),
        }
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let token = [0x42u8; 32];
        let mut msg = create_test_message();

        let bytes = encode_with_auth_tag(&mut msg, &token);
        let decoded = decode_and_verify(&bytes, &token).unwrap();

        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.sequence, 42);
    }

    #[test]
    fn test_wrong_token_fails() {
        let token1 = [0x42u8; 32];
        let token2 = [0x43u8; 32];
        let mut msg = create_test_message();

        let bytes = encode_with_auth_tag(&mut msg, &token1);
        let result = decode_and_verify(&bytes, &token2);

        assert!(matches!(result, Err(CodecError::AuthenticationFailed)));
    }

    #[test]
    fn test_tampered_message_fails() {
        let token = [0x42u8; 32];
        let mut msg = create_test_message();

        let mut bytes = encode_with_auth_tag(&mut msg, &token);

        // Tamper with the message
        if bytes.len() > 10 {
            bytes[10] ^= 0xFF;
        }

        let result = decode_and_verify(&bytes, &token);
        assert!(result.is_err());
    }

    #[test]
    fn test_framing_roundtrip() {
        let data = b"test message data";
        let framed = encode_framed(data).unwrap();
        let decoded = decode_framed(&framed).unwrap();

        assert_eq!(decoded, data);
    }

    #[test]
    fn test_framing_length_prefix() {
        let data = b"hello";
        let framed = encode_framed(data).unwrap();

        assert_eq!(framed.len(), 4 + 5);
        assert_eq!(&framed[0..4], &[0, 0, 0, 5]); // Big-endian length
        assert_eq!(&framed[4..], b"hello");
    }

    #[test]
    fn test_message_too_large() {
        let large_data = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let result = encode_framed(&large_data);

        assert!(matches!(result, Err(CodecError::MessageTooLarge(_))));
    }

    #[test]
    fn test_full_encode_decode() {
        let token = [0x42u8; 32];
        let mut msg = create_test_message();

        let framed = encode_control_message(&mut msg, &token).unwrap();
        let decoded = decode_control_message(&framed, &token).unwrap();

        assert_eq!(decoded.sequence, 42);
    }

    #[test]
    fn test_auth_tag_functions() {
        let token = [0x42u8; 32];
        let data = b"test data";

        let tag = compute_auth_tag(&token, data);
        assert!(verify_auth_tag(&token, data, &tag));
        assert!(!verify_auth_tag(&token, b"wrong data", &tag));
    }
}
