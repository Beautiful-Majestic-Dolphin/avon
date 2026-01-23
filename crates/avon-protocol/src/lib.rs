//! AVON Wire Protocol Definitions
//!
//! This crate provides Protocol Buffer message definitions for the AVON network,
//! including control plane messages and tunnel handshake messages.
//!
//! # Message Types
//!
//! ## Common Types (`avon.v1`)
//! - `DeviceId` - 16-byte UUID device identifier
//! - `Timestamp` - Nanosecond-precision timestamp
//! - `HybridPublicKey` - X25519 + Kyber768 public key
//! - `HybridSignature` - Ed25519 + Dilithium3 signature
//! - `Certificate` - X.509-style certificate with hybrid signature
//!
//! ## Control Plane Messages (`avon.v1`)
//! - `ControlMessage` - Top-level authenticated message wrapper
//! - `PulseRequest/PulseResponse` - Heartbeat and token rotation
//! - `AuthRequest/AuthResponse` - Device authentication
//! - `ConnectRequest/ConnectResponse` - Peer connection requests
//! - `IceCandidates` - NAT traversal candidates
//! - `CertRequest/CertResponse` - Certificate operations
//! - `TunnelEstablished/TunnelClosed` - Tunnel lifecycle
//! - `KeyRotation` - Token rotation
//!
//! ## Tunnel Handshake Messages (`avon.v1`)
//! - `TunnelHandshake` - Wrapper for tunnel establishment
//! - `TunnelInit` - Initiator's first message
//! - `TunnelResponse` - Responder's key encapsulation
//! - `TunnelConfirm` - Initiator's confirmation
//!
//! # Example
//!
//! ```
//! use avon_protocol::v1::{DeviceId, ControlMessage, PulseRequest, Timestamp};
//! use prost::Message;
//!
//! // Create a pulse request
//! let pulse = PulseRequest {
//!     server_nonce: vec![0u8; 32],
//!     timestamp: Some(Timestamp { seconds: 1234567890, nanos: 0 }),
//!     request_rotation: false,
//! };
//!
//! // Create a control message
//! let msg = ControlMessage {
//!     version: 1,
//!     sequence: 1,
//!     device_id: Some(DeviceId { uuid: vec![0u8; 16] }),
//!     auth_tag: vec![],
//!     payload: Some(avon_protocol::v1::control_message::Payload::PulseRequest(pulse)),
//! };
//!
//! // Encode to bytes
//! let bytes = msg.encode_to_vec();
//! assert!(!bytes.is_empty());
//! ```

pub mod codec;
mod generated;

/// Re-export of generated Protocol Buffer types for AVON v1.
pub mod v1 {
    pub use crate::generated::avon::v1::*;
}

/// Protocol version constant.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum message size (64 KB).
pub const MAX_MESSAGE_SIZE: usize = 65536;

/// Auth tag size (HMAC-SHA256).
pub const AUTH_TAG_SIZE: usize = 32;

/// Session ID size.
pub const SESSION_ID_SIZE: usize = 16;

/// Device ID size (UUID).
pub const DEVICE_ID_SIZE: usize = 16;

/// Nonce size for token rotation.
pub const NONCE_SIZE: usize = 32;

pub use prost::Message;
