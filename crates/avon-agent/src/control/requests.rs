//! Request and response types for control plane communication.
//!
//! This module defines the trait for control plane requests and provides
//! wrapper types for responses.

use avon_protocol::v1::{
    control_message, AuthResponse, CertResponse, ConnectResponse, ControlMessage, PulseResponse,
};

/// Response from the control plane.
#[derive(Debug, Clone)]
pub enum ControlResponse {
    Pulse(PulseResponse),
    Auth(AuthResponse),
    Connect(ConnectResponse),
    Cert(CertResponse),
    Unknown,
}

impl ControlResponse {
    /// Creates a ControlResponse from a ControlMessage.
    pub fn from_message(msg: ControlMessage) -> Self {
        match msg.payload {
            Some(control_message::Payload::PulseResponse(r)) => Self::Pulse(r),
            Some(control_message::Payload::AuthResponse(r)) => Self::Auth(r),
            Some(control_message::Payload::ConnectResponse(r)) => Self::Connect(r),
            Some(control_message::Payload::CertResponse(r)) => Self::Cert(r),
            _ => Self::Unknown,
        }
    }

    /// Returns true if this is a successful response.
    pub fn is_success(&self) -> bool {
        match self {
            Self::Pulse(_) => true,
            Self::Auth(r) => r.success,
            Self::Connect(r) => r.allowed,
            Self::Cert(r) => r.certificate.is_some(),
            Self::Unknown => false,
        }
    }

    /// Extracts the pulse response if this is a pulse response.
    pub fn into_pulse(self) -> Option<PulseResponse> {
        match self {
            Self::Pulse(r) => Some(r),
            _ => None,
        }
    }

    /// Extracts the auth response if this is an auth response.
    pub fn into_auth(self) -> Option<AuthResponse> {
        match self {
            Self::Auth(r) => Some(r),
            _ => None,
        }
    }

    /// Extracts the connect response if this is a connect response.
    pub fn into_connect(self) -> Option<ConnectResponse> {
        match self {
            Self::Connect(r) => Some(r),
            _ => None,
        }
    }

    /// Extracts the cert response if this is a cert response.
    pub fn into_cert(self) -> Option<CertResponse> {
        match self {
            Self::Cert(r) => Some(r),
            _ => None,
        }
    }
}

/// Message type identifier for requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    PulseRequest,
    PulseResponse,
    AuthRequest,
    AuthResponse,
    ConnectRequest,
    ConnectResponse,
    IceCandidates,
    CertRequest,
    CertResponse,
    TunnelEstablished,
    TunnelClosed,
    KeyRotation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_response_is_success() {
        let pulse = ControlResponse::Pulse(PulseResponse::default());
        assert!(pulse.is_success());

        let auth_success = ControlResponse::Auth(AuthResponse {
            success: true,
            ..Default::default()
        });
        assert!(auth_success.is_success());

        let auth_fail = ControlResponse::Auth(AuthResponse {
            success: false,
            ..Default::default()
        });
        assert!(!auth_fail.is_success());

        let unknown = ControlResponse::Unknown;
        assert!(!unknown.is_success());
    }

    #[test]
    fn test_control_response_into_methods() {
        let pulse = ControlResponse::Pulse(PulseResponse::default());
        assert!(pulse.clone().into_pulse().is_some());
        assert!(pulse.into_auth().is_none());

        let auth = ControlResponse::Auth(AuthResponse::default());
        assert!(auth.clone().into_auth().is_some());
        assert!(auth.into_pulse().is_none());
    }
}
