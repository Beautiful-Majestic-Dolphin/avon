//! Platform-independent agent core: identity custody, control client, hub
//! session lifecycle and the reconnecting run loop.

pub mod agent;
pub mod control;
pub mod identity;
pub mod peer;
pub mod router;
pub mod session_manager;
pub mod status;
pub mod traits;

pub use agent::{Agent, AgentCoreConfig};
pub use avon_keystore::SoftwareKeyProvider;
pub use identity::{enroll, load, Identity, IdentityError};
pub use status::{Status, StatusHandle};
pub use traits::{FingerprintProvider, KeyProvider, PostureProvider, TunProvider};

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("identity: {0}")]
    Identity(#[from] IdentityError),
    #[error("control: {0}")]
    Control(String),
    #[error("tunnel: {0}")]
    Tunnel(#[from] avon_tunnel::TunnelError),
    #[error("crypto: {0}")]
    Crypto(#[from] avon_crypto::CryptoError),
    #[error("keystore: {0}")]
    Keystore(#[from] avon_keystore::KeyError),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("tun: {0}")]
    Tun(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("transport: {0}")]
    Transport(String),
    #[error("tls: {0}")]
    Tls(String),
    #[error("status: {0}")]
    Status(String),
    #[error("reauthenticate")]
    Reauthenticate,
}

impl From<tonic::Status> for AgentError {
    fn from(s: tonic::Status) -> Self {
        if s.code() == tonic::Code::Unauthenticated {
            Self::Reauthenticate
        } else {
            Self::Control(format!("{}: {}", s.code(), s.message()))
        }
    }
}

impl From<tonic::transport::Error> for AgentError {
    fn from(e: tonic::transport::Error) -> Self {
        Self::Transport(e.to_string())
    }
}

impl From<avon_crypto::cert::CertError> for AgentError {
    fn from(e: avon_crypto::cert::CertError) -> Self {
        Self::Protocol(e.to_string())
    }
}
