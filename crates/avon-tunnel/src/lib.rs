//! ATP/2 — the AVON tunnel protocol (spec §6).
//!
//! Wire: 16-byte header (type, flags, receiver index, counter) followed by
//! an AEAD ciphertext of `inner_type || payload`. Keys come from the control
//! channel; this crate never performs an unauthenticated handshake on UDP.

mod endpoint;
mod establish;
mod header;
mod inner;
mod routes;
mod session;
mod sink;
mod table;
mod timers;

pub use endpoint::{EndpointConfig, EndpointEvent, UdpEndpoint};
pub use establish::{
    choose_suite, rekey_answer, rekey_complete, rekey_offer, Established, Initiator, PendingOffer,
    Responder,
};
pub use header::{max_udp_payload, Header, FLAG_EPOCH_OVERLAP, HEADER_LEN, TYPE_DATA};
pub use inner::Inner;
pub use routes::RouteTable;
pub use session::{Epoch, Role, Session, SessionStats};
pub use sink::{PacketSink, PacketSource};
pub use table::SessionTable;
pub use timers::TimerConfig;

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("packet too short")]
    Short,
    #[error("bad packet type {0:#x}")]
    BadType(u8),
    #[error("bad inner type {0}")]
    BadInner(u8),
    #[error("crypto: {0}")]
    Crypto(#[from] avon_crypto::CryptoError),
    #[error("unknown receiver index {0}")]
    UnknownIndex(u32),
    #[error("replayed packet")]
    Replay,
    #[error("session closed")]
    Closed,
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame: {0}")]
    Frame(#[from] prost::DecodeError),
}
