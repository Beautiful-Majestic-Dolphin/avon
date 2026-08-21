//! Data-plane session state: replay window, send counter, key schedule and
//! the session cipher (spec §6.1, §6.3).

mod cipher;
mod keys;
mod legacy;
mod replay;

pub use cipher::{nonce_for, Role, SessionCipher};
pub use keys::{SessionKeys, Transcript};
pub use legacy::TunnelKeys;
pub use replay::{CounterExhausted, ReplayError, ReplayWindow, SendCounter};
