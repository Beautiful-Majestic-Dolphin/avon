//! Data-plane session state: replay window, send counter, key schedule and
//! the session cipher (spec §6.1, §6.3).

mod legacy;
mod replay;

pub use legacy::TunnelKeys;
pub use replay::{CounterExhausted, ReplayError, ReplayWindow, SendCounter};

// New ATP/2 modules will be added in Task 1.7
