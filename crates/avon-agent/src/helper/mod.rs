//! Privilege separation: everything that needs root lives in
//! `avon-agent-helper`, and the agent talks to it over a validated,
//! intent-only IPC.

pub mod client;
pub mod protocol;
pub mod server;
mod wire;

pub use client::{HelperClient, HelperTun};
pub use protocol::{
    validate, validate_ifname, FirewallRules, HelperError, HelperRequest, HelperResponse,
    HelperState, ProtocolError, MAX_LINE_BYTES, MAX_ROUTES,
};
pub use server::{serve, socket_path};
