//! The AVON gateway: the data-plane hub devices tunnel to.
//!
//! It never sees a session key it did not derive itself. Control brokers a
//! session by relaying the device's ephemeral KEM key here; the gateway
//! verifies the device certificate against its own chain, answers with a
//! signed [`avon_protocol::v2::SessionAnswer`], and from then on the tunnel is
//! between the device and this process alone.
//!
//! Forwarding has exactly three destinations for a packet from a session:
//! another session (relay), the local TUN (a protected network or the
//! internet), or the floor.

pub mod config;
pub mod control_link;
pub mod dataplane;
pub mod decision_log;
pub mod policy_hook;
pub mod redis_mirror;
pub mod routes;
pub mod state;
pub mod tun;

pub use config::GatewayConfig;
pub use policy_hook::{
    parse_flow, AllowAll, CedarFlowPolicy, Decision, Flow, FlowContext, FlowPolicy,
};
pub use routes::RouteTable;
pub use state::{ChainCache, GatewayState, SessionMeta};
