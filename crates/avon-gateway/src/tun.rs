//! The gateway's TUN device — where packets bound for a protected network or
//! the internet leave the overlay and the kernel takes over routing.
//!
//! The platform TUN itself lands with the shared `avon-tun` crate in task 3.9;
//! this module is the seam. Until then a gateway runs in relay-only mode:
//! device-to-device forwarding works in full, egress does not.

use std::sync::Arc;

use async_trait::async_trait;
use avon_tunnel::{PacketSink, PacketSource, TunnelError};

pub struct Tun {
    pub sink: Arc<dyn PacketSink>,
    pub source: Arc<dyn PacketSource>,
    /// False when no kernel device was opened, so the caller can say so once
    /// rather than dropping packets silently.
    pub is_real: bool,
}

/// Open the platform TUN named `name`.
///
/// Returns a relay-only pair until task 3.9 lands `avon-tun`.
pub fn open(name: &str, _mtu: u16) -> Result<Tun, TunnelError> {
    tracing::warn!(
        tun = name,
        "no platform TUN yet (task 3.9): running relay-only, egress to protected networks is off"
    );
    Ok(Tun {
        sink: Arc::new(NullTun),
        source: Arc::new(NullTun),
        is_real: false,
    })
}

/// Accepts and drops everything; never produces a packet.
struct NullTun;

#[async_trait]
impl PacketSink for NullTun {
    async fn deliver(&self, _ip_packet: &[u8]) -> Result<(), TunnelError> {
        metrics::counter!("avon_gateway_packets_dropped_total", "reason" => "no_tun").increment(1);
        Ok(())
    }
}

#[async_trait]
impl PacketSource for NullTun {
    async fn next_packet(&self, _buf: &mut Vec<u8>) -> Result<usize, TunnelError> {
        std::future::pending().await
    }
}
