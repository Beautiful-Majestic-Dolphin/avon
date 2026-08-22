use async_trait::async_trait;

use crate::TunnelError;

/// Delivers decrypted IP packets toward the local network stack.
#[async_trait]
pub trait PacketSink: Send + Sync {
    async fn deliver(&self, ip_packet: &[u8]) -> Result<(), TunnelError>;
}

/// Produces IP packets from the local network stack.
#[async_trait]
pub trait PacketSource: Send + Sync {
    /// Reads one packet into `buf` (cleared first) and returns its length.
    async fn next_packet(&self, buf: &mut Vec<u8>) -> Result<usize, TunnelError>;
}
