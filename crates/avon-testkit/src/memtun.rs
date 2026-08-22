//! An in-memory TUN, so every data-plane test runs without root.

use async_trait::async_trait;
use avon_tunnel::{PacketSink, PacketSource, TunnelError};
use tokio::sync::mpsc;

/// What the local stack "sends" appears on `to_tunnel`; what the tunnel
/// delivers lands in `from_tunnel`.
pub struct MemoryTun {
    to_tunnel_tx: mpsc::Sender<Vec<u8>>,
    to_tunnel_rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    from_tunnel_tx: mpsc::Sender<Vec<u8>>,
    pub from_tunnel_rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl MemoryTun {
    pub fn new() -> std::sync::Arc<Self> {
        let (a_tx, a_rx) = mpsc::channel(1024);
        let (b_tx, b_rx) = mpsc::channel(1024);
        std::sync::Arc::new(Self {
            to_tunnel_tx: a_tx,
            to_tunnel_rx: tokio::sync::Mutex::new(a_rx),
            from_tunnel_tx: b_tx,
            from_tunnel_rx: tokio::sync::Mutex::new(b_rx),
        })
    }

    /// Simulate the local stack sending a packet.
    pub async fn inject(&self, packet: Vec<u8>) {
        let _ = self.to_tunnel_tx.send(packet).await;
    }

    /// Receive a packet the tunnel delivered to the local stack.
    pub async fn recv(&self) -> Option<Vec<u8>> {
        self.from_tunnel_rx.lock().await.recv().await
    }
}

#[async_trait]
impl PacketSink for MemoryTun {
    async fn deliver(&self, ip_packet: &[u8]) -> Result<(), TunnelError> {
        self.from_tunnel_tx
            .send(ip_packet.to_vec())
            .await
            .map_err(|_| TunnelError::Closed)
    }
}

#[async_trait]
impl PacketSource for MemoryTun {
    async fn next_packet(&self, buf: &mut Vec<u8>) -> Result<usize, TunnelError> {
        let p = self
            .to_tunnel_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(TunnelError::Closed)?;
        buf.clear();
        buf.extend_from_slice(&p);
        Ok(p.len())
    }
}
