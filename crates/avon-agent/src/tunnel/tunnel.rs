//! Individual tunnel implementation.
//!
//! Represents a single encrypted tunnel to a peer device, handling
//! packet encryption/decryption and statistics tracking.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::time::Instant;

use anyhow::{Context, Result};
use avon_common::device::DeviceId;
use avon_crypto::session::TunnelKeys;
use avon_crypto::tunnel::{TunnelCipher, TunnelDirection, TunnelPacket};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use super::SessionId;

/// State of a tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TunnelState {
    /// Tunnel is being established.
    Establishing = 0,
    /// Tunnel is active and can send/receive data.
    Active = 1,
    /// Tunnel is being closed.
    Closing = 2,
    /// Tunnel is closed.
    Closed = 3,
}

impl From<u8> for TunnelState {
    fn from(value: u8) -> Self {
        match value {
            0 => TunnelState::Establishing,
            1 => TunnelState::Active,
            2 => TunnelState::Closing,
            3 => TunnelState::Closed,
            _ => TunnelState::Closed,
        }
    }
}

/// Statistics for a tunnel.
#[derive(Debug)]
pub struct TunnelStats {
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
}

impl TunnelStats {
    /// Creates new tunnel statistics.
    pub fn new() -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
        }
    }

    /// Records bytes sent.
    pub fn record_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Records bytes received.
    pub fn record_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        self.packets_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns total bytes sent.
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Returns total bytes received.
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    /// Returns total packets sent.
    pub fn packets_sent(&self) -> u64 {
        self.packets_sent.load(Ordering::Relaxed)
    }

    /// Returns total packets received.
    pub fn packets_received(&self) -> u64 {
        self.packets_received.load(Ordering::Relaxed)
    }
}

impl Default for TunnelStats {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for TunnelStats {
    fn clone(&self) -> Self {
        Self {
            bytes_sent: AtomicU64::new(self.bytes_sent.load(Ordering::Relaxed)),
            bytes_received: AtomicU64::new(self.bytes_received.load(Ordering::Relaxed)),
            packets_sent: AtomicU64::new(self.packets_sent.load(Ordering::Relaxed)),
            packets_received: AtomicU64::new(self.packets_received.load(Ordering::Relaxed)),
        }
    }
}

/// An encrypted tunnel to a peer device.
///
/// Handles packet encryption/decryption using AES-256-GCM with
/// direction-based nonce management to prevent nonce reuse.
pub struct Tunnel {
    session_id: SessionId,
    peer_device: DeviceId,
    peer_addr: RwLock<SocketAddr>,
    socket: UdpSocket,
    send_cipher: TunnelCipher,
    recv_cipher: TunnelCipher,
    established_at: Instant,
    last_activity: RwLock<Instant>,
    stats: TunnelStats,
    state: AtomicU8,
    is_initiator: bool,
}

impl Tunnel {
    /// Creates a new tunnel.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Unique session identifier
    /// * `peer_device` - Device ID of the peer
    /// * `peer_addr` - Socket address of the peer
    /// * `keys` - Derived tunnel keys from handshake
    /// * `is_initiator` - Whether this endpoint initiated the tunnel
    pub async fn new(
        session_id: SessionId,
        peer_device: DeviceId,
        peer_addr: SocketAddr,
        keys: TunnelKeys,
        is_initiator: bool,
    ) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind tunnel socket")?;

        socket
            .connect(peer_addr)
            .await
            .context("Failed to connect tunnel socket")?;

        // Create ciphers with appropriate directions
        // Initiator sends with initiator key, receives with responder key
        // Responder sends with responder key, receives with initiator key
        let (send_cipher, recv_cipher) = if is_initiator {
            (
                TunnelCipher::new(*keys.initiator_key(), TunnelDirection::Initiator),
                TunnelCipher::new(*keys.responder_key(), TunnelDirection::Responder),
            )
        } else {
            (
                TunnelCipher::new(*keys.responder_key(), TunnelDirection::Responder),
                TunnelCipher::new(*keys.initiator_key(), TunnelDirection::Initiator),
            )
        };

        let now = Instant::now();

        Ok(Self {
            session_id,
            peer_device,
            peer_addr: RwLock::new(peer_addr),
            socket,
            send_cipher,
            recv_cipher,
            established_at: now,
            last_activity: RwLock::new(now),
            stats: TunnelStats::new(),
            state: AtomicU8::new(TunnelState::Active as u8),
            is_initiator,
        })
    }

    /// Returns the session ID.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the peer device ID.
    pub fn peer_device(&self) -> &DeviceId {
        &self.peer_device
    }

    /// Returns the peer address.
    pub async fn peer_addr(&self) -> SocketAddr {
        *self.peer_addr.read().await
    }

    /// Updates the peer address (for NAT rebinding).
    pub async fn update_peer_addr(&self, addr: SocketAddr) -> Result<()> {
        self.socket
            .connect(addr)
            .await
            .context("Failed to reconnect socket")?;
        *self.peer_addr.write().await = addr;
        Ok(())
    }

    /// Returns when the tunnel was established.
    pub fn established_at(&self) -> Instant {
        self.established_at
    }

    /// Returns the last activity time.
    pub async fn last_activity(&self) -> Instant {
        *self.last_activity.read().await
    }

    /// Returns the tunnel statistics.
    pub fn stats(&self) -> TunnelStats {
        self.stats.clone()
    }

    /// Returns the current tunnel state.
    pub fn state(&self) -> TunnelState {
        TunnelState::from(self.state.load(Ordering::Relaxed))
    }

    /// Returns whether this endpoint is the initiator.
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Returns whether the tunnel is active.
    pub fn is_active(&self) -> bool {
        self.state() == TunnelState::Active
    }

    /// Sends an encrypted packet through the tunnel.
    ///
    /// # Arguments
    ///
    /// * `packet` - The plaintext packet to send
    ///
    /// # Returns
    ///
    /// The number of bytes sent (ciphertext size).
    pub async fn send(&self, packet: &[u8]) -> Result<usize> {
        if !self.is_active() {
            anyhow::bail!("Tunnel is not active");
        }

        // Encrypt the packet
        let aad = &self.session_id;
        let encrypted = self
            .send_cipher
            .encrypt(packet, aad)
            .context("Failed to encrypt packet")?;

        // Send the encrypted packet
        let bytes = encrypted.to_bytes();
        let sent = self
            .socket
            .send(&bytes)
            .await
            .context("Failed to send packet")?;

        // Update statistics
        self.stats.record_sent(packet.len() as u64);
        *self.last_activity.write().await = Instant::now();

        Ok(sent)
    }

    /// Receives and decrypts a packet from the tunnel.
    ///
    /// # Returns
    ///
    /// The decrypted plaintext packet.
    pub async fn recv(&self) -> Result<Vec<u8>> {
        if !self.is_active() {
            anyhow::bail!("Tunnel is not active");
        }

        // Receive encrypted packet
        let mut buf = vec![0u8; 65536];
        let len = self
            .socket
            .recv(&mut buf)
            .await
            .context("Failed to receive packet")?;

        // Parse the tunnel packet
        let packet = TunnelPacket::from_bytes(&buf[..len])
            .context("Failed to parse tunnel packet")?;

        // Decrypt the packet
        let aad = &self.session_id;
        let plaintext = self
            .recv_cipher
            .decrypt(&packet, aad)
            .context("Failed to decrypt packet")?;

        // Update statistics
        self.stats.record_received(plaintext.len() as u64);
        *self.last_activity.write().await = Instant::now();

        Ok(plaintext)
    }

    /// Sends a close notification to the peer.
    pub async fn send_close_notification(&self) -> Result<()> {
        // Send a special close packet (empty payload with close flag)
        let close_marker = b"AVON_CLOSE";
        let aad = &self.session_id;
        
        let encrypted = self
            .send_cipher
            .encrypt(close_marker, aad)
            .context("Failed to encrypt close notification")?;

        let bytes = encrypted.to_bytes();
        self.socket
            .send(&bytes)
            .await
            .context("Failed to send close notification")?;

        Ok(())
    }

    /// Closes the tunnel.
    pub async fn close(&self) {
        self.state.store(TunnelState::Closing as u8, Ordering::Relaxed);
        // Socket will be closed when dropped
        self.state.store(TunnelState::Closed as u8, Ordering::Relaxed);
    }

    /// Returns the number of remaining nonces before rekey is needed.
    pub fn remaining_nonces(&self) -> u64 {
        self.send_cipher.remaining_nonces()
    }

    /// Checks if the tunnel needs rekeying.
    ///
    /// Returns true if fewer than 2^32 nonces remain.
    pub fn needs_rekey(&self) -> bool {
        self.remaining_nonces() < (1u64 << 32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_state_from_u8() {
        assert_eq!(TunnelState::from(0), TunnelState::Establishing);
        assert_eq!(TunnelState::from(1), TunnelState::Active);
        assert_eq!(TunnelState::from(2), TunnelState::Closing);
        assert_eq!(TunnelState::from(3), TunnelState::Closed);
        assert_eq!(TunnelState::from(255), TunnelState::Closed);
    }

    #[test]
    fn test_tunnel_stats() {
        let stats = TunnelStats::new();
        assert_eq!(stats.bytes_sent(), 0);
        assert_eq!(stats.bytes_received(), 0);
        assert_eq!(stats.packets_sent(), 0);
        assert_eq!(stats.packets_received(), 0);

        stats.record_sent(100);
        assert_eq!(stats.bytes_sent(), 100);
        assert_eq!(stats.packets_sent(), 1);

        stats.record_received(200);
        assert_eq!(stats.bytes_received(), 200);
        assert_eq!(stats.packets_received(), 1);
    }

    #[test]
    fn test_tunnel_stats_clone() {
        let stats = TunnelStats::new();
        stats.record_sent(100);
        stats.record_received(200);

        let cloned = stats.clone();
        assert_eq!(cloned.bytes_sent(), 100);
        assert_eq!(cloned.bytes_received(), 200);
    }
}
