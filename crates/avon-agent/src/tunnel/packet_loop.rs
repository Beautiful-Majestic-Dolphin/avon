//! Packet processing loops for tunnel traffic.
//!
//! Handles reading packets from the TUN device, routing them to the
//! appropriate tunnel, and writing received packets back to the TUN device.

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use dashmap::DashMap;
use tokio::sync::RwLock;

use super::routing::RoutingTable;
use super::tun_device::TunDevice;
use super::tunnel::Tunnel;
use super::SessionId;

/// Packet processing loop for tunnel traffic.
///
/// Runs two concurrent loops:
/// - Outbound: Reads from TUN, routes to appropriate tunnel
/// - Inbound: Receives from tunnels, writes to TUN
pub struct PacketLoop {
    tun: Arc<RwLock<Option<TunDevice>>>,
    tunnels: DashMap<SessionId, Arc<Tunnel>>,
    routing: Arc<RoutingTable>,
}

impl PacketLoop {
    /// Creates a new packet loop.
    pub fn new(
        tun: Arc<RwLock<Option<TunDevice>>>,
        tunnels: DashMap<SessionId, Arc<Tunnel>>,
        routing: Arc<RoutingTable>,
    ) -> Self {
        Self {
            tun,
            tunnels,
            routing,
        }
    }

    /// Runs the packet processing loops.
    ///
    /// This spawns both outbound and inbound loops and runs them concurrently.
    pub async fn run(&self) -> Result<()> {
        // Wait for TUN device to be initialized
        loop {
            if self.tun.read().await.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        tracing::info!("Starting packet processing loops");

        // Run both loops concurrently
        tokio::select! {
            result = self.run_outbound() => {
                tracing::error!("Outbound loop exited: {:?}", result);
                result
            }
            result = self.run_inbound() => {
                tracing::error!("Inbound loop exited: {:?}", result);
                result
            }
        }
    }

    /// Runs the outbound packet loop.
    ///
    /// Reads packets from the TUN device, determines the destination,
    /// looks up the appropriate tunnel, and sends the encrypted packet.
    async fn run_outbound(&self) -> Result<()> {
        loop {
            // Read packet from TUN
            let packet = {
                let tun_guard = self.tun.read().await;
                let tun = tun_guard.as_ref().context("TUN device not initialized")?;
                tun.read_packet().await?
            };

            // Skip empty packets
            if packet.is_empty() {
                continue;
            }

            // Extract destination IP from packet
            let destination = match Self::extract_destination_ip(&packet) {
                Some(ip) => ip,
                None => {
                    tracing::trace!("Could not extract destination IP from packet");
                    continue;
                }
            };

            // Look up tunnel for destination
            let session_id = match self.routing.lookup(&destination) {
                Some(id) => id,
                None => {
                    tracing::trace!(%destination, "No route for destination");
                    continue;
                }
            };

            // Get tunnel and send packet
            if let Some(tunnel) = self.tunnels.get(&session_id) {
                if let Err(e) = tunnel.send(&packet).await {
                    tracing::warn!(
                        error = %e,
                        session_id = %hex::encode(session_id),
                        "Failed to send packet through tunnel"
                    );
                }
            } else {
                tracing::warn!(
                    session_id = %hex::encode(session_id),
                    "Tunnel not found for session"
                );
            }
        }
    }

    /// Runs the inbound packet loop.
    ///
    /// Receives packets from all tunnels and writes them to the TUN device.
    async fn run_inbound(&self) -> Result<()> {
        // In a real implementation, we would use a more sophisticated
        // approach like select! over all tunnel receive futures.
        // For now, we poll each tunnel in a round-robin fashion.

        loop {
            let mut received_any = false;

            // Iterate over all tunnels
            for tunnel_ref in self.tunnels.iter() {
                let tunnel = tunnel_ref.value();

                // Try to receive with a short timeout
                match tokio::time::timeout(std::time::Duration::from_millis(10), tunnel.recv())
                    .await
                {
                    Ok(Ok(packet)) => {
                        received_any = true;

                        // Write packet to TUN
                        let tun_guard = self.tun.read().await;
                        if let Some(tun) = tun_guard.as_ref() {
                            if let Err(e) = tun.write_packet(&packet).await {
                                tracing::warn!(error = %e, "Failed to write packet to TUN");
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::trace!(error = %e, "Tunnel receive error");
                    }
                    Err(_) => {
                        // Timeout - no packet available
                    }
                }
            }

            // If no packets were received, sleep briefly to avoid busy-waiting
            if !received_any {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        }
    }

    /// Extracts the destination IP address from an IP packet.
    fn extract_destination_ip(packet: &[u8]) -> Option<IpAddr> {
        if packet.is_empty() {
            return None;
        }

        // Check IP version from first nibble
        let version = packet[0] >> 4;

        match version {
            4 => Self::extract_ipv4_destination(packet),
            6 => Self::extract_ipv6_destination(packet),
            _ => None,
        }
    }

    /// Extracts destination from IPv4 packet.
    fn extract_ipv4_destination(packet: &[u8]) -> Option<IpAddr> {
        // IPv4 header: destination is at bytes 16-19
        if packet.len() < 20 {
            return None;
        }

        let addr = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

        Some(IpAddr::V4(addr))
    }

    /// Extracts destination from IPv6 packet.
    fn extract_ipv6_destination(packet: &[u8]) -> Option<IpAddr> {
        // IPv6 header: destination is at bytes 24-39
        if packet.len() < 40 {
            return None;
        }

        let mut addr_bytes = [0u8; 16];
        addr_bytes.copy_from_slice(&packet[24..40]);
        let addr = std::net::Ipv6Addr::from(addr_bytes);

        Some(IpAddr::V6(addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ipv4_destination() {
        // Minimal IPv4 packet with destination 10.0.0.1
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45; // Version 4, IHL 5
        packet[16] = 10;
        packet[17] = 0;
        packet[18] = 0;
        packet[19] = 1;

        let dest = PacketLoop::extract_destination_ip(&packet);
        assert_eq!(dest, Some(IpAddr::V4("10.0.0.1".parse().unwrap())));
    }

    #[test]
    fn test_extract_ipv6_destination() {
        // Minimal IPv6 packet with destination ::1
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60; // Version 6
        packet[39] = 1; // ::1

        let dest = PacketLoop::extract_destination_ip(&packet);
        assert_eq!(dest, Some(IpAddr::V6("::1".parse().unwrap())));
    }

    #[test]
    fn test_extract_empty_packet() {
        let packet: Vec<u8> = vec![];
        assert_eq!(PacketLoop::extract_destination_ip(&packet), None);
    }

    #[test]
    fn test_extract_short_ipv4_packet() {
        let packet = vec![0x45u8; 10]; // Too short for IPv4
        assert_eq!(PacketLoop::extract_destination_ip(&packet), None);
    }

    #[test]
    fn test_extract_short_ipv6_packet() {
        let packet = vec![0x60u8; 30]; // Too short for IPv6
        assert_eq!(PacketLoop::extract_destination_ip(&packet), None);
    }

    #[test]
    fn test_extract_unknown_version() {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x30; // Version 3 (invalid)
        assert_eq!(PacketLoop::extract_destination_ip(&packet), None);
    }
}
