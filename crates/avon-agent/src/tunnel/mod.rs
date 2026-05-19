//! Tunnel management for AVON Agent.
//!
//! This module handles the establishment, maintenance, and teardown of
//! encrypted tunnels to peer devices. It includes:
//! - Tunnel establishment with hybrid key exchange
//! - Packet encryption/decryption using AES-256-GCM
//! - TUN device management for packet routing
//! - Routing table for directing packets to tunnels

pub mod handshake;
pub mod packet_loop;
pub mod routing;
pub mod tun_device;
pub mod tunnel;

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use avon_common::device::DeviceId;
use avon_protocol::v1::{control_message, ConnectRequest, TunnelClosed, TunnelEstablished};
use dashmap::DashMap;
use tokio::sync::RwLock;

use crate::control::ControlPlaneClient;
use crate::identity::IdentityManager;

use self::handshake::TunnelHandshake;
use self::packet_loop::PacketLoop;
use self::routing::RoutingTable;
use self::tun_device::TunDevice;
use self::tunnel::Tunnel;

/// Session ID for a tunnel (16 bytes).
pub type SessionId = [u8; 16];

/// Configuration for the tunnel manager.
#[derive(Debug, Clone)]
pub struct TunnelManagerConfig {
    /// Name prefix for TUN devices.
    pub tun_name_prefix: String,
    /// IP address for the TUN device.
    pub tun_address: IpAddr,
    /// Netmask for the TUN device.
    pub tun_netmask: IpAddr,
    /// MTU for the TUN device.
    pub tun_mtu: u32,
    /// Timeout for tunnel handshake.
    pub handshake_timeout: Duration,
    /// Interval for tunnel keepalive.
    pub keepalive_interval: Duration,
}

impl Default for TunnelManagerConfig {
    fn default() -> Self {
        Self {
            tun_name_prefix: "avon".to_string(),
            tun_address: "10.100.0.1".parse().unwrap(),
            tun_netmask: "255.255.255.0".parse().unwrap(),
            tun_mtu: 1400,
            handshake_timeout: Duration::from_secs(30),
            keepalive_interval: Duration::from_secs(30),
        }
    }
}

/// Manages all tunnels for the AVON agent.
///
/// Handles tunnel establishment, packet routing, and lifecycle management.
pub struct TunnelManager {
    tunnels: DashMap<SessionId, Arc<Tunnel>>,
    control_client: Arc<ControlPlaneClient>,
    identity: Arc<IdentityManager>,
    tun_device: Arc<RwLock<Option<TunDevice>>>,
    routing_table: Arc<RoutingTable>,
    config: TunnelManagerConfig,
    session_counter: AtomicU64,
}

impl TunnelManager {
    /// Creates a new tunnel manager.
    ///
    /// # Arguments
    ///
    /// * `control_client` - Control plane client for signaling
    /// * `identity` - Identity manager for authentication
    /// * `config` - Tunnel manager configuration
    pub fn new(
        control_client: Arc<ControlPlaneClient>,
        identity: Arc<IdentityManager>,
        config: TunnelManagerConfig,
    ) -> Self {
        Self {
            tunnels: DashMap::new(),
            control_client,
            identity,
            tun_device: Arc::new(RwLock::new(None)),
            routing_table: Arc::new(RoutingTable::new()),
            config,
            session_counter: AtomicU64::new(1),
        }
    }

    /// Creates a new tunnel manager with default configuration.
    pub fn with_defaults(
        control_client: Arc<ControlPlaneClient>,
        identity: Arc<IdentityManager>,
    ) -> Self {
        Self::new(control_client, identity, TunnelManagerConfig::default())
    }

    /// Initializes the tunnel manager and starts background tasks.
    ///
    /// This creates the TUN device and starts the packet processing loops.
    pub async fn run(&self) -> Result<()> {
        // Initialize TUN device
        self.initialize_tun_device().await?;

        // Start packet processing loops
        let packet_loop = PacketLoop::new(
            self.tun_device.clone(),
            self.tunnels.clone(),
            self.routing_table.clone(),
        );

        // Run the packet loop (this will run until stopped)
        packet_loop.run().await
    }

    /// Initializes the TUN device.
    async fn initialize_tun_device(&self) -> Result<()> {
        let tun_name = format!("{}0", self.config.tun_name_prefix);

        let tun = TunDevice::create(
            &tun_name,
            self.config.tun_address,
            self.config.tun_netmask,
            self.config.tun_mtu,
        )
        .await
        .context("Failed to create TUN device")?;

        tracing::info!(
            name = %tun.name(),
            address = %self.config.tun_address,
            mtu = self.config.tun_mtu,
            "TUN device initialized"
        );

        *self.tun_device.write().await = Some(tun);
        Ok(())
    }

    /// Establishes a tunnel to a target device.
    ///
    /// # Arguments
    ///
    /// * `target` - The device ID of the target peer
    /// * `service_name` - Optional service name for the connection
    ///
    /// # Returns
    ///
    /// The session ID of the established tunnel.
    pub async fn establish_tunnel(
        &self,
        target: DeviceId,
        service_name: Option<String>,
    ) -> Result<SessionId> {
        tracing::info!(%target, ?service_name, "Establishing tunnel");

        // 1. Request connection from control plane
        let connect_request = ConnectRequest {
            target_device: Some(avon_protocol::v1::DeviceId {
                uuid: target.as_bytes().to_vec(),
            }),
            service_name: service_name.unwrap_or_default(),
        };

        let response = self
            .control_client
            .send_request(
                control_message::Payload::ConnectRequest(connect_request),
                Some(self.config.handshake_timeout),
            )
            .await
            .context("Failed to send connect request")?;

        // 2. Extract connection details from response
        let connect_response = response
            .into_connect()
            .context("Expected ConnectResponse")?;

        if !connect_response.allowed {
            anyhow::bail!(
                "Connection denied: {}",
                if connect_response.deny_reason.is_empty() {
                    "Unknown reason".to_string()
                } else {
                    connect_response.deny_reason.clone()
                }
            );
        }

        // Generate session ID
        let session_id = self.generate_session_id();

        // 3. Get peer address from ICE candidates
        let peer_addr = self
            .resolve_peer_address(&connect_response)
            .await
            .context("Failed to resolve peer address")?;

        // 4. Perform tunnel handshake
        let handshake = TunnelHandshake::new(session_id, self.identity.clone());

        let tunnel_keys = handshake
            .initiate(peer_addr, self.config.handshake_timeout)
            .await
            .context("Tunnel handshake failed")?;

        // 5. Create tunnel with derived keys
        let tunnel = Tunnel::new(
            session_id,
            target,
            peer_addr,
            tunnel_keys,
            true, // We are the initiator
        )
        .await
        .context("Failed to create tunnel")?;

        let tunnel = Arc::new(tunnel);

        // 6. Add routing entry (use target device's address from candidates if available)
        for candidate in &connect_response.target_candidates {
            if let Ok(ip) = candidate.ip.parse::<IpAddr>() {
                self.routing_table.add_route(ip, session_id);
                tracing::debug!(%ip, "Added route for peer");
                break;
            }
        }

        // 7. Store tunnel
        self.tunnels.insert(session_id, tunnel.clone());

        // 8. Notify control plane of establishment
        self.notify_tunnel_established(&session_id, &target).await?;

        tracing::info!(
            session_id = %hex::encode(session_id),
            %target,
            %peer_addr,
            "Tunnel established"
        );

        Ok(session_id)
    }

    /// Closes a tunnel.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session ID of the tunnel to close
    pub async fn close_tunnel(&self, session_id: &SessionId) -> Result<()> {
        tracing::info!(session_id = %hex::encode(session_id), "Closing tunnel");

        // 1. Get and remove tunnel
        let tunnel = self
            .tunnels
            .remove(session_id)
            .map(|(_, t)| t)
            .context("Tunnel not found")?;

        // 2. Send close notification to peer
        if let Err(e) = tunnel.send_close_notification().await {
            tracing::warn!(error = %e, "Failed to send close notification");
        }

        // 3. Notify control plane
        self.notify_tunnel_closed(session_id, tunnel.peer_device())
            .await?;

        // 4. Remove routing entries for this tunnel
        self.routing_table.remove_routes_for_session(session_id);

        // 5. Close the tunnel
        tunnel.close().await;

        tracing::info!(session_id = %hex::encode(session_id), "Tunnel closed");

        Ok(())
    }

    /// Returns the number of active tunnels.
    pub fn active_tunnel_count(&self) -> usize {
        self.tunnels.len()
    }

    /// Returns a list of active session IDs.
    pub fn active_sessions(&self) -> Vec<SessionId> {
        self.tunnels.iter().map(|r| *r.key()).collect()
    }

    /// Gets a tunnel by session ID.
    pub fn get_tunnel(&self, session_id: &SessionId) -> Option<Arc<Tunnel>> {
        self.tunnels.get(session_id).map(|r| r.value().clone())
    }

    /// Gets the routing table.
    pub fn routing_table(&self) -> Arc<RoutingTable> {
        self.routing_table.clone()
    }

    /// Generates a new unique session ID.
    fn generate_session_id(&self) -> SessionId {
        let counter = self.session_counter.fetch_add(1, Ordering::Relaxed);
        let device_id = self.identity.device_id();

        let mut session_id = [0u8; 16];
        // First 8 bytes from device ID
        session_id[..8].copy_from_slice(&device_id.as_bytes()[..8]);
        // Last 8 bytes from counter
        session_id[8..].copy_from_slice(&counter.to_be_bytes());

        session_id
    }

    /// Resolves the peer address from connect response.
    async fn resolve_peer_address(
        &self,
        response: &avon_protocol::v1::ConnectResponse,
    ) -> Result<SocketAddr> {
        // Use ICE candidates from target_candidates field
        for candidate in &response.target_candidates {
            let addr_str = format!("{}:{}", candidate.ip, candidate.port);
            if let Ok(socket_addr) = addr_str.parse() {
                return Ok(socket_addr);
            }
        }

        anyhow::bail!("No valid peer address found")
    }

    /// Notifies the control plane that a tunnel was established.
    async fn notify_tunnel_established(
        &self,
        session_id: &SessionId,
        peer_device: &DeviceId,
    ) -> Result<()> {
        let notification = TunnelEstablished {
            session_id: session_id.to_vec(),
            peer_device: Some(avon_protocol::v1::DeviceId {
                uuid: peer_device.as_bytes().to_vec(),
            }),
            established_at: Some(ControlPlaneClient::now_timestamp()),
        };

        self.control_client
            .send_request(
                control_message::Payload::TunnelEstablished(notification),
                None,
            )
            .await
            .context("Failed to notify tunnel establishment")?;

        Ok(())
    }

    /// Notifies the control plane that a tunnel was closed.
    async fn notify_tunnel_closed(
        &self,
        session_id: &SessionId,
        _peer_device: &DeviceId,
    ) -> Result<()> {
        let tunnel = self.tunnels.get(session_id);
        let (bytes_sent, bytes_received) = tunnel
            .map(|t| {
                let stats = t.stats();
                (stats.bytes_sent(), stats.bytes_received())
            })
            .unwrap_or((0, 0));

        let notification = TunnelClosed {
            session_id: session_id.to_vec(),
            reason: avon_protocol::v1::CloseReason::Normal as i32,
            bytes_sent,
            bytes_received,
        };

        self.control_client
            .send_request(control_message::Payload::TunnelClosed(notification), None)
            .await
            .context("Failed to notify tunnel closure")?;

        Ok(())
    }

    /// Handles an incoming tunnel request from a peer.
    pub async fn handle_incoming_tunnel(
        &self,
        session_id: SessionId,
        peer_device: DeviceId,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        tracing::info!(
            session_id = %hex::encode(session_id),
            %peer_device,
            %peer_addr,
            "Handling incoming tunnel request"
        );

        // Perform handshake as responder
        let handshake = TunnelHandshake::new(session_id, self.identity.clone());

        let tunnel_keys = handshake
            .respond(peer_addr, self.config.handshake_timeout)
            .await
            .context("Tunnel handshake failed")?;

        // Create tunnel
        let tunnel = Tunnel::new(
            session_id,
            peer_device,
            peer_addr,
            tunnel_keys,
            false, // We are the responder
        )
        .await
        .context("Failed to create tunnel")?;

        let tunnel = Arc::new(tunnel);

        // Store tunnel
        self.tunnels.insert(session_id, tunnel);

        // Notify control plane
        self.notify_tunnel_established(&session_id, &peer_device)
            .await?;

        tracing::info!(
            session_id = %hex::encode(session_id),
            %peer_device,
            "Incoming tunnel established"
        );

        Ok(())
    }
}

/// Statistics for all tunnels.
#[derive(Debug, Clone, Default)]
pub struct TunnelManagerStats {
    pub active_tunnels: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub total_packets_sent: u64,
    pub total_packets_received: u64,
}

impl TunnelManager {
    /// Collects statistics from all tunnels.
    pub fn collect_stats(&self) -> TunnelManagerStats {
        let mut stats = TunnelManagerStats {
            active_tunnels: self.tunnels.len(),
            ..Default::default()
        };

        for tunnel_ref in self.tunnels.iter() {
            let tunnel_stats = tunnel_ref.value().stats();
            stats.total_bytes_sent += tunnel_stats.bytes_sent();
            stats.total_bytes_received += tunnel_stats.bytes_received();
            stats.total_packets_sent += tunnel_stats.packets_sent();
            stats.total_packets_received += tunnel_stats.packets_received();
        }

        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_manager_config_default() {
        let config = TunnelManagerConfig::default();
        assert_eq!(config.tun_name_prefix, "avon");
        assert_eq!(config.tun_mtu, 1400);
        assert_eq!(config.handshake_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_tunnel_manager_stats_default() {
        let stats = TunnelManagerStats::default();
        assert_eq!(stats.active_tunnels, 0);
        assert_eq!(stats.total_bytes_sent, 0);
    }
}
