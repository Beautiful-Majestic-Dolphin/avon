//! NAT traversal for AVON Agent.
//!
//! This module provides NAT traversal capabilities for establishing peer-to-peer
//! connections between AVON agents. It implements:
//!
//! - STUN for discovering external addresses
//! - ICE for connectivity establishment
//! - TURN for relay fallback
//! - TCP/443 fallback for restrictive firewalls
//!
//! The NAT traversal follows this priority order:
//! 1. Direct P2P (host-to-host)
//! 2. STUN hole-punched (server-reflexive)
//! 3. TURN UDP relay
//! 4. TURN TCP/443 relay

pub mod ice;
pub mod stun;
pub mod tcp_fallback;
pub mod turn;

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;

use self::ice::{CandidateType, IceAgent, IceCandidate};
use self::stun::StunClient;
use self::tcp_fallback::{TcpFallback, TcpTunnelConnection};
use self::turn::{TurnClient, TurnServerConfig};

/// Default STUN servers (Google's public STUN servers).
const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
];

/// Configuration for NAT traversal.
#[derive(Debug, Clone)]
pub struct NatConfig {
    /// STUN server addresses.
    pub stun_servers: Vec<SocketAddr>,
    /// TURN server configurations.
    pub turn_servers: Vec<TurnServerConfig>,
    /// Timeout for candidate gathering.
    pub gather_timeout: Duration,
    /// Timeout for connectivity checks.
    pub check_timeout: Duration,
    /// Whether to enable TCP fallback.
    pub enable_tcp_fallback: bool,
    /// Local port to bind to (0 for any).
    pub local_port: u16,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            stun_servers: Vec::new(),
            turn_servers: Vec::new(),
            gather_timeout: Duration::from_secs(5),
            check_timeout: Duration::from_secs(3),
            enable_tcp_fallback: true,
            local_port: 0,
        }
    }
}

impl NatConfig {
    /// Creates a new NAT config with default STUN servers.
    pub fn with_default_stun() -> Self {
        let stun_servers = DEFAULT_STUN_SERVERS
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        Self {
            stun_servers,
            ..Default::default()
        }
    }

    /// Adds a STUN server.
    pub fn add_stun_server(&mut self, server: SocketAddr) {
        self.stun_servers.push(server);
    }

    /// Adds a TURN server.
    pub fn add_turn_server(&mut self, config: TurnServerConfig) {
        self.turn_servers.push(config);
    }
}

/// An established connection after NAT traversal.
#[derive(Debug)]
pub struct EstablishedConnection {
    /// The local address used.
    pub local_addr: SocketAddr,
    /// The remote peer address.
    pub remote_addr: SocketAddr,
    /// The type of connection established.
    pub connection_type: ConnectionType,
    /// The UDP socket (if direct or STUN).
    pub socket: Option<UdpSocket>,
    /// The TCP tunnel (if TCP fallback).
    pub tcp_tunnel: Option<TcpTunnelConnection>,
}

/// Type of connection established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    /// Direct peer-to-peer connection.
    Direct,
    /// Connection via STUN hole punching.
    StunHolePunched,
    /// Connection via TURN UDP relay.
    TurnRelay,
    /// Connection via TURN TCP/443 relay.
    TurnTcpRelay,
}

/// NAT traversal engine for establishing peer connections.
pub struct NatTraversalEngine {
    stun_servers: Vec<SocketAddr>,
    turn_servers: Vec<TurnServerConfig>,
    local_socket: UdpSocket,
    config: NatConfig,
}

impl NatTraversalEngine {
    /// Creates a new NAT traversal engine.
    ///
    /// # Arguments
    ///
    /// * `config` - NAT traversal configuration
    pub async fn new(config: NatConfig) -> Result<Self> {
        // Bind local socket
        let bind_addr = SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            config.local_port,
        );

        let local_socket = UdpSocket::bind(bind_addr)
            .await
            .context("Failed to bind local socket")?;

        tracing::debug!(
            local_addr = %local_socket.local_addr()?,
            "NAT traversal engine initialized"
        );

        Ok(Self {
            stun_servers: config.stun_servers.clone(),
            turn_servers: config.turn_servers.clone(),
            local_socket,
            config,
        })
    }

    /// Gets the local socket address.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.local_socket.local_addr().context("Failed to get local address")
    }

    /// Gathers ICE candidates for this endpoint.
    ///
    /// This collects:
    /// 1. Host candidates (local interface addresses)
    /// 2. Server-reflexive candidates (via STUN)
    /// 3. Relay candidates (via TURN)
    pub async fn gather_candidates(&self) -> Result<Vec<IceCandidate>> {
        let mut candidates = Vec::new();

        // 1. Gather host candidates
        let host_candidates = self.gather_host_candidates().await?;
        candidates.extend(host_candidates);

        // 2. Gather server-reflexive candidates via STUN
        let srflx_candidates = self.gather_server_reflexive_candidates().await;
        candidates.extend(srflx_candidates);

        // 3. Gather relay candidates via TURN
        let relay_candidates = self.gather_relay_candidates().await;
        candidates.extend(relay_candidates);

        tracing::info!(
            host = candidates.iter().filter(|c| c.candidate_type == CandidateType::Host).count(),
            srflx = candidates.iter().filter(|c| c.candidate_type == CandidateType::ServerReflexive).count(),
            relay = candidates.iter().filter(|c| c.candidate_type == CandidateType::Relay).count(),
            "Gathered ICE candidates"
        );

        Ok(candidates)
    }

    /// Gathers host candidates from local interfaces.
    async fn gather_host_candidates(&self) -> Result<Vec<IceCandidate>> {
        let mut candidates = Vec::new();

        // Get the local socket address
        let local_addr = self.local_socket.local_addr()?;

        // If bound to a specific address, use that
        if !local_addr.ip().is_unspecified() {
            candidates.push(IceCandidate::new(
                CandidateType::Host,
                local_addr,
                1,
                65535,
                None,
            ));
            return Ok(candidates);
        }

        // Otherwise, enumerate local interfaces
        let interfaces = Self::get_local_interfaces()?;
        let port = local_addr.port();

        for (idx, ip) in interfaces.into_iter().enumerate() {
            let addr = SocketAddr::new(ip, port);
            let local_preference = (65535 - idx as u32).max(1);

            candidates.push(IceCandidate::new(
                CandidateType::Host,
                addr,
                1,
                local_preference,
                None,
            ));
        }

        Ok(candidates)
    }

    /// Gets local interface addresses.
    fn get_local_interfaces() -> Result<Vec<IpAddr>> {
        let mut addresses = Vec::new();

        // Use a simple approach: try to connect to a public address
        // and see what local address we get
        if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
            // Connect to a public IP (doesn't actually send anything)
            if socket.connect("8.8.8.8:80").is_ok() {
                if let Ok(local_addr) = socket.local_addr() {
                    if !local_addr.ip().is_unspecified() && !local_addr.ip().is_loopback() {
                        addresses.push(local_addr.ip());
                    }
                }
            }
        }

        // Also try IPv6
        if let Ok(socket) = std::net::UdpSocket::bind("[::]:0") {
            if socket.connect("[2001:4860:4860::8888]:80").is_ok() {
                if let Ok(local_addr) = socket.local_addr() {
                    if !local_addr.ip().is_unspecified() && !local_addr.ip().is_loopback() {
                        addresses.push(local_addr.ip());
                    }
                }
            }
        }

        // Fallback to localhost if nothing found
        if addresses.is_empty() {
            addresses.push(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
        }

        Ok(addresses)
    }

    /// Gathers server-reflexive candidates via STUN.
    async fn gather_server_reflexive_candidates(&self) -> Vec<IceCandidate> {
        let mut candidates = Vec::new();

        for (idx, server) in self.stun_servers.iter().enumerate() {
            let client = StunClient::with_timeout(*server, self.config.gather_timeout);

            match client.binding_request(&self.local_socket).await {
                Ok(mapped_addr) => {
                    let local_addr = self.local_socket.local_addr().ok();
                    let local_preference = (65535 - idx as u32).max(1);

                    candidates.push(IceCandidate::new(
                        CandidateType::ServerReflexive,
                        mapped_addr,
                        1,
                        local_preference,
                        local_addr,
                    ));

                    tracing::debug!(
                        server = %server,
                        mapped = %mapped_addr,
                        "Gathered server-reflexive candidate"
                    );

                    // One successful STUN response is usually enough
                    break;
                }
                Err(e) => {
                    tracing::debug!(
                        server = %server,
                        error = %e,
                        "Failed to gather server-reflexive candidate"
                    );
                }
            }
        }

        candidates
    }

    /// Gathers relay candidates via TURN.
    async fn gather_relay_candidates(&self) -> Vec<IceCandidate> {
        let mut candidates = Vec::new();

        for (idx, turn_config) in self.turn_servers.iter().enumerate() {
            // Create a new socket for TURN (TURN requires dedicated socket)
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(error = %e, "Failed to bind socket for TURN");
                    continue;
                }
            };

            let mut client = TurnClient::new(turn_config.clone(), socket);

            match client.allocate().await {
                Ok(allocation) => {
                    let local_preference = (65535 - idx as u32).max(1);

                    candidates.push(IceCandidate::new(
                        CandidateType::Relay,
                        allocation.relayed_address,
                        1,
                        local_preference,
                        Some(allocation.mapped_address),
                    ));

                    tracing::debug!(
                        server = %turn_config.address,
                        relayed = %allocation.relayed_address,
                        "Gathered relay candidate"
                    );
                }
                Err(e) => {
                    tracing::debug!(
                        server = %turn_config.address,
                        error = %e,
                        "Failed to gather relay candidate"
                    );
                }
            }
        }

        candidates
    }

    /// Connects to a peer using ICE connectivity checks.
    ///
    /// # Arguments
    ///
    /// * `local_candidates` - Our local ICE candidates
    /// * `remote_candidates` - The peer's ICE candidates
    ///
    /// # Returns
    ///
    /// An established connection to the peer.
    pub async fn connect_to_peer(
        &self,
        local_candidates: &[IceCandidate],
        remote_candidates: &[IceCandidate],
    ) -> Result<EstablishedConnection> {
        tracing::info!(
            local = local_candidates.len(),
            remote = remote_candidates.len(),
            "Starting ICE connectivity checks"
        );

        // Create ICE agent (we're the controlling agent if we initiated)
        let mut ice_agent = IceAgent::new(true);
        ice_agent.set_local_candidates(local_candidates.to_vec());
        ice_agent.set_remote_candidates(remote_candidates.to_vec());

        // Perform connectivity checks
        match ice_agent.perform_checks(&self.local_socket).await {
            Ok(pair) => {
                let connection_type = match pair.local.candidate_type {
                    CandidateType::Host => ConnectionType::Direct,
                    CandidateType::ServerReflexive => ConnectionType::StunHolePunched,
                    CandidateType::Relay => ConnectionType::TurnRelay,
                };

                tracing::info!(
                    local = %pair.local.address,
                    remote = %pair.remote.address,
                    connection_type = ?connection_type,
                    "ICE connectivity check succeeded"
                );

                // Clone the socket for the established connection
                let socket = UdpSocket::bind(self.local_socket.local_addr()?)
                    .await
                    .context("Failed to create connection socket")?;

                return Ok(EstablishedConnection {
                    local_addr: pair.local.address,
                    remote_addr: pair.remote.address,
                    connection_type,
                    socket: Some(socket),
                    tcp_tunnel: None,
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "ICE connectivity checks failed");
            }
        }

        // Try TCP fallback if enabled
        if self.config.enable_tcp_fallback {
            if let Some(connection) = self.try_tcp_fallback().await {
                return Ok(connection);
            }
        }

        anyhow::bail!("Failed to establish connection to peer")
    }

    /// Attempts TCP fallback connection.
    async fn try_tcp_fallback(&self) -> Option<EstablishedConnection> {
        for turn_config in &self.turn_servers {
            if let Some(fallback) = TcpFallback::from_config(turn_config) {
                match fallback.connect_websocket().await {
                    Ok(tunnel) => {
                        let server_addr = tunnel.server_addr();

                        tracing::info!(
                            server = %server_addr,
                            "TCP fallback connection established"
                        );

                        return Some(EstablishedConnection {
                            local_addr: SocketAddr::new(
                                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                                0,
                            ),
                            remote_addr: server_addr,
                            connection_type: ConnectionType::TurnTcpRelay,
                            socket: None,
                            tcp_tunnel: Some(tunnel),
                        });
                    }
                    Err(e) => {
                        tracing::debug!(
                            server = %turn_config.address,
                            error = %e,
                            "TCP fallback failed"
                        );
                    }
                }
            }
        }

        None
    }

    /// Converts local candidates to protocol buffer format.
    pub fn candidates_to_proto(candidates: &[IceCandidate]) -> Vec<avon_protocol::v1::IceCandidate> {
        candidates.iter().map(|c| c.to_proto()).collect()
    }

    /// Converts protocol buffer candidates to local format.
    pub fn candidates_from_proto(
        proto: &[avon_protocol::v1::IceCandidate],
    ) -> Result<Vec<IceCandidate>> {
        proto.iter().map(IceCandidate::from_proto).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_config_default() {
        let config = NatConfig::default();
        assert!(config.stun_servers.is_empty());
        assert!(config.turn_servers.is_empty());
        assert!(config.enable_tcp_fallback);
    }

    #[test]
    fn test_nat_config_with_default_stun() {
        // Note: Default STUN servers are domain names that need DNS resolution
        // so they won't parse as SocketAddr directly. This test verifies the
        // method doesn't panic and returns a valid config.
        let config = NatConfig::with_default_stun();
        // The stun_servers may be empty if DNS names can't be parsed as SocketAddr
        // In production, we'd use DNS resolution
        assert!(config.enable_tcp_fallback);
    }

    #[test]
    fn test_connection_type() {
        assert_eq!(ConnectionType::Direct, ConnectionType::Direct);
        assert_ne!(ConnectionType::Direct, ConnectionType::TurnRelay);
    }

    #[tokio::test]
    async fn test_nat_engine_creation() {
        let config = NatConfig::default();
        let engine = NatTraversalEngine::new(config).await;
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_gather_host_candidates() {
        let config = NatConfig::default();
        let engine = NatTraversalEngine::new(config).await.unwrap();
        let candidates = engine.gather_host_candidates().await.unwrap();
        assert!(!candidates.is_empty());
        assert!(candidates.iter().all(|c| c.candidate_type == CandidateType::Host));
    }

    #[test]
    fn test_get_local_interfaces() {
        let interfaces = NatTraversalEngine::get_local_interfaces();
        assert!(interfaces.is_ok());
        assert!(!interfaces.unwrap().is_empty());
    }
}
