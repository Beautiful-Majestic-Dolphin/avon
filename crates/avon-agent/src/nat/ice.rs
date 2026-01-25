//! ICE (Interactive Connectivity Establishment) agent.
//!
//! This module implements ICE candidate gathering, pairing, and connectivity
//! checks as defined in RFC 8445. It coordinates STUN and TURN to establish
//! peer-to-peer connections through NAT.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use super::stun::StunClient;

/// ICE candidate types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateType {
    /// Host candidate - local interface address.
    Host,
    /// Server reflexive candidate - address discovered via STUN.
    ServerReflexive,
    /// Relay candidate - address allocated on a TURN server.
    Relay,
}

impl CandidateType {
    /// Returns the type preference for priority calculation.
    fn type_preference(&self) -> u32 {
        match self {
            CandidateType::Host => 126,
            CandidateType::ServerReflexive => 100,
            CandidateType::Relay => 0,
        }
    }
}

/// An ICE candidate representing a potential connection endpoint.
#[derive(Debug, Clone)]
pub struct IceCandidate {
    pub candidate_type: CandidateType,
    pub address: SocketAddr,
    pub priority: u32,
    pub foundation: String,
    pub base_address: Option<SocketAddr>,
}

impl IceCandidate {
    /// Creates a new ICE candidate.
    pub fn new(
        candidate_type: CandidateType,
        address: SocketAddr,
        component_id: u32,
        local_preference: u32,
        base_address: Option<SocketAddr>,
    ) -> Self {
        let priority = Self::calculate_priority(candidate_type, local_preference, component_id);
        let foundation = Self::calculate_foundation(candidate_type, &address, base_address.as_ref());

        Self {
            candidate_type,
            address,
            priority,
            foundation,
            base_address,
        }
    }

    /// Calculates the priority of a candidate according to RFC 8445.
    fn calculate_priority(candidate_type: CandidateType, local_preference: u32, component_id: u32) -> u32 {
        let type_preference = candidate_type.type_preference();
        (type_preference << 24) | (local_preference << 8) | (256 - component_id)
    }

    /// Calculates the foundation string for a candidate.
    fn calculate_foundation(
        candidate_type: CandidateType,
        address: &SocketAddr,
        base_address: Option<&SocketAddr>,
    ) -> String {
        let type_str = match candidate_type {
            CandidateType::Host => "host",
            CandidateType::ServerReflexive => "srflx",
            CandidateType::Relay => "relay",
        };

        let base = base_address.unwrap_or(address);
        format!("{}_{}", type_str, base.ip())
    }

    /// Converts to protocol buffer representation.
    pub fn to_proto(&self) -> avon_protocol::v1::IceCandidate {
        avon_protocol::v1::IceCandidate {
            r#type: match self.candidate_type {
                CandidateType::Host => avon_protocol::v1::CandidateType::Host as i32,
                CandidateType::ServerReflexive => avon_protocol::v1::CandidateType::ServerReflexive as i32,
                CandidateType::Relay => avon_protocol::v1::CandidateType::Relay as i32,
            },
            ip: self.address.ip().to_string(),
            port: self.address.port() as u32,
            priority: self.priority,
            foundation: self.foundation.clone(),
        }
    }

    /// Creates from protocol buffer representation.
    pub fn from_proto(proto: &avon_protocol::v1::IceCandidate) -> Result<Self> {
        let candidate_type = match proto.r#type {
            x if x == avon_protocol::v1::CandidateType::Host as i32 => CandidateType::Host,
            x if x == avon_protocol::v1::CandidateType::ServerReflexive as i32 => CandidateType::ServerReflexive,
            x if x == avon_protocol::v1::CandidateType::Relay as i32 => CandidateType::Relay,
            _ => anyhow::bail!("Unknown candidate type"),
        };

        let ip: IpAddr = proto.ip.parse().context("Invalid IP address")?;
        let address = SocketAddr::new(ip, proto.port as u16);

        Ok(Self {
            candidate_type,
            address,
            priority: proto.priority,
            foundation: proto.foundation.clone(),
            base_address: None,
        })
    }
}

/// State of a candidate pair during connectivity checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairState {
    /// Pair is waiting to be checked.
    Waiting,
    /// Check is in progress.
    InProgress,
    /// Check succeeded.
    Succeeded,
    /// Check failed.
    Failed,
}

/// A pair of local and remote candidates.
#[derive(Debug, Clone)]
pub struct CandidatePair {
    pub local: IceCandidate,
    pub remote: IceCandidate,
    pub priority: u64,
    pub state: PairState,
}

impl CandidatePair {
    /// Creates a new candidate pair.
    pub fn new(local: IceCandidate, remote: IceCandidate, is_controlling: bool) -> Self {
        let priority = Self::calculate_pair_priority(&local, &remote, is_controlling);
        Self {
            local,
            remote,
            priority,
            state: PairState::Waiting,
        }
    }

    /// Calculates the priority of a candidate pair according to RFC 8445.
    fn calculate_pair_priority(local: &IceCandidate, remote: &IceCandidate, is_controlling: bool) -> u64 {
        let (g, d) = if is_controlling {
            (local.priority as u64, remote.priority as u64)
        } else {
            (remote.priority as u64, local.priority as u64)
        };

        let min = g.min(d);
        let max = g.max(d);

        (1 << 32) * min + 2 * max + if g > d { 1 } else { 0 }
    }
}

/// ICE agent for managing connectivity establishment.
pub struct IceAgent {
    local_candidates: Vec<IceCandidate>,
    remote_candidates: Vec<IceCandidate>,
    check_list: Vec<CandidatePair>,
    is_controlling: bool,
    check_timeout: Duration,
}

impl IceAgent {
    /// Creates a new ICE agent.
    ///
    /// # Arguments
    ///
    /// * `is_controlling` - Whether this agent is the controlling agent
    pub fn new(is_controlling: bool) -> Self {
        Self {
            local_candidates: Vec::new(),
            remote_candidates: Vec::new(),
            check_list: Vec::new(),
            is_controlling,
            check_timeout: Duration::from_secs(3),
        }
    }

    /// Sets the local candidates.
    pub fn set_local_candidates(&mut self, candidates: Vec<IceCandidate>) {
        self.local_candidates = candidates;
    }

    /// Sets the remote candidates.
    pub fn set_remote_candidates(&mut self, candidates: Vec<IceCandidate>) {
        self.remote_candidates = candidates;
    }

    /// Gets the local candidates.
    pub fn local_candidates(&self) -> &[IceCandidate] {
        &self.local_candidates
    }

    /// Gets the remote candidates.
    pub fn remote_candidates(&self) -> &[IceCandidate] {
        &self.remote_candidates
    }

    /// Forms the check list by pairing local and remote candidates.
    pub fn form_check_list(&mut self) {
        self.check_list.clear();

        for local in &self.local_candidates {
            for remote in &self.remote_candidates {
                // Only pair candidates of the same address family
                if local.address.is_ipv4() != remote.address.is_ipv4() {
                    continue;
                }

                let pair = CandidatePair::new(local.clone(), remote.clone(), self.is_controlling);
                self.check_list.push(pair);
            }
        }

        // Sort by priority (highest first)
        self.check_list.sort_by(|a, b| b.priority.cmp(&a.priority));

        tracing::debug!(
            pairs = self.check_list.len(),
            "Formed ICE check list"
        );
    }

    /// Performs connectivity checks and returns the first working pair.
    ///
    /// # Arguments
    ///
    /// * `socket` - The UDP socket to use for checks
    ///
    /// # Returns
    ///
    /// The first candidate pair that successfully connected.
    pub async fn perform_checks(&mut self, socket: &UdpSocket) -> Result<CandidatePair> {
        if self.check_list.is_empty() {
            self.form_check_list();
        }

        if self.check_list.is_empty() {
            anyhow::bail!("No candidate pairs to check");
        }

        tracing::info!(
            pairs = self.check_list.len(),
            "Starting ICE connectivity checks"
        );

        for i in 0..self.check_list.len() {
            if self.check_list[i].state != PairState::Waiting {
                continue;
            }

            self.check_list[i].state = PairState::InProgress;

            let local_addr = self.check_list[i].local.address;
            let remote_addr = self.check_list[i].remote.address;
            let priority = self.check_list[i].priority;

            tracing::debug!(
                local = %local_addr,
                remote = %remote_addr,
                priority = priority,
                "Checking candidate pair"
            );

            match self.check_pair_by_addr(socket, remote_addr).await {
                Ok(()) => {
                    self.check_list[i].state = PairState::Succeeded;
                    tracing::info!(
                        local = %self.check_list[i].local.address,
                        remote = %self.check_list[i].remote.address,
                        "ICE connectivity check succeeded"
                    );
                    return Ok(self.check_list[i].clone());
                }
                Err(e) => {
                    self.check_list[i].state = PairState::Failed;
                    tracing::debug!(
                        local = %self.check_list[i].local.address,
                        remote = %self.check_list[i].remote.address,
                        error = %e,
                        "ICE connectivity check failed"
                    );
                }
            }
        }

        anyhow::bail!("All connectivity checks failed")
    }

    /// Performs a connectivity check for a single candidate pair by address.
    async fn check_pair_by_addr(
        &self,
        socket: &UdpSocket,
        remote_addr: SocketAddr,
    ) -> Result<()> {
        // Use STUN binding request as connectivity check
        let transaction_id = Self::generate_transaction_id();
        let request = StunClient::build_binding_request(transaction_id);

        // Send the check
        socket
            .send_to(&request, remote_addr)
            .await
            .context("Failed to send connectivity check")?;

        // Wait for response
        let mut buf = [0u8; 1024];
        let (len, from) = timeout(self.check_timeout, socket.recv_from(&mut buf))
            .await
            .context("Connectivity check timed out")?
            .context("Failed to receive check response")?;

        // Verify response is from expected peer
        if from != remote_addr {
            // Could be a response from a different check, try to match
            tracing::debug!(
                expected = %remote_addr,
                actual = %from,
                "Response from unexpected address"
            );
        }

        // Parse response to verify it's a valid STUN response
        let response = StunClient::parse_binding_response(&buf[..len])
            .context("Invalid STUN response")?;

        // Verify transaction ID matches
        if response.transaction_id != transaction_id {
            anyhow::bail!("Transaction ID mismatch in connectivity check");
        }

        Ok(())
    }

    /// Generates a random transaction ID.
    fn generate_transaction_id() -> [u8; 12] {
        let mut id = [0u8; 12];
        for byte in &mut id {
            *byte = rand::random();
        }
        id
    }

    /// Gets the check list.
    pub fn check_list(&self) -> &[CandidatePair] {
        &self.check_list
    }

    /// Gets the best succeeded pair.
    pub fn best_pair(&self) -> Option<&CandidatePair> {
        self.check_list
            .iter()
            .find(|p| p.state == PairState::Succeeded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_candidate_priority() {
        let host = IceCandidate::new(
            CandidateType::Host,
            "192.168.1.1:5000".parse().unwrap(),
            1,
            65535,
            None,
        );

        let srflx = IceCandidate::new(
            CandidateType::ServerReflexive,
            "1.2.3.4:5000".parse().unwrap(),
            1,
            65535,
            Some("192.168.1.1:5000".parse().unwrap()),
        );

        // Host should have higher priority than server reflexive
        assert!(host.priority > srflx.priority);
    }

    #[test]
    fn test_candidate_foundation() {
        let host = IceCandidate::new(
            CandidateType::Host,
            "192.168.1.1:5000".parse().unwrap(),
            1,
            65535,
            None,
        );

        assert!(host.foundation.starts_with("host_"));
    }

    #[test]
    fn test_pair_priority() {
        let local = IceCandidate::new(
            CandidateType::Host,
            "192.168.1.1:5000".parse().unwrap(),
            1,
            65535,
            None,
        );

        let remote = IceCandidate::new(
            CandidateType::Host,
            "192.168.1.2:5000".parse().unwrap(),
            1,
            65535,
            None,
        );

        let pair = CandidatePair::new(local, remote, true);
        assert!(pair.priority > 0);
    }

    #[test]
    fn test_form_check_list() {
        let mut agent = IceAgent::new(true);

        let local = IceCandidate::new(
            CandidateType::Host,
            "192.168.1.1:5000".parse().unwrap(),
            1,
            65535,
            None,
        );

        let remote = IceCandidate::new(
            CandidateType::Host,
            "192.168.1.2:5000".parse().unwrap(),
            1,
            65535,
            None,
        );

        agent.set_local_candidates(vec![local]);
        agent.set_remote_candidates(vec![remote]);
        agent.form_check_list();

        assert_eq!(agent.check_list().len(), 1);
    }

    #[test]
    fn test_check_list_sorting() {
        let mut agent = IceAgent::new(true);

        let local_host = IceCandidate::new(
            CandidateType::Host,
            "192.168.1.1:5000".parse().unwrap(),
            1,
            65535,
            None,
        );

        let local_srflx = IceCandidate::new(
            CandidateType::ServerReflexive,
            "1.2.3.4:5000".parse().unwrap(),
            1,
            65535,
            Some("192.168.1.1:5000".parse().unwrap()),
        );

        let remote = IceCandidate::new(
            CandidateType::Host,
            "192.168.1.2:5000".parse().unwrap(),
            1,
            65535,
            None,
        );

        agent.set_local_candidates(vec![local_srflx, local_host]);
        agent.set_remote_candidates(vec![remote]);
        agent.form_check_list();

        // Host-Host pair should be first (higher priority)
        assert_eq!(agent.check_list()[0].local.candidate_type, CandidateType::Host);
    }
}
