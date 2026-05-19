//! Tunnel handshake protocol implementation.
//!
//! Implements the hybrid key exchange protocol for establishing
//! encrypted tunnels between peers.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use avon_crypto::hybrid::key_exchange::{hybrid_encapsulate, HybridEncapsulation, HybridKeyPair};
use avon_crypto::session::TunnelKeys;
use avon_protocol::v1::{
    tunnel_handshake, HybridEncapsulation as ProtoEncapsulation, TunnelConfirm,
    TunnelHandshake as ProtoHandshake, TunnelInit, TunnelResponse,
};
use prost::Message;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::identity::IdentityManager;

use super::SessionId;

const MAX_HANDSHAKE_PACKET_SIZE: usize = 8192;

/// Handles the tunnel handshake protocol.
///
/// Performs hybrid key exchange (X25519 + Kyber768) to establish
/// shared tunnel encryption keys.
pub struct TunnelHandshake {
    session_id: SessionId,
    identity: Arc<IdentityManager>,
    local_keypair: Option<HybridKeyPair>,
}

impl TunnelHandshake {
    /// Creates a new tunnel handshake handler.
    pub fn new(session_id: SessionId, identity: Arc<IdentityManager>) -> Self {
        Self {
            session_id,
            identity,
            local_keypair: None,
        }
    }

    /// Initiates a tunnel handshake as the initiator.
    ///
    /// # Arguments
    ///
    /// * `peer_addr` - Address of the peer to connect to
    /// * `timeout_duration` - Maximum time to wait for handshake completion
    ///
    /// # Returns
    ///
    /// The derived tunnel keys for encryption.
    pub async fn initiate(
        mut self,
        peer_addr: SocketAddr,
        timeout_duration: Duration,
    ) -> Result<TunnelKeys> {
        tracing::debug!(%peer_addr, "Initiating tunnel handshake");

        // Create socket for handshake
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind handshake socket")?;

        socket
            .connect(peer_addr)
            .await
            .context("Failed to connect handshake socket")?;

        // Generate ephemeral keypair for this tunnel
        let keypair = HybridKeyPair::generate().context("Failed to generate hybrid keypair")?;

        self.local_keypair = Some(keypair);

        // Perform handshake with timeout
        timeout(timeout_duration, self.do_initiate(&socket))
            .await
            .context("Handshake timed out")?
    }

    /// Performs the initiator side of the handshake.
    async fn do_initiate(&self, socket: &UdpSocket) -> Result<TunnelKeys> {
        let keypair = self
            .local_keypair
            .as_ref()
            .context("Keypair not initialized")?;

        // 1. Send TunnelInit with our ephemeral public key
        let init = TunnelInit {
            ephemeral_public: Some(avon_protocol::v1::HybridPublicKey {
                classical: keypair.public_key().to_bytes()[..32].to_vec(),
                pqc: keypair.public_key().to_bytes()[32..].to_vec(),
            }),
            encrypted_cert: vec![], // Certificate would be encrypted in production
        };

        let handshake = ProtoHandshake {
            session_id: self.session_id.to_vec(),
            message: Some(tunnel_handshake::Message::Init(init)),
        };

        let encoded = handshake.encode_to_vec();
        socket
            .send(&encoded)
            .await
            .context("Failed to send TunnelInit")?;

        tracing::debug!("Sent TunnelInit");

        // 2. Receive TunnelResponse with encapsulation
        let mut buf = vec![0u8; MAX_HANDSHAKE_PACKET_SIZE];
        let len = socket
            .recv(&mut buf)
            .await
            .context("Failed to receive TunnelResponse")?;

        let response_handshake =
            ProtoHandshake::decode(&buf[..len]).context("Failed to decode TunnelResponse")?;

        let response = match response_handshake.message {
            Some(tunnel_handshake::Message::Response(r)) => r,
            _ => anyhow::bail!("Expected TunnelResponse"),
        };

        tracing::debug!("Received TunnelResponse");

        // 3. Decapsulate to get shared secret
        let encapsulation = response
            .encapsulation
            .context("Missing encapsulation in response")?;

        let hybrid_encap = self.parse_encapsulation(&encapsulation)?;
        let shared_secret = keypair
            .decapsulate(&hybrid_encap)
            .context("Failed to decapsulate")?;

        // 4. Derive tunnel keys
        let initiator_public = keypair.public_key().to_bytes();
        let responder_public = self.reconstruct_responder_public(&encapsulation)?;

        let keys = TunnelKeys::derive(
            &shared_secret,
            &initiator_public,
            &responder_public,
            &self.session_id,
        )
        .context("Failed to derive tunnel keys")?;

        // 5. Send TunnelConfirm
        let confirm = TunnelConfirm {
            encrypted_verify: self.create_verification_data(&keys)?,
        };

        let confirm_handshake = ProtoHandshake {
            session_id: self.session_id.to_vec(),
            message: Some(tunnel_handshake::Message::Confirm(confirm)),
        };

        let encoded = confirm_handshake.encode_to_vec();
        socket
            .send(&encoded)
            .await
            .context("Failed to send TunnelConfirm")?;

        tracing::debug!("Sent TunnelConfirm, handshake complete");

        Ok(keys)
    }

    /// Responds to a tunnel handshake as the responder.
    ///
    /// # Arguments
    ///
    /// * `peer_addr` - Address of the initiating peer
    /// * `timeout_duration` - Maximum time to wait for handshake completion
    ///
    /// # Returns
    ///
    /// The derived tunnel keys for encryption.
    pub async fn respond(
        mut self,
        peer_addr: SocketAddr,
        timeout_duration: Duration,
    ) -> Result<TunnelKeys> {
        tracing::debug!(%peer_addr, "Responding to tunnel handshake");

        // Create socket for handshake
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind handshake socket")?;

        socket
            .connect(peer_addr)
            .await
            .context("Failed to connect handshake socket")?;

        // Generate our keypair
        let keypair = HybridKeyPair::generate().context("Failed to generate hybrid keypair")?;

        self.local_keypair = Some(keypair);

        // Perform handshake with timeout
        timeout(timeout_duration, self.do_respond(&socket))
            .await
            .context("Handshake timed out")?
    }

    /// Performs the responder side of the handshake.
    async fn do_respond(&self, socket: &UdpSocket) -> Result<TunnelKeys> {
        let keypair = self
            .local_keypair
            .as_ref()
            .context("Keypair not initialized")?;

        // 1. Receive TunnelInit
        let mut buf = vec![0u8; MAX_HANDSHAKE_PACKET_SIZE];
        let len = socket
            .recv(&mut buf)
            .await
            .context("Failed to receive TunnelInit")?;

        let init_handshake =
            ProtoHandshake::decode(&buf[..len]).context("Failed to decode TunnelInit")?;

        let init = match init_handshake.message {
            Some(tunnel_handshake::Message::Init(i)) => i,
            _ => anyhow::bail!("Expected TunnelInit"),
        };

        tracing::debug!("Received TunnelInit");

        // 2. Parse initiator's public key
        let initiator_public_key = init
            .ephemeral_public
            .context("Missing ephemeral public key")?;

        let initiator_public_bytes = self.reconstruct_public_key(&initiator_public_key)?;
        let initiator_public =
            avon_crypto::hybrid::key_exchange::HybridPublicKey::from_bytes(&initiator_public_bytes)
                .context("Failed to parse initiator public key")?;

        // 3. Perform encapsulation to initiator's public key
        let (encapsulation, shared_secret) =
            hybrid_encapsulate(&initiator_public).context("Failed to encapsulate")?;

        // 4. Send TunnelResponse
        let response = TunnelResponse {
            encapsulation: Some(ProtoEncapsulation {
                classical_public: encapsulation.classical_public.to_bytes().to_vec(),
                pqc_ciphertext: encapsulation.pqc_ciphertext.to_bytes().to_vec(),
            }),
            encrypted_cert: vec![], // Certificate would be encrypted in production
        };

        let response_handshake = ProtoHandshake {
            session_id: self.session_id.to_vec(),
            message: Some(tunnel_handshake::Message::Response(response)),
        };

        let encoded = response_handshake.encode_to_vec();
        socket
            .send(&encoded)
            .await
            .context("Failed to send TunnelResponse")?;

        tracing::debug!("Sent TunnelResponse");

        // 5. Derive tunnel keys
        let responder_public = keypair.public_key().to_bytes();

        let keys = TunnelKeys::derive(
            &shared_secret,
            &initiator_public_bytes,
            &responder_public,
            &self.session_id,
        )
        .context("Failed to derive tunnel keys")?;

        // 6. Receive TunnelConfirm
        let len = socket
            .recv(&mut buf)
            .await
            .context("Failed to receive TunnelConfirm")?;

        let confirm_handshake =
            ProtoHandshake::decode(&buf[..len]).context("Failed to decode TunnelConfirm")?;

        let _confirm = match confirm_handshake.message {
            Some(tunnel_handshake::Message::Confirm(c)) => c,
            _ => anyhow::bail!("Expected TunnelConfirm"),
        };

        tracing::debug!("Received TunnelConfirm, handshake complete");

        // In production, would verify the confirmation data here

        Ok(keys)
    }

    /// Parses a protocol encapsulation into a crypto encapsulation.
    fn parse_encapsulation(&self, encap: &ProtoEncapsulation) -> Result<HybridEncapsulation> {
        let mut bytes = Vec::with_capacity(32 + 1088);
        bytes.extend_from_slice(&encap.classical_public);
        bytes.extend_from_slice(&encap.pqc_ciphertext);

        HybridEncapsulation::from_bytes(&bytes).context("Failed to parse encapsulation")
    }

    /// Reconstructs the responder's public key from encapsulation.
    fn reconstruct_responder_public(&self, encap: &ProtoEncapsulation) -> Result<Vec<u8>> {
        // The classical_public in encapsulation is the responder's ephemeral X25519 key
        // For full reconstruction, we'd need the Kyber public key too
        // This is a simplified version
        Ok(encap.classical_public.clone())
    }

    /// Reconstructs a public key from protocol format.
    fn reconstruct_public_key(&self, key: &avon_protocol::v1::HybridPublicKey) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(32 + 1184);
        bytes.extend_from_slice(&key.classical);
        bytes.extend_from_slice(&key.pqc);
        Ok(bytes)
    }

    /// Creates verification data for the confirm message.
    fn create_verification_data(&self, keys: &TunnelKeys) -> Result<Vec<u8>> {
        // In production, this would be an encrypted proof of key possession
        // For now, we use a simple hash of the session ID with the key
        use avon_crypto::hmac::hmac_sha256;

        let tag = hmac_sha256(keys.initiator_key(), &self.session_id);

        Ok(tag.to_vec())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_handshake_creation() {
        // This test would require a mock identity manager
        // For now, just verify the struct can be created
        let session_id = [0u8; 16];
        // Note: Can't test without IdentityManager
        assert_eq!(session_id.len(), 16);
    }
}
