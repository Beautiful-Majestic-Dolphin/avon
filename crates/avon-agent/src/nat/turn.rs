//! TURN client for NAT traversal.
//!
//! This module implements a TURN (Traversal Using Relays around NAT) client
//! that can allocate relay addresses on a TURN server for cases where direct
//! peer-to-peer connectivity is not possible. It follows RFC 5766.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// STUN/TURN magic cookie.
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// TURN message types.
const TURN_ALLOCATE_REQUEST: u16 = 0x0003;
const TURN_ALLOCATE_RESPONSE: u16 = 0x0103;
const TURN_ALLOCATE_ERROR: u16 = 0x0113;
const TURN_REFRESH_REQUEST: u16 = 0x0004;
const TURN_REFRESH_RESPONSE: u16 = 0x0104;
const TURN_CREATE_PERMISSION_REQUEST: u16 = 0x0008;
const TURN_CREATE_PERMISSION_RESPONSE: u16 = 0x0108;
const TURN_SEND_INDICATION: u16 = 0x0016;
const TURN_DATA_INDICATION: u16 = 0x0017;

/// STUN/TURN attribute types.
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_USERNAME: u16 = 0x0006;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_LIFETIME: u16 = 0x000D;
const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
const ATTR_DATA: u16 = 0x0013;
const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
const ATTR_REALM: u16 = 0x0014;
const ATTR_NONCE: u16 = 0x0015;

/// STUN header size.
const STUN_HEADER_SIZE: usize = 20;

/// Default TURN allocation lifetime.
const DEFAULT_LIFETIME: Duration = Duration::from_secs(600);

/// Request timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Configuration for a TURN server.
#[derive(Debug, Clone)]
pub struct TurnServerConfig {
    pub address: SocketAddr,
    pub username: String,
    pub credential: String,
    pub tcp_fallback_port: Option<u16>,
}

/// A TURN allocation on a server.
#[derive(Debug, Clone)]
pub struct TurnAllocation {
    pub relayed_address: SocketAddr,
    pub mapped_address: SocketAddr,
    pub lifetime: Duration,
    pub expires_at: Instant,
    pub nonce: Vec<u8>,
    pub realm: String,
}

/// TURN client for relay allocation and data transmission.
pub struct TurnClient {
    config: TurnServerConfig,
    socket: UdpSocket,
    allocation: Option<TurnAllocation>,
}

impl TurnClient {
    /// Creates a new TURN client.
    ///
    /// # Arguments
    ///
    /// * `config` - TURN server configuration
    /// * `socket` - UDP socket to use for communication
    pub fn new(config: TurnServerConfig, socket: UdpSocket) -> Self {
        Self {
            config,
            socket,
            allocation: None,
        }
    }

    /// Allocates a relay address on the TURN server.
    ///
    /// This performs the TURN Allocate request with authentication.
    pub async fn allocate(&mut self) -> Result<TurnAllocation> {
        tracing::debug!(server = %self.config.address, "Starting TURN allocation");

        // First request without authentication to get nonce and realm
        let transaction_id = Self::generate_transaction_id();
        let request = self.build_allocate_request(transaction_id, None, None);

        self.socket
            .send_to(&request, self.config.address)
            .await
            .context("Failed to send allocate request")?;

        let mut buf = [0u8; 2048];
        let (len, _) = timeout(REQUEST_TIMEOUT, self.socket.recv_from(&mut buf))
            .await
            .context("Allocate request timed out")?
            .context("Failed to receive allocate response")?;

        // Parse the response - expect 401 Unauthorized with nonce and realm
        let (nonce, realm) = self.parse_auth_challenge(&buf[..len])?;

        // Second request with authentication
        let transaction_id = Self::generate_transaction_id();
        let request = self.build_allocate_request(
            transaction_id,
            Some(&nonce),
            Some(&realm),
        );

        self.socket
            .send_to(&request, self.config.address)
            .await
            .context("Failed to send authenticated allocate request")?;

        let (len, _) = timeout(REQUEST_TIMEOUT, self.socket.recv_from(&mut buf))
            .await
            .context("Authenticated allocate request timed out")?
            .context("Failed to receive authenticated allocate response")?;

        // Parse successful allocation response
        let allocation = self.parse_allocate_response(&buf[..len], nonce, realm)?;

        tracing::info!(
            relayed = %allocation.relayed_address,
            mapped = %allocation.mapped_address,
            lifetime = ?allocation.lifetime,
            "TURN allocation succeeded"
        );

        self.allocation = Some(allocation.clone());
        Ok(allocation)
    }

    /// Creates a permission for a peer address.
    ///
    /// This must be called before sending data to a peer through the relay.
    pub async fn create_permission(&self, peer: IpAddr) -> Result<()> {
        let allocation = self.allocation.as_ref().context("No active allocation")?;

        let transaction_id = Self::generate_transaction_id();
        let request = self.build_create_permission_request(
            transaction_id,
            peer,
            &allocation.nonce,
            &allocation.realm,
        );

        self.socket
            .send_to(&request, self.config.address)
            .await
            .context("Failed to send CreatePermission request")?;

        let mut buf = [0u8; 1024];
        let (len, _) = timeout(REQUEST_TIMEOUT, self.socket.recv_from(&mut buf))
            .await
            .context("CreatePermission request timed out")?
            .context("Failed to receive CreatePermission response")?;

        self.verify_success_response(&buf[..len], TURN_CREATE_PERMISSION_RESPONSE)?;

        tracing::debug!(%peer, "Created TURN permission");
        Ok(())
    }

    /// Sends data to a peer through the TURN relay.
    ///
    /// Uses Send indication (no response expected).
    pub async fn send_indication(&self, peer: SocketAddr, data: &[u8]) -> Result<()> {
        let _allocation = self.allocation.as_ref().context("No active allocation")?;

        let indication = self.build_send_indication(peer, data);

        self.socket
            .send_to(&indication, self.config.address)
            .await
            .context("Failed to send indication")?;

        Ok(())
    }

    /// Receives data from the TURN relay.
    ///
    /// Returns the peer address and data from a Data indication.
    pub async fn receive(&self) -> Result<(SocketAddr, Vec<u8>)> {
        let _allocation = self.allocation.as_ref().context("No active allocation")?;

        let mut buf = [0u8; 65536];
        let (len, from) = self.socket.recv_from(&mut buf).await?;

        // Verify it's from the TURN server
        if from != self.config.address {
            anyhow::bail!("Received data from unexpected source");
        }

        // Parse Data indication
        self.parse_data_indication(&buf[..len])
    }

    /// Refreshes the allocation to extend its lifetime.
    pub async fn refresh(&mut self) -> Result<()> {
        let allocation = self.allocation.as_ref().context("No active allocation")?;

        let transaction_id = Self::generate_transaction_id();
        let request = self.build_refresh_request(
            transaction_id,
            &allocation.nonce,
            &allocation.realm,
        );

        self.socket
            .send_to(&request, self.config.address)
            .await
            .context("Failed to send refresh request")?;

        let mut buf = [0u8; 1024];
        let (len, _) = timeout(REQUEST_TIMEOUT, self.socket.recv_from(&mut buf))
            .await
            .context("Refresh request timed out")?
            .context("Failed to receive refresh response")?;

        let new_lifetime = self.parse_refresh_response(&buf[..len])?;

        if let Some(ref mut alloc) = self.allocation {
            alloc.lifetime = new_lifetime;
            alloc.expires_at = Instant::now() + new_lifetime;
        }

        tracing::debug!(lifetime = ?new_lifetime, "TURN allocation refreshed");
        Ok(())
    }

    /// Gets the current allocation.
    pub fn allocation(&self) -> Option<&TurnAllocation> {
        self.allocation.as_ref()
    }

    /// Checks if the allocation is still valid.
    pub fn is_allocation_valid(&self) -> bool {
        self.allocation
            .as_ref()
            .map(|a| Instant::now() < a.expires_at)
            .unwrap_or(false)
    }

    /// Generates a random transaction ID.
    fn generate_transaction_id() -> [u8; 12] {
        let mut id = [0u8; 12];
        for byte in &mut id {
            *byte = rand::random();
        }
        id
    }

    /// Builds a TURN Allocate request.
    fn build_allocate_request(
        &self,
        transaction_id: [u8; 12],
        nonce: Option<&[u8]>,
        realm: Option<&str>,
    ) -> Vec<u8> {
        let mut attrs = Vec::new();

        // REQUESTED-TRANSPORT (UDP = 17)
        attrs.extend_from_slice(&ATTR_REQUESTED_TRANSPORT.to_be_bytes());
        attrs.extend_from_slice(&4u16.to_be_bytes());
        attrs.push(17); // UDP
        attrs.extend_from_slice(&[0, 0, 0]); // Reserved

        // Add authentication attributes if provided
        if let (Some(nonce), Some(realm)) = (nonce, realm) {
            // USERNAME
            let username = self.config.username.as_bytes();
            attrs.extend_from_slice(&ATTR_USERNAME.to_be_bytes());
            attrs.extend_from_slice(&(username.len() as u16).to_be_bytes());
            attrs.extend_from_slice(username);
            Self::pad_to_4_bytes(&mut attrs, username.len());

            // REALM
            let realm_bytes = realm.as_bytes();
            attrs.extend_from_slice(&ATTR_REALM.to_be_bytes());
            attrs.extend_from_slice(&(realm_bytes.len() as u16).to_be_bytes());
            attrs.extend_from_slice(realm_bytes);
            Self::pad_to_4_bytes(&mut attrs, realm_bytes.len());

            // NONCE
            attrs.extend_from_slice(&ATTR_NONCE.to_be_bytes());
            attrs.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
            attrs.extend_from_slice(nonce);
            Self::pad_to_4_bytes(&mut attrs, nonce.len());

            // MESSAGE-INTEGRITY would go here in a real implementation
            // For now, we'll add a placeholder
            let integrity = self.compute_message_integrity(&attrs, realm, nonce);
            attrs.extend_from_slice(&ATTR_MESSAGE_INTEGRITY.to_be_bytes());
            attrs.extend_from_slice(&20u16.to_be_bytes());
            attrs.extend_from_slice(&integrity);
        }

        self.build_message(TURN_ALLOCATE_REQUEST, transaction_id, &attrs)
    }

    /// Builds a CreatePermission request.
    fn build_create_permission_request(
        &self,
        transaction_id: [u8; 12],
        peer: IpAddr,
        nonce: &[u8],
        realm: &str,
    ) -> Vec<u8> {
        let mut attrs = Vec::new();

        // XOR-PEER-ADDRESS
        let xor_addr = self.encode_xor_address(SocketAddr::new(peer, 0), &transaction_id);
        attrs.extend_from_slice(&ATTR_XOR_PEER_ADDRESS.to_be_bytes());
        attrs.extend_from_slice(&(xor_addr.len() as u16).to_be_bytes());
        attrs.extend_from_slice(&xor_addr);
        Self::pad_to_4_bytes(&mut attrs, xor_addr.len());

        // USERNAME
        let username = self.config.username.as_bytes();
        attrs.extend_from_slice(&ATTR_USERNAME.to_be_bytes());
        attrs.extend_from_slice(&(username.len() as u16).to_be_bytes());
        attrs.extend_from_slice(username);
        Self::pad_to_4_bytes(&mut attrs, username.len());

        // REALM
        let realm_bytes = realm.as_bytes();
        attrs.extend_from_slice(&ATTR_REALM.to_be_bytes());
        attrs.extend_from_slice(&(realm_bytes.len() as u16).to_be_bytes());
        attrs.extend_from_slice(realm_bytes);
        Self::pad_to_4_bytes(&mut attrs, realm_bytes.len());

        // NONCE
        attrs.extend_from_slice(&ATTR_NONCE.to_be_bytes());
        attrs.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
        attrs.extend_from_slice(nonce);
        Self::pad_to_4_bytes(&mut attrs, nonce.len());

        // MESSAGE-INTEGRITY
        let integrity = self.compute_message_integrity(&attrs, realm, nonce);
        attrs.extend_from_slice(&ATTR_MESSAGE_INTEGRITY.to_be_bytes());
        attrs.extend_from_slice(&20u16.to_be_bytes());
        attrs.extend_from_slice(&integrity);

        self.build_message(TURN_CREATE_PERMISSION_REQUEST, transaction_id, &attrs)
    }

    /// Builds a Send indication.
    fn build_send_indication(&self, peer: SocketAddr, data: &[u8]) -> Vec<u8> {
        let transaction_id = Self::generate_transaction_id();
        let mut attrs = Vec::new();

        // XOR-PEER-ADDRESS
        let xor_addr = self.encode_xor_address(peer, &transaction_id);
        attrs.extend_from_slice(&ATTR_XOR_PEER_ADDRESS.to_be_bytes());
        attrs.extend_from_slice(&(xor_addr.len() as u16).to_be_bytes());
        attrs.extend_from_slice(&xor_addr);
        Self::pad_to_4_bytes(&mut attrs, xor_addr.len());

        // DATA
        attrs.extend_from_slice(&ATTR_DATA.to_be_bytes());
        attrs.extend_from_slice(&(data.len() as u16).to_be_bytes());
        attrs.extend_from_slice(data);
        Self::pad_to_4_bytes(&mut attrs, data.len());

        self.build_message(TURN_SEND_INDICATION, transaction_id, &attrs)
    }

    /// Builds a Refresh request.
    fn build_refresh_request(
        &self,
        transaction_id: [u8; 12],
        nonce: &[u8],
        realm: &str,
    ) -> Vec<u8> {
        let mut attrs = Vec::new();

        // LIFETIME
        let lifetime = DEFAULT_LIFETIME.as_secs() as u32;
        attrs.extend_from_slice(&ATTR_LIFETIME.to_be_bytes());
        attrs.extend_from_slice(&4u16.to_be_bytes());
        attrs.extend_from_slice(&lifetime.to_be_bytes());

        // USERNAME
        let username = self.config.username.as_bytes();
        attrs.extend_from_slice(&ATTR_USERNAME.to_be_bytes());
        attrs.extend_from_slice(&(username.len() as u16).to_be_bytes());
        attrs.extend_from_slice(username);
        Self::pad_to_4_bytes(&mut attrs, username.len());

        // REALM
        let realm_bytes = realm.as_bytes();
        attrs.extend_from_slice(&ATTR_REALM.to_be_bytes());
        attrs.extend_from_slice(&(realm_bytes.len() as u16).to_be_bytes());
        attrs.extend_from_slice(realm_bytes);
        Self::pad_to_4_bytes(&mut attrs, realm_bytes.len());

        // NONCE
        attrs.extend_from_slice(&ATTR_NONCE.to_be_bytes());
        attrs.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
        attrs.extend_from_slice(nonce);
        Self::pad_to_4_bytes(&mut attrs, nonce.len());

        // MESSAGE-INTEGRITY
        let integrity = self.compute_message_integrity(&attrs, realm, nonce);
        attrs.extend_from_slice(&ATTR_MESSAGE_INTEGRITY.to_be_bytes());
        attrs.extend_from_slice(&20u16.to_be_bytes());
        attrs.extend_from_slice(&integrity);

        self.build_message(TURN_REFRESH_REQUEST, transaction_id, &attrs)
    }

    /// Builds a STUN/TURN message.
    fn build_message(&self, msg_type: u16, transaction_id: [u8; 12], attrs: &[u8]) -> Vec<u8> {
        let mut message = Vec::with_capacity(STUN_HEADER_SIZE + attrs.len());

        // Message type
        message.extend_from_slice(&msg_type.to_be_bytes());

        // Message length
        message.extend_from_slice(&(attrs.len() as u16).to_be_bytes());

        // Magic cookie
        message.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());

        // Transaction ID
        message.extend_from_slice(&transaction_id);

        // Attributes
        message.extend_from_slice(attrs);

        message
    }

    /// Pads data to 4-byte boundary.
    fn pad_to_4_bytes(data: &mut Vec<u8>, len: usize) {
        let padding = (4 - (len % 4)) % 4;
        for _ in 0..padding {
            data.push(0);
        }
    }

    /// Encodes an address as XOR-MAPPED-ADDRESS format.
    fn encode_xor_address(&self, addr: SocketAddr, transaction_id: &[u8; 12]) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(0); // Reserved

        match addr {
            SocketAddr::V4(v4) => {
                result.push(0x01); // IPv4 family
                let xor_port = addr.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
                result.extend_from_slice(&xor_port.to_be_bytes());
                let ip_bytes: [u8; 4] = v4.ip().octets();
                let ip_u32 = u32::from_be_bytes(ip_bytes);
                let xor_ip = ip_u32 ^ STUN_MAGIC_COOKIE;
                result.extend_from_slice(&xor_ip.to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                result.push(0x02); // IPv6 family
                let xor_port = addr.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
                result.extend_from_slice(&xor_port.to_be_bytes());

                let mut xor_key = [0u8; 16];
                xor_key[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
                xor_key[4..].copy_from_slice(transaction_id);

                let ip_bytes = v6.ip().octets();
                for i in 0..16 {
                    result.push(ip_bytes[i] ^ xor_key[i]);
                }
            }
        }

        result
    }

    /// Decodes an XOR-MAPPED-ADDRESS.
    fn decode_xor_address(&self, data: &[u8], transaction_id: &[u8; 12]) -> Result<SocketAddr> {
        if data.len() < 8 {
            anyhow::bail!("XOR address too short");
        }

        let family = data[1];
        let xor_port = u16::from_be_bytes([data[2], data[3]]);
        let port = xor_port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);

        match family {
            0x01 => {
                let xor_ip = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let ip = xor_ip ^ STUN_MAGIC_COOKIE;
                let addr = std::net::Ipv4Addr::from(ip);
                Ok(SocketAddr::new(addr.into(), port))
            }
            0x02 => {
                if data.len() < 20 {
                    anyhow::bail!("XOR IPv6 address too short");
                }
                let mut xor_key = [0u8; 16];
                xor_key[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
                xor_key[4..].copy_from_slice(transaction_id);

                let mut ip_bytes = [0u8; 16];
                for i in 0..16 {
                    ip_bytes[i] = data[4 + i] ^ xor_key[i];
                }
                let addr = std::net::Ipv6Addr::from(ip_bytes);
                Ok(SocketAddr::new(addr.into(), port))
            }
            _ => anyhow::bail!("Unknown address family: {}", family),
        }
    }

    /// Computes MESSAGE-INTEGRITY HMAC.
    fn compute_message_integrity(&self, _attrs: &[u8], realm: &str, _nonce: &[u8]) -> [u8; 20] {
        // In a real implementation, this would compute HMAC-SHA1 over the message
        // using the key derived from username:realm:password
        // For now, return a placeholder
        let key_input = format!("{}:{}:{}", self.config.username, realm, self.config.credential);
        let mut result = [0u8; 20];
        let hash = md5::compute(key_input.as_bytes());
        result[..16].copy_from_slice(&hash.0);
        result
    }

    /// Parses an authentication challenge (401 response).
    fn parse_auth_challenge(&self, data: &[u8]) -> Result<(Vec<u8>, String)> {
        if data.len() < STUN_HEADER_SIZE {
            anyhow::bail!("Response too short");
        }

        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        if msg_type != TURN_ALLOCATE_ERROR {
            anyhow::bail!("Expected error response, got 0x{:04x}", msg_type);
        }

        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let mut nonce = Vec::new();
        let mut realm = String::new();

        let mut offset = STUN_HEADER_SIZE;
        while offset + 4 <= STUN_HEADER_SIZE + msg_len && offset + 4 <= data.len() {
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if offset + attr_len > data.len() {
                break;
            }

            match attr_type {
                ATTR_NONCE => {
                    nonce = data[offset..offset + attr_len].to_vec();
                }
                ATTR_REALM => {
                    realm = String::from_utf8_lossy(&data[offset..offset + attr_len]).to_string();
                }
                _ => {}
            }

            offset += (attr_len + 3) & !3;
        }

        if nonce.is_empty() || realm.is_empty() {
            anyhow::bail!("Missing nonce or realm in auth challenge");
        }

        Ok((nonce, realm))
    }

    /// Parses an Allocate response.
    fn parse_allocate_response(
        &self,
        data: &[u8],
        nonce: Vec<u8>,
        realm: String,
    ) -> Result<TurnAllocation> {
        if data.len() < STUN_HEADER_SIZE {
            anyhow::bail!("Response too short");
        }

        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        if msg_type == TURN_ALLOCATE_ERROR {
            let error = self.parse_error_code(data)?;
            anyhow::bail!("Allocate failed: {}", error);
        }
        if msg_type != TURN_ALLOCATE_RESPONSE {
            anyhow::bail!("Expected allocate response, got 0x{:04x}", msg_type);
        }

        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;

        // Extract transaction ID for XOR decoding
        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&data[8..20]);

        let mut relayed_address = None;
        let mut mapped_address = None;
        let mut lifetime = DEFAULT_LIFETIME;

        let mut offset = STUN_HEADER_SIZE;
        while offset + 4 <= STUN_HEADER_SIZE + msg_len && offset + 4 <= data.len() {
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if offset + attr_len > data.len() {
                break;
            }

            match attr_type {
                ATTR_XOR_RELAYED_ADDRESS => {
                    relayed_address = Some(
                        self.decode_xor_address(&data[offset..offset + attr_len], &transaction_id)?,
                    );
                }
                ATTR_XOR_MAPPED_ADDRESS => {
                    mapped_address = Some(
                        self.decode_xor_address(&data[offset..offset + attr_len], &transaction_id)?,
                    );
                }
                ATTR_MAPPED_ADDRESS => {
                    if mapped_address.is_none() {
                        // Parse non-XOR mapped address as fallback
                        mapped_address = self.parse_mapped_address(&data[offset..offset + attr_len]).ok();
                    }
                }
                ATTR_LIFETIME => {
                    if attr_len >= 4 {
                        let secs = u32::from_be_bytes([
                            data[offset],
                            data[offset + 1],
                            data[offset + 2],
                            data[offset + 3],
                        ]);
                        lifetime = Duration::from_secs(secs as u64);
                    }
                }
                _ => {}
            }

            offset += (attr_len + 3) & !3;
        }

        let relayed_address = relayed_address.context("No relayed address in response")?;
        let mapped_address = mapped_address.context("No mapped address in response")?;

        Ok(TurnAllocation {
            relayed_address,
            mapped_address,
            lifetime,
            expires_at: Instant::now() + lifetime,
            nonce,
            realm,
        })
    }

    /// Parses a Refresh response.
    fn parse_refresh_response(&self, data: &[u8]) -> Result<Duration> {
        self.verify_success_response(data, TURN_REFRESH_RESPONSE)?;

        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let mut lifetime = DEFAULT_LIFETIME;

        let mut offset = STUN_HEADER_SIZE;
        while offset + 4 <= STUN_HEADER_SIZE + msg_len && offset + 4 <= data.len() {
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if attr_type == ATTR_LIFETIME && attr_len >= 4 {
                let secs = u32::from_be_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                lifetime = Duration::from_secs(secs as u64);
            }

            offset += (attr_len + 3) & !3;
        }

        Ok(lifetime)
    }

    /// Parses a Data indication.
    fn parse_data_indication(&self, data: &[u8]) -> Result<(SocketAddr, Vec<u8>)> {
        if data.len() < STUN_HEADER_SIZE {
            anyhow::bail!("Data indication too short");
        }

        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        if msg_type != TURN_DATA_INDICATION {
            anyhow::bail!("Not a data indication: 0x{:04x}", msg_type);
        }

        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;

        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&data[8..20]);

        let mut peer_address = None;
        let mut payload = Vec::new();

        let mut offset = STUN_HEADER_SIZE;
        while offset + 4 <= STUN_HEADER_SIZE + msg_len && offset + 4 <= data.len() {
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if offset + attr_len > data.len() {
                break;
            }

            match attr_type {
                ATTR_XOR_PEER_ADDRESS => {
                    peer_address = Some(
                        self.decode_xor_address(&data[offset..offset + attr_len], &transaction_id)?,
                    );
                }
                ATTR_DATA => {
                    payload = data[offset..offset + attr_len].to_vec();
                }
                _ => {}
            }

            offset += (attr_len + 3) & !3;
        }

        let peer_address = peer_address.context("No peer address in data indication")?;
        Ok((peer_address, payload))
    }

    /// Verifies a success response.
    fn verify_success_response(&self, data: &[u8], expected_type: u16) -> Result<()> {
        if data.len() < STUN_HEADER_SIZE {
            anyhow::bail!("Response too short");
        }

        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        if msg_type != expected_type {
            if (msg_type & 0x0110) == 0x0110 {
                let error = self.parse_error_code(data)?;
                anyhow::bail!("Request failed: {}", error);
            }
            anyhow::bail!("Unexpected response type: 0x{:04x}", msg_type);
        }

        Ok(())
    }

    /// Parses an error code from an error response.
    fn parse_error_code(&self, data: &[u8]) -> Result<String> {
        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;

        let mut offset = STUN_HEADER_SIZE;
        while offset + 4 <= STUN_HEADER_SIZE + msg_len && offset + 4 <= data.len() {
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if attr_type == ATTR_ERROR_CODE && attr_len >= 4 {
                let class = data[offset + 2] & 0x07;
                let number = data[offset + 3];
                let code = (class as u16) * 100 + (number as u16);
                let reason = if attr_len > 4 {
                    String::from_utf8_lossy(&data[offset + 4..offset + attr_len]).to_string()
                } else {
                    String::new()
                };
                return Ok(format!("{}: {}", code, reason));
            }

            offset += (attr_len + 3) & !3;
        }

        Ok("Unknown error".to_string())
    }

    /// Parses a non-XOR MAPPED-ADDRESS.
    fn parse_mapped_address(&self, data: &[u8]) -> Result<SocketAddr> {
        if data.len() < 8 {
            anyhow::bail!("Mapped address too short");
        }

        let family = data[1];
        let port = u16::from_be_bytes([data[2], data[3]]);

        match family {
            0x01 => {
                let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                Ok(SocketAddr::new(ip.into(), port))
            }
            0x02 => {
                if data.len() < 20 {
                    anyhow::bail!("IPv6 mapped address too short");
                }
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&data[4..20]);
                let ip = std::net::Ipv6Addr::from(ip_bytes);
                Ok(SocketAddr::new(ip.into(), port))
            }
            _ => anyhow::bail!("Unknown address family: {}", family),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_turn_server_config() {
        let config = TurnServerConfig {
            address: "192.0.2.1:3478".parse().unwrap(),
            username: "user".to_string(),
            credential: "pass".to_string(),
            tcp_fallback_port: Some(443),
        };

        assert_eq!(config.address.port(), 3478);
        assert_eq!(config.tcp_fallback_port, Some(443));
    }

    #[test]
    fn test_generate_transaction_id() {
        let id1 = TurnClient::generate_transaction_id();
        let id2 = TurnClient::generate_transaction_id();
        assert_ne!(id1, id2);
    }
}
