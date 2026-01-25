//! STUN client for NAT traversal.
//!
//! This module implements a STUN (Session Traversal Utilities for NAT) client
//! that can discover the external IP address and port of a device behind NAT.
//! It follows RFC 5389 for STUN message format and processing.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// STUN magic cookie (RFC 5389).
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN message types.
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;

/// STUN attribute types.
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;

/// STUN header size in bytes.
const STUN_HEADER_SIZE: usize = 20;

/// Default STUN request timeout.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

/// Maximum number of retries for STUN requests.
const MAX_RETRIES: u32 = 3;

/// STUN client for discovering external addresses.
pub struct StunClient {
    server: SocketAddr,
    timeout: Duration,
}

/// Response from a STUN binding request.
#[derive(Debug, Clone)]
pub struct StunResponse {
    pub transaction_id: [u8; 12],
    pub mapped_address: SocketAddr,
}

impl StunClient {
    /// Creates a new STUN client.
    ///
    /// # Arguments
    ///
    /// * `server` - The STUN server address
    pub fn new(server: SocketAddr) -> Self {
        Self {
            server,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Creates a new STUN client with a custom timeout.
    pub fn with_timeout(server: SocketAddr, timeout: Duration) -> Self {
        Self { server, timeout }
    }

    /// Performs a STUN binding request to discover the external address.
    ///
    /// # Arguments
    ///
    /// * `socket` - The UDP socket to use for the request
    ///
    /// # Returns
    ///
    /// The external (mapped) address as seen by the STUN server.
    pub async fn binding_request(&self, socket: &UdpSocket) -> Result<SocketAddr> {
        let mut last_error = None;

        for attempt in 0..MAX_RETRIES {
            let transaction_id = Self::generate_transaction_id();
            let request = Self::build_binding_request(transaction_id);

            match self.send_and_receive(socket, &request, transaction_id).await {
                Ok(response) => {
                    tracing::debug!(
                        server = %self.server,
                        mapped_address = %response.mapped_address,
                        "STUN binding request succeeded"
                    );
                    return Ok(response.mapped_address);
                }
                Err(e) => {
                    tracing::debug!(
                        server = %self.server,
                        attempt = attempt + 1,
                        error = %e,
                        "STUN binding request failed, retrying"
                    );
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("STUN request failed")))
    }

    /// Sends a STUN request and waits for a response.
    async fn send_and_receive(
        &self,
        socket: &UdpSocket,
        request: &[u8],
        expected_transaction_id: [u8; 12],
    ) -> Result<StunResponse> {
        socket
            .send_to(request, self.server)
            .await
            .context("Failed to send STUN request")?;

        let mut buf = [0u8; 1024];
        let (len, _from) = timeout(self.timeout, socket.recv_from(&mut buf))
            .await
            .context("STUN request timed out")?
            .context("Failed to receive STUN response")?;

        let response = Self::parse_binding_response(&buf[..len])?;

        if response.transaction_id != expected_transaction_id {
            anyhow::bail!("Transaction ID mismatch");
        }

        Ok(response)
    }

    /// Generates a random transaction ID.
    fn generate_transaction_id() -> [u8; 12] {
        let mut id = [0u8; 12];
        for byte in &mut id {
            *byte = rand::random();
        }
        id
    }

    /// Builds a STUN binding request message.
    ///
    /// # Arguments
    ///
    /// * `transaction_id` - The 12-byte transaction ID
    ///
    /// # Returns
    ///
    /// The serialized STUN binding request.
    pub fn build_binding_request(transaction_id: [u8; 12]) -> Vec<u8> {
        let mut request = Vec::with_capacity(STUN_HEADER_SIZE);

        // Message type: Binding Request (0x0001)
        request.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());

        // Message length: 0 (no attributes)
        request.extend_from_slice(&0u16.to_be_bytes());

        // Magic cookie
        request.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());

        // Transaction ID (12 bytes)
        request.extend_from_slice(&transaction_id);

        request
    }

    /// Parses a STUN binding response.
    ///
    /// # Arguments
    ///
    /// * `data` - The raw response data
    ///
    /// # Returns
    ///
    /// The parsed STUN response.
    pub fn parse_binding_response(data: &[u8]) -> Result<StunResponse> {
        if data.len() < STUN_HEADER_SIZE {
            anyhow::bail!("Response too short");
        }

        // Parse message type
        let message_type = u16::from_be_bytes([data[0], data[1]]);
        if message_type != STUN_BINDING_RESPONSE {
            anyhow::bail!("Not a binding response: 0x{:04x}", message_type);
        }

        // Parse message length
        let message_length = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < STUN_HEADER_SIZE + message_length {
            anyhow::bail!("Response truncated");
        }

        // Verify magic cookie
        let magic_cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if magic_cookie != STUN_MAGIC_COOKIE {
            anyhow::bail!("Invalid magic cookie");
        }

        // Extract transaction ID
        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&data[8..20]);

        // Parse attributes to find XOR-MAPPED-ADDRESS or MAPPED-ADDRESS
        let mut offset = STUN_HEADER_SIZE;
        let mut mapped_address = None;

        while offset + 4 <= STUN_HEADER_SIZE + message_length {
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if offset + attr_length > data.len() {
                break;
            }

            match attr_type {
                STUN_ATTR_XOR_MAPPED_ADDRESS => {
                    mapped_address =
                        Some(Self::parse_xor_mapped_address(&data[offset..offset + attr_length], &transaction_id)?);
                    break;
                }
                STUN_ATTR_MAPPED_ADDRESS => {
                    if mapped_address.is_none() {
                        mapped_address =
                            Some(Self::parse_mapped_address(&data[offset..offset + attr_length])?);
                    }
                }
                _ => {}
            }

            // Attributes are padded to 4-byte boundaries
            offset += (attr_length + 3) & !3;
        }

        let mapped_address = mapped_address.context("No mapped address in response")?;

        Ok(StunResponse {
            transaction_id,
            mapped_address,
        })
    }

    /// Parses an XOR-MAPPED-ADDRESS attribute.
    fn parse_xor_mapped_address(data: &[u8], transaction_id: &[u8; 12]) -> Result<SocketAddr> {
        if data.len() < 8 {
            anyhow::bail!("XOR-MAPPED-ADDRESS too short");
        }

        let family = data[1];
        let xor_port = u16::from_be_bytes([data[2], data[3]]);
        let port = xor_port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);

        match family {
            0x01 => {
                // IPv4
                if data.len() < 8 {
                    anyhow::bail!("XOR-MAPPED-ADDRESS IPv4 too short");
                }
                let xor_addr = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let addr = xor_addr ^ STUN_MAGIC_COOKIE;
                let ip = std::net::Ipv4Addr::from(addr);
                Ok(SocketAddr::new(ip.into(), port))
            }
            0x02 => {
                // IPv6
                if data.len() < 20 {
                    anyhow::bail!("XOR-MAPPED-ADDRESS IPv6 too short");
                }
                let mut xor_key = [0u8; 16];
                xor_key[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
                xor_key[4..].copy_from_slice(transaction_id);

                let mut addr_bytes = [0u8; 16];
                for i in 0..16 {
                    addr_bytes[i] = data[4 + i] ^ xor_key[i];
                }
                let ip = std::net::Ipv6Addr::from(addr_bytes);
                Ok(SocketAddr::new(ip.into(), port))
            }
            _ => anyhow::bail!("Unknown address family: {}", family),
        }
    }

    /// Parses a MAPPED-ADDRESS attribute (non-XOR, for older servers).
    fn parse_mapped_address(data: &[u8]) -> Result<SocketAddr> {
        if data.len() < 8 {
            anyhow::bail!("MAPPED-ADDRESS too short");
        }

        let family = data[1];
        let port = u16::from_be_bytes([data[2], data[3]]);

        match family {
            0x01 => {
                // IPv4
                let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                Ok(SocketAddr::new(ip.into(), port))
            }
            0x02 => {
                // IPv6
                if data.len() < 20 {
                    anyhow::bail!("MAPPED-ADDRESS IPv6 too short");
                }
                let mut addr_bytes = [0u8; 16];
                addr_bytes.copy_from_slice(&data[4..20]);
                let ip = std::net::Ipv6Addr::from(addr_bytes);
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
    fn test_build_binding_request() {
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let request = StunClient::build_binding_request(transaction_id);

        assert_eq!(request.len(), STUN_HEADER_SIZE);
        assert_eq!(request[0..2], [0x00, 0x01]); // Binding Request
        assert_eq!(request[2..4], [0x00, 0x00]); // Length = 0
        assert_eq!(request[4..8], [0x21, 0x12, 0xA4, 0x42]); // Magic cookie
        assert_eq!(request[8..20], transaction_id);
    }

    #[test]
    fn test_parse_binding_response_ipv4() {
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        // Build a mock response with XOR-MAPPED-ADDRESS
        let mut response = Vec::new();
        response.extend_from_slice(&[0x01, 0x01]); // Binding Response
        response.extend_from_slice(&[0x00, 0x0C]); // Length = 12
        response.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&transaction_id);

        // XOR-MAPPED-ADDRESS attribute
        response.extend_from_slice(&[0x00, 0x20]); // Type
        response.extend_from_slice(&[0x00, 0x08]); // Length = 8
        response.push(0x00); // Reserved
        response.push(0x01); // Family = IPv4

        // XOR'd port (5000 ^ 0x2112 = 0x0B9A)
        let port: u16 = 5000;
        let xor_port = port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
        response.extend_from_slice(&xor_port.to_be_bytes());

        // XOR'd address (192.168.1.1 ^ magic cookie)
        let addr = u32::from_be_bytes([192, 168, 1, 1]);
        let xor_addr = addr ^ STUN_MAGIC_COOKIE;
        response.extend_from_slice(&xor_addr.to_be_bytes());

        let parsed = StunClient::parse_binding_response(&response).unwrap();
        assert_eq!(parsed.transaction_id, transaction_id);
        assert_eq!(parsed.mapped_address.port(), 5000);
        assert_eq!(
            parsed.mapped_address.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn test_generate_transaction_id() {
        let id1 = StunClient::generate_transaction_id();
        let id2 = StunClient::generate_transaction_id();
        assert_ne!(id1, id2);
    }
}
