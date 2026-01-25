//! TCP/443 fallback for restrictive firewalls.
//!
//! This module provides a TCP-based fallback for NAT traversal when UDP is
//! blocked by restrictive firewalls. It uses WebSocket over TCP port 443 to
//! tunnel TURN traffic, which typically passes through corporate firewalls.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::turn::TurnServerConfig;

/// Connection timeout for TCP fallback.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Read timeout for TCP operations.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// WebSocket upgrade request template.
const WS_UPGRADE_REQUEST: &str = "GET / HTTP/1.1\r\n\
Host: {host}\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Key: {key}\r\n\
Sec-WebSocket-Version: 13\r\n\
Sec-WebSocket-Protocol: turn\r\n\
\r\n";

/// A TCP tunnel connection for TURN fallback.
pub struct TcpTunnelConnection {
    stream: TcpStream,
    server_addr: SocketAddr,
    is_websocket: bool,
}

impl std::fmt::Debug for TcpTunnelConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpTunnelConnection")
            .field("server_addr", &self.server_addr)
            .field("is_websocket", &self.is_websocket)
            .finish_non_exhaustive()
    }
}

/// TCP fallback handler for NAT traversal.
pub struct TcpFallback {
    turn_server: SocketAddr,
    tcp_port: u16,
}

impl TcpFallback {
    /// Creates a new TCP fallback handler.
    ///
    /// # Arguments
    ///
    /// * `turn_server` - The TURN server address (UDP port)
    /// * `tcp_port` - The TCP port to use (typically 443)
    pub fn new(turn_server: SocketAddr, tcp_port: u16) -> Self {
        Self {
            turn_server,
            tcp_port,
        }
    }

    /// Creates a TCP fallback from TURN server configuration.
    pub fn from_config(config: &TurnServerConfig) -> Option<Self> {
        config.tcp_fallback_port.map(|port| Self {
            turn_server: config.address,
            tcp_port: port,
        })
    }

    /// Connects to the TURN server over TCP/443.
    ///
    /// This establishes a WebSocket connection that can be used to tunnel
    /// TURN traffic through restrictive firewalls.
    pub async fn connect(&self) -> Result<TcpTunnelConnection> {
        let tcp_addr = SocketAddr::new(self.turn_server.ip(), self.tcp_port);

        tracing::debug!(
            server = %tcp_addr,
            "Attempting TCP fallback connection"
        );

        // Connect with timeout
        let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(tcp_addr))
            .await
            .context("TCP connection timed out")?
            .context("Failed to connect to TURN server over TCP")?;

        // Disable Nagle's algorithm for lower latency
        stream.set_nodelay(true)?;

        tracing::info!(
            server = %tcp_addr,
            "TCP fallback connection established"
        );

        Ok(TcpTunnelConnection {
            stream,
            server_addr: tcp_addr,
            is_websocket: false,
        })
    }

    /// Connects to the TURN server using WebSocket over TCP/443.
    ///
    /// This is useful when the firewall only allows HTTPS traffic.
    pub async fn connect_websocket(&self) -> Result<TcpTunnelConnection> {
        let tcp_addr = SocketAddr::new(self.turn_server.ip(), self.tcp_port);

        tracing::debug!(
            server = %tcp_addr,
            "Attempting WebSocket fallback connection"
        );

        // Connect with timeout
        let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(tcp_addr))
            .await
            .context("WebSocket connection timed out")?
            .context("Failed to connect to TURN server over TCP")?;

        stream.set_nodelay(true)?;

        // Perform WebSocket handshake
        Self::websocket_handshake(&mut stream, &tcp_addr).await?;

        tracing::info!(
            server = %tcp_addr,
            "WebSocket fallback connection established"
        );

        Ok(TcpTunnelConnection {
            stream,
            server_addr: tcp_addr,
            is_websocket: true,
        })
    }

    /// Performs the WebSocket upgrade handshake.
    async fn websocket_handshake(stream: &mut TcpStream, addr: &SocketAddr) -> Result<()> {
        // Generate a random WebSocket key
        let key = Self::generate_websocket_key();

        // Build the upgrade request
        let request = WS_UPGRADE_REQUEST
            .replace("{host}", &addr.to_string())
            .replace("{key}", &key);

        // Send the upgrade request
        stream
            .write_all(request.as_bytes())
            .await
            .context("Failed to send WebSocket upgrade request")?;

        // Read the response
        let mut response = vec![0u8; 1024];
        let n = timeout(READ_TIMEOUT, stream.read(&mut response))
            .await
            .context("WebSocket handshake timed out")?
            .context("Failed to read WebSocket response")?;

        let response_str = String::from_utf8_lossy(&response[..n]);

        // Verify the response
        if !response_str.contains("101") || !response_str.to_lowercase().contains("upgrade") {
            anyhow::bail!("WebSocket upgrade failed: {}", response_str.lines().next().unwrap_or(""));
        }

        Ok(())
    }

    /// Generates a random WebSocket key.
    fn generate_websocket_key() -> String {
        let mut key = [0u8; 16];
        for byte in &mut key {
            *byte = rand::random();
        }
        base64_encode(&key)
    }
}

impl TcpTunnelConnection {
    /// Sends data through the TCP tunnel.
    ///
    /// For WebSocket connections, this frames the data appropriately.
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        if self.is_websocket {
            self.send_websocket_frame(data).await
        } else {
            self.send_raw(data).await
        }
    }

    /// Receives data from the TCP tunnel.
    ///
    /// For WebSocket connections, this handles frame parsing.
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        if self.is_websocket {
            self.recv_websocket_frame().await
        } else {
            self.recv_raw().await
        }
    }

    /// Sends raw data (for non-WebSocket connections).
    async fn send_raw(&mut self, data: &[u8]) -> Result<()> {
        // Send length prefix (4 bytes, big-endian)
        let len = (data.len() as u32).to_be_bytes();
        self.stream.write_all(&len).await?;
        self.stream.write_all(data).await?;
        Ok(())
    }

    /// Receives raw data (for non-WebSocket connections).
    async fn recv_raw(&mut self) -> Result<Vec<u8>> {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        if len > 65536 {
            anyhow::bail!("Message too large: {} bytes", len);
        }

        // Read data
        let mut data = vec![0u8; len];
        self.stream.read_exact(&mut data).await?;
        Ok(data)
    }

    /// Sends a WebSocket binary frame.
    async fn send_websocket_frame(&mut self, data: &[u8]) -> Result<()> {
        let mut frame = Vec::new();

        // FIN bit + opcode (binary = 0x02)
        frame.push(0x82);

        // Mask bit + payload length
        let len = data.len();
        if len < 126 {
            frame.push(0x80 | len as u8);
        } else if len < 65536 {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }

        // Masking key (required for client-to-server)
        let mask: [u8; 4] = [rand::random(), rand::random(), rand::random(), rand::random()];
        frame.extend_from_slice(&mask);

        // Masked payload
        for (i, byte) in data.iter().enumerate() {
            frame.push(byte ^ mask[i % 4]);
        }

        self.stream.write_all(&frame).await?;
        Ok(())
    }

    /// Receives a WebSocket frame.
    async fn recv_websocket_frame(&mut self) -> Result<Vec<u8>> {
        loop {
            // Read first two bytes
            let mut header = [0u8; 2];
            self.stream.read_exact(&mut header).await?;

            let _fin = (header[0] & 0x80) != 0;
            let opcode = header[0] & 0x0F;
            let masked = (header[1] & 0x80) != 0;
            let mut payload_len = (header[1] & 0x7F) as usize;

            // Handle extended payload length
            if payload_len == 126 {
                let mut ext = [0u8; 2];
                self.stream.read_exact(&mut ext).await?;
                payload_len = u16::from_be_bytes(ext) as usize;
            } else if payload_len == 127 {
                let mut ext = [0u8; 8];
                self.stream.read_exact(&mut ext).await?;
                payload_len = u64::from_be_bytes(ext) as usize;
            }

            if payload_len > 65536 {
                anyhow::bail!("WebSocket frame too large: {} bytes", payload_len);
            }

            // Read masking key if present
            let mask = if masked {
                let mut m = [0u8; 4];
                self.stream.read_exact(&mut m).await?;
                Some(m)
            } else {
                None
            };

            // Read payload
            let mut payload = vec![0u8; payload_len];
            self.stream.read_exact(&mut payload).await?;

            // Unmask if needed
            if let Some(mask) = mask {
                for (i, byte) in payload.iter_mut().enumerate() {
                    *byte ^= mask[i % 4];
                }
            }

            // Handle different opcodes
            match opcode {
                0x01 | 0x02 => return Ok(payload), // Text or binary
                0x08 => anyhow::bail!("WebSocket connection closed"),
                0x09 => {
                    // Ping - send pong and continue loop to read next frame
                    self.send_websocket_pong(&payload).await?;
                }
                0x0A => {
                    // Pong - ignore and continue loop to read next frame
                }
                _ => anyhow::bail!("Unknown WebSocket opcode: {}", opcode),
            }
        }
    }

    /// Sends a WebSocket pong frame.
    async fn send_websocket_pong(&mut self, data: &[u8]) -> Result<()> {
        let mut frame = Vec::new();
        frame.push(0x8A); // FIN + pong opcode

        let len = data.len();
        if len < 126 {
            frame.push(0x80 | len as u8);
        } else {
            anyhow::bail!("Pong payload too large");
        }

        // Masking key
        let mask: [u8; 4] = [rand::random(), rand::random(), rand::random(), rand::random()];
        frame.extend_from_slice(&mask);

        // Masked payload
        for (i, byte) in data.iter().enumerate() {
            frame.push(byte ^ mask[i % 4]);
        }

        self.stream.write_all(&frame).await?;
        Ok(())
    }

    /// Gets the server address.
    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    /// Checks if this is a WebSocket connection.
    pub fn is_websocket(&self) -> bool {
        self.is_websocket
    }

    /// Closes the connection.
    pub async fn close(&mut self) -> Result<()> {
        if self.is_websocket {
            // Send WebSocket close frame
            let frame = [0x88, 0x80, 0, 0, 0, 0]; // Close frame with empty mask
            let _ = self.stream.write_all(&frame).await;
        }
        self.stream.shutdown().await?;
        Ok(())
    }
}

/// Simple base64 encoding for WebSocket key.
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b0 = data[i];
        let b1 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] } else { 0 };

        result.push(ALPHABET[(b0 >> 2) as usize] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4 | b1 >> 4) as usize] as char);

        if i + 1 < data.len() {
            result.push(ALPHABET[((b1 & 0x0F) << 2 | b2 >> 6) as usize] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(ALPHABET[(b2 & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_fallback_creation() {
        let fallback = TcpFallback::new("1.2.3.4:3478".parse().unwrap(), 443);
        assert_eq!(fallback.tcp_port, 443);
    }

    #[test]
    fn test_from_config_with_tcp_port() {
        let config = TurnServerConfig {
            address: "1.2.3.4:3478".parse().unwrap(),
            username: "user".to_string(),
            credential: "pass".to_string(),
            tcp_fallback_port: Some(443),
        };

        let fallback = TcpFallback::from_config(&config);
        assert!(fallback.is_some());
        assert_eq!(fallback.unwrap().tcp_port, 443);
    }

    #[test]
    fn test_from_config_without_tcp_port() {
        let config = TurnServerConfig {
            address: "1.2.3.4:3478".parse().unwrap(),
            username: "user".to_string(),
            credential: "pass".to_string(),
            tcp_fallback_port: None,
        };

        let fallback = TcpFallback::from_config(&config);
        assert!(fallback.is_none());
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"a"), "YQ==");
        assert_eq!(base64_encode(b"ab"), "YWI=");
        assert_eq!(base64_encode(b"abc"), "YWJj");
    }

    #[test]
    fn test_websocket_key_generation() {
        let key1 = TcpFallback::generate_websocket_key();
        let key2 = TcpFallback::generate_websocket_key();

        // Keys should be different
        assert_ne!(key1, key2);

        // Keys should be valid base64 (24 chars for 16 bytes)
        assert_eq!(key1.len(), 24);
        assert_eq!(key2.len(), 24);
    }
}
