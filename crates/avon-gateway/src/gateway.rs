//! UDP Gateway for the AVON control plane.
//!
//! Handles incoming UDP packets, rate limiting, and packet processing.

use metrics::{counter, histogram};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

use crate::packet_handler::PacketHandler;
use crate::rate_limiter::RateLimiter;

/// Maximum UDP packet size.
const MAX_PACKET_SIZE: usize = 65535;

/// Gateway metrics.
pub struct GatewayMetrics;

impl GatewayMetrics {
    /// Records a received packet.
    pub fn record_received() {
        counter!("gateway_packets_received_total").increment(1);
    }

    /// Records a packet dropped due to rate limiting.
    pub fn record_rate_limited() {
        counter!("gateway_packets_dropped_rate_limit_total").increment(1);
    }

    /// Records a packet dropped due to auth failure.
    pub fn record_auth_failed() {
        counter!("gateway_packets_dropped_auth_failed_total").increment(1);
    }

    /// Records a successfully processed packet.
    pub fn record_processed() {
        counter!("gateway_packets_processed_total").increment(1);
    }

    /// Records response time.
    pub fn record_response_time(duration_ms: f64) {
        histogram!("gateway_response_time_seconds").record(duration_ms / 1000.0);
    }

    /// Records a sent response.
    pub fn record_response_sent() {
        counter!("gateway_responses_sent_total").increment(1);
    }
}

/// UDP Gateway for the AVON control plane.
pub struct UdpGateway {
    socket: Arc<UdpSocket>,
    rate_limiter: Arc<RateLimiter>,
    packet_handler: Arc<PacketHandler>,
}

impl UdpGateway {
    /// Binds the gateway to the specified address.
    pub async fn bind(
        addr: SocketAddr,
        rate_limiter: Arc<RateLimiter>,
        packet_handler: Arc<PacketHandler>,
    ) -> anyhow::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        info!(?addr, "UDP gateway bound");

        Ok(Self {
            socket,
            rate_limiter,
            packet_handler,
        })
    }

    /// Returns the local address the gateway is bound to.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Runs the gateway's main receive loop.
    pub async fn run(&self) -> anyhow::Result<()> {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];

        info!("UDP gateway starting receive loop");

        loop {
            let (len, source) = match self.socket.recv_from(&mut buf).await {
                Ok(result) => result,
                Err(e) => {
                    error!(error = %e, "Failed to receive packet");
                    continue;
                }
            };

            GatewayMetrics::record_received();
            let start = Instant::now();

            // Check rate limit
            if !self.rate_limiter.check(source.ip()) {
                debug!(?source, "Rate limited");
                GatewayMetrics::record_rate_limited();
                continue;
            }

            // Clone data for async processing
            let packet = buf[..len].to_vec();
            let handler = self.packet_handler.clone();
            let socket = Arc::clone(&self.socket);

            // Spawn task to handle packet
            tokio::spawn(async move {
                let response = handler.handle_packet(&packet, source).await;

                let elapsed = start.elapsed().as_secs_f64() * 1000.0;
                GatewayMetrics::record_response_time(elapsed);

                if let Some(response_data) = response {
                    GatewayMetrics::record_processed();

                    if let Err(e) = socket.send_to(&response_data, source).await {
                        warn!(?source, error = %e, "Failed to send response");
                    } else {
                        GatewayMetrics::record_response_sent();
                        debug!(?source, len = response_data.len(), "Sent response");
                    }
                }
            });
        }
    }
}

/// Health check server for Kubernetes probes.
pub struct HealthServer {
    listener: tokio::net::TcpListener,
}

impl HealthServer {
    /// Binds the health server to the specified port.
    pub async fn bind(port: u16) -> anyhow::Result<Self> {
        let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        info!(?addr, "Health server bound");

        Ok(Self { listener })
    }

    /// Runs the health server.
    pub async fn run(&self) -> anyhow::Result<()> {
        info!("Health server starting");

        loop {
            let (mut socket, addr) = match self.listener.accept().await {
                Ok(result) => result,
                Err(e) => {
                    error!(error = %e, "Failed to accept connection");
                    continue;
                }
            };

            debug!(?addr, "Health check request");

            // Simple HTTP response
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
            if let Err(e) =
                tokio::io::AsyncWriteExt::write_all(&mut socket, response.as_bytes()).await
            {
                warn!(?addr, error = %e, "Failed to send health response");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::config::RateLimitConfig;
    use crate::device_registry::DeviceRegistry;

    #[tokio::test]
    async fn test_gateway_bind() {
        let registry = Arc::new(
            DeviceRegistry::new("redis://localhost:6379".to_string())
                .await
                .unwrap(),
        );
        let rate_limiter = Arc::new(RateLimiter::new(RateLimitConfig::default()));
        let packet_handler = Arc::new(PacketHandler::new(registry));

        // Bind to a random port
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let gateway = UdpGateway::bind(addr, rate_limiter, packet_handler)
            .await
            .unwrap();

        let local_addr = gateway.local_addr().unwrap();
        assert!(local_addr.port() > 0);
    }

    #[tokio::test]
    async fn test_health_server_bind() {
        let server = HealthServer::bind(0).await.unwrap();
        let addr = server.listener.local_addr().unwrap();
        assert!(addr.port() > 0);
    }
}
