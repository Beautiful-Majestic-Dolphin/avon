//! AVON UDP Gateway
//!
//! This crate provides the UDP gateway service for the AVON control plane.
//! The gateway handles incoming control plane packets, performs rate limiting,
//! and routes messages to appropriate handlers.
//!
//! # Architecture
//!
//! The gateway consists of several components:
//!
//! - [`UdpGateway`](gateway::UdpGateway) - Main UDP receive loop
//! - [`RateLimiter`](rate_limiter::RateLimiter) - Per-IP rate limiting
//! - [`DeviceRegistry`](device_registry::DeviceRegistry) - In-memory device cache
//! - [`PacketHandler`](packet_handler::PacketHandler) - Packet processing and routing
//!
//! # Example
//!
//! ```no_run
//! use avon_gateway::{
//!     config::GatewayConfig,
//!     device_registry::DeviceRegistry,
//!     gateway::{UdpGateway, HealthServer},
//!     packet_handler::PacketHandler,
//!     rate_limiter::RateLimiter,
//! };
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = GatewayConfig::default();
//!     
//!     let registry = Arc::new(DeviceRegistry::new(config.redis_url.clone()).await?);
//!     let rate_limiter = Arc::new(RateLimiter::new(config.rate_limit.clone()));
//!     let packet_handler = Arc::new(PacketHandler::new(registry.clone()));
//!     
//!     let gateway = UdpGateway::bind(
//!         config.listen_addr,
//!         rate_limiter,
//!         packet_handler,
//!     ).await?;
//!     
//!     gateway.run().await
//! }
//! ```

pub mod config;
pub mod device_registry;
pub mod gateway;
pub mod packet_handler;
pub mod rate_limiter;

pub use config::{GatewayConfig, RateLimitConfig};
pub use device_registry::{DeviceRegistry, DeviceState, RegistryError};
pub use gateway::{GatewayMetrics, HealthServer, UdpGateway};
pub use packet_handler::{PacketError, PacketHandler};
pub use rate_limiter::RateLimiter;
