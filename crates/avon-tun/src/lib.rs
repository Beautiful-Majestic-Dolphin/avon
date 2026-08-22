//! Platform TUN device for AVON.
//!
//! On Linux the device is a true `/dev/net/tun` interface managed via
//! netlink; on macOS it is a utun interface configured via `ifconfig`/`route`;
//! on Windows it is a stub until phase 5.

use thiserror::Error;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::Tun;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::Tun;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::Tun;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod stub;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub use stub::Tun;

pub mod checksum;
pub mod config;

#[derive(Debug, Error)]
pub enum TunError {
    #[error("invalid TUN name (must be 1..=15 chars)")]
    InvalidName,
    #[error("TUN not supported on this platform: {0}")]
    Unsupported(&'static str),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("netlink: {0}")]
    Netlink(String),
    #[error("tunnel: {0}")]
    Tunnel(#[from] avon_tunnel::TunnelError),
    #[error("agent: {0}")]
    Agent(String),
}

impl From<TunError> for avon_tunnel::TunnelError {
    fn from(e: TunError) -> Self {
        avon_tunnel::TunnelError::Io(std::io::Error::other(e.to_string()))
    }
}
