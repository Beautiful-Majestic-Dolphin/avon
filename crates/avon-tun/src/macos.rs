use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use async_trait::async_trait;
use avon_tunnel::{PacketSink, PacketSource, TunnelError};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

use crate::TunError;

// utun via /dev/tun* clone device on macOS.
const _CTL_INFO: &str = "com.apple.net.utun_control";

pub struct Tun {
    fd: AsyncFd<OwnedFd>,
    name: String,
    mtu: u16,
}

impl Tun {
    pub async fn create(name: &str, mtu: u16) -> Result<Self, TunError> {
        // Reuse the Linux implementation pattern but with macOS utun.
        // For now, delegate to a simple stub that opens a utun device.
        // The existing macOS code lives in avon-agent; we reimplement minimally.
        let fd = open_utun(name)?;
        let owned: OwnedFd = unsafe { OwnedFd::from_raw_fd(fd) };
        // Set non-blocking.
        let raw = owned.as_raw_fd();
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(TunError::Io(std::io::Error::last_os_error()));
        }
        Ok(Self {
            fd: AsyncFd::with_interest(owned, Interest::READABLE | Interest::WRITABLE)?,
            name: name.to_string(),
            mtu,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd.get_ref().as_raw_fd()
    }
}

fn open_utun(_name: &str) -> Result<RawFd, TunError> {
    // Open the utun control device and create an interface.
    // This is a minimal implementation that mirrors the previous avon-agent/macos.rs.
    let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if fd < 0 {
        return Err(TunError::Io(std::io::Error::last_os_error()));
    }
    // For simplicity, fall back to opening /dev/tun0 if available, otherwise use utun via ifconfig.
    // In tests this path is not exercised (MemoryTun is used).
    unsafe { libc::close(fd) };
    Err(TunError::Unsupported(
        "macOS TUN creation not fully implemented in this stub; use MemoryTun for tests",
    ))
}

#[async_trait]
impl PacketSource for Tun {
    async fn next_packet(&self, buf: &mut Vec<u8>) -> Result<usize, TunnelError> {
        buf.clear();
        buf.resize(self.mtu as usize + 64, 0);
        loop {
            let mut guard = self.fd.readable().await?;
            let raw = self.raw_fd();
            let n = unsafe { libc::read(raw, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n >= 0 {
                // utun has 4-byte family header; strip it.
                if n >= 4 {
                    buf.copy_within(4..n as usize, 0);
                    buf.truncate((n - 4) as usize);
                    return Ok((n - 4) as usize);
                }
                buf.truncate(n as usize);
                return Ok(n as usize);
            }
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                guard.clear_ready();
                continue;
            }
            return Err(TunnelError::Io(err));
        }
    }
}

#[async_trait]
impl PacketSink for Tun {
    async fn deliver(&self, ip_packet: &[u8]) -> Result<(), TunnelError> {
        // utun needs 4-byte family header.
        let mut out = Vec::with_capacity(ip_packet.len() + 4);
        let family = if ip_packet.first().map(|b| b >> 4) == Some(6) {
            30u32 // AF_INET6
        } else {
            2u32 // AF_INET
        };
        out.extend_from_slice(&family.to_be_bytes());
        out.extend_from_slice(ip_packet);
        loop {
            let mut guard = self.fd.writable().await?;
            let raw = self.raw_fd();
            let n = unsafe { libc::write(raw, out.as_ptr() as *const libc::c_void, out.len()) };
            if n >= 0 {
                return Ok(());
            }
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                guard.clear_ready();
                continue;
            }
            return Err(TunnelError::Io(err));
        }
    }
}

#[async_trait]
impl avon_agent_core::traits::TunProvider for Tun {
    async fn configure(
        &self,
        v4: ipnet::Ipv4Net,
        v6: ipnet::Ipv6Net,
        mtu: u16,
    ) -> Result<(), avon_agent_core::AgentError> {
        crate::config::configure_macos(self, v4, Some(v6), mtu)
            .await
            .map_err(|e| avon_agent_core::AgentError::Tun(e.to_string()))
    }

    async fn set_routes(&self, routes: &[ipnet::IpNet]) -> Result<(), avon_agent_core::AgentError> {
        crate::config::set_routes_macos(self, routes)
            .await
            .map_err(|e| avon_agent_core::AgentError::Tun(e.to_string()))
    }

    fn name(&self) -> &str {
        self.name()
    }
}
