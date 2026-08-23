use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use async_trait::async_trait;
use avon_tunnel::{PacketSink, PacketSource, TunnelError};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

use crate::TunError;

const TUN_PATH: &str = "/dev/net/tun";
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

#[repr(C)]
struct IfReq {
    name: [u8; 16],
    flags: libc::c_short,
    _pad: [u8; 22],
}

pub struct Tun {
    fd: AsyncFd<OwnedFd>,
    name: String,
    mtu: u16,
}

impl Tun {
    pub async fn create(name: &str, mtu: u16) -> Result<Self, TunError> {
        if name.is_empty() || name.len() > 15 {
            return Err(TunError::InvalidName);
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(TUN_PATH)?;
        let raw: RawFd = file.as_raw_fd();
        let mut req = IfReq {
            name: [0; 16],
            flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        req.name[..name.len()].copy_from_slice(name.as_bytes());
        // SAFETY: `req` is a correctly sized, initialized ifreq and `raw` is an open fd to /dev/net/tun.
        let rc = unsafe { libc::ioctl(raw, TUNSETIFF, &mut req as *mut IfReq) };
        if rc < 0 {
            return Err(TunError::Io(std::io::Error::last_os_error()));
        }
        // SAFETY: setting O_NONBLOCK on an fd we own.
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(TunError::Io(std::io::Error::last_os_error()));
        }
        let owned: OwnedFd = file.into();
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

    /// Adopt an fd received over IPC (SCM_RIGHTS). Sets O_NONBLOCK and wraps in AsyncFd.
    pub fn from_owned_fd(fd: OwnedFd, name: &str, mtu: u16) -> Result<Self, TunError> {
        let raw = fd.as_raw_fd();
        // SAFETY: setting O_NONBLOCK on an fd we own.
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(TunError::Io(std::io::Error::last_os_error()));
        }
        Ok(Self {
            fd: AsyncFd::with_interest(fd, Interest::READABLE | Interest::WRITABLE)?,
            name: name.to_string(),
            mtu,
        })
    }
}

#[async_trait]
impl PacketSource for Tun {
    async fn next_packet(&self, buf: &mut Vec<u8>) -> Result<usize, TunnelError> {
        buf.clear();
        buf.resize(self.mtu as usize + 64, 0);
        loop {
            let mut guard = self.fd.readable().await?;
            let raw = self.raw_fd();
            // SAFETY: reading into a valid buffer of the stated length from an fd we own.
            let n = unsafe { libc::read(raw, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n >= 0 {
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
        loop {
            let mut guard = self.fd.writable().await?;
            let raw = self.raw_fd();
            // SAFETY: writing a valid buffer to an fd we own.
            let n = unsafe {
                libc::write(
                    raw,
                    ip_packet.as_ptr() as *const libc::c_void,
                    ip_packet.len(),
                )
            };
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
        crate::config::configure(self, v4, Some(v6), mtu)
            .await
            .map_err(|e| avon_agent_core::AgentError::Tun(e.to_string()))
    }

    async fn set_routes(&self, routes: &[ipnet::IpNet]) -> Result<(), avon_agent_core::AgentError> {
        crate::config::set_routes(self, routes)
            .await
            .map_err(|e| avon_agent_core::AgentError::Tun(e.to_string()))
    }

    fn name(&self) -> &str {
        self.name()
    }
}
