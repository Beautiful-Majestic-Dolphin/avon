//! Windows data plane on WinTun.
//!
//! WinTun's receive call blocks, so the read side runs on a dedicated thread
//! that forwards packets over a channel; the write side is lock-free and is
//! called directly. `wintun.dll` is loaded from the executable's own directory
//! so an installed layout is self-contained and `PATH` never decides which DLL
//! the agent maps.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use avon_tunnel::{PacketSink, PacketSource, TunnelError};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use tokio::sync::mpsc;

use crate::TunError;

/// Absolute paths only: a privileged service must not let `PATH` choose.
pub const NETSH: &str = r"C:\Windows\System32\netsh.exe";

/// 4 MiB of ring is enough for a 1280-byte MTU at line rate and costs less
/// non-paged pool than WinTun's 64 MiB maximum.
const RING_CAPACITY: u32 = 4 * 1024 * 1024;

/// How many packets may queue between the reader thread and the tunnel task
/// before the reader starts dropping — a stalled tunnel must not grow memory
/// without bound.
const READ_QUEUE: usize = 1024;

pub struct Tun {
    name: String,
    mtu: u16,
    luid: u64,
    adapter: Arc<wintun::Adapter>,
    session: Arc<wintun::Session>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    reader: Option<std::thread::JoinHandle<()>>,
}

fn dll_path() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("wintun.dll")))
        .unwrap_or_else(|| std::path::PathBuf::from("wintun.dll"))
}

fn platform(e: impl std::fmt::Display) -> TunError {
    TunError::Io(std::io::Error::other(e.to_string()))
}

impl Tun {
    /// Open the adapter if it already exists, otherwise create it. Reopening
    /// matters after a crash: a leftover adapter must not block a restart.
    pub async fn create(name: &str, mtu: u16) -> Result<Self, TunError> {
        if name.is_empty() || name.len() > 15 {
            return Err(TunError::InvalidName);
        }
        // SAFETY: loading a DLL we ship beside the executable.
        let wintun = unsafe { wintun::load_from_path(dll_path()) }.map_err(platform)?;
        let adapter = match wintun::Adapter::open(&wintun, name) {
            Ok(a) => a,
            Err(_) => wintun::Adapter::create(&wintun, name, "AVON", None).map_err(platform)?,
        };
        adapter.set_mtu(mtu as usize).map_err(platform)?;
        // SAFETY: NET_LUID_LH is a union of a u64 and a bitfield view of the
        // same bytes; reading the u64 is always valid.
        let luid = unsafe { adapter.get_luid().Value };
        let session = Arc::new(adapter.start_session(RING_CAPACITY).map_err(platform)?);

        let (tx, rx) = mpsc::channel(READ_QUEUE);
        let reader_session = session.clone();
        let reader = std::thread::Builder::new()
            .name("avon-wintun-rx".into())
            .spawn(move || {
                while let Ok(packet) = reader_session.receive_blocking() {
                    if tx.blocking_send(packet.bytes().to_vec()).is_err() {
                        break; // the agent is shutting down
                    }
                }
            })
            .map_err(TunError::Io)?;

        Ok(Self {
            name: name.to_string(),
            mtu,
            luid,
            adapter,
            session,
            rx: tokio::sync::Mutex::new(rx),
            reader: Some(reader),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// The interface LUID, which is how the Windows filtering and routing APIs
    /// name an adapter.
    pub fn luid(&self) -> u64 {
        self.luid
    }

    pub fn adapter(&self) -> &Arc<wintun::Adapter> {
        &self.adapter
    }

    async fn netsh(args: &[String]) -> Result<(), TunError> {
        let out = tokio::process::Command::new(NETSH)
            .args(args)
            .output()
            .await
            .map_err(TunError::Io)?;
        if !out.status.success() {
            return Err(platform(format!(
                "netsh {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stdout).trim()
            )));
        }
        Ok(())
    }

    fn family(addr: IpAddr) -> &'static str {
        if addr.is_ipv4() {
            "ipv4"
        } else {
            "ipv6"
        }
    }

    async fn set_address_v4(&self, v4: Ipv4Net) -> Result<(), TunError> {
        let mask = std::net::Ipv4Addr::from(if v4.prefix_len() == 0 {
            0
        } else {
            u32::MAX << (32 - v4.prefix_len())
        });
        Self::netsh(&[
            "interface".into(),
            "ipv4".into(),
            "set".into(),
            "address".into(),
            format!("name={}", self.name),
            "source=static".into(),
            format!("address={}", v4.addr()),
            format!("mask={mask}"),
        ])
        .await
    }

    async fn set_address_v6(&self, v6: Ipv6Net) -> Result<(), TunError> {
        Self::netsh(&[
            "interface".into(),
            "ipv6".into(),
            "set".into(),
            "address".into(),
            format!("interface={}", self.name),
            format!("address={v6}"),
        ])
        .await
    }

    async fn set_interface_mtu(&self, mtu: u16) -> Result<(), TunError> {
        for family in ["ipv4", "ipv6"] {
            Self::netsh(&[
                "interface".into(),
                family.into(),
                "set".into(),
                "subinterface".into(),
                self.name.clone(),
                format!("mtu={mtu}"),
                "store=active".into(),
            ])
            .await?;
        }
        Ok(())
    }

    /// Install a route bound to this interface. Already-present routes are not
    /// an error: the agent re-applies its route set on every reconnect.
    pub async fn add_route(&self, route: IpNet) -> Result<(), TunError> {
        let r = Self::netsh(&[
            "interface".into(),
            Self::family(route.addr()).into(),
            "add".into(),
            "route".into(),
            format!("prefix={route}"),
            format!("interface={}", self.name),
            "store=active".into(),
        ])
        .await;
        match r {
            Ok(()) => Ok(()),
            Err(e) => {
                tracing::debug!(route = %route, error = %e, "route add ignored");
                Ok(())
            }
        }
    }

    pub async fn remove_route(&self, route: IpNet) -> Result<(), TunError> {
        let r = Self::netsh(&[
            "interface".into(),
            Self::family(route.addr()).into(),
            "delete".into(),
            "route".into(),
            format!("prefix={route}"),
            format!("interface={}", self.name),
            "store=active".into(),
        ])
        .await;
        if let Err(e) = r {
            tracing::debug!(route = %route, error = %e, "route delete ignored");
        }
        Ok(())
    }
}

impl std::fmt::Debug for Tun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tun")
            .field("name", &self.name)
            .field("mtu", &self.mtu)
            .field("luid", &self.luid)
            .finish()
    }
}

impl Drop for Tun {
    fn drop(&mut self) {
        // Shutting the session down unblocks `receive_blocking`, which is the
        // only way the reader thread ever exits.
        let _ = self.session.shutdown();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[async_trait]
impl PacketSource for Tun {
    async fn next_packet(&self, buf: &mut Vec<u8>) -> Result<usize, TunnelError> {
        let packet = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| TunnelError::Io(std::io::Error::other("wintun reader stopped")))?;
        buf.clear();
        buf.extend_from_slice(&packet);
        Ok(packet.len())
    }
}

#[async_trait]
impl PacketSink for Tun {
    async fn deliver(&self, ip_packet: &[u8]) -> Result<(), TunnelError> {
        let len = u16::try_from(ip_packet.len())
            .map_err(|_| TunnelError::Io(std::io::Error::other("packet too large for wintun")))?;
        let mut packet = self
            .session
            .allocate_send_packet(len)
            .map_err(|e| TunnelError::Io(std::io::Error::other(format!("wintun allocate: {e}"))))?;
        packet.bytes_mut().copy_from_slice(ip_packet);
        self.session.send_packet(packet);
        Ok(())
    }
}

#[async_trait]
impl avon_agent_core::traits::TunProvider for Tun {
    async fn configure(
        &self,
        v4: Ipv4Net,
        v6: Ipv6Net,
        mtu: u16,
    ) -> Result<(), avon_agent_core::AgentError> {
        self.set_address_v4(v4)
            .await
            .map_err(|e| avon_agent_core::AgentError::Tun(e.to_string()))?;
        self.set_address_v6(v6)
            .await
            .map_err(|e| avon_agent_core::AgentError::Tun(e.to_string()))?;
        self.set_interface_mtu(mtu)
            .await
            .map_err(|e| avon_agent_core::AgentError::Tun(e.to_string()))
    }

    async fn set_routes(&self, routes: &[IpNet]) -> Result<(), avon_agent_core::AgentError> {
        for route in routes {
            self.add_route(*route)
                .await
                .map_err(|e| avon_agent_core::AgentError::Tun(e.to_string()))?;
        }
        Ok(())
    }

    fn name(&self) -> &str {
        self.name()
    }
}
