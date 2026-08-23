use async_trait::async_trait;
use avon_tunnel::{PacketSink, PacketSource, TunnelError};

use crate::TunError;

pub struct Tun {
    #[cfg(target_os = "windows")]
    _adapter: Option<wintun::Adapter>,
    _name: String,
    _mtu: u16,
}

impl Tun {
    pub async fn create(name: &str, mtu: u16) -> Result<Self, TunError> {
        if name.is_empty() || name.len() > 15 {
            return Err(TunError::InvalidName);
        }
        #[cfg(target_os = "windows")]
        {
            let adapter = wintun::Adapter::create(
                &wintun::load().map_err(|e| TunError::Io(std::io::Error::other(e.to_string())))?,
                "AVON",
                name,
                None,
            )
            .map_err(|e| TunError::Io(std::io::Error::other(e.to_string())))?;
            return Ok(Self {
                _adapter: Some(adapter),
                _name: name.to_string(),
                _mtu: mtu,
            });
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (name, mtu);
            Err(TunError::Unsupported("WinTun only on Windows"))
        }
    }

    #[cfg(target_os = "windows")]
    pub fn from_adapter(adapter: wintun::Adapter, name: &str, mtu: u16) -> Self {
        Self {
            _adapter: Some(adapter),
            _name: name.to_string(),
            _mtu: mtu,
        }
    }

    pub fn name(&self) -> &str {
        &self._name
    }

    pub fn mtu(&self) -> u16 {
        self._mtu
    }
}

#[async_trait]
impl PacketSource for Tun {
    async fn next_packet(&self, _buf: &mut Vec<u8>) -> Result<usize, TunnelError> {
        Err(TunnelError::Io(std::io::Error::other(
            "windows TUN not supported",
        )))
    }
}

#[async_trait]
impl PacketSink for Tun {
    async fn deliver(&self, _ip_packet: &[u8]) -> Result<(), TunnelError> {
        Err(TunnelError::Io(std::io::Error::other(
            "windows TUN not supported",
        )))
    }
}

#[async_trait]
impl avon_agent_core::traits::TunProvider for Tun {
    async fn configure(
        &self,
        _v4: ipnet::Ipv4Net,
        _v6: ipnet::Ipv6Net,
        _mtu: u16,
    ) -> Result<(), avon_agent_core::AgentError> {
        Err(avon_agent_core::AgentError::Tun(
            "windows TUN not supported".into(),
        ))
    }

    async fn set_routes(
        &self,
        _routes: &[ipnet::IpNet],
    ) -> Result<(), avon_agent_core::AgentError> {
        Err(avon_agent_core::AgentError::Tun(
            "windows TUN not supported".into(),
        ))
    }

    fn name(&self) -> &str {
        self.name()
    }
}
