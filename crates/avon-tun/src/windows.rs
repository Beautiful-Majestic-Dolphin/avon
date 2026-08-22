use async_trait::async_trait;
use avon_tunnel::{PacketSink, PacketSource, TunnelError};

use crate::TunError;

pub struct Tun;

impl Tun {
    pub async fn create(_name: &str, _mtu: u16) -> Result<Self, TunError> {
        Err(TunError::Unsupported("windows support arrives in phase 5"))
    }

    pub fn name(&self) -> &str {
        "unsupported"
    }

    pub fn mtu(&self) -> u16 {
        0
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
        "unsupported"
    }
}
