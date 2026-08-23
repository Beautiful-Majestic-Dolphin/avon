//! The unprivileged side. Runs inside the agent process, which has no
//! capabilities: it asks for a TUN, receives the descriptor, and from then on
//! does packet I/O itself. Addressing, routes and the firewall stay behind the
//! IPC.

use std::path::Path;

use async_trait::async_trait;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use super::protocol::{FirewallRules, HelperError, HelperRequest, HelperResponse};
use super::wire::Wire;

pub struct HelperClient {
    wire: Wire,
}

impl HelperClient {
    pub async fn connect(socket: &Path) -> Result<Self, HelperError> {
        let stream = tokio::net::UnixStream::connect(socket).await?;
        Ok(Self {
            wire: Wire::new(stream),
        })
    }

    async fn call(
        &mut self,
        req: HelperRequest,
    ) -> Result<(HelperResponse, Vec<std::os::fd::OwnedFd>), HelperError> {
        let line = serde_json::to_string(&req).map_err(|e| HelperError::Protocol(e.to_string()))?;
        self.wire.write_line(&line).await?;
        let (line, fds) = self.wire.read_line().await?.ok_or(HelperError::Closed)?;
        let resp: HelperResponse =
            serde_json::from_str(&line).map_err(|e| HelperError::Protocol(e.to_string()))?;
        if let HelperResponse::Error { message } = resp {
            return Err(HelperError::Remote(message));
        }
        Ok((resp, fds))
    }

    async fn call_ok(&mut self, req: HelperRequest) -> Result<(), HelperError> {
        match self.call(req).await? {
            (HelperResponse::Ok, _) => Ok(()),
            (other, _) => Err(HelperError::Protocol(format!(
                "unexpected response {other:?}"
            ))),
        }
    }

    /// Ask the helper to create the interface and hand back its descriptor.
    pub async fn create_tun(&mut self, name: &str, mtu: u16) -> Result<avon_tun::Tun, HelperError> {
        let req = HelperRequest::CreateTun {
            name: name.to_string(),
            mtu,
        };
        let (resp, mut fds) = self.call(req).await?;
        match resp {
            HelperResponse::TunReady { name, mtu } => {
                let fd = if fds.is_empty() {
                    return Err(HelperError::Protocol(
                        "helper acknowledged the TUN without sending its descriptor".into(),
                    ));
                } else {
                    fds.remove(0)
                };
                avon_tun::Tun::from_owned_fd(fd, &name, mtu)
                    .map_err(|e| HelperError::Tun(e.to_string()))
            }
            other => Err(HelperError::Protocol(format!(
                "unexpected response {other:?}"
            ))),
        }
    }

    pub async fn configure(
        &mut self,
        v4: Ipv4Net,
        v6: Option<Ipv6Net>,
        mtu: u16,
        allowed_routes: &[IpNet],
    ) -> Result<(), HelperError> {
        self.call_ok(HelperRequest::Configure {
            v4: v4.to_string(),
            v6: v6.map(|n| n.to_string()),
            mtu,
            allowed_routes: allowed_routes.iter().map(|r| r.to_string()).collect(),
        })
        .await
    }

    pub async fn set_routes(&mut self, add: &[IpNet], remove: &[IpNet]) -> Result<(), HelperError> {
        self.call_ok(HelperRequest::SetRoutes {
            add: add.iter().map(|r| r.to_string()).collect(),
            remove: remove.iter().map(|r| r.to_string()).collect(),
        })
        .await
    }

    pub async fn apply_firewall(&mut self, rules: &FirewallRules) -> Result<(), HelperError> {
        self.call_ok(HelperRequest::ApplyFirewall {
            rules: rules.clone(),
        })
        .await
    }

    pub async fn clear_firewall(&mut self) -> Result<(), HelperError> {
        self.call_ok(HelperRequest::ClearFirewall).await
    }

    pub async fn shutdown(&mut self) -> Result<(), HelperError> {
        self.call_ok(HelperRequest::Shutdown).await
    }
}

/// A [`TunProvider`](avon_agent_core::traits::TunProvider) whose packet I/O runs
/// on the descriptor the helper handed over, and whose privileged operations go
/// back over the IPC. This is what the agent runs with when it is unprivileged.
pub struct HelperTun {
    tun: avon_tun::Tun,
    client: tokio::sync::Mutex<HelperClient>,
    allowed_routes: Vec<IpNet>,
}

impl HelperTun {
    /// Create the interface through `client` and keep the connection for later
    /// route and firewall changes.
    pub async fn create(
        mut client: HelperClient,
        name: &str,
        mtu: u16,
        allowed_routes: Vec<IpNet>,
    ) -> Result<Self, HelperError> {
        let tun = client.create_tun(name, mtu).await?;
        Ok(Self {
            tun,
            client: tokio::sync::Mutex::new(client),
            allowed_routes,
        })
    }

    pub async fn apply_firewall(&self, rules: &FirewallRules) -> Result<(), HelperError> {
        self.client.lock().await.apply_firewall(rules).await
    }

    pub async fn clear_firewall(&self) -> Result<(), HelperError> {
        self.client.lock().await.clear_firewall().await
    }
}

#[async_trait]
impl avon_tunnel::PacketSource for HelperTun {
    async fn next_packet(&self, buf: &mut Vec<u8>) -> Result<usize, avon_tunnel::TunnelError> {
        self.tun.next_packet(buf).await
    }
}

#[async_trait]
impl avon_tunnel::PacketSink for HelperTun {
    async fn deliver(&self, ip_packet: &[u8]) -> Result<(), avon_tunnel::TunnelError> {
        self.tun.deliver(ip_packet).await
    }
}

#[async_trait]
impl avon_agent_core::traits::TunProvider for HelperTun {
    async fn configure(
        &self,
        v4: Ipv4Net,
        v6: Ipv6Net,
        mtu: u16,
    ) -> Result<(), avon_agent_core::AgentError> {
        let allowed = if self.allowed_routes.is_empty() {
            vec![IpNet::V4(v4), IpNet::V6(v6)]
        } else {
            self.allowed_routes.clone()
        };
        self.client
            .lock()
            .await
            .configure(v4, Some(v6), mtu, &allowed)
            .await
            .map_err(|e| avon_agent_core::AgentError::Tun(e.to_string()))
    }

    async fn set_routes(&self, routes: &[IpNet]) -> Result<(), avon_agent_core::AgentError> {
        self.client
            .lock()
            .await
            .set_routes(routes, &[])
            .await
            .map_err(|e| avon_agent_core::AgentError::Tun(e.to_string()))
    }

    fn name(&self) -> &str {
        self.tun.name()
    }
}
