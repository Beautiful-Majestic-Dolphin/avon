use std::net::SocketAddr;
use std::sync::Arc;

use avon_common::ids::SessionId;
use avon_crypto::cert::Certificate;
use avon_protocol::v2::{tunnel_frame, Close, Rekey, TunnelFrame};
use avon_tunnel::{
    EndpointEvent, Inner, PacketSink, Role, Session, SessionTable, TimerConfig, UdpEndpoint,
};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use tokio::sync::RwLock;

use crate::control::ControlClient;
use crate::identity::Identity;
use crate::router::Router;
use crate::AgentError;

pub struct HubInfo {
    pub session_id: SessionId,
    pub overlay_v4: Ipv4Net,
    pub overlay_v6: Ipv6Net,
    pub routes: Vec<IpNet>,
    pub gateway_endpoint: SocketAddr,
    pub session: Arc<Session>,
}

pub struct SessionManager {
    pub endpoint: Arc<UdpEndpoint>,
    pub table: Arc<SessionTable>,
    pub router: Router,
    pub hub: RwLock<Option<Arc<Session>>>,
    // Pending rekey: (ephemeral keypair, new local index)
    pending_rekey: parking_lot::Mutex<Option<(avon_crypto::hybrid::kem::HybridKemKeyPair, u32)>>,
}

impl SessionManager {
    pub fn new(
        endpoint: Arc<UdpEndpoint>,
        table: Arc<SessionTable>,
        router: Router,
        _timers: TimerConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            endpoint,
            table,
            router,
            hub: RwLock::new(None),
            pending_rekey: parking_lot::Mutex::new(None),
        })
    }

    pub async fn open_hub_session(
        &self,
        control: &ControlClient,
        identity: &Identity,
    ) -> Result<HubInfo, AgentError> {
        // Offer suites: prefer AES then ChaCha
        let suites = vec![
            avon_crypto::aead::Suite::Aes256Gcm,
            avon_crypto::aead::Suite::ChaCha20Poly1305,
        ];
        let pending = avon_tunnel::Initiator::offer(&suites)?;
        let initiator_index = self.table.allocate_index()?;
        let pb_suites: Vec<i32> = suites.iter().map(|s| s.id() as i32).collect();
        let resp = control
            .open_session(avon_protocol::v2::OpenSessionRequest {
                eph_kem_pk: pending.eph_pk_bytes.clone(),
                suites: pb_suites,
                wants_overlay_ip: true,
                initiator_index,
            })
            .await?;

        let session_id = SessionId::from_slice(&resp.session_id)
            .map_err(|e| AgentError::Protocol(e.to_string()))?;
        let answer = resp
            .answer
            .ok_or_else(|| AgentError::Protocol("no answer".into()))?;
        let gw_cert_pb = resp
            .gateway_certificate
            .ok_or_else(|| AgentError::Protocol("no gateway cert".into()))?;
        let gw_cert = Certificate::decode(&gw_cert_pb.encoded)?;

        // Verify the answer against the gateway cert (and also check chain to pinned root).
        // The gateway cert itself must chain to our pinned root.
        {
            let now = chrono::Utc::now().timestamp();
            identity
                .chain
                .verifier
                .verify(&gw_cert, std::slice::from_ref(&identity.chain.issuing), now)
                .map_err(|e| AgentError::Protocol(format!("gateway cert verify: {e}")))?;
        }

        let est = avon_tunnel::Initiator::complete(
            pending,
            &answer,
            session_id,
            identity.certificate.id(),
            identity.provider.kem(),
            &gw_cert,
        )?;

        let gateway_endpoint: SocketAddr = answer
            .responder_endpoint
            .parse()
            .map_err(|_| AgentError::Protocol("bad responder endpoint".into()))?;

        let session = Session::new(
            session_id,
            Role::Initiator,
            est.suite,
            gw_cert.id(),
            est.keys,
            initiator_index,
            answer.responder_index,
            Some(gateway_endpoint),
        );
        self.table.insert(session.clone());
        *self.hub.write().await = Some(session.clone());

        // Install routes from the response.
        let mut routes = vec![];
        for ru in &resp.routes {
            for cidr in &ru.cidrs {
                if let Ok(net) = cidr.parse::<IpNet>() {
                    routes.push(net);
                }
            }
        }
        self.router.set_routes(&routes, session_id);

        // Parse overlay addresses.
        let overlay_v4: Ipv4Net = resp
            .overlay_ipv4
            .parse()
            .map_err(|_| AgentError::Protocol("overlay v4".into()))?;
        let overlay_v6: Ipv6Net = resp
            .overlay_ipv6
            .parse()
            .map_err(|_| AgentError::Protocol("overlay v6".into()))?;

        // Nudge gateway to learn our endpoint.
        let _ = self.endpoint.send_inner(&session, &Inner::Keepalive).await;

        // Also store gateway cert for status display? Not needed.

        Ok(HubInfo {
            session_id,
            overlay_v4,
            overlay_v6,
            routes,
            gateway_endpoint,
            session,
        })
    }

    pub async fn handle_event(
        &self,
        ev: EndpointEvent,
        tun: &dyn PacketSink,
    ) -> Result<(), AgentError> {
        match ev {
            EndpointEvent::Ip { session, packet } => {
                // Deliver to TUN.
                let _ = tun.deliver(&packet).await;
                // Update metrics? not needed.
                drop(session);
            }
            EndpointEvent::Control { session, frame } => match frame.msg {
                Some(tunnel_frame::Msg::RekeyAck(ack)) => {
                    let pending = self.pending_rekey.lock().take();
                    if let Some((eph, new_local)) = pending {
                        if let Ok(next) = session.complete_rekey(&eph, &ack.ct) {
                            session.rotate(next, new_local, ack.new_index);
                            self.table.rebind_index(&session, new_local);
                        }
                    }
                }
                Some(tunnel_frame::Msg::Close(c)) => {
                    self.router.remove_session(&session.id());
                    self.table.remove(&session.id());
                    let mut hub = self.hub.write().await;
                    if hub
                        .as_ref()
                        .map(|h| h.id() == session.id())
                        .unwrap_or(false)
                    {
                        *hub = None;
                    }
                    drop(c);
                }
                _ => {}
            },
            EndpointEvent::RekeyDue(session) => {
                // Initiate rekey.
                let (eph, pk) = match avon_tunnel::rekey_offer() {
                    Ok(v) => v,
                    Err(_) => {
                        session.set_rekey_pending(false);
                        return Ok(());
                    }
                };
                let new_index = match self.table.allocate_index() {
                    Ok(v) => v,
                    Err(_) => {
                        session.set_rekey_pending(false);
                        return Ok(());
                    }
                };
                let frame = TunnelFrame {
                    msg: Some(tunnel_frame::Msg::Rekey(Rekey {
                        new_epoch: session.epoch() + 1,
                        eph_kem_pk: pk,
                        new_index,
                    })),
                };
                if self.endpoint.send_frame(&session, &frame).await.is_ok() {
                    *self.pending_rekey.lock() = Some((eph, new_index));
                } else {
                    session.set_rekey_pending(false);
                }
            }
            EndpointEvent::Idle(session) => {
                self.router.remove_session(&session.id());
                self.table.remove(&session.id());
                let mut hub = self.hub.write().await;
                if hub
                    .as_ref()
                    .map(|h| h.id() == session.id())
                    .unwrap_or(false)
                {
                    *hub = None;
                }
            }
            EndpointEvent::PeerEndpointChanged { .. } => {}
        }
        Ok(())
    }

    pub async fn forward_from_tun(&self, packet: &[u8]) -> Result<(), AgentError> {
        // Parse dst.
        let dst =
            parse_dst(packet).ok_or_else(|| AgentError::Protocol("malformed packet".into()))?;
        let sid = self
            .router
            .lookup(dst)
            .ok_or_else(|| AgentError::Protocol("no route".into()))?;
        let session = self
            .table
            .by_id(&sid)
            .ok_or_else(|| AgentError::Protocol("no session".into()))?;
        self.endpoint
            .send_inner(&session, &Inner::Ip(packet))
            .await?;
        Ok(())
    }

    pub async fn hub_session(&self) -> Option<Arc<Session>> {
        self.hub.read().await.clone()
    }

    pub async fn close_all(&self, reason: &str) {
        let sessions = self.table.iter();
        for s in sessions {
            let frame = TunnelFrame {
                msg: Some(tunnel_frame::Msg::Close(Close {
                    reason: reason.to_string(),
                })),
            };
            let _ = self.endpoint.send_frame(&s, &frame).await;
            self.router.remove_session(&s.id());
            self.table.remove(&s.id());
        }
        *self.hub.write().await = None;
    }
}

fn parse_dst(packet: &[u8]) -> Option<std::net::IpAddr> {
    let version = packet.first()? >> 4;
    match version {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            Some(std::net::IpAddr::from([
                packet[16], packet[17], packet[18], packet[19],
            ]))
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let mut d = [0u8; 16];
            d.copy_from_slice(&packet[24..40]);
            Some(std::net::IpAddr::from(d))
        }
        _ => None,
    }
}
