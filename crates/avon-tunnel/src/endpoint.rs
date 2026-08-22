use std::net::SocketAddr;
use std::sync::Arc;

use avon_crypto::session::Role;
use avon_protocol::v2::TunnelFrame;
use prost::Message;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::header::{max_udp_payload, Header};
use crate::inner::Inner;
use crate::session::Session;
use crate::table::SessionTable;
use crate::timers::TimerConfig;
use crate::TunnelError;

pub struct EndpointConfig {
    pub bind: SocketAddr,
    pub overlay_mtu: u16,
    pub timers: TimerConfig,
}

#[derive(Debug)]
pub enum EndpointEvent {
    Control {
        session: Arc<Session>,
        frame: TunnelFrame,
    },
    Ip {
        session: Arc<Session>,
        packet: Vec<u8>,
    },
    RekeyDue(Arc<Session>),
    Idle(Arc<Session>),
    PeerEndpointChanged {
        session: Arc<Session>,
        endpoint: SocketAddr,
    },
}

/// One UDP socket for every session this process owns. Sessions are found by
/// receiver index, so a single socket serves any number of peers.
pub struct UdpEndpoint {
    socket: UdpSocket,
    table: Arc<SessionTable>,
    cfg: EndpointConfig,
    local_addr: SocketAddr,
}

impl UdpEndpoint {
    pub async fn bind(
        cfg: EndpointConfig,
        table: Arc<SessionTable>,
    ) -> Result<Arc<Self>, TunnelError> {
        let socket = UdpSocket::bind(cfg.bind).await?;
        let local_addr = socket.local_addr()?;
        Ok(Arc::new(Self {
            socket,
            table,
            cfg,
            local_addr,
        }))
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    pub fn table(&self) -> &Arc<SessionTable> {
        &self.table
    }

    pub async fn send_inner(
        &self,
        session: &Session,
        inner: &Inner<'_>,
    ) -> Result<(), TunnelError> {
        let peer = session
            .peer_endpoint()
            .ok_or_else(|| TunnelError::Protocol("peer endpoint unknown".into()))?;
        self.send_inner_to(session, peer, inner).await
    }

    pub async fn send_inner_to(
        &self,
        session: &Session,
        peer: SocketAddr,
        inner: &Inner<'_>,
    ) -> Result<(), TunnelError> {
        let mut dgram = Vec::with_capacity(max_udp_payload(self.cfg.overlay_mtu));
        session.seal(inner, &mut dgram)?;
        self.socket.send_to(&dgram, peer).await?;
        Ok(())
    }

    pub async fn send_frame(
        &self,
        session: &Session,
        frame: &TunnelFrame,
    ) -> Result<(), TunnelError> {
        let bytes = frame.encode_to_vec();
        self.send_inner(session, &Inner::Control(&bytes)).await
    }

    /// Spawn the receive and timer loops; the owner handles the events.
    pub fn run(self: Arc<Self>) -> mpsc::Receiver<EndpointEvent> {
        let (tx, rx) = mpsc::channel(1024);
        tokio::spawn(self.clone().recv_loop(tx.clone()));
        tokio::spawn(self.timer_loop(tx));
        rx
    }

    async fn recv_loop(self: Arc<Self>, tx: mpsc::Sender<EndpointEvent>) {
        let mut buf = vec![0u8; max_udp_payload(self.cfg.overlay_mtu) + 64];
        let mut scratch = Vec::with_capacity(max_udp_payload(self.cfg.overlay_mtu));
        loop {
            let (len, from) = match self.socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "udp recv");
                    continue;
                }
            };
            metrics::counter!("avon_tunnel_packets_received_total").increment(1);
            // Header first: a malformed or non-data packet never reaches a key.
            let (header, body) = match Header::decode(&buf[..len]) {
                Ok(v) => v,
                Err(_) => {
                    metrics::counter!("avon_tunnel_packets_dropped_total", "reason" => "header")
                        .increment(1);
                    continue;
                }
            };
            let Some(session) = self.table.by_index(header.receiver_index) else {
                metrics::counter!("avon_tunnel_packets_dropped_total", "reason" => "unknown_index")
                    .increment(1);
                continue;
            };
            let inner = match session.open(&header, body, &mut scratch) {
                Ok(i) => i,
                Err(TunnelError::Replay) => continue,
                Err(_) => {
                    metrics::counter!("avon_tunnel_packets_dropped_total", "reason" => "auth")
                        .increment(1);
                    continue;
                }
            };
            // Only a packet that authenticated may move the peer's endpoint.
            if session.peer_endpoint() != Some(from) {
                session.set_peer_endpoint(from);
                let _ = tx
                    .send(EndpointEvent::PeerEndpointChanged {
                        session: session.clone(),
                        endpoint: from,
                    })
                    .await;
            }
            match inner {
                Inner::Ip(p) => {
                    let _ = tx
                        .send(EndpointEvent::Ip {
                            session: session.clone(),
                            packet: p.to_vec(),
                        })
                        .await;
                }
                Inner::Control(f) => match TunnelFrame::decode(f) {
                    Ok(frame) => {
                        let _ = tx
                            .send(EndpointEvent::Control {
                                session: session.clone(),
                                frame,
                            })
                            .await;
                    }
                    Err(_) => {
                        metrics::counter!("avon_tunnel_packets_dropped_total", "reason" => "frame")
                            .increment(1)
                    }
                },
                Inner::Keepalive => {}
            }
        }
    }

    async fn timer_loop(self: Arc<Self>, tx: mpsc::Sender<EndpointEvent>) {
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(100));
        loop {
            tick.tick().await;
            for session in self.table.iter() {
                if session.is_closed() {
                    continue;
                }
                if let Some(idx) = session.expire_previous_epoch(self.cfg.timers.epoch_overlap) {
                    self.table.release_index(idx);
                }
                if session.idle_for() >= self.cfg.timers.idle_timeout {
                    let _ = tx.send(EndpointEvent::Idle(session.clone())).await;
                    continue;
                }
                // Only the initiator drives rekey, and only once per epoch:
                // the flag is cleared by `rotate`.
                if session.role() == Role::Initiator
                    && !session.rekey_pending()
                    && (session.epoch_age() >= self.cfg.timers.rekey_after
                        || session.packets_sent_this_epoch() >= self.cfg.timers.rekey_after_packets)
                {
                    session.set_rekey_pending(true);
                    let _ = tx.send(EndpointEvent::RekeyDue(session.clone())).await;
                }
                if session.peer_endpoint().is_some()
                    && session.since_last_tx() >= self.cfg.timers.keepalive
                {
                    if let Err(e) = self.send_inner(&session, &Inner::Keepalive).await {
                        tracing::debug!(error = %e, "keepalive send failed");
                    }
                }
            }
        }
    }
}
