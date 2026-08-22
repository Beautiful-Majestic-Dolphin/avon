use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::control::ControlClient;
use crate::identity::Identity;
use crate::router::Router;
use crate::session_manager::SessionManager;
use crate::status::StatusHandle;
use crate::traits::{PostureProvider, TunProvider};
use crate::AgentError;
use avon_protocol::v2::{pulse_down, pulse_up, PulseDown, PulseHeartbeat, PulseUp};
use avon_tunnel::{EndpointConfig, SessionTable, TimerConfig, UdpEndpoint};

pub struct AgentCoreConfig {
    pub control: String,
    pub pulse_interval: Duration,
    pub timers: TimerConfig,
    pub overlay_mtu: u16,
    pub bind: SocketAddr,
    pub suites: Vec<avon_crypto::aead::Suite>,
}

impl Default for AgentCoreConfig {
    fn default() -> Self {
        Self {
            control: "https://localhost:8443".into(),
            pulse_interval: Duration::from_secs(10),
            timers: TimerConfig::default(),
            overlay_mtu: 1280,
            bind: SocketAddr::from(([0, 0, 0, 0], 0)),
            suites: vec![
                avon_crypto::aead::Suite::Aes256Gcm,
                avon_crypto::aead::Suite::ChaCha20Poly1305,
            ],
        }
    }
}

pub struct Agent {
    cfg: AgentCoreConfig,
    identity: Arc<Identity>,
    tun: Arc<dyn TunProvider>,
    posture: Arc<dyn PostureProvider>,
    status: StatusHandle,
}

impl Agent {
    pub fn new(
        cfg: AgentCoreConfig,
        identity: Identity,
        tun: Arc<dyn TunProvider>,
        posture: Arc<dyn PostureProvider>,
    ) -> Self {
        let status = StatusHandle::new(identity.device_id, identity.certificate.tbs.not_after);
        status.set_state("enrolled");
        Self {
            cfg,
            identity: Arc::new(identity),
            tun,
            posture,
            status,
        }
    }

    pub fn status_handle(&self) -> StatusHandle {
        self.status.clone()
    }

    pub async fn run(
        self,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), AgentError> {
        avon_tls::install_default_provider();

        // Bind endpoint.
        let table = Arc::new(SessionTable::new());
        let endpoint = UdpEndpoint::bind(
            EndpointConfig {
                bind: self.cfg.bind,
                overlay_mtu: self.cfg.overlay_mtu,
                timers: self.cfg.timers.clone(),
            },
            table.clone(),
        )
        .await?;
        let router = Router::new();
        let session_mgr = SessionManager::new(
            endpoint.clone(),
            table.clone(),
            router,
            self.cfg.timers.clone(),
        );
        let session_mgr = Arc::new(session_mgr);

        // Event stream from endpoint.
        let mut events = endpoint.clone().run();

        let mut shutdown = Box::pin(shutdown);
        let mut hub_need_open = true;
        let mut control: Option<Arc<ControlClient>> = None;
        let mut pulse_tx: Option<tokio::sync::mpsc::Sender<PulseUp>> = None;
        let mut pulse_rx: Option<tonic::Streaming<PulseDown>> = None;
        let mut backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(30);
        let mut pulse_interval = tokio::time::interval(self.cfg.pulse_interval);
        // Tun packet buffer for forwarding.
        let tun = self.tun.clone();
        let posture = self.posture.clone();
        let status = self.status.clone();
        let cfg_control = self.cfg.control.clone();
        let identity = self.identity.clone();

        // Spawn tun -> tunnel forwarder as independent task that watches hub session via router.
        // Instead we will handle tun packets in the main loop via a channel.
        let (tun_pkt_tx, mut tun_pkt_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(128);
        {
            let tun = tun.clone();
            let mgr = session_mgr.clone();
            tokio::spawn(async move {
                let mut buf = Vec::with_capacity(2048);
                while let Ok(n) = tun.next_packet(&mut buf).await {
                    let pkt = buf[..n].to_vec();
                    // Try to forward; if no route, drop.
                    let _ = mgr.forward_from_tun(&pkt).await;
                    // Also forward to main loop for status? Not needed.
                    let _ = tun_pkt_tx.send(pkt).await;
                }
            });
        }

        status.set_state("connecting");

        loop {
            // Handle control connection if needed.
            if hub_need_open || control.is_none() {
                // Try to connect and authenticate if we don't have control.
                if control.is_none() {
                    status.set_state("connecting");
                    match ControlClient::connect(&identity, &cfg_control).await {
                        Ok(c) => match c.authenticate(&identity).await {
                            Ok(()) => {
                                status.set_state("authenticated");
                                let ctrl = Arc::new(c);
                                // Open hub session.
                                match session_mgr.open_hub_session(&ctrl, &identity).await {
                                    Ok(info) => {
                                        // Configure tun.
                                        if let Err(e) = tun
                                            .configure(
                                                info.overlay_v4,
                                                info.overlay_v6,
                                                self.cfg.overlay_mtu,
                                            )
                                            .await
                                        {
                                            tracing::warn!(error = %e, "tun configure failed");
                                        }
                                        if let Err(e) = tun.set_routes(&info.routes).await {
                                            tracing::warn!(error = %e, "set routes failed");
                                        }
                                        status.set_connected(
                                            Some(info.overlay_v4.to_string()),
                                            Some(info.overlay_v6.to_string()),
                                            Some(info.session_id),
                                            Some(info.session.epoch()),
                                            Some(info.gateway_endpoint.to_string()),
                                        );
                                        // Start pulse.
                                        match ctrl.pulse().await {
                                            Ok((tx, rx)) => {
                                                pulse_tx = Some(tx);
                                                pulse_rx = Some(rx);
                                                // Send initial heartbeat.
                                                if let Some(tx) = pulse_tx.as_ref() {
                                                    let hb = PulseHeartbeat {
                                                        posture: Some(posture.collect()),
                                                        sessions: vec![],
                                                    };
                                                    let _ = tx
                                                        .send(PulseUp {
                                                            msg: Some(pulse_up::Msg::Heartbeat(hb)),
                                                        })
                                                        .await;
                                                }
                                            }
                                            Err(e) => {
                                                tracing::warn!(error = %e, "pulse start failed");
                                            }
                                        }
                                        control = Some(ctrl);
                                        hub_need_open = false;
                                        backoff = Duration::from_secs(1);
                                        // Nudge pulse interval to fire soon.
                                        pulse_interval.reset();
                                    }
                                    Err(e) => {
                                        tracing::warn!(error = %e, "open hub failed");
                                        tokio::time::sleep(backoff).await;
                                        backoff = (backoff * 2).min(max_backoff);
                                        control = Some(ctrl);
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "authenticate failed");
                                tokio::time::sleep(backoff).await;
                                backoff = (backoff * 2).min(max_backoff);
                            }
                        },
                        Err(e) => {
                            tracing::warn!(error = %e, "control connect failed");
                            tokio::time::sleep(backoff).await;
                            backoff = (backoff * 2).min(max_backoff);
                        }
                    }
                } else if hub_need_open {
                    // We have control but hub is gone: try to reopen.
                    if let Some(ctrl) = control.clone() {
                        match session_mgr.open_hub_session(&ctrl, &identity).await {
                            Ok(info) => {
                                if let Err(e) = tun
                                    .configure(
                                        info.overlay_v4,
                                        info.overlay_v6,
                                        self.cfg.overlay_mtu,
                                    )
                                    .await
                                {
                                    tracing::warn!(error = %e, "tun configure failed");
                                }
                                if let Err(e) = tun.set_routes(&info.routes).await {
                                    tracing::warn!(error = %e, "set routes failed");
                                }
                                status.set_connected(
                                    Some(info.overlay_v4.to_string()),
                                    Some(info.overlay_v6.to_string()),
                                    Some(info.session_id),
                                    Some(info.session.epoch()),
                                    Some(info.gateway_endpoint.to_string()),
                                );
                                hub_need_open = false;
                                backoff = Duration::from_secs(1);
                            }
                            Err(e) => {
                                tracing::debug!(error = %e, "hub reopen failed");
                                tokio::time::sleep(Duration::from_millis(500)).await;
                            }
                        }
                    }
                }
            }

            tokio::select! {
                _ = &mut shutdown => {
                    // Graceful close
                    session_mgr.close_all("shutdown").await;
                    if let Some(ctrl) = control.as_ref() {
                        for s in session_mgr.table.iter() {
                            let _ = ctrl.report(avon_protocol::v2::SessionReport {
                                session_id: s.id().to_vec(),
                                event: "closed".into(),
                                reason: "shutdown".into(),
                            }).await;
                        }
                    }
                    break;
                }
                // Endpoint events
                ev = events.recv() => {
                    if let Some(ev) = ev {
                        // Capture if this was a hub session closure before handling.
                        let was_hub = match &ev {
                            avon_tunnel::EndpointEvent::Control { session, frame } => {
                                // Check if this is a Close for hub
                                if let Some(avon_protocol::v2::tunnel_frame::Msg::Close(_)) = frame.msg.as_ref() {
                                    session_mgr.hub.read().await.as_ref().map(|h| h.id() == session.id()).unwrap_or(false)
                                } else { false }
                            }
                            avon_tunnel::EndpointEvent::Idle(session) => {
                                session_mgr.hub.read().await.as_ref().map(|h| h.id() == session.id()).unwrap_or(false)
                            }
                            _ => false,
                        };
                        let _ = session_mgr.handle_event(ev, tun.as_ref()).await;
                        // Update status for hub epoch/bytes.
                        if let Some(h) = session_mgr.hub.read().await.clone() {
                            status.set_epoch(h.epoch());
                            status.set_bytes(
                                h.stats().bytes_tx.load(std::sync::atomic::Ordering::Relaxed),
                                h.stats().bytes_rx.load(std::sync::atomic::Ordering::Relaxed),
                            );
                        }
                        // If hub was closed, mark degraded and need reopen.
                        if (was_hub || session_mgr.hub.read().await.is_none())
                            && session_mgr.hub.read().await.is_none()
                        {
                            status.clear_session();
                            status.set_degraded();
                            hub_need_open = true;
                        }
                    }
                }
                // Pulse down messages
                msg = async {
                    if let Some(rx) = pulse_rx.as_mut() {
                        rx.message().await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    match msg {
                        Ok(Some(down)) => {
                            match down.msg {
                                Some(pulse_down::Msg::Ack(ack)) => {
                                    status.set_last_pulse(ack.server_time_unix);
                                    if status.snapshot().state != "connected" {
                                        status.set_state("connected");
                                    }
                                }
                                Some(pulse_down::Msg::Close(c)) => {
                                    if let Ok(id) = avon_common::ids::SessionId::from_slice(&c.session_id) {
                                        session_mgr.table.remove(&id);
                                        session_mgr.router.remove_session(&id);
                                        if session_mgr.hub.read().await.as_ref().map(|h| h.id() == id).unwrap_or(false) {
                                            *session_mgr.hub.write().await = None;
                                            status.clear_session();
                                            hub_need_open = true;
                                        }
                                    }
                                }
                                Some(pulse_down::Msg::Routes(update)) => {
                                    if let Ok(id) = avon_common::ids::SessionId::from_slice(&update.session_id) {
                                        if update.remove {
                                            for cidr in update.cidrs {
                                                if let Ok(net) = cidr.parse::<ipnet::IpNet>() {
                                                    session_mgr.router.inner().remove(net);
                                                }
                                            }
                                        } else {
                                            for cidr in update.cidrs {
                                                if let Ok(net) = cidr.parse::<ipnet::IpNet>() {
                                                    session_mgr.router.inner().insert(net, id);
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        Ok(None) => {
                            // Stream closed.
                            tracing::info!("pulse stream closed");
                            pulse_tx = None;
                            pulse_rx = None;
                            status.set_degraded();
                            // Trigger reconnect if control likely dead.
                            // Try to keep control but re-pulse next loop will attempt.
                            // If control channel itself is dead, next open_hub will fail and we'll reconnect.
                            // Mark control as potentially stale; keep it but will test pulse re-establish.
                            // For now, keep control and try to re-pulse in next iteration.
                            // If re-pulse fails, we'll go to full reconnect.
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "pulse error");
                            pulse_tx = None;
                            pulse_rx = None;
                            status.set_degraded();
                        }
                    }
                }
                // Pulse heartbeat tick
                _ = pulse_interval.tick(), if pulse_tx.is_some() => {
                    let hb = PulseHeartbeat {
                        posture: Some(posture.collect()),
                        sessions: {
                            let hub = session_mgr.hub.read().await.clone();
                            if let Some(h) = hub {
                                vec![avon_protocol::v2::SessionStats {
                                    session_id: h.id().to_vec(),
                                    bytes_tx: h.stats().bytes_tx.load(std::sync::atomic::Ordering::Relaxed),
                                    bytes_rx: h.stats().bytes_rx.load(std::sync::atomic::Ordering::Relaxed),
                                    epoch: h.epoch(),
                                }]
                            } else { vec![] }
                        },
                    };
                    if let Some(tx) = pulse_tx.as_ref() {
                        if tx.send(PulseUp { msg: Some(pulse_up::Msg::Heartbeat(hb)) }).await.is_err() {
                            pulse_tx = None;
                            pulse_rx = None;
                            status.set_degraded();
                        }
                    }
                }
                // Tun packets already handled in background task; this branch handles the channel for completeness
                pkt = tun_pkt_rx.recv() => {
                    if let Some(_pkt) = pkt {
                        // Already forwarded in background task; just update bytes if needed.
                        if let Some(h) = session_mgr.hub.read().await.clone() {
                            status.set_bytes(
                                h.stats().bytes_tx.load(std::sync::atomic::Ordering::Relaxed),
                                h.stats().bytes_rx.load(std::sync::atomic::Ordering::Relaxed),
                            );
                        }
                    }
                }
            }

            // If pulse is gone but control is still present, try to re-establish pulse.
            if control.is_some() && pulse_tx.is_none() && !hub_need_open {
                // Attempt to re-pulse; if it fails, mark control for reconnect.
                if let Some(ctrl) = control.clone() {
                    match ctrl.pulse().await {
                        Ok((tx, rx)) => {
                            pulse_tx = Some(tx);
                            pulse_rx = Some(rx);
                            status.set_state("connected");
                            // Send heartbeat.
                            if let Some(tx) = pulse_tx.as_ref() {
                                let hb = PulseHeartbeat {
                                    posture: Some(posture.collect()),
                                    sessions: vec![],
                                };
                                let _ = tx
                                    .send(PulseUp {
                                        msg: Some(pulse_up::Msg::Heartbeat(hb)),
                                    })
                                    .await;
                            }
                        }
                        Err(_) => {
                            // Control likely down.
                            control = None;
                            hub_need_open = true; // will trigger full reconnect including control.
                            status.set_degraded();
                            tokio::time::sleep(backoff).await;
                            backoff = (backoff * 2).min(max_backoff);
                        }
                    }
                }
            }

            // If hub is gone but control is present, ensure we try to reopen quickly.
            // This is already handled by hub_need_open flag and the top of loop.
            // But we also handle the case where hub was cleared via pulse close etc.
            if control.is_some() && session_mgr.hub.read().await.is_none() {
                hub_need_open = true;
            }
        }

        Ok(())
    }
}
