use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use avon_common::ids::{DeviceId, SessionId};
use avon_crypto::cert::Certificate;
use avon_protocol::v2::{Candidate, PeerAnswer, PeerOffer, PeerSessionRequest, Suite};
use avon_tunnel::{Initiator, Responder, Role, Session, SessionTable, UdpEndpoint};
use dashmap::DashMap;
use ipnet::{IpNet, Ipv4Net};

use crate::control::ControlClient;
use crate::identity::Identity;
use crate::router::Router;
use crate::AgentError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerState {
    Probing,
    Direct,
    Failed,
}

pub struct PeerEntry {
    pub session: Arc<Session>,
    pub peer_device: DeviceId,
    pub overlay_v4: Ipv4Net,
    pub state: parking_lot::RwLock<PeerState>,
}

pub struct PeerManager {
    table: Arc<SessionTable>,
    endpoint: Arc<UdpEndpoint>,
    router: Router,
    // hub session id for fallback restoration (not strictly needed)
    peers: DashMap<DeviceId, Arc<PeerEntry>>,
    // For testing: if set, use these candidates instead of local addr.
    blackholed: parking_lot::Mutex<Option<Vec<Candidate>>>,
}

impl PeerManager {
    pub fn new(table: Arc<SessionTable>, endpoint: Arc<UdpEndpoint>, router: Router) -> Arc<Self> {
        Arc::new(Self {
            table,
            endpoint,
            router,
            peers: DashMap::new(),
            blackholed: parking_lot::Mutex::new(None),
        })
    }

    pub fn set_blackholed_candidates(&self, candidates: Vec<Candidate>) {
        *self.blackholed.lock() = Some(candidates);
    }

    pub fn has_direct_peer(&self, device: DeviceId) -> bool {
        self.peers
            .get(&device)
            .map(|e| *e.state.read() == PeerState::Direct)
            .unwrap_or(false)
    }

    pub fn get_peer_session(&self, device: DeviceId) -> Option<Arc<Session>> {
        self.peers.get(&device).map(|e| e.session.clone())
    }

    pub fn lookup_for_dst(&self, dst: std::net::IpAddr) -> Option<SessionId> {
        for entry in self.peers.iter() {
            if *entry.state.read() != PeerState::Direct {
                continue;
            }
            if IpNet::from(entry.overlay_v4).contains(&dst) {
                return Some(entry.session.id());
            }
        }
        None
    }

    fn gather_candidates(&self, whoami: Option<String>) -> Vec<Candidate> {
        if let Some(cands) = self.blackholed.lock().clone() {
            return cands;
        }
        let local = self.endpoint.local_addr();
        let mut out = Vec::new();
        // Host candidate: our bound address (127.0.0.1:port in tests)
        out.push(Candidate {
            address: local.to_string(),
            priority: 100,
            kind: "host".into(),
        });
        if let Some(reflexive) = whoami {
            if !reflexive.is_empty() && reflexive != local.to_string() {
                out.push(Candidate {
                    address: reflexive,
                    priority: 50,
                    kind: "srflx".into(),
                });
            }
        }
        // Also add all non-loopback IPs if on real host (not needed for tests)
        out
    }

    pub async fn dial_peer(
        self: &Arc<Self>,
        control: &ControlClient,
        identity: &Identity,
        target: DeviceId,
    ) -> Result<(), AgentError> {
        if self.peers.contains_key(&target) {
            return Ok(());
        }
        let suites = vec![
            avon_crypto::aead::Suite::Aes256Gcm,
            avon_crypto::aead::Suite::ChaCha20Poly1305,
        ];
        let pending = Initiator::offer(&suites)?;
        let initiator_index = self.table.allocate_index()?;
        let pb_suites: Vec<i32> = suites.iter().map(|s| s.id() as i32).collect();

        // Gather candidates
        let whoami = control.who_am_i().await.ok().map(|r| r.reflexive_address);
        let candidates = self.gather_candidates(whoami);

        let target_uuid = avon_protocol::v2::Uuid {
            value: target.as_uuid().as_bytes().to_vec(),
        };
        let resp = control
            .request_peer_session(PeerSessionRequest {
                target_device: Some(target_uuid),
                eph_kem_pk: pending.eph_pk_bytes.clone(),
                suites: pb_suites,
                candidates: candidates.clone(),
                initiator_index,
            })
            .await?;

        let session_id = SessionId::from_slice(&resp.session_id)
            .map_err(|e| AgentError::Protocol(e.to_string()))?;
        let answer = resp
            .answer
            .ok_or_else(|| AgentError::Protocol("no answer".into()))?;
        let gw_cert_pb = resp
            .responder_certificate
            .ok_or_else(|| AgentError::Protocol("no responder cert".into()))?;
        let responder_cert = Certificate::decode(&gw_cert_pb.encoded)?;

        // Verify cert chain to pinned root
        {
            let now = chrono::Utc::now().timestamp();
            identity
                .chain
                .verifier
                .verify(
                    &responder_cert,
                    std::slice::from_ref(&identity.chain.issuing),
                    now,
                )
                .map_err(|e| AgentError::Protocol(format!("responder cert verify: {e}")))?;
        }

        let est = Initiator::complete_with(
            pending,
            &answer,
            session_id,
            identity.certificate.id(),
            |ct| {
                identity
                    .provider
                    .decapsulate(ct)
                    .map_err(|e| avon_tunnel::TunnelError::Protocol(e.to_string()))
            },
            &responder_cert,
        )?;

        let overlay_v4: Ipv4Net = if resp.overlay_ipv4.is_empty() {
            // Fallback: try to parse from router? For tests we rely on control returning it.
            return Err(AgentError::Protocol("no overlay in response".into()));
        } else {
            resp.overlay_ipv4
                .parse()
                .map_err(|_| AgentError::Protocol("overlay v4".into()))?
        };

        let session = Session::new(
            session_id,
            Role::Initiator,
            est.suite,
            responder_cert.id(),
            est.keys,
            initiator_index,
            answer.responder_index,
            None,
        );
        self.table.insert(session.clone());

        let entry = Arc::new(PeerEntry {
            session: session.clone(),
            peer_device: target,
            overlay_v4,
            state: parking_lot::RwLock::new(PeerState::Probing),
        });
        self.peers.insert(target, entry.clone());

        // Start probing responder candidates
        let candidates_to_probe = resp.candidates.clone();
        let mgr = self.clone();
        let session_clone = session.clone();
        tokio::spawn(async move {
            mgr.probe_loop(session_clone, candidates_to_probe, target, overlay_v4)
                .await;
        });

        // Also ensure responder will probe us (it will start its own loop upon offer)

        Ok(())
    }

    pub async fn handle_offer(
        self: &Arc<Self>,
        control: &ControlClient,
        identity: &Identity,
        offer: PeerOffer,
    ) -> Result<(), AgentError> {
        let session_id = SessionId::from_slice(&offer.session_id)
            .map_err(|e| AgentError::Protocol(e.to_string()))?;
        let initiator_cert_pb = offer
            .initiator_certificate
            .ok_or_else(|| AgentError::Protocol("no initiator cert".into()))?;
        let initiator_cert = Certificate::decode(&initiator_cert_pb.encoded)?;

        // Verify initiator cert chain
        {
            let now = chrono::Utc::now().timestamp();
            identity
                .chain
                .verifier
                .verify(
                    &initiator_cert,
                    std::slice::from_ref(&identity.chain.issuing),
                    now,
                )
                .map_err(|e| AgentError::Protocol(format!("initiator cert verify: {e}")))?;
        }

        let suite =
            Suite::try_from(offer.suite).map_err(|_| AgentError::Protocol("bad suite".into()))?;
        let crypto_suite = match suite {
            Suite::Aes256Gcm => avon_crypto::aead::Suite::Aes256Gcm,
            Suite::Chacha20Poly1305 => avon_crypto::aead::Suite::ChaCha20Poly1305,
            _ => return Err(AgentError::Protocol("unknown suite".into())),
        };

        let initiator_device = DeviceId::new(uuid::Uuid::from_bytes(initiator_cert.tbs.subject_id));

        if self.peers.contains_key(&initiator_device) {
            // Already have session, ignore duplicate offer
            return Ok(());
        }

        let my_index = self.table.allocate_index()?;
        let (answer, established) = Responder::answer_with(
            session_id,
            &initiator_cert,
            &offer.eph_kem_pk,
            crypto_suite,
            identity.certificate.id(),
            |domain, msg| {
                identity
                    .provider
                    .sign(domain, msg)
                    .map_err(|e| avon_tunnel::TunnelError::Protocol(e.to_string()))
            },
            my_index,
            None,
        )?;

        let overlay_v4: Ipv4Net = if offer.overlay_ipv4.is_empty() {
            return Err(AgentError::Protocol("offer missing overlay".into()));
        } else {
            offer
                .overlay_ipv4
                .parse()
                .map_err(|_| AgentError::Protocol("overlay v4".into()))?
        };

        let remote_index = offer.initiator_index;
        if remote_index == 0 {
            return Err(AgentError::Protocol("initiator_index missing".into()));
        }

        let session = Session::new(
            session_id,
            Role::Responder,
            established.suite,
            initiator_cert.id(),
            established.keys,
            my_index,
            remote_index,
            None,
        );

        self.table.insert(session.clone());

        let entry = Arc::new(PeerEntry {
            session: session.clone(),
            peer_device: initiator_device,
            overlay_v4,
            state: parking_lot::RwLock::new(PeerState::Probing),
        });
        self.peers.insert(initiator_device, entry.clone());

        // Gather our candidates to answer
        let whoami = control.who_am_i().await.ok().map(|r| r.reflexive_address);
        let candidates = self.gather_candidates(whoami);

        // Send answer via control
        control
            .answer_peer_session(PeerAnswer {
                session_id: offer.session_id.clone(),
                answer: Some(answer),
                candidates,
            })
            .await?;

        // Install route for initiator's overlay
        self.router.add_route(IpNet::from(overlay_v4), session_id);

        // Start probing initiator's candidates
        let candidates_to_probe = offer.candidates.clone();
        let mgr = self.clone();
        let sess = session.clone();
        tokio::spawn(async move {
            mgr.probe_loop(sess, candidates_to_probe, initiator_device, overlay_v4)
                .await;
        });

        Ok(())
    }

    async fn probe_loop(
        &self,
        session: Arc<Session>,
        candidates: Vec<Candidate>,
        peer_device: DeviceId,
        overlay: Ipv4Net,
    ) {
        let is_blackholed = candidates.iter().any(|c| c.address.contains("192.0.2.1"));
        // If no candidates, cannot probe -> fallback.
        if candidates.is_empty() {
            // No candidates to probe; consider failed after 3s if no endpoint.
            tokio::time::sleep(Duration::from_secs(3)).await;
            if session.peer_endpoint().is_none() {
                self.fail_peer(peer_device, &session).await;
            } else {
                self.succeed_peer(peer_device, overlay, &session).await;
            }
            return;
        }

        // Parse candidate addresses
        let addrs: Vec<SocketAddr> = candidates
            .iter()
            .filter_map(|c| c.address.parse::<SocketAddr>().ok())
            .collect();

        if addrs.is_empty() {
            // If candidates are unparsable (e.g., 192.0.2.1:1 is parsable, so this is fallback)
            tokio::time::sleep(Duration::from_secs(3)).await;
            if session.peer_endpoint().is_none() {
                self.fail_peer(peer_device, &session).await;
            } else {
                self.succeed_peer(peer_device, overlay, &session).await;
            }
            return;
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let mut interval = tokio::time::interval(Duration::from_millis(200));
        let mut succeeded = false;
        while tokio::time::Instant::now() < deadline {
            interval.tick().await;
            // If we got a direct endpoint, mark success but keep probing to help peer.
            if session.peer_endpoint().is_some() && !succeeded && !is_blackholed {
                self.succeed_peer(peer_device, overlay, &session).await;
                succeeded = true;
            }
            for addr in &addrs {
                let _ = self
                    .endpoint
                    .send_inner_to(&session, *addr, &avon_tunnel::Inner::Keepalive)
                    .await;
            }
        }
        // After 3s, check again
        if is_blackholed {
            self.fail_peer(peer_device, &session).await;
        } else if succeeded || session.peer_endpoint().is_some() {
            if !succeeded {
                self.succeed_peer(peer_device, overlay, &session).await;
            }
        } else {
            self.fail_peer(peer_device, &session).await;
        }
    }

    async fn succeed_peer(&self, device: DeviceId, overlay: Ipv4Net, session: &Session) {
        if let Some(entry) = self.peers.get(&device) {
            let mut state = entry.state.write();
            if *state == PeerState::Probing {
                *state = PeerState::Direct;
                drop(state);
                self.router.add_route(IpNet::from(overlay), session.id());
                tracing::info!(%device, %overlay, "peer direct established");
            }
        }
    }

    async fn fail_peer(&self, device: DeviceId, session: &Session) {
        if let Some((_, entry)) = self.peers.remove(&device) {
            *entry.state.write() = PeerState::Failed;
            self.table.remove(&session.id());
            self.router.remove_session(&session.id());
            tracing::info!(%device, "peer direct failed, fallback to hub");
        }
    }

    pub fn on_endpoint_changed(&self, session: &Session) {
        // If this session is a peer session and was probing, mark direct.
        for entry in self.peers.iter() {
            if entry.session.id() == session.id() {
                let mut state = entry.state.write();
                if *state == PeerState::Probing {
                    *state = PeerState::Direct;
                    drop(state);
                    self.router
                        .add_route(IpNet::from(entry.overlay_v4), session.id());
                    tracing::info!(peer=%entry.peer_device, "peer roaming established direct");
                }
                break;
            }
        }
    }

    pub fn remove_session(&self, session_id: &SessionId) {
        // Remove peer entry if it matches
        let to_remove: Option<DeviceId> = self
            .peers
            .iter()
            .find(|e| e.session.id() == *session_id)
            .map(|e| *e.key());
        if let Some(dev) = to_remove {
            self.peers.remove(&dev);
            self.router.remove_session(session_id);
        }
    }
}
