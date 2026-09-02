//! Everything the control link and the data plane share.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use avon_common::ids::{DeviceId, GatewayId, SessionId, TenantId};
use avon_crypto::cert::crl::Crl;
use avon_crypto::cert::{Certificate, ChainVerifier};
use avon_crypto::hybrid::signature::HybridSigningKeyPair;
use avon_protocol::v2::{gateway_up, GatewayUp, SessionEvent};
use avon_tunnel::{SessionTable, UdpEndpoint};
use dashmap::DashMap;
use ipnet::IpNet;
use tokio::sync::{mpsc, RwLock};

use crate::decision_log;
use crate::policy_hook::{CedarFlowPolicy, FlowPolicy};
use crate::routes::RouteTable;

/// The trust material the gateway validates device certificates against.
/// Replaced wholesale when control pushes a new CRL.
pub struct ChainCache {
    pub root: Certificate,
    pub issuing: Certificate,
    pub verifier: ChainVerifier,
    pub crl: Crl,
}

impl ChainCache {
    pub fn is_revoked(&self, serial: &[u8; 16]) -> bool {
        self.crl.serials.contains(serial)
    }
}

/// What the gateway remembers about a session beyond its keys: enough to
/// validate sources, route to it, and report it.
#[derive(Clone, Debug)]
pub struct SessionMeta {
    pub device_id: DeviceId,
    pub tenant: TenantId,
    pub serial: [u8; 16],
    pub overlay_v4: Option<IpNet>,
    pub overlay_v6: Option<IpNet>,
    pub advertised: Vec<IpNet>,
}

impl SessionMeta {
    /// A session may only source packets from its own overlay addresses or
    /// from the networks it advertises. Anything else is spoofed.
    pub fn owns_source(&self, src: IpAddr) -> bool {
        if self.overlay_v4.map(|n| n.addr()) == Some(src)
            || self.overlay_v6.map(|n| n.addr()) == Some(src)
        {
            return true;
        }
        self.advertised.iter().any(|n| n.contains(&src))
    }

    /// The routes that reach this session: its own addresses as hosts, plus
    /// whatever it advertises.
    pub fn routes(&self) -> Vec<IpNet> {
        let mut v = Vec::with_capacity(2 + self.advertised.len());
        if let Some(n) = self.overlay_v4 {
            if let Ok(host) = IpNet::new(n.addr(), 32) {
                v.push(host);
            }
        }
        if let Some(n) = self.overlay_v6 {
            if let Ok(host) = IpNet::new(n.addr(), 128) {
                v.push(host);
            }
        }
        v.extend(self.advertised.iter().copied());
        v
    }
}

pub struct GatewayState {
    pub id: GatewayId,
    pub table: Arc<SessionTable>,
    pub endpoint: Arc<UdpEndpoint>,
    pub routes: RouteTable,
    pub policy: RwLock<Arc<CedarFlowPolicy>>,
    pub signing: HybridSigningKeyPair,
    pub cert: Certificate,
    pub chain: RwLock<ChainCache>,
    pub sessions_meta: DashMap<SessionId, SessionMeta>,
    /// The tenant overlay pools. A destination inside them belongs to some
    /// session; a destination outside them is somebody else's network and goes
    /// out the TUN for the kernel to route.
    pub overlay_prefixes: Vec<IpNet>,
    pub public_endpoint: String,
    /// Set once the control link is up; session events are reported through it.
    pub up: RwLock<Option<mpsc::Sender<GatewayUp>>>,
    pub redis: RwLock<Option<redis::aio::ConnectionManager>>,
}

impl GatewayState {
    /// Load the identity `avon-bootstrap` wrote, bind the tunnel socket, fetch
    /// the trust chain from control, and assemble the shared state. Returns the
    /// endpoint's event stream for the data plane to consume.
    ///
    /// This registers once to learn the chain; [`crate::control_link`]
    /// registers again when it opens its stream. Registration is an upsert, so
    /// the second one costs a round trip and nothing else.
    pub async fn bootstrap(
        cfg: &crate::config::GatewayConfig,
        _policy: Arc<dyn FlowPolicy>,
    ) -> anyhow::Result<(Arc<Self>, mpsc::Receiver<avon_tunnel::EndpointEvent>)> {
        let cert_path = cfg.identity_dir.join("gateway.avon.crt");
        let cert = Certificate::decode(&std::fs::read(&cert_path).with_context(|| {
            format!("reading AVON identity certificate {}", cert_path.display())
        })?)?;
        let key_path = cfg.identity_dir.join("gateway.avon.key");
        let signing = HybridSigningKeyPair::from_secret_bytes(
            &std::fs::read(&key_path)
                .with_context(|| format!("reading AVON identity key {}", key_path.display()))?,
        )?;
        let id = GatewayId::from(uuid::Uuid::from_bytes(cert.tbs.subject_id));

        let table = Arc::new(SessionTable::new());
        let endpoint = UdpEndpoint::bind(
            avon_tunnel::EndpointConfig {
                bind: cfg.listen_udp,
                overlay_mtu: cfg.overlay_mtu,
                timers: cfg.timers(),
            },
            table.clone(),
        )
        .await?;
        tracing::info!(addr = %endpoint.local_addr(), gateway = %id, "tunnel listening");

        let chain = crate::control_link::fetch_chain(cfg).await?;
        // Session mirroring is best-effort: it lets a second gateway learn a
        // peer's roamed endpoint from Redis. The gateway forwards packets with
        // or without it, so connecting to Redis must never delay -- let alone
        // block -- the data plane coming up. This used to be
        // `ConnectionManager::new(c).await.ok()` inline, which has no
        // connection timeout: a Redis that is unreachable (a different network,
        // an outage) wedged gateway bootstrap forever, before it ever served.
        // Connect in the background instead and fill `redis` if and when it
        // succeeds; `redis_client()` already logged and returned None on a bad
        // URL, so a Some here is worth an attempt.
        let redis_client = cfg.redis_client();

        let events = endpoint.clone().run();
        // Create a placeholder Cedar policy; the real decision log will be wired after the state is Arc.
        let dummy_tx = {
            let (tx, _rx) = mpsc::channel::<avon_protocol::v2::DecisionRecord>(1);
            tx
        };
        let placeholder = Arc::new(CedarFlowPolicy::new(dummy_tx));
        let state = Arc::new(Self {
            id,
            table,
            endpoint,
            routes: RouteTable::new(),
            policy: RwLock::new(placeholder),
            signing,
            cert,
            chain: RwLock::new(chain),
            sessions_meta: DashMap::new(),
            overlay_prefixes: cfg.overlay_prefixes.clone(),
            public_endpoint: cfg.public_endpoint.clone(),
            up: RwLock::new(None),
            redis: RwLock::new(None),
        });
        if let Some(client) = redis_client {
            let state_for_redis = state.clone();
            tokio::spawn(async move {
                // Bound the whole connect, retries included: ConnectionManager
                // has no connection timeout of its own, so a stalled TLS
                // handshake to an unroutable Redis would otherwise never return.
                match tokio::time::timeout(
                    Duration::from_secs(10),
                    redis::aio::ConnectionManager::new(client),
                )
                .await
                {
                    Ok(Ok(conn)) => {
                        *state_for_redis.redis.write().await = Some(conn);
                        tracing::info!("redis connected; session mirroring enabled");
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "redis connect failed; session mirroring disabled");
                    }
                    Err(_) => {
                        tracing::warn!("redis connect timed out; session mirroring disabled");
                    }
                }
            });
        }
        // Now that the state is Arc, create the real decision log that forwards to the current `up` sender.
        let real_tx = decision_log::spawn_for_state(state.clone());
        let real_policy = Arc::new(CedarFlowPolicy::new(real_tx));
        *state.policy.write().await = real_policy;
        Ok((state, events))
    }

    /// Anything not inside the overlay is either a protected network behind
    /// this gateway or the internet; either way the kernel decides, so the
    /// packet goes to the TUN.
    pub fn is_protected_or_external(&self, dst: IpAddr) -> bool {
        !self.overlay_prefixes.iter().any(|n| n.contains(&dst))
    }

    pub async fn report(&self, event: SessionEvent) {
        let tx = self.up.read().await.clone();
        if let Some(tx) = tx {
            if tx.send(event_msg(event)).await.is_err() {
                tracing::debug!("control link closed; session event dropped");
            }
        }
    }

    /// Tear a session down everywhere: sockets, routes, metadata, mirror, and
    /// tell control why.
    pub async fn close_session(&self, id: &SessionId, reason: &str) {
        let Some(session) = self.table.remove(id) else {
            return;
        };
        session.close();
        self.routes.remove_session(id);
        self.sessions_meta.remove(id);
        crate::redis_mirror::unmirror(self, id).await;
        metrics::counter!("avon_gateway_sessions_closed_total", "reason" => reason.to_string())
            .increment(1);
        self.report(SessionEvent {
            session_id: id.to_vec(),
            event: "closed".into(),
            reason: reason.to_string(),
            endpoint: session
                .peer_endpoint()
                .map(|e| e.to_string())
                .unwrap_or_default(),
            bytes_tx: session
                .stats()
                .bytes_tx
                .load(std::sync::atomic::Ordering::Relaxed),
            bytes_rx: session
                .stats()
                .bytes_rx
                .load(std::sync::atomic::Ordering::Relaxed),
        })
        .await;
    }
}

fn event_msg(e: SessionEvent) -> GatewayUp {
    GatewayUp {
        msg: Some(gateway_up::Msg::SessionEvent(e)),
    }
}
