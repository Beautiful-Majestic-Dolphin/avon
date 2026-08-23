pub mod admin;
pub mod agent;
pub mod gateway;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use avon_common::ids::{DeviceId, TenantId};
use avon_config::TlsArgs;
use avon_crypto::cert::crl::Crl;
use avon_crypto::cert::{Certificate, ChainVerifier};
use avon_policy::engine::Engine;
use dashmap::DashMap;
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use tokio::sync::{Mutex, RwLock};

use crate::ca_client::CaClient;
use crate::session_token::SessionStore;

/// The AVON chain and the newest CRL, refreshed when the CA issues a new one.
pub struct ChainCache {
    pub root: Certificate,
    pub issuing: Certificate,
    pub tls_ca_pem: String,
    pub verifier: ChainVerifier,
    pub crl: Crl,
    pub crl_raw: avon_protocol::v2::Crl,
}

pub struct AppState {
    pub pool: PgPool,
    pub ca: CaClient,
    pub tls: TlsArgs,
    pub sessions: SessionStore,
    pub session_ttl_secs: u64,
    pub pulse_interval_secs: u32,
    pub chain: Arc<RwLock<ChainCache>>,
    pub server_cert_sha256: [u8; 32],
    pub gateways: crate::gateway_stream::GatewayRegistry,
    pub devices: crate::pulse::DeviceStreams,
    pub challenges: crate::attest::Challenges,
    pub pending_answers: crate::sessions::PendingAnswers,
    pub peer_pending: crate::peer::PendingPeerAnswers,
    pub engines: DashMap<TenantId, Arc<Engine>>,
    pub device_patch_at: Mutex<HashMap<DeviceId, Instant>>,
}

impl AppState {
    pub async fn new(
        pool: PgPool,
        redis: ConnectionManager,
        ca: CaClient,
        tls: TlsArgs,
        session_ttl_secs: u64,
        pulse_interval_secs: u32,
    ) -> anyhow::Result<Arc<Self>> {
        let chain_pb = ca.chain().await?;
        let root = Certificate::decode(
            &chain_pb
                .root
                .ok_or_else(|| anyhow::anyhow!("no root"))?
                .encoded,
        )?;
        let issuing = Certificate::decode(
            &chain_pb
                .issuing
                .ok_or_else(|| anyhow::anyhow!("no issuing"))?
                .encoded,
        )?;
        let verifier = ChainVerifier::new(vec![root.clone()])?;
        let crl_raw = ca.crl().await?;
        let crl = Crl::verify(&crl_raw.tbs, &crl_raw.signature, &issuing.tbs.signing_key)?;
        let cert_pem = std::fs::read(&tls.cert)?;
        let server_cert_sha256 = avon_tls::cert_sha256_from_pem(&cert_pem)?;
        Ok(Arc::new(Self {
            pool,
            ca,
            tls,
            sessions: SessionStore::new(redis, session_ttl_secs),
            session_ttl_secs,
            pulse_interval_secs,
            chain: Arc::new(RwLock::new(ChainCache {
                root,
                issuing,
                tls_ca_pem: chain_pb.tls_ca_pem,
                verifier,
                crl,
                crl_raw,
            })),
            server_cert_sha256,
            gateways: Default::default(),
            devices: Default::default(),
            challenges: Default::default(),
            pending_answers: Default::default(),
            peer_pending: Default::default(),
            engines: DashMap::new(),
            device_patch_at: Mutex::new(HashMap::new()),
        }))
    }
}
