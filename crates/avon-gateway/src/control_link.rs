//! The gateway's link to control: register, then a bidirectional stream of
//! offers down and answers/events up.
//!
//! Sessions outlive this link. Keys are local, so a control outage stops new
//! sessions being brokered but does not interrupt forwarding for existing ones.

use std::sync::Arc;
use std::time::Duration;

use avon_common::ids::{DeviceId, SessionId, TenantId};
use avon_crypto::aead::Suite;
use avon_crypto::cert::crl::Crl;
use avon_crypto::cert::Certificate;
use avon_protocol::v2::gateway_service_client::GatewayServiceClient;
use avon_protocol::v2::{
    gateway_down, gateway_up, GatewayRegistration, GatewayUp, RouteUpdate, SessionOffer,
};
use avon_tunnel::{Responder, Role, Session};
use ipnet::IpNet;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::transport::{Channel, Endpoint};

use crate::config::GatewayConfig;
use crate::state::{ChainCache, GatewayState, SessionMeta};

const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Connect, register and serve the event stream, reconnecting for as long as
/// the process lives.
pub async fn run_control_link(state: Arc<GatewayState>, cfg: GatewayConfig) -> anyhow::Result<()> {
    let mut backoff = BACKOFF_MIN;
    loop {
        match connect_and_serve(&state, &cfg).await {
            Ok(()) => {
                tracing::info!("control stream ended; reconnecting");
                backoff = BACKOFF_MIN;
            }
            Err(e) => {
                tracing::warn!(error = %e, backoff = ?backoff, "control link failed");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
}

pub async fn connect(cfg: &GatewayConfig) -> anyhow::Result<GatewayServiceClient<Channel>> {
    let channel = Endpoint::from_shared(cfg.control_url.clone())?
        .tls_config(avon_tls::client_tls_config(
            &cfg.tls,
            &cfg.control_server_name,
        )?)?
        .connect()
        .await?;
    Ok(GatewayServiceClient::new(channel))
}

fn registration(cfg: &GatewayConfig) -> GatewayRegistration {
    GatewayRegistration {
        public_endpoint: cfg.public_endpoint.clone(),
        region: cfg.region.clone(),
        capacity: cfg.capacity,
        version: env!("CARGO_PKG_VERSION").to_string(),
        protected_cidrs: cfg.protected_cidrs.iter().map(|c| c.to_string()).collect(),
    }
}

/// Register once to learn what to trust. A gateway cannot verify a device
/// certificate — and so cannot accept a session — until it has this.
pub async fn fetch_chain(cfg: &GatewayConfig) -> anyhow::Result<ChainCache> {
    let config = connect(cfg)
        .await?
        .register(registration(cfg))
        .await?
        .into_inner();
    let chain_pb = config
        .chain
        .ok_or_else(|| anyhow::anyhow!("control returned no chain"))?;
    let root = Certificate::decode(
        &chain_pb
            .root
            .ok_or_else(|| anyhow::anyhow!("chain has no root"))?
            .encoded,
    )?;
    let issuing = Certificate::decode(
        &chain_pb
            .issuing
            .ok_or_else(|| anyhow::anyhow!("chain has no issuing ca"))?
            .encoded,
    )?;
    let crl_pb = config
        .crl
        .ok_or_else(|| anyhow::anyhow!("control returned no crl"))?;
    let crl = Crl::verify(&crl_pb.tbs, &crl_pb.signature, &issuing.tbs.signing_key)?;
    Ok(ChainCache {
        verifier: avon_crypto::cert::ChainVerifier::new(vec![root.clone()])?,
        root,
        issuing,
        crl,
    })
}

async fn connect_and_serve(state: &Arc<GatewayState>, cfg: &GatewayConfig) -> anyhow::Result<()> {
    let mut client = connect(cfg).await?;
    let config = client.register(registration(cfg)).await?.into_inner();
    if let Some(crl) = config.crl {
        apply_crl(state, &crl).await;
    }
    for snap in config.snapshots {
        apply_snapshot(state, snap).await;
    }
    tracing::info!(endpoint = %cfg.public_endpoint, "registered with control");

    let (up_tx, up_rx) = mpsc::channel::<GatewayUp>(64);
    *state.up.write().await = Some(up_tx);
    let mut down = client
        .events(ReceiverStream::new(up_rx))
        .await?
        .into_inner();

    while let Some(msg) = down.next().await {
        let msg = msg?;
        match msg.msg {
            Some(gateway_down::Msg::SessionOffer(offer)) => {
                if let Err(e) = accept_offer(state, cfg, offer).await {
                    tracing::warn!(error = %e, "session offer rejected");
                }
            }
            Some(gateway_down::Msg::Close(c)) => {
                if let Ok(id) = SessionId::from_slice(&c.session_id) {
                    state.close_session(&id, &c.reason).await;
                }
            }
            Some(gateway_down::Msg::Crl(crl)) => apply_crl(state, &crl).await,
            Some(gateway_down::Msg::Routes(update)) => apply_routes(state, update),
            Some(gateway_down::Msg::Policy(snap)) => apply_snapshot(state, snap).await,
            Some(gateway_down::Msg::DeviceUpdate(upd)) => apply_device_update(state, upd).await,
            None => {}
        }
    }
    *state.up.write().await = None;
    Ok(())
}

/// Answer an offer, install the session, and start routing to it. The device
/// allocated its own receiver index before the offer, so the session can send
/// as soon as the first packet reveals the peer's endpoint.
async fn accept_offer(
    state: &Arc<GatewayState>,
    cfg: &GatewayConfig,
    offer: SessionOffer,
) -> anyhow::Result<()> {
    let session_id = SessionId::from_slice(&offer.session_id)?;
    let encoded = offer
        .device_certificate
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("offer has no device certificate"))?;
    let device_cert = Certificate::decode(&encoded.encoded)?;

    // Control chose this device, but the gateway verifies the certificate
    // itself: control is not in the trust path for session establishment.
    {
        let chain = state.chain.read().await;
        chain.verifier.verify(
            &device_cert,
            std::slice::from_ref(&chain.issuing),
            chrono::Utc::now().timestamp(),
        )?;
        if chain.is_revoked(&device_cert.tbs.serial) {
            anyhow::bail!("device certificate is revoked");
        }
    }

    let suite = Suite::from_id(u8::try_from(offer.suite)?)
        .ok_or_else(|| anyhow::anyhow!("unknown suite {}", offer.suite))?;
    if offer.initiator_index == 0 {
        anyhow::bail!("offer has no initiator index");
    }

    let my_index = state.table.allocate_index()?;
    let (answer, est) = Responder::answer(
        session_id,
        &device_cert,
        &offer.eph_kem_pk,
        suite,
        state.cert.id(),
        &state.signing,
        my_index,
        Some(cfg.public_endpoint.clone()),
    )?;

    let session = Session::new(
        session_id,
        Role::Responder,
        est.suite,
        device_cert.id(),
        est.keys,
        my_index,
        offer.initiator_index,
        None,
    );
    state.table.insert(session);

    let meta = SessionMeta {
        device_id: DeviceId::from(uuid::Uuid::from_bytes(device_cert.tbs.subject_id)),
        tenant: device_cert.tbs.tenant_id.parse::<TenantId>()?,
        serial: device_cert.tbs.serial,
        overlay_v4: parse_net(&offer.overlay_ipv4),
        overlay_v6: parse_net(&offer.overlay_ipv6),
        advertised: offer
            .advertised_routes
            .iter()
            .filter_map(|c| c.parse().ok())
            .collect(),
    };
    for net in meta.routes() {
        state.routes.insert(net, session_id);
    }
    crate::redis_mirror::mirror_session(state, &session_id, &meta).await;
    state.sessions_meta.insert(session_id, meta);

    let tx = state.up.read().await.clone();
    if let Some(tx) = tx {
        tx.send(GatewayUp {
            msg: Some(gateway_up::Msg::SessionAnswer(answer)),
        })
        .await?;
    }
    metrics::counter!("avon_gateway_sessions_opened_total").increment(1);
    tracing::info!(session = %session_id, "session established");
    Ok(())
}

fn parse_net(s: &str) -> Option<IpNet> {
    if s.is_empty() {
        return None;
    }
    s.parse::<IpNet>()
        .ok()
        .or_else(|| s.parse::<std::net::IpAddr>().ok().map(IpNet::from))
}

fn apply_routes(state: &Arc<GatewayState>, update: RouteUpdate) {
    let Ok(session) = SessionId::from_slice(&update.session_id) else {
        return;
    };
    for cidr in &update.cidrs {
        let Ok(net) = cidr.parse::<IpNet>() else {
            continue;
        };
        if update.remove {
            state.routes.remove(net);
        } else {
            state.routes.insert(net, session);
        }
    }
}

/// A new CRL replaces the old one, then every session whose peer certificate
/// it names is torn down — a revoked device must lose its tunnel, not just be
/// refused the next one.
async fn apply_crl(state: &Arc<GatewayState>, raw: &avon_protocol::v2::Crl) {
    let verified = {
        let chain = state.chain.read().await;
        match Crl::verify(&raw.tbs, &raw.signature, &chain.issuing.tbs.signing_key) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "rejected an unverifiable CRL");
                return;
            }
        }
    };
    {
        let mut chain = state.chain.write().await;
        if verified.version < chain.crl.version {
            tracing::debug!(
                have = chain.crl.version,
                got = verified.version,
                "ignoring an older CRL"
            );
            return;
        }
        chain.crl = verified;
    }

    let revoked: Vec<SessionId> = {
        let chain = state.chain.read().await;
        state
            .sessions_meta
            .iter()
            .filter(|e| chain.is_revoked(&e.value().serial))
            .map(|e| *e.key())
            .collect()
    };
    for id in revoked {
        state.close_session(&id, "certificate revoked").await;
    }
}

async fn apply_snapshot(state: &Arc<GatewayState>, snap: avon_protocol::v2::PolicySnapshot) {
    let data = match avon_policy::snapshot::decode(&snap.encoded) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "failed to decode policy snapshot");
            return;
        }
    };
    let tenant = data.tenant_id.into();
    let policy = state.policy.read().await.clone();
    if let Err(e) = policy.apply_snapshot(tenant, data) {
        tracing::warn!(error = %e, "failed to apply policy snapshot");
    } else {
        tracing::info!(%tenant, version = snap.version, "policy snapshot applied");
    }
}

async fn apply_device_update(state: &Arc<GatewayState>, upd: avon_protocol::v2::DeviceUpdate) {
    let (Some(tenant), Some(device)) = (upd.tenant_id.as_ref(), upd.device_id.as_ref()) else {
        return;
    };
    let Ok(tenant) = avon_protocol::bytes_to_uuid(&tenant.value).map(TenantId::new) else {
        return;
    };
    let Ok(device) = avon_protocol::bytes_to_uuid(&device.value).map(DeviceId::new) else {
        return;
    };
    let Ok(attrs) = serde_json::from_str::<avon_policy::entities::DeviceAttrs>(&upd.attrs_json)
    else {
        return;
    };
    let inactive = attrs.status != "active";
    let policy = state.policy.read().await.clone();
    policy.patch_device(tenant, device, attrs);
    if inactive {
        for entry in state.sessions_meta.iter() {
            if entry.value().device_id == device {
                let sid = *entry.key();
                state.close_session(&sid, "device no longer active").await;
            }
        }
    }
}
