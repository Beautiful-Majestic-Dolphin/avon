//! Brokering a data-plane session between a device and a gateway. Control
//! never sees session keys: it relays the device's ephemeral KEM key to the
//! gateway and the gateway's signed answer back.

use std::sync::Arc;
use std::time::Duration;

use avon_common::ids::{GatewayId, SessionId};
use avon_protocol::v2::{
    gateway_down, Certificate as PbCert, GatewayDown, OpenSessionRequest, OpenSessionResponse,
    RouteUpdate, SessionAnswer, SessionOffer, SessionReport, Suite,
};
use dashmap::DashMap;
use sqlx::types::ipnetwork::IpNetwork;
use tokio::sync::oneshot;
use tonic::Status;

use crate::service::AppState;
use crate::session_token::SessionInfo;

/// Offers awaiting a gateway's answer, keyed by session id.
#[derive(Default, Clone)]
pub struct PendingAnswers(Arc<DashMap<Vec<u8>, oneshot::Sender<SessionAnswer>>>);

impl PendingAnswers {
    pub fn register(&self, session_id: &[u8]) -> oneshot::Receiver<SessionAnswer> {
        let (tx, rx) = oneshot::channel();
        self.0.insert(session_id.to_vec(), tx);
        rx
    }
    pub fn resolve(&self, answer: SessionAnswer) -> bool {
        match self.0.remove(&answer.session_id) {
            Some((_, tx)) => tx.send(answer).is_ok(),
            None => false,
        }
    }
    pub fn cancel(&self, session_id: &[u8]) {
        self.0.remove(session_id);
    }
}

const OFFER_TIMEOUT: Duration = Duration::from_secs(5);

struct DeviceRow {
    overlay_v4: IpNetwork,
    overlay_v6: IpNetwork,
    advertised: Vec<IpNetwork>,
    certificate: Vec<u8>,
}

/// `devices` as stored: overlay addresses and certificate are nullable until
/// enrollment and issuance have both completed.
type StoredDevice = (
    Option<IpNetwork>,
    Option<IpNetwork>,
    Vec<IpNetwork>,
    Option<Vec<u8>>,
);

async fn load_device(state: &AppState, info: &SessionInfo) -> Result<DeviceRow, Status> {
    let row: Option<StoredDevice> = sqlx::query_as(
        "SELECT d.overlay_ipv4, d.overlay_ipv6, d.advertised_routes, \
                (SELECT c.certificate FROM certificates c \
                  WHERE c.subject_id = d.id AND c.revoked_at IS NULL AND c.not_after > now() \
                  ORDER BY c.not_after DESC LIMIT 1) \
         FROM devices d WHERE d.id = $1 AND d.status = 'active'",
    )
    .bind(info.device)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| Status::unavailable("database"))?;
    let (v4, v6, advertised, cert) =
        row.ok_or_else(|| Status::permission_denied("device not active"))?;
    Ok(DeviceRow {
        overlay_v4: v4
            .ok_or_else(|| Status::failed_precondition("device has no overlay address"))?,
        overlay_v6: v6
            .ok_or_else(|| Status::failed_precondition("device has no overlay address"))?,
        advertised,
        certificate: cert
            .ok_or_else(|| Status::failed_precondition("device has no valid certificate"))?,
    })
}

/// The tenant's overlay prefix lengths. A device row stores a host address; the
/// agent needs the pool prefix to configure that address as on-link.
async fn pool_prefixes(state: &AppState, info: &SessionInfo) -> Result<(u8, u8), Status> {
    let (v4, v6): (IpNetwork, IpNetwork) =
        sqlx::query_as("SELECT ipv4_cidr, ipv6_cidr FROM ipam_pools WHERE tenant_id = $1")
            .bind(info.tenant)
            .fetch_one(&state.pool)
            .await
            .map_err(|_| Status::unavailable("database"))?;
    Ok((v4.prefix(), v6.prefix()))
}

pub async fn open_session(
    state: &AppState,
    info: &SessionInfo,
    req: OpenSessionRequest,
) -> Result<OpenSessionResponse, Status> {
    if req.eph_kem_pk.len() != avon_crypto::hybrid::kem::HYBRID_KEM_PUBLIC_KEY_BYTES {
        return Err(Status::invalid_argument("eph_kem_pk length"));
    }
    if req.initiator_index == 0 {
        return Err(Status::invalid_argument("initiator_index must be nonzero"));
    }
    let suites: Vec<Suite> = req
        .suites
        .iter()
        .filter_map(|s| Suite::try_from(*s).ok())
        .filter(|s| *s != Suite::Unspecified)
        .collect();
    let suite = if suites.contains(&Suite::Aes256Gcm) {
        Suite::Aes256Gcm
    } else {
        *suites
            .first()
            .ok_or_else(|| Status::invalid_argument("no supported suite"))?
    };

    let device = load_device(state, info).await?;
    let (gateway_id, gateway) = state
        .gateways
        .pick(None)
        .ok_or_else(|| Status::unavailable("no gateway available"))?;
    let session_id = SessionId::random().map_err(|_| Status::internal("rng"))?;
    sqlx::query(
        "INSERT INTO sessions (id, tenant_id, device_id, gateway_id, state, suite) \
         VALUES ($1, $2, $3, $4, 'offered', $5)",
    )
    .bind(session_id.to_vec())
    .bind(info.tenant)
    .bind(info.device)
    .bind(gateway_id.as_uuid())
    .bind(format!("{suite:?}"))
    .execute(&state.pool)
    .await
    .map_err(|_| Status::unavailable("database"))?;

    let routes_for_device = routes_for(state, info, gateway_id).await?;
    let (v4_prefix, v6_prefix) = pool_prefixes(state, info).await?;
    let rx = state.pending_answers.register(session_id.as_bytes());
    // The offer carries host addresses (/32, /128): the gateway turns them
    // straight into route-table entries for this session.
    let offer = SessionOffer {
        session_id: session_id.to_vec(),
        device_certificate: Some(PbCert {
            encoded: device.certificate.clone(),
        }),
        eph_kem_pk: req.eph_kem_pk,
        suite: suite as i32,
        overlay_ipv4: device.overlay_v4.to_string(),
        overlay_ipv6: device.overlay_v6.to_string(),
        advertised_routes: device.advertised.iter().map(|r| r.to_string()).collect(),
        initiator_index: req.initiator_index,
    };
    gateway
        .tx
        .send(GatewayDown {
            msg: Some(gateway_down::Msg::SessionOffer(offer)),
        })
        .await
        .map_err(|_| Status::unavailable("gateway stream closed"))?;

    let answer = match tokio::time::timeout(OFFER_TIMEOUT, rx).await {
        Ok(Ok(a)) => a,
        _ => {
            state.pending_answers.cancel(session_id.as_bytes());
            sqlx::query(
                "UPDATE sessions SET state = 'closed', close_reason = 'offer timeout', \
                 closed_at = now() WHERE id = $1",
            )
            .bind(session_id.to_vec())
            .execute(&state.pool)
            .await
            .ok();
            return Err(Status::unavailable("gateway did not answer"));
        }
    };
    sqlx::query("UPDATE sessions SET state = 'active', activated_at = now() WHERE id = $1")
        .bind(session_id.to_vec())
        .execute(&state.pool)
        .await
        .map_err(|_| Status::unavailable("database"))?;
    metrics::counter!("avon_control_sessions_opened_total").increment(1);

    let gateway_cert: (Vec<u8>,) = sqlx::query_as(
        "SELECT certificate FROM certificates \
         WHERE subject_id = $1 AND revoked_at IS NULL AND not_after > now() \
         ORDER BY not_after DESC LIMIT 1",
    )
    .bind(gateway_id.as_uuid())
    .fetch_one(&state.pool)
    .await
    .map_err(|_| Status::unavailable("gateway certificate"))?;

    Ok(OpenSessionResponse {
        session_id: session_id.to_vec(),
        answer: Some(answer),
        gateway_certificate: Some(PbCert {
            encoded: gateway_cert.0,
        }),
        // The device's addresses with the pool prefix, so the agent can put
        // them on its interface and treat the overlay as on-link.
        overlay_ipv4: format!("{}/{v4_prefix}", device.overlay_v4.ip()),
        overlay_ipv6: format!("{}/{v6_prefix}", device.overlay_v6.ip()),
        routes: vec![RouteUpdate {
            session_id: session_id.to_vec(),
            cidrs: routes_for_device,
            remove: false,
        }],
    })
}

/// What the device should send through this session: the networks the gateway
/// protects, plus routes other devices in the tenant advertise (reachable by
/// relay through the same gateway). The overlay prefix itself is not a route —
/// the device's own address lives there and the agent adds it as an interface
/// address, not a next hop.
async fn routes_for(
    state: &AppState,
    info: &SessionInfo,
    gateway: GatewayId,
) -> Result<Vec<String>, Status> {
    let (protected,): (Vec<IpNetwork>,) =
        sqlx::query_as("SELECT protected_cidrs FROM gateways WHERE id = $1")
            .bind(gateway.as_uuid())
            .fetch_one(&state.pool)
            .await
            .map_err(|_| Status::unavailable("database"))?;
    let peers: Vec<(Vec<IpNetwork>,)> = sqlx::query_as(
        "SELECT advertised_routes FROM devices \
         WHERE tenant_id = $1 AND id <> $2 AND status = 'active' \
           AND array_length(advertised_routes, 1) > 0",
    )
    .bind(info.tenant)
    .bind(info.device)
    .fetch_all(&state.pool)
    .await
    .map_err(|_| Status::unavailable("database"))?;

    let mut routes: Vec<String> = peers
        .into_iter()
        .flat_map(|(r,)| r.into_iter().map(|c| c.to_string()))
        .collect();
    routes.extend(protected.iter().map(|c| c.to_string()));
    routes.sort();
    routes.dedup();
    Ok(routes)
}

pub async fn report_session(
    state: &AppState,
    info: &SessionInfo,
    report: SessionReport,
) -> Result<(), Status> {
    if report.event.as_str() == "closed" {
        sqlx::query(
            "UPDATE sessions SET state = 'closed', closed_at = now(), close_reason = $3 \
             WHERE id = $1 AND device_id = $2",
        )
        .bind(&report.session_id)
        .bind(info.device)
        .bind(&report.reason)
        .execute(&state.pool)
        .await
        .map_err(|_| Status::unavailable("database"))?;
    }
    Ok(())
}
