//! Brokered peer-to-peer sessions. The initiator's `RequestPeerSession` is
//! delivered to the target via its pulse stream; the target's
//! `AnswerPeerSession` completes the handshake.

use std::sync::Arc;
use std::time::Duration;

use avon_common::ids::{DeviceId, SessionId};
use avon_protocol::v2::{
    pulse_down, Certificate as PbCert, PeerAnswer, PeerOffer, PeerSessionRequest,
    PeerSessionResponse, PulseDown, Suite,
};
use dashmap::DashMap;
use tokio::sync::oneshot;
use tonic::Status;

use crate::service::AppState;
use crate::session_token::SessionInfo;

const OFFER_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Default, Clone)]
pub struct PendingPeerAnswers(Arc<DashMap<Vec<u8>, oneshot::Sender<PeerAnswer>>>);

impl PendingPeerAnswers {
    pub fn register(&self, session_id: &[u8]) -> oneshot::Receiver<PeerAnswer> {
        let (tx, rx) = oneshot::channel();
        self.0.insert(session_id.to_vec(), tx);
        rx
    }
    pub fn resolve(&self, answer: PeerAnswer) -> bool {
        match self.0.remove(answer.session_id.as_slice()) {
            Some((_, tx)) => tx.send(answer).is_ok(),
            None => false,
        }
    }
    pub fn cancel(&self, session_id: &[u8]) {
        self.0.remove(session_id);
    }
}

#[allow(clippy::type_complexity)]
async fn load_device_cert_and_overlay(
    state: &AppState,
    device: DeviceId,
) -> Result<(Vec<u8>, String, String), Status> {
    let row: Option<(
        Option<sqlx::types::ipnetwork::IpNetwork>,
        Option<sqlx::types::ipnetwork::IpNetwork>,
        Option<Vec<u8>>,
        uuid::Uuid,
    )> = sqlx::query_as(
        "SELECT d.overlay_ipv4, d.overlay_ipv6, \
                (SELECT c.certificate FROM certificates c WHERE c.subject_id = d.id AND c.revoked_at IS NULL AND c.not_after > now() ORDER BY c.not_after DESC LIMIT 1), \
                d.tenant_id \
         FROM devices d WHERE d.id = $1 AND d.status = 'active'",
    )
    .bind(device)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| Status::unavailable("database"))?;
    let (v4, v6, cert, _tenant) = row.ok_or_else(|| Status::not_found("peer device not found"))?;
    let cert = cert.ok_or_else(|| Status::failed_precondition("peer has no certificate"))?;
    let v4s = v4.map(|n| n.to_string()).unwrap_or_default();
    let v6s = v6.map(|n| n.to_string()).unwrap_or_default();
    Ok((cert, v4s, v6s))
}

pub async fn request_peer_session(
    state: &AppState,
    info: &SessionInfo,
    req: PeerSessionRequest,
) -> Result<PeerSessionResponse, Status> {
    if req.eph_kem_pk.len() != avon_crypto::hybrid::kem::HYBRID_KEM_PUBLIC_KEY_BYTES {
        return Err(Status::invalid_argument("eph_kem_pk length"));
    }
    let target_uuid = req
        .target_device
        .ok_or_else(|| Status::invalid_argument("target_device"))?;
    let target_bytes = target_uuid.value.clone();
    if target_bytes.len() != 16 {
        return Err(Status::invalid_argument("target_device length"));
    }
    let target_id = DeviceId::new(
        uuid::Uuid::from_slice(&target_bytes)
            .map_err(|_| Status::invalid_argument("target_device"))?,
    );
    if target_id == info.device {
        return Err(Status::invalid_argument("cannot dial self"));
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

    // Load target device and verify same tenant and active.
    let (_target_cert_bytes, _, _) = load_device_cert_and_overlay(state, target_id).await?;
    // Verify same tenant: fetch target tenant
    let (target_tenant,): (uuid::Uuid,) =
        sqlx::query_as("SELECT tenant_id FROM devices WHERE id = $1")
            .bind(target_id)
            .fetch_one(&state.pool)
            .await
            .map_err(|_| Status::unavailable("database"))?;
    if target_tenant != info.tenant.as_uuid() {
        return Err(Status::permission_denied("peer in different tenant"));
    }
    if !state.devices.is_connected(target_id) {
        return Err(Status::unavailable("peer offline"));
    }

    // Load initiator certificate and overlay for offer.
    let (initiator_cert_bytes, initiator_v4, initiator_v6) =
        load_device_cert_and_overlay(state, info.device).await?;
    let initiator_cert = PbCert {
        encoded: initiator_cert_bytes,
    };

    let session_id = SessionId::random().map_err(|_| Status::internal("rng"))?;
    sqlx::query(
        "INSERT INTO sessions (id, tenant_id, device_id, peer_device_id, state, suite) VALUES ($1, $2, $3, $4, 'offered', $5)",
    )
    .bind(session_id.to_vec())
    .bind(info.tenant)
    .bind(info.device)
    .bind(target_id)
    .bind(format!("{suite:?}"))
    .execute(&state.pool)
    .await
    .map_err(|_| Status::unavailable("database"))?;

    let rx = state.peer_pending.register(session_id.as_bytes());
    let offer = PeerOffer {
        session_id: session_id.to_vec(),
        initiator_certificate: Some(initiator_cert),
        eph_kem_pk: req.eph_kem_pk.clone(),
        suite: suite as i32,
        candidates: req.candidates.clone(),
        overlay_ipv4: initiator_v4,
        overlay_ipv6: initiator_v6,
        initiator_index: req.initiator_index,
    };
    let pushed = state.devices.send(
        target_id,
        PulseDown {
            msg: Some(pulse_down::Msg::PeerOffer(offer)),
        },
    );
    if !pushed {
        state.peer_pending.cancel(session_id.as_bytes());
        sqlx::query(
            "UPDATE sessions SET state='closed', close_reason='peer offline', closed_at=now() WHERE id=$1",
        )
        .bind(session_id.to_vec())
        .execute(&state.pool)
        .await
        .ok();
        return Err(Status::unavailable("peer offline"));
    }

    let peer_answer = match tokio::time::timeout(OFFER_TIMEOUT, rx).await {
        Ok(Ok(a)) => a,
        _ => {
            state.peer_pending.cancel(session_id.as_bytes());
            sqlx::query(
                "UPDATE sessions SET state='closed', close_reason='offer timeout', closed_at=now() WHERE id=$1",
            )
            .bind(session_id.to_vec())
            .execute(&state.pool)
            .await
            .ok();
            return Err(Status::unavailable("peer did not answer"));
        }
    };

    if peer_answer.session_id != session_id.to_vec() {
        return Err(Status::invalid_argument("answer session id mismatch"));
    }

    // Verify answer's session_id belongs to that target? Already checked.
    let answer = peer_answer
        .answer
        .ok_or_else(|| Status::invalid_argument("answer missing"))?;

    // Fetch responder certificate and overlay for initiator to verify.
    let (responder_cert_bytes, responder_v4, responder_v6) =
        load_device_cert_and_overlay(state, target_id).await?;
    let responder_cert = PbCert {
        encoded: responder_cert_bytes,
    };

    sqlx::query("UPDATE sessions SET state='active', activated_at=now() WHERE id=$1")
        .bind(session_id.to_vec())
        .execute(&state.pool)
        .await
        .map_err(|_| Status::unavailable("database"))?;

    metrics::counter!("avon_control_peer_sessions_opened_total").increment(1);

    Ok(PeerSessionResponse {
        session_id: session_id.to_vec(),
        answer: Some(answer),
        candidates: peer_answer.candidates.clone(),
        responder_certificate: Some(responder_cert),
        overlay_ipv4: responder_v4,
        overlay_ipv6: responder_v6,
    })
}

pub async fn answer_peer_session(
    state: &AppState,
    info: &SessionInfo,
    req: PeerAnswer,
) -> Result<(), Status> {
    if req.session_id.is_empty() {
        return Err(Status::invalid_argument("session_id"));
    }
    // Check session exists and caller is the peer target.
    let row: Option<(uuid::Uuid, uuid::Uuid, String)> =
        sqlx::query_as("SELECT device_id, peer_device_id, state::text FROM sessions WHERE id=$1")
            .bind(&req.session_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(|_| Status::unavailable("database"))?;
    let (initiator, peer, sess_state) =
        row.ok_or_else(|| Status::not_found("session not found"))?;
    if peer != info.device.as_uuid() && initiator != info.device.as_uuid() {
        return Err(Status::permission_denied("not a participant"));
    }
    if sess_state != "offered" {
        return Err(Status::failed_precondition("session not offered"));
    }
    // Resolve waiter.
    if !state.peer_pending.resolve(req) {
        return Err(Status::not_found("no pending peer offer"));
    }
    Ok(())
}
