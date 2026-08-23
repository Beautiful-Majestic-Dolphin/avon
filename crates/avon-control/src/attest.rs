//! Device attestation: issue a challenge, check what comes back, record it.
//!
//! The nonce is the whole freshness argument. A quote proves what the TPM's
//! PCRs held when it was made, and nothing about *when* that was — its clock
//! counts milliseconds since the TPM was manufactured. So the control plane
//! issues a random nonce, remembers it for a short window, and accepts exactly
//! one quote against it. A captured quote replayed later answers a nonce that
//! is no longer outstanding.

use std::sync::Arc;
use std::time::{Duration, Instant};

use avon_attest::{AttestationState, Evidence, QuotePolicy};
use avon_common::ids::DeviceId;
use avon_protocol::v2::{AttestationChallenge, AttestationEvidence};
use dashmap::DashMap;
use rand::RngCore;
use tonic::Status;

use crate::service::AppState;

/// How long an outstanding challenge stays answerable.
pub const CHALLENGE_TTL: Duration = Duration::from_secs(120);
/// How often a connected device is re-challenged.
pub const REATTEST_INTERVAL: Duration = Duration::from_secs(900);
const NONCE_BYTES: usize = 32;

#[derive(Clone)]
struct Outstanding {
    nonce: Vec<u8>,
    issued: Instant,
}

/// Challenges waiting to be answered, one per device.
#[derive(Default, Clone)]
pub struct Challenges(Arc<DashMap<DeviceId, Outstanding>>);

impl Challenges {
    /// Mint a challenge and remember it, replacing any earlier one: a device
    /// that never answered gets a fresh question rather than an open-ended
    /// window on an old one.
    pub fn issue(&self, device: DeviceId) -> AttestationChallenge {
        let mut nonce = vec![0u8; NONCE_BYTES];
        rand::thread_rng().fill_bytes(&mut nonce);
        self.0.insert(
            device,
            Outstanding {
                nonce: nonce.clone(),
                issued: Instant::now(),
            },
        );
        AttestationChallenge { nonce }
    }

    /// Take the outstanding nonce, if it is still answerable. Taking it means a
    /// quote can only be presented once.
    pub fn take(&self, device: DeviceId) -> Option<Vec<u8>> {
        let (_, out) = self.0.remove(&device)?;
        (out.issued.elapsed() <= CHALLENGE_TTL).then_some(out.nonce)
    }

    pub fn forget(&self, device: DeviceId) {
        self.0.remove(&device);
    }

    /// Drop challenges nobody answered, so a fleet that never attests does not
    /// grow this map without bound.
    pub fn sweep(&self) {
        self.0
            .retain(|_, out| out.issued.elapsed() <= CHALLENGE_TTL);
    }
}

/// Verify evidence against the challenge this device was given and record the
/// outcome. Returns the state that was stored.
pub async fn handle_evidence(
    state: &AppState,
    device: DeviceId,
    tenant: avon_common::ids::TenantId,
    ev: AttestationEvidence,
) -> Result<AttestationState, Status> {
    let Some(nonce) = state.challenges.take(device) else {
        // Nothing outstanding: either the challenge expired or this is
        // unsolicited. Either way there is nothing to check it against.
        tracing::warn!(%device, "attestation evidence arrived with no outstanding challenge");
        return Ok(AttestationState::Unverified);
    };

    let parsed = match avon_attest::evidence::parse(&ev.format, &ev.evidence) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(%device, error = %e, "attestation evidence did not parse");
            record(
                state,
                device,
                tenant,
                AttestationState::Failed,
                None,
                &e.to_string(),
            )
            .await?;
            return Ok(AttestationState::Failed);
        }
    };
    if matches!(parsed, Evidence::None) {
        record(
            state,
            device,
            tenant,
            AttestationState::None,
            None,
            "device has no attestation hardware",
        )
        .await?;
        return Ok(AttestationState::None);
    }

    // Trust on first use, then pin: the AK a device attested with is stored and
    // every later quote must use the same one.
    let known_ak: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT attestation -> 'ak_public' ->> 0 FROM devices WHERE id = $1 AND attestation ? 'ak_public'",
    )
    .bind(device)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| Status::unavailable("database"))?
    .flatten()
    .and_then(|hex: String| hex::decode(hex).ok());

    let verified = avon_attest::verify(
        &parsed,
        &nonce,
        known_ak.as_deref(),
        &QuotePolicy::default(),
    );
    let ak_public = match &parsed {
        Evidence::Tpm2Quote { ak_public, .. } => Some(ak_public.clone()),
        Evidence::None => None,
    };
    if verified.state != AttestationState::Verified {
        tracing::warn!(%device, reason = %verified.reason, "attestation failed");
    }
    record(
        state,
        device,
        tenant,
        verified.state,
        Some((&verified, ak_public.as_deref())),
        &verified.reason,
    )
    .await?;
    Ok(verified.state)
}

async fn record(
    state: &AppState,
    device: DeviceId,
    tenant: avon_common::ids::TenantId,
    result: AttestationState,
    detail: Option<(&avon_attest::Verified, Option<&[u8]>)>,
    reason: &str,
) -> Result<(), Status> {
    let mut doc = serde_json::json!({
        "reason": reason,
        "checked_at_unix": chrono::Utc::now().timestamp(),
    });
    if let Some((v, ak_public)) = detail {
        doc["pcr_digest"] = serde_json::json!(hex::encode(v.pcr_digest));
        doc["ak_sha256"] = serde_json::json!(hex::encode(v.ak_sha256));
        doc["reset_count"] = serde_json::json!(v.reset_count);
        doc["firmware_version"] = serde_json::json!(v.firmware_version);
        // Only pin the key once it has actually verified with it.
        if v.state == AttestationState::Verified {
            if let Some(ak) = ak_public {
                doc["ak_public"] = serde_json::json!([hex::encode(ak)]);
            }
        }
    }
    sqlx::query(
        "UPDATE devices SET attestation_state = $2::attestation_state, \
         attestation = COALESCE(attestation, '{}'::jsonb) || $3::jsonb WHERE id = $1",
    )
    .bind(device)
    .bind(result.as_str())
    .bind(&doc)
    .execute(&state.pool)
    .await
    .map_err(|_| Status::unavailable("database"))?;

    metrics::counter!("avon_control_attestations_total", "result" => result.as_str()).increment(1);
    // Policy decisions depend on this attribute, so push it out immediately.
    crate::policy_push::patch_device_attrs(state, tenant, device).await;
    Ok(())
}
