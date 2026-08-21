//! Credential renewal. The old certificate stays valid until it expires, so a
//! device that crashes mid-renewal can retry with what it already has.

use avon_crypto::cert::{SubjectKind, TbsCertificate};
use avon_protocol::v2::{Credential, Csr};
use tonic::Status;

use crate::service::AppState;
use crate::session_token::SessionInfo;

pub async fn renew(state: &AppState, info: &SessionInfo, csr: Csr) -> Result<Credential, Status> {
    let template = TbsCertificate::decode(&csr.tbs_template)
        .map_err(|_| Status::invalid_argument("csr template"))?;
    if template.kind != SubjectKind::Device {
        return Err(Status::invalid_argument("csr kind"));
    }
    // The same signing key must be used across renewals (identity continuity).
    let current: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT certificate FROM certificates \
         WHERE subject_id = $1 AND revoked_at IS NULL ORDER BY not_after DESC LIMIT 1",
    )
    .bind(info.device)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| Status::unavailable("database"))?;
    if let Some((raw,)) = current {
        if let Ok(c) = avon_crypto::cert::Certificate::decode(&raw) {
            if c.tbs.signing_key != template.signing_key {
                return Err(Status::permission_denied(
                    "signing key must match the current credential",
                ));
            }
        }
    }
    let sans = vec![format!(
        "spiffe://avon/{}/device/{}",
        info.tenant, info.device
    )];
    let (cred, _serial) = state
        .ca
        .issue_device(info.tenant.as_uuid(), info.device.as_uuid(), csr, 3, sans)
        .await
        .map_err(|_| Status::unavailable("certificate authority"))?;
    metrics::counter!("avon_control_renewals_total").increment(1);
    Ok(cred)
}
