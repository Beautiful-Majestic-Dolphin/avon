//! Device authentication: what a device must prove beyond its TLS certificate,
//! and how later requests are tied back to that proof.

use avon_common::ids::{DeviceId, TenantId};
use avon_crypto::cert::Certificate;
use tonic::{Request, Status};

use crate::authz::{require_device, session_token};
use crate::service::AppState;
use crate::session_token::SessionInfo;

/// The bytes a device signs in domain `Auth`: the server's nonce plus both
/// ends of the TLS connection, so a proof cannot be replayed elsewhere.
pub fn auth_message(
    nonce: &[u8; 32],
    tls_client_cert_sha256: &[u8; 32],
    server_tls_cert_sha256: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(96);
    m.extend_from_slice(nonce);
    m.extend_from_slice(tls_client_cert_sha256);
    m.extend_from_slice(server_tls_cert_sha256);
    m
}

/// Chain + validity + TLS binding + revocation + device status.
pub async fn verify_device_certificate(
    state: &AppState,
    cert: &Certificate,
    tls_cert_sha256: [u8; 32],
) -> Result<(TenantId, DeviceId), Status> {
    let now = chrono::Utc::now().timestamp();
    {
        let chain = state.chain.read().await;
        chain
            .verifier
            .verify(cert, std::slice::from_ref(&chain.issuing), now)
            .map_err(|_| Status::unauthenticated("certificate invalid"))?;
        if cert.tbs.tls_cert_sha256 != Some(tls_cert_sha256) {
            return Err(Status::unauthenticated(
                "certificate not bound to this TLS identity",
            ));
        }
        if chain.crl.contains(&cert.tbs.serial) {
            return Err(Status::permission_denied("certificate revoked"));
        }
    }
    let tenant: TenantId = cert
        .tbs
        .tenant_id
        .parse()
        .map_err(|_| Status::unauthenticated("certificate tenant"))?;
    let device = DeviceId::new(uuid::Uuid::from_bytes(cert.tbs.subject_id));
    let status: Option<(String,)> =
        sqlx::query_as("SELECT status::text FROM devices WHERE id = $1 AND tenant_id = $2")
            .bind(device)
            .bind(tenant)
            .fetch_optional(&state.pool)
            .await
            .map_err(|_| Status::unavailable("database"))?;
    match status.as_ref().map(|s| s.0.as_str()) {
        Some("active") => Ok((tenant, device)),
        Some(_) => Err(Status::permission_denied("device not active")),
        None => Err(Status::unauthenticated("unknown device")),
    }
}

/// What a request claims about the caller, read without awaiting. Streaming
/// requests are not `Sync`, so a handler cannot hold `&Request<Streaming<_>>`
/// across an await; it calls this first, then [`session_for`].
pub struct DeviceCredentials {
    pub tenant: TenantId,
    pub device: DeviceId,
    pub tls_cert_sha256: [u8; 32],
    pub token: [u8; 32],
}

pub fn device_credentials<T>(req: &Request<T>) -> Result<DeviceCredentials, Status> {
    let (tenant, device, tls_cert_sha256) = require_device(req)?;
    let token = session_token(req)?;
    Ok(DeviceCredentials {
        tenant,
        device,
        tls_cert_sha256,
        token,
    })
}

/// Resolve the session and check it against the TLS identity that presented it.
pub async fn session_for(
    state: &AppState,
    creds: DeviceCredentials,
) -> Result<SessionInfo, Status> {
    let info = state
        .sessions
        .lookup(&creds.token)
        .await?
        .ok_or_else(|| Status::unauthenticated("session expired"))?;
    if info.tenant != creds.tenant
        || info.device != creds.device
        || info.tls_cert_sha256 != creds.tls_cert_sha256
    {
        return Err(Status::unauthenticated(
            "session does not match TLS identity",
        ));
    }
    Ok(info)
}

/// For every unary device RPC after Authenticate.
pub async fn authenticated_device<T: Sync>(
    state: &AppState,
    req: &Request<T>,
) -> Result<SessionInfo, Status> {
    session_for(state, device_credentials(req)?).await
}
