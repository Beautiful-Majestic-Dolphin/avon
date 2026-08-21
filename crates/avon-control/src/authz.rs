//! Who is calling: SPIFFE identity from the TLS peer certificate, plus the
//! session token carried in request metadata.

use avon_common::ids::{DeviceId, SpiffeKind, TenantId};
use avon_tls::peer_identity;
use base64ct::{Base64UrlUnpadded, Encoding};
use tonic::{Request, Status};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub enum Principal {
    Service {
        name: String,
        instance: Option<Uuid>,
    },
    Device {
        tenant: TenantId,
        device: DeviceId,
        tls_cert_sha256: [u8; 32],
    },
    Anonymous,
}

pub fn principal_of<T>(req: &Request<T>) -> Principal {
    match peer_identity(req) {
        Ok(peer) => match peer.spiffe.map(|s| s.kind) {
            Some(SpiffeKind::Service { name, instance }) => Principal::Service { name, instance },
            Some(SpiffeKind::Device { tenant, device }) => Principal::Device {
                tenant,
                device,
                tls_cert_sha256: peer.cert_sha256,
            },
            None => Principal::Anonymous,
        },
        Err(_) => Principal::Anonymous,
    }
}

pub fn require_service<T>(req: &Request<T>, allowed: &[&str]) -> Result<Principal, Status> {
    match principal_of(req) {
        Principal::Service { name, instance } => {
            if allowed.contains(&name.as_str()) {
                Ok(Principal::Service { name, instance })
            } else {
                Err(Status::permission_denied(format!(
                    "service {name} not allowed"
                )))
            }
        }
        _ => Err(Status::unauthenticated(
            "service client certificate required",
        )),
    }
}

pub fn require_device<T>(req: &Request<T>) -> Result<(TenantId, DeviceId, [u8; 32]), Status> {
    match principal_of(req) {
        Principal::Device {
            tenant,
            device,
            tls_cert_sha256,
        } => Ok((tenant, device, tls_cert_sha256)),
        _ => Err(Status::unauthenticated(
            "device client certificate required",
        )),
    }
}

pub fn session_token<T>(req: &Request<T>) -> Result<[u8; 32], Status> {
    let value = req
        .metadata()
        .get("x-avon-session")
        .ok_or_else(|| Status::unauthenticated("missing x-avon-session"))?
        .to_str()
        .map_err(|_| Status::unauthenticated("invalid x-avon-session"))?;
    let bytes = Base64UrlUnpadded::decode_vec(value)
        .map_err(|_| Status::unauthenticated("invalid x-avon-session"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Status::unauthenticated("invalid x-avon-session"))?;
    Ok(arr)
}
