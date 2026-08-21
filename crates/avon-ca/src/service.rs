use std::sync::Arc;

use avon_common::ids::{SpiffeKind, TenantId};
use avon_crypto::cert::SubjectKind;
use avon_protocol::v2::ca_service_server::CaService as CaServiceTrait;
use avon_protocol::v2::{
    Certificate as PbCert, Chain, Credential, Crl, Empty, IssueDeviceRequest, IssueDeviceResponse,
    IssueServiceRequest, IssueServiceResponse, RevokeRequest,
};
use avon_tls::peer_identity;
use sqlx::PgPool;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::keys::CaKeys;
use crate::pki::{
    current_crl, revoke, store_issued, verify_csr, Issuer, PkiError, SERVICE_LIFETIME_SECS,
};

pub struct CaService {
    pub pool: PgPool,
    pub keys: Arc<CaKeys>,
    pub device_lifetime_secs: i64,
}

fn require<T>(req: &Request<T>, allowed: &[&str]) -> Result<(), Status> {
    let peer =
        peer_identity(req).map_err(|_| Status::unauthenticated("client certificate required"))?;
    match peer.spiffe.map(|s| s.kind) {
        Some(SpiffeKind::Service { name, .. }) if allowed.contains(&name.as_str()) => Ok(()),
        _ => Err(Status::permission_denied("not authorized for CaService")),
    }
}

fn pki_status(e: PkiError) -> Status {
    match e {
        PkiError::CsrProof | PkiError::CsrTemplate(_) => Status::invalid_argument(e.to_string()),
        PkiError::Db(_) => Status::unavailable("database"),
        other => Status::internal(other.to_string()),
    }
}

impl CaService {
    fn chain(&self) -> Chain {
        Chain {
            root: Some(PbCert {
                encoded: self.keys.root_cert.encode(),
            }),
            issuing: Some(PbCert {
                encoded: self.keys.issuing_cert.encode(),
            }),
            tls_ca_pem: self.keys.tls_ca_cert_pem.clone(),
        }
    }

    fn credential(&self, issued: &crate::pki::Issued) -> Credential {
        let lifetime = issued.not_after - issued.certificate.tbs.not_before;
        Credential {
            certificate: Some(PbCert {
                encoded: issued.certificate.encode(),
            }),
            tls_certificate_pem: issued.tls_cert_pem.clone(),
            chain: Some(self.chain()),
            renew_after_unix: issued.certificate.tbs.not_before + lifetime / 2,
        }
    }
}

fn uuid_of(u: Option<&avon_protocol::v2::Uuid>, what: &str) -> Result<Uuid, Status> {
    let bytes = u
        .map(|u| u.value.as_slice())
        .ok_or_else(|| Status::invalid_argument(format!("{what} required")))?;
    avon_protocol::bytes_to_uuid(bytes)
        .map_err(|_| Status::invalid_argument(format!("{what} must be 16 bytes")))
}

#[tonic::async_trait]
impl CaServiceTrait for CaService {
    async fn issue_device_credential(
        &self,
        req: Request<IssueDeviceRequest>,
    ) -> Result<Response<IssueDeviceResponse>, Status> {
        require(&req, &["control"])?;
        let r = req.into_inner();
        let tenant = TenantId::new(uuid_of(r.tenant_id.as_ref(), "tenant_id")?);
        let device = uuid_of(r.device_id.as_ref(), "device_id")?;
        let kind = match r.kind {
            3 => SubjectKind::Device,
            4 => SubjectKind::Gateway,
            _ => return Err(Status::invalid_argument("kind must be 3 or 4")),
        };
        let csr = verify_csr(
            r.csr
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("csr required"))?,
        )
        .map_err(pki_status)?;
        if csr.template.kind != kind
            || csr.template.tenant_id != tenant.to_string()
            || csr.template.subject_id != *device.as_bytes()
        {
            return Err(Status::invalid_argument(
                "csr template does not match request",
            ));
        }
        let issued = Issuer { keys: &self.keys }
            .issue(
                csr,
                kind,
                Some(tenant),
                device,
                r.sans,
                self.device_lifetime_secs,
            )
            .map_err(pki_status)?;
        store_issued(
            &self.pool,
            &issued,
            Some(tenant),
            device,
            if kind == SubjectKind::Device {
                "device"
            } else {
                "gateway"
            },
            &self.keys.issuing.verifying_key().key_id(),
        )
        .await
        .map_err(pki_status)?;
        metrics::counter!("avon_ca_certificates_issued_total", "kind" => "device").increment(1);
        Ok(Response::new(IssueDeviceResponse {
            credential: Some(self.credential(&issued)),
            serial: issued.serial.to_vec(),
        }))
    }

    async fn issue_service_credential(
        &self,
        req: Request<IssueServiceRequest>,
    ) -> Result<Response<IssueServiceResponse>, Status> {
        require(&req, &["control", "bootstrap"])?;
        let r = req.into_inner();
        let service_id = uuid_of(r.service_id.as_ref(), "service_id")?;
        let csr = verify_csr(
            r.csr
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("csr required"))?,
        )
        .map_err(pki_status)?;
        if csr.template.kind != SubjectKind::Service {
            return Err(Status::invalid_argument("csr kind must be service"));
        }
        let mut sans = vec![format!("spiffe://avon/service/{}", r.service_name)];
        sans.extend(r.dns_sans);
        let issued = Issuer { keys: &self.keys }
            .issue(
                csr,
                SubjectKind::Service,
                None,
                service_id,
                sans,
                SERVICE_LIFETIME_SECS,
            )
            .map_err(pki_status)?;
        store_issued(
            &self.pool,
            &issued,
            None,
            service_id,
            "service",
            &self.keys.issuing.verifying_key().key_id(),
        )
        .await
        .map_err(pki_status)?;
        Ok(Response::new(IssueServiceResponse {
            credential: Some(self.credential(&issued)),
            serial: issued.serial.to_vec(),
        }))
    }

    async fn get_chain(&self, req: Request<Empty>) -> Result<Response<Chain>, Status> {
        require(&req, &["control", "gateway", "admin", "bootstrap"])?;
        Ok(Response::new(self.chain()))
    }

    async fn revoke(&self, req: Request<RevokeRequest>) -> Result<Response<Crl>, Status> {
        require(&req, &["control", "admin"])?;
        let r = req.into_inner();
        let serial: [u8; 16] = r
            .serial
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("serial must be 16 bytes"))?;
        let crl = revoke(&self.pool, &self.keys, &serial, &r.reason)
            .await
            .map_err(|e| match e {
                PkiError::X509(_) => Status::not_found("serial"),
                other => pki_status(other),
            })?;
        metrics::counter!("avon_ca_revocations_total").increment(1);
        Ok(Response::new(crl))
    }

    async fn current_crl(&self, req: Request<Empty>) -> Result<Response<Crl>, Status> {
        require(&req, &["control", "admin"])?;
        Ok(Response::new(
            current_crl(&self.pool, &self.keys)
                .await
                .map_err(pki_status)?,
        ))
    }
}
