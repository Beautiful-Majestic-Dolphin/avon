//! gRPC service implementation for the AVON Certificate Authority.

use std::sync::Arc;

use avon_common::device::DeviceId;
use avon_protocol::v1::ca_service_server::CaService;
use avon_protocol::v1::{
    CertificateStatus as ProtoCertStatus, GetCaCertsRequest, GetCaCertsResponse, IssueCertRequest,
    IssueCertResponse, OcspRequest, OcspResponse, RevokeCertRequest, RevokeCertResponse,
    VerifyCertRequest, VerifyCertResponse,
};
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

use crate::ca::{CaError, CertificateAuthority, CertificateStatus};
use crate::ocsp::OcspResponder;

pub struct CaMetrics;

impl CaMetrics {
    pub fn record_certificate_issued() {
        metrics::counter!("avon_ca_certificates_issued_total").increment(1);
    }

    pub fn record_certificate_verified(valid: bool) {
        let label = if valid { "valid" } else { "invalid" };
        metrics::counter!("avon_ca_certificates_verified_total", "result" => label).increment(1);
    }

    pub fn record_certificate_revoked() {
        metrics::counter!("avon_ca_certificates_revoked_total").increment(1);
    }

    pub fn record_ocsp_request() {
        metrics::counter!("avon_ca_ocsp_requests_total").increment(1);
    }
}

pub struct CaServiceImpl {
    ca: Arc<CertificateAuthority>,
    ocsp: Arc<OcspResponder>,
}

impl CaServiceImpl {
    pub fn new(ca: Arc<CertificateAuthority>, ocsp: Arc<OcspResponder>) -> Self {
        Self { ca, ocsp }
    }
}

#[tonic::async_trait]
impl CaService for CaServiceImpl {
    async fn issue_certificate(
        &self,
        request: Request<IssueCertRequest>,
    ) -> Result<Response<IssueCertResponse>, Status> {
        let req = request.into_inner();

        let device_id = DeviceId::try_from_slice(&req.device_id)
            .map_err(|_| Status::invalid_argument("Invalid device ID"))?;

        debug!(?device_id, "Processing certificate issuance request");

        let lifetime = if req.lifetime_secs > 0 {
            Some(std::time::Duration::from_secs(req.lifetime_secs as u64))
        } else {
            None
        };

        match self
            .ca
            .issue_ephemeral_cert(
                device_id,
                &req.public_key_classical,
                &req.public_key_pqc,
                lifetime,
            )
            .await
        {
            Ok(cert) => {
                CaMetrics::record_certificate_issued();
                info!(?device_id, serial = cert.serial, "Certificate issued");

                Ok(Response::new(IssueCertResponse {
                    success: true,
                    certificate_der: cert.certificate_der,
                    signature_classical: cert.classical_signature,
                    signature_pqc: cert.pqc_signature,
                    ocsp_staple: cert.ocsp_staple,
                    expires_at: cert.expires_at.timestamp(),
                    serial_number: cert.serial,
                    error_message: String::new(),
                }))
            }
            Err(e) => {
                warn!(?device_id, error = %e, "Failed to issue certificate");
                Ok(Response::new(IssueCertResponse {
                    success: false,
                    certificate_der: vec![],
                    signature_classical: vec![],
                    signature_pqc: vec![],
                    ocsp_staple: vec![],
                    expires_at: 0,
                    serial_number: 0,
                    error_message: e.to_string(),
                }))
            }
        }
    }

    async fn verify_certificate(
        &self,
        request: Request<VerifyCertRequest>,
    ) -> Result<Response<VerifyCertResponse>, Status> {
        let req = request.into_inner();

        debug!("Processing certificate verification request");

        match self.ca.verify_certificate(&req.certificate_der) {
            Ok(verified) => {
                if req.check_revocation && self.ocsp.is_revoked(verified.serial) {
                    CaMetrics::record_certificate_verified(false);
                    return Ok(Response::new(VerifyCertResponse {
                        valid: false,
                        device_id: verified.device_id.as_bytes().to_vec(),
                        not_before: verified.not_before.timestamp(),
                        not_after: verified.not_after.timestamp(),
                        serial_number: verified.serial,
                        error_message: "Certificate has been revoked".to_string(),
                    }));
                }

                CaMetrics::record_certificate_verified(true);
                Ok(Response::new(VerifyCertResponse {
                    valid: true,
                    device_id: verified.device_id.as_bytes().to_vec(),
                    not_before: verified.not_before.timestamp(),
                    not_after: verified.not_after.timestamp(),
                    serial_number: verified.serial,
                    error_message: String::new(),
                }))
            }
            Err(e) => {
                CaMetrics::record_certificate_verified(false);
                let error_message = match &e {
                    CaError::CertificateExpired => "Certificate has expired".to_string(),
                    CaError::CertificateNotYetValid => "Certificate is not yet valid".to_string(),
                    CaError::InvalidSignature => "Invalid certificate signature".to_string(),
                    _ => e.to_string(),
                };

                Ok(Response::new(VerifyCertResponse {
                    valid: false,
                    device_id: vec![],
                    not_before: 0,
                    not_after: 0,
                    serial_number: 0,
                    error_message,
                }))
            }
        }
    }

    async fn get_ocsp_response(
        &self,
        request: Request<OcspRequest>,
    ) -> Result<Response<OcspResponse>, Status> {
        let req = request.into_inner();

        debug!(serial = req.serial_number, "Processing OCSP request");
        CaMetrics::record_ocsp_request();

        match self.ocsp.get_response(req.serial_number).await {
            Ok(staple) => {
                let status = match staple.status {
                    CertificateStatus::Good => ProtoCertStatus::Good,
                    CertificateStatus::Revoked => ProtoCertStatus::Revoked,
                    CertificateStatus::Unknown => ProtoCertStatus::Unknown,
                };

                Ok(Response::new(OcspResponse {
                    found: true,
                    ocsp_response: staple.response,
                    this_update: staple.this_update.timestamp(),
                    next_update: staple.next_update.timestamp(),
                    status: status.into(),
                }))
            }
            Err(e) => {
                warn!(serial = req.serial_number, error = %e, "Failed to get OCSP response");
                Ok(Response::new(OcspResponse {
                    found: false,
                    ocsp_response: vec![],
                    this_update: 0,
                    next_update: 0,
                    status: ProtoCertStatus::Unknown.into(),
                }))
            }
        }
    }

    async fn revoke_certificate(
        &self,
        request: Request<RevokeCertRequest>,
    ) -> Result<Response<RevokeCertResponse>, Status> {
        let req = request.into_inner();

        info!(
            serial = req.serial_number,
            reason = %req.reason,
            "Processing certificate revocation request"
        );

        self.ocsp.revoke(req.serial_number, req.reason);
        CaMetrics::record_certificate_revoked();

        Ok(Response::new(RevokeCertResponse {
            success: true,
            error_message: String::new(),
        }))
    }

    async fn get_ca_certificates(
        &self,
        _request: Request<GetCaCertsRequest>,
    ) -> Result<Response<GetCaCertsResponse>, Status> {
        debug!("Processing CA certificates request");

        Ok(Response::new(GetCaCertsResponse {
            root_certificate_der: self.ca.root_certificate_der().to_vec(),
            intermediate_certificate_der: self.ca.intermediate_certificate_der().to_vec(),
            root_public_key: self.ca.root_public_key(),
            intermediate_public_key: self.ca.intermediate_public_key(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CaConfig;

    async fn create_test_service() -> CaServiceImpl {
        let config = CaConfig::default();
        let ca = Arc::new(CertificateAuthority::new(&config).await.unwrap());
        let ocsp = Arc::new(OcspResponder::new(ca.clone()));
        CaServiceImpl::new(ca, ocsp)
    }

    #[tokio::test]
    async fn test_issue_certificate() {
        let service = create_test_service().await;

        let device_id = DeviceId::new();
        let request = Request::new(IssueCertRequest {
            device_id: device_id.as_bytes().to_vec(),
            public_key_classical: vec![0u8; 32],
            public_key_pqc: vec![0u8; 1184],
            lifetime_secs: 3600,
        });

        let response = service.issue_certificate(request).await.unwrap();
        let resp = response.into_inner();

        assert!(resp.success);
        assert!(!resp.certificate_der.is_empty());
        assert!(!resp.signature_classical.is_empty());
        assert!(!resp.signature_pqc.is_empty());
    }

    #[tokio::test]
    async fn test_get_ca_certificates() {
        let service = create_test_service().await;

        let request = Request::new(GetCaCertsRequest {});
        let response = service.get_ca_certificates(request).await.unwrap();
        let resp = response.into_inner();

        assert!(!resp.root_certificate_der.is_empty());
        assert!(!resp.intermediate_certificate_der.is_empty());
        assert!(!resp.root_public_key.is_empty());
        assert!(!resp.intermediate_public_key.is_empty());
    }

    #[tokio::test]
    async fn test_revoke_certificate() {
        let service = create_test_service().await;

        let request = Request::new(RevokeCertRequest {
            serial_number: 1,
            reason: "Test revocation".to_string(),
        });

        let response = service.revoke_certificate(request).await.unwrap();
        let resp = response.into_inner();

        assert!(resp.success);

        let ocsp_request = Request::new(OcspRequest { serial_number: 1 });
        let ocsp_response = service.get_ocsp_response(ocsp_request).await.unwrap();
        let ocsp_resp = ocsp_response.into_inner();

        assert!(ocsp_resp.found);
        assert_eq!(ocsp_resp.status, ProtoCertStatus::Revoked as i32);
    }
}
