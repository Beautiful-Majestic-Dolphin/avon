use avon_common::ids::TenantId;
use avon_crypto::cert::{Certificate, HardwareBinding, SubjectKind, TbsCertificate};
use avon_crypto::hybrid::signature::{Domain, HybridSignature};
use avon_protocol::v2::Csr;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::x509::sign_tls_csr;
use super::PkiError;
use crate::keys::CaKeys;

pub const DEVICE_LIFETIME_SECS: i64 = 86_400;
pub const SERVICE_LIFETIME_SECS: i64 = 7 * 86_400;

pub struct CsrData {
    pub template: TbsCertificate,
    pub tls_csr_pem: String,
    pub hardware_binding: Option<HardwareBinding>,
}

/// Verify proof of possession and template hygiene. Validity, serial and
/// issuer are set by the CA, so the template must carry zeros for them.
pub fn verify_csr(csr: &Csr) -> Result<CsrData, PkiError> {
    let template = TbsCertificate::decode(&csr.tbs_template)
        .map_err(|e| PkiError::CsrTemplate(e.to_string()))?;
    if !matches!(
        template.kind,
        SubjectKind::Device | SubjectKind::Gateway | SubjectKind::Service
    ) {
        return Err(PkiError::CsrTemplate(
            "kind must be device, gateway or service".into(),
        ));
    }
    if template.serial != [0; 16]
        || template.issuer_key_id != [0; 32]
        || template.not_before != 0
        || template.not_after != 0
    {
        return Err(PkiError::CsrTemplate(
            "serial, issuer and validity must be zero".into(),
        ));
    }
    if template.kem_key.is_none() {
        return Err(PkiError::CsrTemplate("kem key required".into()));
    }
    let proof = HybridSignature::from_bytes(&csr.proof).map_err(|_| PkiError::CsrProof)?;
    template
        .signing_key
        .verify(Domain::Csr, &csr.tbs_template, &proof)
        .map_err(|_| PkiError::CsrProof)?;
    let hardware_binding = if csr.hardware_binding.is_empty() {
        None
    } else {
        Some(
            HardwareBinding::decode(&csr.hardware_binding)
                .map_err(|e| PkiError::CsrTemplate(e.to_string()))?,
        )
    };
    Ok(CsrData {
        template,
        tls_csr_pem: csr.tls_csr_pem.clone(),
        hardware_binding,
    })
}

pub struct Issued {
    pub certificate: Certificate,
    pub tls_cert_pem: String,
    pub tls_cert_der: Vec<u8>,
    pub serial: [u8; 16],
    pub not_after: i64,
}

pub struct Issuer<'a> {
    pub keys: &'a CaKeys,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Issuer<'_> {
    pub fn issue(
        &self,
        csr: CsrData,
        kind: SubjectKind,
        tenant: Option<TenantId>,
        subject: Uuid,
        sans: Vec<String>,
        lifetime_secs: i64,
    ) -> Result<Issued, PkiError> {
        let serial =
            avon_crypto::random::random_bytes_fixed::<16>().map_err(|_| PkiError::Random)?;
        let not_before = now() - 300;
        let not_after = now() + lifetime_secs;
        let (tls_cert_pem, tls_cert_der) = sign_tls_csr(
            self.keys,
            &csr.tls_csr_pem,
            &serial,
            &sans,
            not_before,
            not_after,
        )?;
        let tbs = TbsCertificate {
            version: 2,
            serial,
            tenant_id: tenant.map(|t| t.to_string()).unwrap_or_default(),
            subject_id: *subject.as_bytes(),
            kind,
            signing_key: csr.template.signing_key,
            kem_key: csr.template.kem_key,
            not_before,
            not_after,
            issuer_key_id: self.keys.issuing.verifying_key().key_id(),
            sans,
            tls_cert_sha256: Some(Sha256::digest(&tls_cert_der).into()),
            hardware_binding: csr.hardware_binding,
        };
        let certificate = Certificate::sign(tbs, &self.keys.issuing)?;
        Ok(Issued {
            certificate,
            tls_cert_pem,
            tls_cert_der,
            serial,
            not_after,
        })
    }
}
