use std::net::IpAddr;

use avon_crypto::cert::{HardwareBinding, SubjectKind, TbsCertificate};
use avon_protocol::v2::{EnrollRequest, EnrollResponse, Uuid as PbUuid};
use sqlx::PgPool;
use tonic::Status;
use uuid::Uuid;

use crate::ca_client::CaClient;
use crate::store::{self, EnrollError};

/// One message for every rejection reason, so a caller cannot use enrollment
/// as an oracle for which tokens exist.
fn rejected() -> Status {
    Status::permission_denied("enrollment rejected")
}

pub async fn enroll(
    pool: &PgPool,
    ca: &CaClient,
    req: EnrollRequest,
    client_ip: Option<IpAddr>,
) -> Result<EnrollResponse, Status> {
    if req.token.is_empty() || req.token.len() > 256 {
        return Err(rejected());
    }
    let csr = req
        .csr
        .ok_or_else(|| Status::invalid_argument("csr required"))?;
    let template = TbsCertificate::decode(&csr.tbs_template)
        .map_err(|_| Status::invalid_argument("csr template"))?;
    if template.kind != SubjectKind::Device
        || !template.tenant_id.is_empty()
        || template.subject_id != [0; 16]
    {
        return Err(Status::invalid_argument(
            "csr template must be a device template with empty tenant and zero subject",
        ));
    }
    let fingerprint = req
        .fingerprint
        .as_ref()
        .filter(|f| f.version == 2 && f.hash.len() == 32)
        .map(|f| f.hash.clone());

    let token_hash = store::hash_token(&req.token);
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| Status::unavailable("database"))?;
    let token = match store::consume_token(&mut tx, &token_hash).await {
        Ok(t) => t,
        Err(EnrollError::Db(e)) => {
            tracing::error!(error = %e, "enrollment db error");
            return Err(Status::unavailable("database"));
        }
        Err(e) => {
            tracing::warn!(reason = %e, "enrollment rejected");
            return Err(rejected());
        }
    };
    if let Some(expected) = &token.expected_fingerprint {
        if fingerprint.as_deref() != Some(expected.as_slice()) {
            tracing::warn!(reason = "fingerprint mismatch", "enrollment rejected");
            return Err(rejected());
        }
    }
    if token.require_attestation
        && req
            .attestation
            .as_ref()
            .map(|a| a.format == "none" || a.evidence.is_empty())
            .unwrap_or(true)
    {
        tracing::warn!(reason = "attestation required", "enrollment rejected");
        return Err(rejected());
    }

    let device_id = Uuid::new_v4();
    let name = token
        .device_name
        .clone()
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| {
            if req.requested_name.is_empty() {
                device_id.to_string()
            } else {
                req.requested_name.chars().take(255).collect()
            }
        });
    let status = if token.require_approval {
        "pending"
    } else {
        "active"
    };
    let key_provider = if csr.hardware_binding.is_empty() {
        "software".to_string()
    } else {
        let binding = HardwareBinding::decode(&csr.hardware_binding)
            .map_err(|_| Status::invalid_argument("binding decode"))?;
        // Verify binding against the keys in the CSR template and the device hint (fingerprint hash)
        if let Some(kem) = &template.kem_key {
            let hint = fingerprint.clone().unwrap_or_default();
            avon_keystore::verify_binding(&binding, &template.signing_key, kem, &hint).map_err(
                |e| {
                    tracing::warn!(reason = %e, "binding verification failed");
                    Status::invalid_argument("binding verification failed")
                },
            )?;
        } else {
            return Err(Status::invalid_argument("kem required for binding"));
        }
        binding.provider.as_str().to_string()
    };

    // The CSR is forwarded unchanged: its proof covers the template the device
    // signed (empty tenant, zero subject); the CA fills both from the request.
    store::create_device(
        &mut tx,
        token.tenant_id,
        device_id,
        &name,
        &token.device_kind,
        status,
        token.device_class_id,
        fingerprint.as_deref(),
        &key_provider,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "create device");
        Status::unavailable("database")
    })?;
    store::add_device_pods(&mut tx, device_id, &token.pod_ids)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "add device pods");
            Status::unavailable("database")
        })?;
    // Overlay addresses are allocated once, in the same transaction, so a
    // device's address is fixed from the moment it exists.
    crate::ipam::allocate(&mut tx, token.tenant_id, device_id.into())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "overlay address allocation");
            Status::unavailable("database")
        })?;
    store::record_enrollment(&mut tx, token.id, device_id, client_ip)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "record enrollment");
            Status::unavailable("database")
        })?;

    let tenant = token.tenant_id.as_uuid();
    let sans = vec![format!("spiffe://avon/{tenant}/device/{device_id}")];
    let (credential, _serial) = ca
        .issue_device(tenant, device_id, csr, 3, sans)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "ca issuance failed");
            Status::unavailable("certificate authority")
        })?;
    tx.commit()
        .await
        .map_err(|_| Status::unavailable("database"))?;
    metrics::counter!("avon_control_enrollments_total", "status" => status).increment(1);
    tracing::info!(%device_id, tenant = %tenant, status, "device enrolled");

    Ok(EnrollResponse {
        device_id: Some(PbUuid {
            value: device_id.as_bytes().to_vec(),
        }),
        tenant_id: Some(PbUuid {
            value: tenant.as_bytes().to_vec(),
        }),
        credential: Some(credential),
        status: status.to_string(),
    })
}
