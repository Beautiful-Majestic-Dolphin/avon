pub mod software;

use std::path::Path;

use avon_common::ids::{DeviceId, TenantId};
use avon_crypto::cert::{Certificate, ChainVerifier, SubjectKind, TbsCertificate};
use avon_crypto::hybrid::kem::HybridKemPublicKey;
use avon_crypto::hybrid::signature::{Domain, HybridSigningKeyPair};
use avon_protocol::v2::Csr;
use rcgen::KeyPair;

use crate::traits::KeyProvider;

pub use software::SoftwareKeyProvider;

use crate::traits::FingerprintProvider;

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto: {0}")]
    Crypto(#[from] avon_crypto::CryptoError),
    #[error("cert: {0}")]
    Cert(#[from] avon_crypto::cert::CertError),
    #[error("tls: {0}")]
    Tls(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("corrupt: {0}")]
    Corrupt(&'static str),
    #[error("already enrolled")]
    AlreadyEnrolled,
    #[error("not enrolled")]
    NotEnrolled,
    #[error("control: {0}")]
    Control(String),
}

pub struct ChainCache {
    pub root: Certificate,
    pub issuing: Certificate,
    pub verifier: ChainVerifier,
    pub tls_ca_pem: String,
}

impl Clone for ChainCache {
    fn clone(&self) -> Self {
        let verifier = ChainVerifier::new(vec![self.root.clone()]).unwrap_or_else(|_| {
            // `allow` unwrap lint: this is infallible for a previously verified root
            #[allow(clippy::unwrap_used)]
            {
                ChainVerifier::new(vec![self.root.clone()]).unwrap()
            }
        });
        Self {
            root: self.root.clone(),
            issuing: self.issuing.clone(),
            verifier,
            tls_ca_pem: self.tls_ca_pem.clone(),
        }
    }
}

/// What the agent keeps in memory after enrollment or load.
pub struct Identity {
    pub device_id: DeviceId,
    pub tenant_id: TenantId,
    pub certificate: Certificate,
    pub tls_cert_pem: String,
    pub chain: ChainCache,
    pub provider: Box<dyn crate::traits::KeyProvider>,
    pub renew_after: i64,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedIdentity {
    device_id: String,
    tenant_id: String,
    certificate_hex: String,
    tls_cert_pem: String,
    root_hex: String,
    issuing_hex: String,
    tls_ca_pem: String,
    renew_after: i64,
    control: String,
}

fn write_private(path: &Path, data: &[u8]) -> Result<(), IdentityError> {
    let tmp = path.with_extension("tmp");
    {
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?
        };
        #[cfg(not(unix))]
        let mut f = std::fs::File::create(&tmp)?;
        use std::io::Write;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn make_csr(
    signing: &HybridSigningKeyPair,
    kem: &HybridKemPublicKey,
    tls_key: &KeyPair,
    tenant: &str,
    subject: [u8; 16],
    kind: SubjectKind,
) -> Csr {
    let template = TbsCertificate {
        version: 2,
        serial: [0; 16],
        tenant_id: tenant.to_string(),
        subject_id: subject,
        kind,
        signing_key: signing.verifying_key(),
        kem_key: Some(kem.clone()),
        not_before: 0,
        not_after: 0,
        issuer_key_id: [0; 32],
        sans: vec![],
        tls_cert_sha256: None,
    }
    .encode();
    #[allow(clippy::expect_used)]
    let proof = signing
        .sign(Domain::Csr, &template)
        .expect("csr sign")
        .to_bytes();
    #[allow(clippy::expect_used)]
    let tls_csr_pem = rcgen::CertificateParams::new(Vec::<String>::new())
        .expect("params")
        .serialize_request(tls_key)
        .expect("csr")
        .pem()
        .expect("pem");
    Csr {
        tbs_template: template,
        proof,
        tls_csr_pem,
    }
}

/// Enroll against `control` (e.g. `https://localhost:8443`) with `token`,
/// pinning the server certificate against `ca_pem` and SNI `server_name`.
/// Writes `identity.key`, `identity.bin`, `identity.json` and `ca.pem` into
/// `data_dir`.
pub async fn enroll(
    control: &str,
    token: &str,
    data_dir: &Path,
    ca_pem: &[u8],
    server_name: &str,
    fingerprint: &dyn FingerprintProvider,
    version: &str,
) -> Result<Identity, IdentityError> {
    if data_dir.join("identity.json").exists() {
        return Err(IdentityError::AlreadyEnrolled);
    }
    std::fs::create_dir_all(data_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))?;
    }

    let provider = SoftwareKeyProvider::generate(data_dir)?;
    provider.save()?;

    // Build a CSR with empty tenant/subject as the control expects for new devices.
    let tls_key =
        KeyPair::from_pem(provider.tls_key_pem()).map_err(|e| IdentityError::Tls(e.to_string()))?;
    let csr = make_csr(
        provider.signing(),
        &provider.kem().public_key(),
        &tls_key,
        "",
        [0; 16],
        SubjectKind::Device,
    );

    // Anonymous TLS channel pinned to the provided CA.
    let fp = fingerprint.collect();
    let url = control.to_string();
    let ca_bytes = ca_pem.to_vec();
    let server_name = server_name.to_string();
    let token_s = token.to_string();
    let version_s = version.to_string();

    let channel = tonic::transport::Endpoint::from_shared(url.clone())
        .map_err(|e| IdentityError::Control(e.to_string()))?
        .tls_config(
            tonic::transport::ClientTlsConfig::new()
                .domain_name(server_name.clone())
                .ca_certificate(tonic::transport::Certificate::from_pem(ca_bytes.clone())),
        )
        .map_err(|e| IdentityError::Tls(e.to_string()))?
        .connect()
        .await
        .map_err(|e| IdentityError::Control(e.to_string()))?;

    let mut client = avon_protocol::v2::agent_service_client::AgentServiceClient::new(channel);
    let resp = client
        .enroll(avon_protocol::v2::EnrollRequest {
            token: token_s,
            csr: Some(csr),
            fingerprint: Some(fp),
            attestation: None,
            requested_name: "agent".into(),
            agent_version: version_s,
        })
        .await
        .map_err(|e| IdentityError::Control(e.to_string()))?
        .into_inner();

    let device_id = avon_protocol::bytes_to_uuid(
        &resp
            .device_id
            .ok_or(IdentityError::Corrupt("device_id"))?
            .value,
    )
    .map_err(|e| IdentityError::Protocol(e.to_string()))?;
    let tenant_id = avon_protocol::bytes_to_uuid(
        &resp
            .tenant_id
            .ok_or(IdentityError::Corrupt("tenant_id"))?
            .value,
    )
    .map_err(|e| IdentityError::Protocol(e.to_string()))?;
    let cred = resp
        .credential
        .ok_or(IdentityError::Corrupt("credential"))?;
    let certificate = Certificate::decode(
        &cred
            .certificate
            .ok_or(IdentityError::Corrupt("cert"))?
            .encoded,
    )?;
    let tls_cert_pem = cred.tls_certificate_pem.clone();
    let chain_pb = cred.chain.ok_or(IdentityError::Corrupt("chain"))?;
    let root = Certificate::decode(&chain_pb.root.ok_or(IdentityError::Corrupt("root"))?.encoded)?;
    let issuing = Certificate::decode(
        &chain_pb
            .issuing
            .ok_or(IdentityError::Corrupt("issuing"))?
            .encoded,
    )?;
    let tls_ca_pem = chain_pb.tls_ca_pem.clone();
    let renew_after = cred.renew_after_unix;

    // Verify chain.
    let verifier = ChainVerifier::new(vec![root.clone()])?;
    let now = chrono::Utc::now().timestamp();
    verifier.verify(&certificate, std::slice::from_ref(&issuing), now)?;
    // Check tls_cert_sha256 binds to the returned leaf.
    let tls_der = pem::parse(&tls_cert_pem)
        .map_err(|e| IdentityError::Tls(e.to_string()))?
        .into_contents();
    let hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&tls_der).into()
    };
    if certificate.tbs.tls_cert_sha256 != Some(hash) {
        return Err(IdentityError::Corrupt("tls binding"));
    }

    // Persist. Store the full CA bundle provided for enrollment as tls_ca_pem,
    // so later control connections can verify the server (which is signed by
    // the test PKI's CA, not necessarily the chain's TLS CA).
    let full_ca_pem = String::from_utf8(ca_pem.to_vec()).unwrap_or(tls_ca_pem.clone());
    let persisted = PersistedIdentity {
        device_id: device_id.to_string(),
        tenant_id: tenant_id.to_string(),
        certificate_hex: hex::encode(certificate.encode()),
        tls_cert_pem: tls_cert_pem.clone(),
        root_hex: hex::encode(root.encode()),
        issuing_hex: hex::encode(issuing.encode()),
        tls_ca_pem: full_ca_pem.clone(),
        renew_after,
        control: control.to_string(),
    };
    write_private(
        &data_dir.join("identity.json"),
        &serde_json::to_vec_pretty(&persisted).map_err(|_| IdentityError::Corrupt("encode"))?,
    )?;
    write_private(data_dir.join("ca.pem").as_path(), ca_pem)?;
    // Also keep the provider's sealed files already written via save().
    // Update the TLS key in the sealed store to match the cert we received?
    // The cert was issued for the key we generated, so no need to re-save.

    let verifying_chain = ChainVerifier::new(vec![root.clone()])?;
    Ok(Identity {
        device_id: DeviceId::from(device_id),
        tenant_id: TenantId::from(tenant_id),
        certificate,
        tls_cert_pem,
        chain: ChainCache {
            root,
            issuing,
            verifier: verifying_chain,
            tls_ca_pem: full_ca_pem,
        },
        provider: Box::new(provider),
        renew_after,
    })
}

pub async fn load(data_dir: &Path) -> Result<Identity, IdentityError> {
    let provider = SoftwareKeyProvider::load(data_dir)?;
    let data = std::fs::read(data_dir.join("identity.json"))?;
    let persisted: PersistedIdentity =
        serde_json::from_slice(&data).map_err(|_| IdentityError::Corrupt("json"))?;
    let device_id = persisted
        .device_id
        .parse::<uuid::Uuid>()
        .map_err(|_| IdentityError::Corrupt("device_id"))?;
    let tenant_id = persisted
        .tenant_id
        .parse::<uuid::Uuid>()
        .map_err(|_| IdentityError::Corrupt("tenant_id"))?;
    let cert_bytes =
        hex::decode(&persisted.certificate_hex).map_err(|_| IdentityError::Corrupt("cert hex"))?;
    let certificate = Certificate::decode(&cert_bytes)?;
    let root = Certificate::decode(
        &hex::decode(&persisted.root_hex).map_err(|_| IdentityError::Corrupt("root hex"))?,
    )?;
    let issuing = Certificate::decode(
        &hex::decode(&persisted.issuing_hex).map_err(|_| IdentityError::Corrupt("issuing hex"))?,
    )?;
    let verifier = ChainVerifier::new(vec![root.clone()])?;
    let now = chrono::Utc::now().timestamp();
    verifier.verify(&certificate, std::slice::from_ref(&issuing), now)?;

    Ok(Identity {
        device_id: DeviceId::from(device_id),
        tenant_id: TenantId::from(tenant_id),
        certificate,
        tls_cert_pem: persisted.tls_cert_pem,
        chain: ChainCache {
            root,
            issuing,
            verifier,
            tls_ca_pem: persisted.tls_ca_pem,
        },
        provider: Box::new(provider),
        renew_after: persisted.renew_after,
    })
}
