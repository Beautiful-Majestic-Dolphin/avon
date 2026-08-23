//! Test PKI: an Ed25519 X.509 CA for TLS identities plus an AVON hybrid
//! root/issuing pair for certificates in the AVON format.

use std::path::Path;

use avon_config::TlsArgs;
use avon_crypto::cert::{Certificate, SubjectKind, TbsCertificate};
use avon_crypto::hybrid::kem::HybridKemPublicKey;
use avon_crypto::hybrid::signature::{Domain, HybridSigningKeyPair};
use avon_protocol::v2::Csr;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType, PKCS_ED25519,
};

pub struct TlsIdentity {
    pub cert_pem: String,
    pub key_pem: String,
}

pub struct TestPki {
    pub tls_ca_pem: String,
    pub tls_ca_cert: rcgen::Certificate,
    pub tls_ca_key: KeyPair,
    pub root_kp: HybridSigningKeyPair,
    pub root: Certificate,
    pub issuing_kp: HybridSigningKeyPair,
    pub issuing: Certificate,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

impl TestPki {
    pub fn new() -> Self {
        let tls_ca_key = KeyPair::generate_for(&PKCS_ED25519).expect("ca key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .distinguished_name
            .push(DnType::CommonName, "AVON Test TLS CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let tls_ca_cert = params.self_signed(&tls_ca_key).expect("self sign");
        let tls_ca_pem = tls_ca_cert.pem();

        let root_kp = HybridSigningKeyPair::generate().expect("root kp");
        let root = Certificate::sign(
            TbsCertificate {
                version: 2,
                serial: [1; 16],
                tenant_id: String::new(),
                subject_id: [0; 16],
                kind: SubjectKind::RootCa,
                signing_key: root_kp.verifying_key(),
                kem_key: None,
                not_before: now() - 60,
                not_after: now() + 10 * 365 * 86_400,
                issuer_key_id: root_kp.verifying_key().key_id(),
                sans: vec![],
                tls_cert_sha256: None,
                hardware_binding: None,
            },
            &root_kp,
        )
        .expect("root cert");
        let issuing_kp = HybridSigningKeyPair::generate().expect("issuing kp");
        let issuing = Certificate::sign(
            TbsCertificate {
                version: 2,
                serial: [2; 16],
                tenant_id: String::new(),
                subject_id: [0; 16],
                kind: SubjectKind::IssuingCa,
                signing_key: issuing_kp.verifying_key(),
                kem_key: None,
                not_before: now() - 60,
                not_after: now() + 2 * 365 * 86_400,
                issuer_key_id: root_kp.verifying_key().key_id(),
                sans: vec![],
                tls_cert_sha256: None,
                hardware_binding: None,
            },
            &root_kp,
        )
        .expect("issuing cert");
        Self {
            tls_ca_pem,
            tls_ca_cert,
            tls_ca_key,
            root_kp,
            root,
            issuing_kp,
            issuing,
        }
    }

    pub fn issue_tls(&self, spiffe: &str, dns: &[&str]) -> TlsIdentity {
        let key = KeyPair::generate_for(&PKCS_ED25519).expect("leaf key");
        let mut params =
            CertificateParams::new(dns.iter().map(|d| d.to_string()).collect::<Vec<_>>())
                .expect("params");
        params
            .subject_alt_names
            .push(SanType::URI(spiffe.try_into().expect("uri")));
        params.distinguished_name.push(DnType::CommonName, spiffe);
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let cert = params
            .signed_by(&key, &self.tls_ca_cert, &self.tls_ca_key)
            .expect("sign leaf");
        TlsIdentity {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }

    /// Write `<name>.crt`, `<name>.key` and the shared `trust-ca.crt` into `dir`
    /// and return matching TlsArgs. The trust bundle deliberately does not use
    /// `ca.crt`: that would collide with the leaf files when `name` is "ca".
    pub fn write_to(&self, dir: &Path, name: &str, spiffe: &str, dns: &[&str]) -> TlsArgs {
        let id = self.issue_tls(spiffe, dns);
        let cert = dir.join(format!("{name}.crt"));
        let key = dir.join(format!("{name}.key"));
        let ca = dir.join("trust-ca.crt");
        std::fs::write(&cert, id.cert_pem).expect("write cert");
        std::fs::write(&key, id.key_pem).expect("write key");
        std::fs::write(&ca, &self.tls_ca_pem).expect("write ca");
        TlsArgs { cert, key, ca }
    }
}

impl Default for TestPki {
    fn default() -> Self {
        Self::new()
    }
}

/// A CSR proving possession of the hybrid signing key and carrying a PKCS#10
/// request for the Ed25519 TLS key. Serial, issuer and validity are zero: the
/// CA sets them.
pub fn make_csr(
    signing: &HybridSigningKeyPair,
    kem: &HybridKemPublicKey,
    tls_key: &KeyPair,
    kind: SubjectKind,
    tenant: &str,
    subject: [u8; 16],
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
        hardware_binding: None,
    }
    .encode();
    let proof = signing
        .sign(Domain::Csr, &template)
        .expect("csr proof")
        .to_bytes();
    let params = CertificateParams::new(Vec::<String>::new()).expect("params");
    let tls_csr_pem = params
        .serialize_request(tls_key)
        .expect("csr")
        .pem()
        .expect("pem");
    Csr {
        tbs_template: template,
        proof,
        tls_csr_pem,
        hardware_binding: Vec::new(),
    }
}
