//! A gateway identity: a device row of kind `gateway`, a `gateways` row, and a
//! CA-issued credential whose SPIFFE id names the gateway instance.

use avon_crypto::cert::{Certificate, SubjectKind};
use avon_crypto::hybrid::kem::HybridKemKeyPair;
use avon_crypto::hybrid::signature::HybridSigningKeyPair;
use avon_protocol::v2::gateway_service_client::GatewayServiceClient;
use rcgen::{KeyPair, PKCS_ED25519};
use tonic::transport::Channel;
use uuid::Uuid;

use crate::services::{device_channel, ControlFixture};

pub struct TestGateway {
    pub signing: HybridSigningKeyPair,
    pub kem: HybridKemKeyPair,
    pub tls_key_pem: String,
    pub tls_cert_pem: String,
    pub certificate: Certificate,
    pub gateway_id: Uuid,
}

impl TestGateway {
    pub async fn enroll(f: &ControlFixture) -> Self {
        let gateway_id = Uuid::new_v4();
        let tenant = avon_db::DEFAULT_TENANT_ID;
        sqlx::query(
            "INSERT INTO devices (id, tenant_id, name, kind, status) \
             VALUES ($1, $2, 'test-gateway', 'gateway', 'active')",
        )
        .bind(gateway_id)
        .bind(tenant)
        .execute(f.db.pool())
        .await
        .expect("insert gateway device");

        let signing = HybridSigningKeyPair::generate().expect("signing");
        let kem = HybridKemKeyPair::generate().expect("kem");
        let tls_key = KeyPair::generate_for(&PKCS_ED25519).expect("tls key");
        let csr = crate::pki::make_csr(
            &signing,
            &kem.public_key(),
            &tls_key,
            SubjectKind::Gateway,
            "",
            [0; 16],
        );
        let (cred, _serial) = f
            .state()
            .ca
            .issue_device(
                tenant,
                gateway_id,
                csr,
                4,
                vec![format!("spiffe://avon/service/gateway/{gateway_id}")],
            )
            .await
            .expect("issue gateway credential");
        let certificate =
            Certificate::decode(&cred.certificate.expect("certificate").encoded).expect("decode");
        Self {
            signing,
            kem,
            tls_key_pem: tls_key.serialize_pem(),
            tls_cert_pem: cred.tls_certificate_pem,
            certificate,
            gateway_id,
        }
    }

    pub async fn channel(&self, f: &ControlFixture) -> Channel {
        device_channel(f, &self.tls_cert_pem, &self.tls_key_pem).await
    }

    pub async fn client(&self, f: &ControlFixture) -> GatewayServiceClient<Channel> {
        GatewayServiceClient::new(self.channel(f).await)
    }

    /// The gateway's composite signing key, for signing session answers.
    pub fn signing_keypair(&self) -> HybridSigningKeyPair {
        HybridSigningKeyPair::from_secret_bytes(&self.signing.to_secret_bytes())
            .expect("re-import signing key")
    }
}
