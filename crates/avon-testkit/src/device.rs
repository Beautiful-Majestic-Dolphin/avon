//! A device that can enrol, authenticate and then call the agent API the way a
//! real agent does: composite keys of its own, mTLS with the CA-issued leaf,
//! and a session token recovered by decapsulating with its static KEM key.

use avon_crypto::cert::{Certificate, SubjectKind};
use avon_crypto::hybrid::kem::{HybridKemCiphertext, HybridKemKeyPair};
use avon_crypto::hybrid::signature::{Domain, HybridSigningKeyPair};
use avon_crypto::session_token::open_session_token;
use avon_protocol::v2::agent_service_client::AgentServiceClient;
use avon_protocol::v2::gateway_service_client::GatewayServiceClient;
use avon_protocol::v2::{
    auth_message, AuthHello, AuthMessage, AuthProof, Certificate as PbCert, Csr, EnrollRequest,
    Fingerprint,
};
use rcgen::{KeyPair, PKCS_ED25519};
use sha2::{Digest, Sha256};
use tonic::codegen::InterceptedService;
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::transport::Channel;
use tonic::{Request, Status};
use uuid::Uuid;

use crate::services::{agent_client_anonymous, device_channel, ControlFixture};

#[derive(Clone)]
pub struct SessionInterceptor {
    token: String,
}

impl Interceptor for SessionInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        req.metadata_mut().insert(
            "x-avon-session",
            MetadataValue::try_from(self.token.clone()).expect("token metadata"),
        );
        Ok(req)
    }
}

pub type DeviceClient = AgentServiceClient<InterceptedService<Channel, SessionInterceptor>>;

pub struct TestDevice {
    pub signing: HybridSigningKeyPair,
    pub kem: HybridKemKeyPair,
    pub tls_key_pem: String,
    pub tls_cert_pem: String,
    pub certificate: Certificate,
    pub device_id: Uuid,
    pub tenant_id: Uuid,
}

fn csr_for(signing: &HybridSigningKeyPair, kem: &HybridKemKeyPair, tls_key: &KeyPair) -> Csr {
    crate::pki::make_csr(
        signing,
        &kem.public_key(),
        tls_key,
        SubjectKind::Device,
        "",
        [0; 16],
    )
}

impl TestDevice {
    /// Insert an enrollment token, enrol with it, and keep the credential.
    pub async fn enroll(f: &ControlFixture, token: &str) -> Self {
        let hash = avon_control::store::hash_token(token);
        sqlx::query(
            "INSERT INTO enrollment_tokens (tenant_id, token_hash, max_uses, expires_at) \
             VALUES ($1, $2, 1, now() + interval '1 hour')",
        )
        .bind(avon_db::DEFAULT_TENANT_ID)
        .bind(&hash[..])
        .execute(f.db.pool())
        .await
        .expect("insert token");

        let signing = HybridSigningKeyPair::generate().expect("signing");
        let kem = HybridKemKeyPair::generate().expect("kem");
        let tls_key = KeyPair::generate_for(&PKCS_ED25519).expect("tls key");
        let mut client = agent_client_anonymous(f).await;
        let resp = client
            .enroll(EnrollRequest {
                token: token.into(),
                csr: Some(csr_for(&signing, &kem, &tls_key)),
                fingerprint: Some(Fingerprint {
                    version: 2,
                    hash: vec![7; 32],
                    identifier_kinds: vec!["machine-id".into()],
                }),
                attestation: None,
                requested_name: "test-device".into(),
                agent_version: "0.2.0".into(),
            })
            .await
            .expect("enroll")
            .into_inner();

        let device_id = avon_protocol::bytes_to_uuid(&resp.device_id.expect("device id").value)
            .expect("device uuid");
        let tenant_id = avon_protocol::bytes_to_uuid(&resp.tenant_id.expect("tenant id").value)
            .expect("tenant uuid");
        let cred = resp.credential.expect("credential");
        let certificate =
            Certificate::decode(&cred.certificate.expect("certificate").encoded).expect("decode");
        Self {
            signing,
            kem,
            tls_key_pem: tls_key.serialize_pem(),
            tls_cert_pem: cred.tls_certificate_pem,
            certificate,
            device_id,
            tenant_id,
        }
    }

    fn tls_cert_der(&self) -> Vec<u8> {
        pem::parse(&self.tls_cert_pem)
            .expect("tls cert pem")
            .into_contents()
    }

    fn tls_cert_sha256(&self) -> [u8; 32] {
        Sha256::digest(self.tls_cert_der()).into()
    }

    pub async fn channel(&self, f: &ControlFixture) -> Channel {
        device_channel(f, &self.tls_cert_pem, &self.tls_key_pem).await
    }

    /// Run hello → challenge → proof and recover the session token.
    pub async fn authenticate_raw(&self, f: &ControlFixture) -> Result<[u8; 32], Status> {
        let channel = self.channel(f).await;
        let mut client = AgentServiceClient::new(channel);
        let (tx, rx) = tokio::sync::mpsc::channel::<AuthMessage>(4);
        let mut down = client
            .authenticate(tokio_stream::wrappers::ReceiverStream::new(rx))
            .await?
            .into_inner();

        tx.send(AuthMessage {
            msg: Some(auth_message::Msg::Hello(AuthHello {
                certificate: Some(PbCert {
                    encoded: self.certificate.encode(),
                }),
            })),
        })
        .await
        .map_err(|_| Status::cancelled("send hello"))?;

        let challenge = match down.message().await?.and_then(|m| m.msg) {
            Some(auth_message::Msg::Challenge(c)) => c,
            _ => return Err(Status::internal("expected challenge")),
        };
        let nonce: [u8; 32] = challenge
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| Status::internal("nonce"))?;
        let server_hash: [u8; 32] = challenge
            .server_tls_cert_sha256
            .as_slice()
            .try_into()
            .map_err(|_| Status::internal("server hash"))?;
        let msg = avon_control::auth::auth_message(&nonce, &self.tls_cert_sha256(), &server_hash);
        let sig = self
            .signing
            .sign(Domain::Auth, &msg)
            .map_err(|_| Status::internal("sign"))?;
        tx.send(AuthMessage {
            msg: Some(auth_message::Msg::Proof(AuthProof {
                signature: sig.to_bytes(),
            })),
        })
        .await
        .map_err(|_| Status::cancelled("send proof"))?;

        let result = match down.message().await?.and_then(|m| m.msg) {
            Some(auth_message::Msg::Result(r)) => r,
            _ => return Err(Status::internal("expected result")),
        };
        let ct = HybridKemCiphertext::from_bytes(&result.kem_ciphertext)
            .map_err(|_| Status::internal("ciphertext"))?;
        let ss = self
            .kem
            .decapsulate(&ct)
            .map_err(|_| Status::internal("decapsulate"))?;
        open_session_token(&result.sealed_token, &ss, &nonce)
            .map_err(|_| Status::unauthenticated("could not open session token"))
    }

    pub async fn authenticate(&self, f: &ControlFixture) -> Result<DeviceClient, Status> {
        let token = self.authenticate_raw(f).await?;
        Ok(self.client_with_token(f, token).await)
    }

    pub async fn client_with_token(&self, f: &ControlFixture, token: [u8; 32]) -> DeviceClient {
        use base64ct::Encoding;
        let channel = self.channel(f).await;
        AgentServiceClient::with_interceptor(
            channel,
            SessionInterceptor {
                token: base64ct::Base64UrlUnpadded::encode_string(&token),
            },
        )
    }

    pub async fn client_without_token(&self, f: &ControlFixture) -> AgentServiceClient<Channel> {
        AgentServiceClient::new(self.channel(f).await)
    }

    pub async fn gateway_client(&self, f: &ControlFixture) -> GatewayServiceClient<Channel> {
        GatewayServiceClient::new(self.channel(f).await)
    }

    /// Keep the certificate and TLS identity, sign with a different key.
    pub fn swap_signing_key(&mut self) {
        self.signing = HybridSigningKeyPair::generate().expect("signing");
    }

    /// Keep the certificate, lose the KEM secret it names.
    pub fn swap_kem_key(&mut self) {
        self.kem = HybridKemKeyPair::generate().expect("kem");
    }

    /// A renewal request: fresh TLS key, same composite identity.
    pub fn new_csr(&mut self) -> Csr {
        let tls_key = KeyPair::generate_for(&PKCS_ED25519).expect("tls key");
        let csr = crate::pki::make_csr(
            &self.signing,
            &self.kem.public_key(),
            &tls_key,
            SubjectKind::Device,
            &self.tenant_id.to_string(),
            *self.device_id.as_bytes(),
        );
        self.tls_key_pem = tls_key.serialize_pem();
        csr
    }

    /// Adopt a renewed credential.
    pub fn adopt(&mut self, tls_cert_pem: String, certificate: Certificate) {
        self.tls_cert_pem = tls_cert_pem;
        self.certificate = certificate;
    }
}
