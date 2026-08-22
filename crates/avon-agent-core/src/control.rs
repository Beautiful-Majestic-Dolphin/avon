use std::sync::Arc;

use avon_crypto::cert::Certificate;
use avon_crypto::hybrid::kem::HybridKemCiphertext;
use avon_crypto::hybrid::signature::Domain;
use avon_crypto::session_token::open_session_token;
use avon_protocol::v2::agent_service_client::AgentServiceClient;
use avon_protocol::v2::{
    auth_message, AuthHello, AuthMessage, AuthProof, Certificate as PbCert, OpenSessionRequest,
    OpenSessionResponse, PulseDown, PulseUp, SessionReport, WhoAmIResponse,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tonic::codegen::InterceptedService;
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::transport::Channel;
use tonic::{Request, Status};

use crate::identity::Identity;
use crate::AgentError;

#[derive(Clone)]
pub(crate) struct SessionInterceptor {
    pub(crate) token: String,
}

impl Interceptor for SessionInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        let val = MetadataValue::try_from(self.token.clone())
            .map_err(|_| Status::internal("invalid session token"))?;
        req.metadata_mut().insert("x-avon-session", val);
        Ok(req)
    }
}

pub type DeviceChannel = Channel;
pub(crate) type AuthenticatedClient =
    AgentServiceClient<InterceptedService<Channel, SessionInterceptor>>;

fn tls_client_hash(cert_pem: &str) -> Result<[u8; 32], AgentError> {
    let der = pem::parse(cert_pem)
        .map_err(|e| AgentError::Protocol(e.to_string()))?
        .into_contents();
    Ok(Sha256::digest(&der).into())
}

fn auth_message_bytes(nonce: &[u8; 32], client_hash: &[u8; 32], server_hash: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(96);
    m.extend_from_slice(nonce);
    m.extend_from_slice(client_hash);
    m.extend_from_slice(server_hash);
    m
}

pub struct ControlClient {
    channel: Channel,
    token: Arc<RwLock<Option<String>>>,
    gateway_certs: Arc<RwLock<Vec<Certificate>>>,
    /// The server's TLS cert sha256 as seen in challenge.
    server_cert_sha256: Arc<RwLock<Option<[u8; 32]>>>,
}

impl ControlClient {
    /// Connect with mTLS using the device's TLS cert and the CA bundle from
    /// `identity.chain.tls_ca_pem`, or from `data_dir/ca.pem` if the chain's
    /// PEM is empty. `control` is like `https://host:port`.
    pub async fn connect(identity: &Identity, control: &str) -> Result<Self, AgentError> {
        avon_tls::install_default_provider();
        let ca_pem = if identity.chain.tls_ca_pem.is_empty() {
            // Fallback to file? For now require chain.
            return Err(AgentError::Protocol("no tls ca".into()));
        } else {
            identity.chain.tls_ca_pem.clone()
        };
        // Need to know control server name: derive from URL or use "localhost" for tests.
        let server_name = url_for_server_name(control);
        let channel: Channel = tonic::transport::Endpoint::from_shared(control.to_string())
            .map_err(|e| AgentError::Protocol(e.to_string()))?
            .tls_config(
                tonic::transport::ClientTlsConfig::new()
                    .domain_name(server_name)
                    .ca_certificate(tonic::transport::Certificate::from_pem(ca_pem.as_bytes()))
                    .identity(tonic::transport::Identity::from_pem(
                        identity.tls_cert_pem.as_bytes(),
                        identity.provider.tls_key_pem().as_bytes(),
                    )),
            )
            .map_err(|e| AgentError::Tls(e.to_string()))?
            .connect()
            .await
            .map_err(|e: tonic::transport::Error| AgentError::Transport(e.to_string()))?;
        Ok(Self {
            channel,
            token: Arc::new(RwLock::new(None)),
            gateway_certs: Arc::new(RwLock::new(vec![])),
            server_cert_sha256: Arc::new(RwLock::new(None)),
        })
    }

    /// Connect without yet having a token: used for enrollment TLS; not for
    /// authenticated RPCs. For the agent we always connect with mTLS.
    pub async fn connect_with_ca(
        control: &str,
        ca_pem: &[u8],
        server_name: &str,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<Channel, AgentError> {
        avon_tls::install_default_provider();
        let ch: Channel = tonic::transport::Endpoint::from_shared(control.to_string())
            .map_err(|e| AgentError::Protocol(e.to_string()))?
            .tls_config(
                tonic::transport::ClientTlsConfig::new()
                    .domain_name(server_name)
                    .ca_certificate(tonic::transport::Certificate::from_pem(ca_pem))
                    .identity(tonic::transport::Identity::from_pem(cert_pem, key_pem)),
            )
            .map_err(|e| AgentError::Tls(e.to_string()))?
            .connect()
            .await
            .map_err(|e: tonic::transport::Error| AgentError::Transport(e.to_string()))?;
        Ok(ch)
    }

    fn channel_clone(&self) -> Channel {
        self.channel.clone()
    }

    pub async fn authenticate(&self, identity: &Identity) -> Result<(), AgentError> {
        let client_hash = tls_client_hash(&identity.tls_cert_pem)?;
        let mut client = AgentServiceClient::new(self.channel_clone());
        let (tx, rx) = tokio::sync::mpsc::channel::<AuthMessage>(4);
        let mut down = client
            .authenticate(tokio_stream::wrappers::ReceiverStream::new(rx))
            .await
            .map_err(|e| AgentError::Control(e.to_string()))?
            .into_inner();

        tx.send(AuthMessage {
            msg: Some(auth_message::Msg::Hello(AuthHello {
                certificate: Some(PbCert {
                    encoded: identity.certificate.encode(),
                }),
            })),
        })
        .await
        .map_err(|_| AgentError::Control("send hello".into()))?;

        let challenge = match down
            .message()
            .await
            .map_err(|e| AgentError::Control(e.to_string()))?
        {
            Some(AuthMessage {
                msg: Some(auth_message::Msg::Challenge(c)),
            }) => c,
            _ => return Err(AgentError::Protocol("expected challenge".into())),
        };
        let nonce: [u8; 32] = challenge
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| AgentError::Protocol("nonce len".into()))?;
        let server_hash: [u8; 32] = challenge
            .server_tls_cert_sha256
            .as_slice()
            .try_into()
            .map_err(|_| AgentError::Protocol("server hash len".into()))?;
        *self.server_cert_sha256.write().await = Some(server_hash);
        let msg = auth_message_bytes(&nonce, &client_hash, &server_hash);
        let sig = identity
            .provider
            .signing()
            .sign(Domain::Auth, &msg)
            .map_err(AgentError::Crypto)?;
        tx.send(AuthMessage {
            msg: Some(auth_message::Msg::Proof(AuthProof {
                signature: sig.to_bytes(),
            })),
        })
        .await
        .map_err(|_| AgentError::Control("send proof".into()))?;

        let result = match down
            .message()
            .await
            .map_err(|e| AgentError::Control(e.to_string()))?
        {
            Some(AuthMessage {
                msg: Some(auth_message::Msg::Result(r)),
            }) => r,
            _ => return Err(AgentError::Protocol("expected result".into())),
        };
        let ct =
            HybridKemCiphertext::from_bytes(&result.kem_ciphertext).map_err(AgentError::Crypto)?;
        let ss = identity
            .provider
            .kem()
            .decapsulate(&ct)
            .map_err(AgentError::Crypto)?;
        let token =
            open_session_token(&result.sealed_token, &ss, &nonce).map_err(AgentError::Crypto)?;
        let token_str = Base64UrlUnpadded::encode_string(&token);
        *self.token.write().await = Some(token_str);

        // Store gateway certs for later verification.
        let mut gw = vec![];
        for pb in result.gateway_certificates {
            if let Ok(c) = Certificate::decode(&pb.encoded) {
                gw.push(c);
            }
        }
        // Also store chain's issuing? not needed.
        *self.gateway_certs.write().await = gw;
        // Also update the channel's view of gateway certs from the latest chain?
        // The OpenSession response will carry the specific gateway cert.

        Ok(())
    }

    async fn authenticated_client(&self) -> Result<AuthenticatedClient, AgentError> {
        let token = self
            .token
            .read()
            .await
            .clone()
            .ok_or_else(|| AgentError::Protocol("not authenticated".into()))?;
        Ok(AgentServiceClient::with_interceptor(
            self.channel_clone(),
            SessionInterceptor { token },
        ))
    }

    pub async fn open_session(
        &self,
        req: OpenSessionRequest,
    ) -> Result<OpenSessionResponse, AgentError> {
        let mut client = self.authenticated_client().await?;
        let resp = client.open_session(req).await.map_err(AgentError::from)?;
        Ok(resp.into_inner())
    }

    pub async fn pulse(
        &self,
    ) -> Result<
        (
            tokio::sync::mpsc::Sender<PulseUp>,
            tonic::Streaming<PulseDown>,
        ),
        AgentError,
    > {
        let mut client = self.authenticated_client().await?;
        let (tx, rx) = tokio::sync::mpsc::channel::<PulseUp>(32);
        let stream = client
            .pulse(tokio_stream::wrappers::ReceiverStream::new(rx))
            .await
            .map_err(AgentError::from)?
            .into_inner();
        Ok((tx, stream))
    }

    pub async fn report(&self, report: SessionReport) -> Result<(), AgentError> {
        let mut client = self.authenticated_client().await?;
        client
            .report_session(report)
            .await
            .map_err(AgentError::from)?;
        Ok(())
    }

    pub async fn renew(
        &self,
        csr: avon_protocol::v2::Csr,
    ) -> Result<avon_protocol::v2::Credential, AgentError> {
        let mut client = self.authenticated_client().await?;
        let resp = client
            .renew_credential(avon_protocol::v2::RenewRequest { csr: Some(csr) })
            .await
            .map_err(AgentError::from)?;
        resp.into_inner()
            .credential
            .ok_or_else(|| AgentError::Protocol("no credential".into()))
    }

    pub async fn who_am_i(&self) -> Result<WhoAmIResponse, AgentError> {
        let mut client = self.authenticated_client().await?;
        let resp = client
            .who_am_i(avon_protocol::v2::Empty {})
            .await
            .map_err(AgentError::from)?;
        Ok(resp.into_inner())
    }

    pub async fn request_peer_session(
        &self,
        req: avon_protocol::v2::PeerSessionRequest,
    ) -> Result<avon_protocol::v2::PeerSessionResponse, AgentError> {
        let mut client = self.authenticated_client().await?;
        let resp = client
            .request_peer_session(req)
            .await
            .map_err(AgentError::from)?;
        Ok(resp.into_inner())
    }

    pub async fn answer_peer_session(
        &self,
        req: avon_protocol::v2::PeerAnswer,
    ) -> Result<(), AgentError> {
        let mut client = self.authenticated_client().await?;
        client
            .answer_peer_session(req)
            .await
            .map_err(AgentError::from)?;
        Ok(())
    }

    pub async fn gateway_certificates(&self) -> Vec<Certificate> {
        self.gateway_certs.read().await.clone()
    }

    pub fn token_string(&self) -> Option<String> {
        self.token.try_read().ok()?.clone()
    }
}

fn url_for_server_name(url: &str) -> String {
    // Very small parser: expect https://host:port or https://host
    if let Ok(parsed) = url::Url::parse(url) {
        if let Some(host) = parsed.host_str() {
            return host.to_string();
        }
    }
    "localhost".to_string()
}
