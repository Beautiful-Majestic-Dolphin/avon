use std::pin::Pin;
use std::sync::Arc;

use avon_crypto::cert::Certificate;
use avon_crypto::hybrid::signature::{Domain, HybridSignature};
use avon_crypto::session_token::seal_session_token;
use avon_protocol::v2::agent_service_server::AgentService;
use avon_protocol::v2::{
    auth_message as auth_msg, Ack, AuthChallenge, AuthMessage, AuthResult, Certificate as PbCert,
    Chain, Empty, EnrollRequest, EnrollResponse, OpenSessionRequest, OpenSessionResponse,
    PeerAnswer, PeerSessionRequest, PeerSessionResponse, PulseDown, PulseUp, RenewRequest,
    RenewResponse, SessionReport, WhoAmIResponse,
};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

use crate::auth::{auth_message, authenticated_device, verify_device_certificate};
use crate::authz::require_device;

use super::AppState;

pub struct AgentServiceImpl {
    pub state: Arc<AppState>,
}

impl AgentServiceImpl {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl AgentService for AgentServiceImpl {
    async fn enroll(
        &self,
        req: Request<EnrollRequest>,
    ) -> Result<Response<EnrollResponse>, Status> {
        let client_ip = req.remote_addr().map(|a| a.ip());
        let inner = req.into_inner();
        crate::enroll::enroll(&self.state.pool, &self.state.ca, inner, client_ip)
            .await
            .map(Response::new)
    }

    type AuthenticateStream = Pin<Box<dyn Stream<Item = Result<AuthMessage, Status>> + Send>>;

    async fn authenticate(
        &self,
        req: Request<Streaming<AuthMessage>>,
    ) -> Result<Response<Self::AuthenticateStream>, Status> {
        let (_, _, tls_client_hash) = require_device(&req)?;
        let state = self.state.clone();
        let mut inbound = req.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<AuthMessage, Status>>(4);

        tokio::spawn(async move {
            let result: Result<(), Status> = async {
                // 1. Hello: the device presents its AVON certificate.
                let hello = match inbound.message().await? {
                    Some(AuthMessage {
                        msg: Some(auth_msg::Msg::Hello(h)),
                    }) => h,
                    _ => return Err(Status::invalid_argument("expected hello")),
                };
                let cert = Certificate::decode(
                    &hello
                        .certificate
                        .ok_or_else(|| Status::invalid_argument("certificate"))?
                        .encoded,
                )
                .map_err(|_| Status::invalid_argument("certificate encoding"))?;
                let (tenant, device) =
                    verify_device_certificate(&state, &cert, tls_client_hash).await?;

                // 2. Challenge.
                let nonce = avon_crypto::random::random_bytes_fixed::<32>()
                    .map_err(|_| Status::internal("rng"))?;
                tx.send(Ok(AuthMessage {
                    msg: Some(auth_msg::Msg::Challenge(AuthChallenge {
                        nonce: nonce.to_vec(),
                        server_tls_cert_sha256: state.server_cert_sha256.to_vec(),
                    })),
                }))
                .await
                .map_err(|_| Status::cancelled("client gone"))?;

                // 3. Proof: a composite signature over the challenge and both
                //    ends of the TLS connection.
                let proof = match tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    inbound.message(),
                )
                .await
                {
                    Ok(Ok(Some(AuthMessage {
                        msg: Some(auth_msg::Msg::Proof(p)),
                    }))) => p,
                    _ => return Err(Status::unauthenticated("expected proof")),
                };
                let sig = HybridSignature::from_bytes(&proof.signature)
                    .map_err(|_| Status::unauthenticated("proof"))?;
                let msg = auth_message(&nonce, &tls_client_hash, &state.server_cert_sha256);
                cert.tbs
                    .signing_key
                    .verify(Domain::Auth, &msg, &sig)
                    .map_err(|_| Status::unauthenticated("proof invalid"))?;

                // 4. Token, encapsulated to the certificate's static KEM key.
                let kem_pk = cert
                    .tbs
                    .kem_key
                    .as_ref()
                    .ok_or_else(|| Status::unauthenticated("certificate has no kem key"))?;
                let (ct, ss) = kem_pk.encapsulate().map_err(|_| Status::internal("kem"))?;
                let token = state
                    .sessions
                    .issue(tenant, device, tls_client_hash)
                    .await?;
                let sealed = seal_session_token(&token, &ss, &nonce)
                    .map_err(|_| Status::internal("seal"))?;
                let gateways = crate::gateway_stream::gateway_certificates(&state.pool)
                    .await
                    .unwrap_or_default();
                let result = {
                    let chain = state.chain.read().await;
                    AuthResult {
                        kem_ciphertext: ct.to_bytes(),
                        sealed_token: sealed,
                        expires_at_unix: chrono::Utc::now().timestamp()
                            + state.session_ttl_secs as i64,
                        chain: Some(Chain {
                            root: Some(PbCert {
                                encoded: chain.root.encode(),
                            }),
                            issuing: Some(PbCert {
                                encoded: chain.issuing.encode(),
                            }),
                            tls_ca_pem: chain.tls_ca_pem.clone(),
                        }),
                        gateway_certificates: gateways
                            .into_iter()
                            .map(|g| PbCert { encoded: g })
                            .collect(),
                    }
                };
                sqlx::query(
                    "UPDATE devices SET last_seen_at = now(), liveness = 'online' WHERE id = $1",
                )
                .bind(device)
                .execute(&state.pool)
                .await
                .ok();
                metrics::counter!("avon_control_authentications_total", "result" => "ok")
                    .increment(1);
                tx.send(Ok(AuthMessage {
                    msg: Some(auth_msg::Msg::Result(result)),
                }))
                .await
                .map_err(|_| Status::cancelled("client gone"))?;
                Ok(())
            }
            .await;
            if let Err(e) = result {
                metrics::counter!("avon_control_authentications_total", "result" => "fail")
                    .increment(1);
                let _ = tx.send(Err(e)).await;
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn renew_credential(
        &self,
        _req: Request<RenewRequest>,
    ) -> Result<Response<RenewResponse>, Status> {
        Err(Status::unimplemented("renew_credential"))
    }

    type PulseStream = Pin<Box<dyn Stream<Item = Result<PulseDown, Status>> + Send>>;

    async fn pulse(
        &self,
        _req: Request<Streaming<PulseUp>>,
    ) -> Result<Response<Self::PulseStream>, Status> {
        Err(Status::unimplemented("pulse"))
    }

    async fn open_session(
        &self,
        _req: Request<OpenSessionRequest>,
    ) -> Result<Response<OpenSessionResponse>, Status> {
        Err(Status::unimplemented("open_session"))
    }

    async fn request_peer_session(
        &self,
        _req: Request<PeerSessionRequest>,
    ) -> Result<Response<PeerSessionResponse>, Status> {
        Err(Status::unimplemented("request_peer_session"))
    }

    async fn answer_peer_session(
        &self,
        _req: Request<PeerAnswer>,
    ) -> Result<Response<Ack>, Status> {
        Err(Status::unimplemented("answer_peer_session"))
    }

    async fn report_session(&self, _req: Request<SessionReport>) -> Result<Response<Ack>, Status> {
        Err(Status::unimplemented("report_session"))
    }

    async fn who_am_i(&self, req: Request<Empty>) -> Result<Response<WhoAmIResponse>, Status> {
        let _ = authenticated_device(&self.state, &req).await?;
        let addr = req.remote_addr().map(|a| a.to_string()).unwrap_or_default();
        Ok(Response::new(WhoAmIResponse {
            reflexive_address: addr,
        }))
    }
}
