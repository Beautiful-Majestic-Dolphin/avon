use std::pin::Pin;
use std::sync::Arc;

use avon_protocol::v2::agent_service_server::AgentService;
use avon_protocol::v2::{
    Ack, AuthMessage, Empty, EnrollRequest, EnrollResponse, OpenSessionRequest,
    OpenSessionResponse, PeerAnswer, PeerSessionRequest, PeerSessionResponse, PulseDown, PulseUp,
    RenewRequest, RenewResponse, SessionReport, WhoAmIResponse,
};
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

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
        _req: Request<Streaming<AuthMessage>>,
    ) -> Result<Response<Self::AuthenticateStream>, Status> {
        Err(Status::unimplemented("authenticate"))
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

    async fn who_am_i(&self, _req: Request<Empty>) -> Result<Response<WhoAmIResponse>, Status> {
        Err(Status::unimplemented("who_am_i"))
    }
}
