use crate::service::AppState;
use avon_protocol::v2::admin_service_server::AdminService;
use avon_protocol::v2::{
    Ack, ApproveDeviceRequest, CreateIkev2Request, CreateIkev2Response, ExplainRequest,
    ExplainResponse, ImportMudRequest, ImportMudResponse, ListIkev2Request, ListIkev2Response,
    ListSessionsRequest, ListSessionsResponse, RevokeDeviceRequest, SuspendDeviceRequest,
};
use std::sync::Arc;
use tonic::{Request, Response, Status};

pub struct AdminServiceImpl {
    _state: Arc<AppState>,
}

impl AdminServiceImpl {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { _state: state }
    }
}

#[tonic::async_trait]
impl AdminService for AdminServiceImpl {
    async fn explain(
        &self,
        _request: Request<ExplainRequest>,
    ) -> Result<Response<ExplainResponse>, Status> {
        Ok(Response::new(ExplainResponse {
            allow: false,
            reason: "default deny".into(),
            matched_policies: vec![],
            matched: vec![],
            cedar: "deny".into(),
        }))
    }
    async fn revoke_device(
        &self,
        _request: Request<RevokeDeviceRequest>,
    ) -> Result<Response<Ack>, Status> {
        Ok(Response::new(Ack {
            ok: true,
            message: "".into(),
        }))
    }
    async fn suspend_device(
        &self,
        _request: Request<SuspendDeviceRequest>,
    ) -> Result<Response<Ack>, Status> {
        Ok(Response::new(Ack {
            ok: true,
            message: "".into(),
        }))
    }
    async fn approve_device(
        &self,
        _request: Request<ApproveDeviceRequest>,
    ) -> Result<Response<Ack>, Status> {
        Ok(Response::new(Ack {
            ok: true,
            message: "".into(),
        }))
    }
    async fn list_sessions(
        &self,
        _request: Request<ListSessionsRequest>,
    ) -> Result<Response<ListSessionsResponse>, Status> {
        Ok(Response::new(ListSessionsResponse { sessions: vec![] }))
    }
    async fn import_mud(
        &self,
        _request: Request<ImportMudRequest>,
    ) -> Result<Response<ImportMudResponse>, Status> {
        Ok(Response::new(ImportMudResponse {
            created: vec![],
            skipped: vec![],
        }))
    }
    async fn list_ikev2_devices(
        &self,
        _request: Request<ListIkev2Request>,
    ) -> Result<Response<ListIkev2Response>, Status> {
        Ok(Response::new(ListIkev2Response { devices: vec![] }))
    }
    async fn create_ikev2_device(
        &self,
        _request: Request<CreateIkev2Request>,
    ) -> Result<Response<CreateIkev2Response>, Status> {
        Ok(Response::new(CreateIkev2Response {
            device_id: "".into(),
        }))
    }
}
