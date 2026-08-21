use std::pin::Pin;
use std::sync::Arc;

use avon_protocol::v2::gateway_service_server::GatewayService;
use avon_protocol::v2::{GatewayConfig, GatewayDown, GatewayRegistration, GatewayUp};
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

use super::AppState;

pub struct GatewayServiceImpl {
    pub state: Arc<AppState>,
}

impl GatewayServiceImpl {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl GatewayService for GatewayServiceImpl {
    async fn register(
        &self,
        _req: Request<GatewayRegistration>,
    ) -> Result<Response<GatewayConfig>, Status> {
        Err(Status::unimplemented("register"))
    }

    type EventsStream = Pin<Box<dyn Stream<Item = Result<GatewayDown, Status>> + Send>>;

    async fn events(
        &self,
        _req: Request<Streaming<GatewayUp>>,
    ) -> Result<Response<Self::EventsStream>, Status> {
        Err(Status::unimplemented("events"))
    }
}
