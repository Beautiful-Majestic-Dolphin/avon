use std::pin::Pin;
use std::sync::Arc;

use avon_common::ids::GatewayId;
use avon_protocol::v2::gateway_service_server::GatewayService;
use avon_protocol::v2::{
    gateway_up, GatewayConfig, GatewayDown, GatewayRegistration, GatewayStats, GatewayUp,
    SessionEvent,
};
use avon_protocol::v2::{Certificate as PbCert, Chain};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

use crate::authz::{require_service, Principal};
use crate::gateway_stream::GatewayHandle;
use crate::policy_push;

use super::AppState;

pub struct GatewayServiceImpl {
    pub state: Arc<AppState>,
}

impl GatewayServiceImpl {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

/// A gateway's SPIFFE id names the gateway instance; without it we cannot tell
/// which gateway is calling.
fn gateway_id<T>(req: &Request<T>) -> Result<GatewayId, Status> {
    match require_service(req, &["gateway"])? {
        Principal::Service {
            instance: Some(id), ..
        } => Ok(GatewayId::new(id)),
        _ => Err(Status::permission_denied(
            "gateway certificate must name a gateway instance",
        )),
    }
}

#[tonic::async_trait]
impl GatewayService for GatewayServiceImpl {
    async fn register(
        &self,
        req: Request<GatewayRegistration>,
    ) -> Result<Response<GatewayConfig>, Status> {
        let id = gateway_id(&req)?;
        let r = req.into_inner();
        let protected: Vec<sqlx::types::ipnetwork::IpNetwork> = r
            .protected_cidrs
            .iter()
            .filter_map(|c| c.parse().ok())
            .collect();
        if protected.len() != r.protected_cidrs.len() {
            return Err(Status::invalid_argument("protected_cidrs must be CIDRs"));
        }
        sqlx::query(
            "INSERT INTO gateways (id, public_endpoint, region, capacity, protected_cidrs, last_seen_at) \
             VALUES ($1, $2, $3, $4, $5, now()) \
             ON CONFLICT (id) DO UPDATE SET public_endpoint = EXCLUDED.public_endpoint, \
             region = EXCLUDED.region, capacity = EXCLUDED.capacity, \
             protected_cidrs = EXCLUDED.protected_cidrs, last_seen_at = now()",
        )
        .bind(id.as_uuid())
        .bind(&r.public_endpoint)
        .bind(&r.region)
        .bind(r.capacity as i32)
        .bind(&protected)
        .execute(&self.state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "gateway registration");
            Status::unavailable("database")
        })?;

        let chain = self.state.chain.read().await;
        let snapshots = policy_push::snapshots_for_registration(&self.state)
            .await
            .unwrap_or_default();
        tracing::info!(gateway = %id, endpoint = %r.public_endpoint, "gateway registered");
        Ok(Response::new(GatewayConfig {
            chain: Some(Chain {
                root: Some(PbCert {
                    encoded: chain.root.encode(),
                }),
                issuing: Some(PbCert {
                    encoded: chain.issuing.encode(),
                }),
                tls_ca_pem: chain.tls_ca_pem.clone(),
            }),
            crl: Some(chain.crl_raw.clone()),
            keepalive_secs: 25,
            rekey_secs: 120,
            snapshots,
        }))
    }

    type EventsStream = Pin<Box<dyn Stream<Item = Result<GatewayDown, Status>> + Send>>;

    async fn events(
        &self,
        req: Request<Streaming<GatewayUp>>,
    ) -> Result<Response<Self::EventsStream>, Status> {
        let id = gateway_id(&req)?;
        let endpoint_row: Option<(String, String)> =
            sqlx::query_as("SELECT public_endpoint, region FROM gateways WHERE id = $1")
                .bind(id.as_uuid())
                .fetch_optional(&self.state.pool)
                .await
                .map_err(|_| Status::unavailable("database"))?;
        let (endpoint, region) = endpoint_row
            .ok_or_else(|| Status::failed_precondition("register before opening events"))?;

        let state = self.state.clone();
        let mut inbound = req.into_inner();
        let (down_tx, down_rx) = tokio::sync::mpsc::channel::<GatewayDown>(256);
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<GatewayDown, Status>>(256);
        state.gateways.insert(
            id,
            GatewayHandle {
                tx: down_tx,
                endpoint,
                region,
            },
        );

        let forward_tx = tx.clone();
        tokio::spawn(async move {
            let mut down_rx = down_rx;
            while let Some(msg) = down_rx.recv().await {
                if forward_tx.send(Ok(msg)).await.is_err() {
                    break;
                }
            }
        });

        tokio::spawn(async move {
            while let Ok(Some(up)) = inbound.message().await {
                match up.msg {
                    Some(gateway_up::Msg::SessionEvent(e)) => {
                        record_session_event(&state, &e).await;
                    }
                    Some(gateway_up::Msg::Stats(s)) => {
                        record_stats(&state, id, &s).await;
                    }
                    Some(gateway_up::Msg::SessionAnswer(answer)) => {
                        if !state.pending_answers.resolve(answer) {
                            tracing::debug!(gateway = %id, "answer for an unknown or expired offer");
                        }
                    }
                    Some(gateway_up::Msg::Decisions(d)) => {
                        if let Err(e) = policy_push::record_decisions(&state, id, d.records).await {
                            tracing::warn!(gateway = %id, error = %e, "failed to record decisions");
                        }
                    }
                    None => {}
                }
            }
            state.gateways.remove(id);
            tracing::info!(gateway = %id, "gateway event stream closed");
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

async fn record_session_event(state: &AppState, e: &SessionEvent) {
    let _ = sqlx::query(
        "UPDATE sessions SET state = CASE $2 WHEN 'closed' THEN 'closed'::session_state \
         WHEN 'active' THEN 'active'::session_state ELSE state END, \
         close_reason = CASE WHEN $2 = 'closed' THEN $3 ELSE close_reason END, \
         closed_at = CASE WHEN $2 = 'closed' THEN now() ELSE closed_at END, \
         bytes_tx = $4, bytes_rx = $5 WHERE id = $1",
    )
    .bind(&e.session_id)
    .bind(&e.event)
    .bind(&e.reason)
    .bind(e.bytes_tx as i64)
    .bind(e.bytes_rx as i64)
    .execute(&state.pool)
    .await;
}

async fn record_stats(state: &AppState, id: GatewayId, s: &GatewayStats) {
    let _ =
        sqlx::query("UPDATE gateways SET active_sessions = $2, last_seen_at = now() WHERE id = $1")
            .bind(id.as_uuid())
            .bind(s.active_sessions as i32)
            .execute(&state.pool)
            .await;
}
