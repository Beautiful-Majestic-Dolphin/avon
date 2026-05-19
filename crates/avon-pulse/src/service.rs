//! gRPC Service implementation for the AVON Pulse Manager.
//!
//! This module implements the PulseService gRPC interface.

use std::sync::Arc;

use avon_common::device::DeviceId;
use avon_protocol::v1::pulse_service_server::PulseService;
use avon_protocol::v1::{
    LivenessRequest, LivenessResponse, LivenessStatus as ProtoLivenessStatus, RecordPulseRequest,
    RecordPulseResult, RotationRequest, RotationResponse, SchedulePulseRequest,
    SchedulePulseResponse,
};
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

use crate::rotation::TokenRotationManager;
use crate::scheduler::{DevicePosture, LivenessStatus, PulseResponse, PulseScheduler};

pub struct PulseServiceImpl {
    scheduler: Arc<PulseScheduler>,
    rotation_manager: Arc<TokenRotationManager>,
}

impl PulseServiceImpl {
    pub fn new(
        scheduler: Arc<PulseScheduler>,
        rotation_manager: Arc<TokenRotationManager>,
    ) -> Self {
        Self {
            scheduler,
            rotation_manager,
        }
    }
}

#[tonic::async_trait]
impl PulseService for PulseServiceImpl {
    async fn schedule_pulse(
        &self,
        request: Request<SchedulePulseRequest>,
    ) -> Result<Response<SchedulePulseResponse>, Status> {
        let req = request.into_inner();

        let device_id = if req.device_id.len() == 16 {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&req.device_id);
            DeviceId::from_bytes(&bytes)
        } else {
            return Ok(Response::new(SchedulePulseResponse {
                success: false,
                server_nonce: vec![],
                pulse_id: 0,
                error_message: "Invalid device ID".to_string(),
            }));
        };

        debug!(?device_id, "Schedule pulse request received");

        match self.rotation_manager.initiate_rotation(device_id).await {
            Ok(context) => {
                info!(
                    ?device_id,
                    pulse_id = context.rotation_id,
                    "Pulse scheduled"
                );

                Ok(Response::new(SchedulePulseResponse {
                    success: true,
                    server_nonce: context.server_nonce.to_vec(),
                    pulse_id: context.rotation_id as i64,
                    error_message: String::new(),
                }))
            }
            Err(e) => {
                warn!(?device_id, error = %e, "Failed to schedule pulse");

                Ok(Response::new(SchedulePulseResponse {
                    success: false,
                    server_nonce: vec![],
                    pulse_id: 0,
                    error_message: e.to_string(),
                }))
            }
        }
    }

    async fn record_pulse(
        &self,
        request: Request<RecordPulseRequest>,
    ) -> Result<Response<RecordPulseResult>, Status> {
        let req = request.into_inner();

        let device_id = if req.device_id.len() == 16 {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&req.device_id);
            DeviceId::from_bytes(&bytes)
        } else {
            return Ok(Response::new(RecordPulseResult {
                success: false,
                rotation_required: false,
                new_server_nonce: vec![],
                error_message: "Invalid device ID".to_string(),
            }));
        };

        let client_nonce: [u8; 32] = if req.client_nonce.len() == 32 {
            let mut nonce = [0u8; 32];
            nonce.copy_from_slice(&req.client_nonce);
            nonce
        } else {
            return Ok(Response::new(RecordPulseResult {
                success: false,
                rotation_required: false,
                new_server_nonce: vec![],
                error_message: "Invalid client nonce".to_string(),
            }));
        };

        let auth_tag: [u8; 32] = if req.auth_tag.len() == 32 {
            let mut tag = [0u8; 32];
            tag.copy_from_slice(&req.auth_tag);
            tag
        } else {
            return Ok(Response::new(RecordPulseResult {
                success: false,
                rotation_required: false,
                new_server_nonce: vec![],
                error_message: "Invalid auth tag".to_string(),
            }));
        };

        let posture = req
            .posture
            .map(|p| DevicePosture {
                os_version: p.os_version,
                agent_version: p.agent_version,
                firewall_enabled: p.firewall_enabled,
                disk_encrypted: p.disk_encrypted,
                last_update_check: p
                    .last_update
                    .as_ref()
                    .and_then(|t| chrono::DateTime::from_timestamp(t.seconds, 0)),
            })
            .unwrap_or_default();

        let response = PulseResponse {
            device_id,
            pulse_id: req.pulse_id as u64,
            client_nonce,
            auth_tag,
            posture,
        };

        debug!(
            ?device_id,
            pulse_id = req.pulse_id,
            "Recording pulse response"
        );

        match self.scheduler.handle_pulse_response(response).await {
            Ok(()) => {
                let rotation_required = self.rotation_manager.should_rotate(&device_id).await;
                let new_server_nonce = if rotation_required {
                    match self.rotation_manager.initiate_rotation(device_id).await {
                        Ok(ctx) => ctx.server_nonce.to_vec(),
                        Err(_) => vec![],
                    }
                } else {
                    vec![]
                };

                info!(?device_id, "Pulse response recorded");

                Ok(Response::new(RecordPulseResult {
                    success: true,
                    rotation_required,
                    new_server_nonce,
                    error_message: String::new(),
                }))
            }
            Err(e) => {
                warn!(?device_id, error = %e, "Failed to record pulse response");

                Ok(Response::new(RecordPulseResult {
                    success: false,
                    rotation_required: false,
                    new_server_nonce: vec![],
                    error_message: e.to_string(),
                }))
            }
        }
    }

    async fn get_device_liveness(
        &self,
        request: Request<LivenessRequest>,
    ) -> Result<Response<LivenessResponse>, Status> {
        let req = request.into_inner();

        let device_id = if req.device_id.len() == 16 {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&req.device_id);
            DeviceId::from_bytes(&bytes)
        } else {
            return Ok(Response::new(LivenessResponse {
                status: ProtoLivenessStatus::Unknown as i32,
                last_seen: 0,
                last_pulse_at: 0,
                missed_pulses: 0,
            }));
        };

        let liveness = self.scheduler.check_device_liveness(&device_id);
        let pulse_info = self.scheduler.get_device_pulse_info(&device_id);

        let (status, last_seen) = match liveness {
            LivenessStatus::Online { last_seen } => {
                (ProtoLivenessStatus::Online as i32, last_seen.timestamp())
            }
            LivenessStatus::Stale { last_seen } => {
                (ProtoLivenessStatus::Stale as i32, last_seen.timestamp())
            }
            LivenessStatus::Offline => (ProtoLivenessStatus::Offline as i32, 0),
        };

        let (last_pulse_at, missed_pulses) = pulse_info
            .map(|(_, pulse_at, missed)| {
                (pulse_at.map(|t| t.timestamp()).unwrap_or(0), missed as i32)
            })
            .unwrap_or((0, 0));

        debug!(?device_id, ?liveness, "Liveness check");

        Ok(Response::new(LivenessResponse {
            status,
            last_seen,
            last_pulse_at,
            missed_pulses,
        }))
    }

    async fn trigger_rotation(
        &self,
        request: Request<RotationRequest>,
    ) -> Result<Response<RotationResponse>, Status> {
        let req = request.into_inner();

        let device_id = if req.device_id.len() == 16 {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&req.device_id);
            DeviceId::from_bytes(&bytes)
        } else {
            return Ok(Response::new(RotationResponse {
                success: false,
                server_nonce: vec![],
                rotation_id: 0,
                error_message: "Invalid device ID".to_string(),
            }));
        };

        debug!(?device_id, force = req.force, "Trigger rotation request");

        if req.force {
            self.rotation_manager.cancel_pending_rotation(&device_id);
        }

        match self.rotation_manager.initiate_rotation(device_id).await {
            Ok(context) => {
                info!(
                    ?device_id,
                    rotation_id = context.rotation_id,
                    "Rotation triggered"
                );

                Ok(Response::new(RotationResponse {
                    success: true,
                    server_nonce: context.server_nonce.to_vec(),
                    rotation_id: context.rotation_id as i64,
                    error_message: String::new(),
                }))
            }
            Err(e) => {
                warn!(?device_id, error = %e, "Failed to trigger rotation");

                Ok(Response::new(RotationResponse {
                    success: false,
                    server_nonce: vec![],
                    rotation_id: 0,
                    error_message: e.to_string(),
                }))
            }
        }
    }
}

pub struct PulseMetrics;

impl PulseMetrics {
    pub fn init() {
        metrics::describe_counter!(
            "avon_pulse_scheduled_total",
            "Total number of pulses scheduled"
        );
        metrics::describe_counter!(
            "avon_pulse_responses_total",
            "Total number of pulse responses received"
        );
        metrics::describe_counter!("avon_pulse_missed_total", "Total number of missed pulses");
        metrics::describe_counter!(
            "avon_token_rotations_total",
            "Total number of token rotations completed"
        );
        metrics::describe_gauge!(
            "avon_pulse_pending_count",
            "Number of pending pulse responses"
        );
        metrics::describe_gauge!(
            "avon_pulse_tracked_devices",
            "Number of devices being tracked"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_liveness_status_conversion() {
        assert_eq!(ProtoLivenessStatus::Unknown as i32, 0);
        assert_eq!(ProtoLivenessStatus::Online as i32, 1);
        assert_eq!(ProtoLivenessStatus::Stale as i32, 2);
        assert_eq!(ProtoLivenessStatus::Offline as i32, 3);
    }
}
