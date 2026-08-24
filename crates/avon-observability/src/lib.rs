//! Operational plumbing shared by every AVON service.

mod health;
mod metrics;
mod tracing;

pub use health::{
    grpc_health, health_probe_from_env, serve_health, GrpcHealth, Readiness, ReadyFlag,
};
pub use metrics::install_metrics;
pub use tracing::init_tracing;

#[derive(Debug, thiserror::Error)]
pub enum ObservabilityError {
    #[error("tracing init failed: {0}")]
    Tracing(String),
    #[error("metrics exporter failed: {0}")]
    Metrics(String),
    #[error("health server failed: {0}")]
    Health(#[from] std::io::Error),
}
