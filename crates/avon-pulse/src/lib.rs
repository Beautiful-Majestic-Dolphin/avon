//! AVON Pulse Manager Library
//!
//! This crate provides the pulse manager service for the AVON network,
//! handling device heartbeats, liveness tracking, and token rotation.

pub mod config;
pub mod db;
pub mod rotation;
pub mod scheduler;
pub mod service;

pub use config::PulseConfig;
pub use db::{DbError, DeviceRecord, PulseDatabase};
pub use rotation::{RotationContext, RotationError, TokenRotationManager};
pub use scheduler::{
    DevicePosture, LivenessStatus, OutboundPulse, PulseResponse, PulseScheduler, SchedulerError,
};
pub use service::{PulseMetrics, PulseServiceImpl};
