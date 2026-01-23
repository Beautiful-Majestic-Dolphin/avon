//! AVON Common Types and Utilities
//!
//! This crate provides shared types and utilities used across AVON components.
//!
//! # Modules
//!
//! - [`config`] - Configuration types for control plane and agent
//! - [`device`] - Device identification and management types
//! - [`pod`] - Pod organizational unit types
//! - [`policy`] - Access control policy types
//! - [`tunnel`] - Tunnel session types
//!
//! # Example
//!
//! ```
//! use avon_common::device::{DeviceId, DeviceInfo, DeviceStatus};
//! use avon_common::pod::{PodId, Pod};
//! use avon_common::policy::{Policy, PolicyAction};
//! use avon_common::tunnel::{SessionId, TunnelInfo};
//! use avon_common::config::{ControlPlaneConfig, AgentConfig};
//!
//! // Create a new device
//! let fingerprint = [0u8; 32];
//! let device = DeviceInfo::new("my-laptop".to_string(), fingerprint);
//! assert_eq!(device.status, DeviceStatus::PendingEnrollment);
//!
//! // Create pods for organization
//! let engineering = Pod::new("engineering".to_string());
//! let servers = Pod::new("servers".to_string());
//!
//! // Create a policy allowing engineering to access servers
//! let policy = Policy::allow("eng-to-servers".to_string(), engineering.id, servers.id);
//! assert!(policy.allows());
//! ```

pub mod config;
pub mod device;
pub mod pod;
pub mod policy;
pub mod tunnel;

pub use config::{AgentConfig, ControlPlaneConfig};
pub use device::{DeviceId, DeviceInfo, DeviceStatus};
pub use pod::{Pod, PodId};
pub use policy::{Policy, PolicyAction, PolicyConditions, PolicyId, RequiredPosture, TimeWindow};
pub use tunnel::{SessionId, TunnelInfo, TunnelStatus};
