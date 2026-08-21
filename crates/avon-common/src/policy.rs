//! Policy-related types for AVON.
//!
//! Policies define access control rules between pods and devices.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::pod::PodId;

/// Unique identifier for a policy in the AVON network.
///
/// A PolicyId is a 16-byte UUID that uniquely identifies a policy.
///
/// # Example
///
/// ```
/// use avon_common::policy::PolicyId;
///
/// let id = PolicyId::new();
/// let bytes = id.as_bytes();
/// let restored = PolicyId::from_bytes(bytes);
/// assert_eq!(id, restored);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyId(pub Uuid);

impl PolicyId {
    /// Creates a new random PolicyId.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Creates a PolicyId from a 16-byte array.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 16]) -> Self {
        Self(Uuid::from_bytes(*bytes))
    }

    /// Returns the PolicyId as a 16-byte array.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl Default for PolicyId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for PolicyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A policy defines access control rules between pods.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    /// Unique identifier for the policy.
    pub id: PolicyId,
    /// Human-readable name for the policy.
    pub name: String,
    /// Source pod (None means any source).
    pub source_pod: Option<PodId>,
    /// Destination pod (None means any destination).
    pub destination_pod: Option<PodId>,
    /// Action to take when the policy matches.
    pub action: PolicyAction,
    /// Priority for policy evaluation (higher = evaluated first).
    pub priority: i32,
    /// Whether the policy is currently enabled.
    pub enabled: bool,
    /// Optional conditions for the policy.
    pub conditions: Option<PolicyConditions>,
}

impl Policy {
    /// Creates a new allow policy between two pods.
    #[must_use]
    pub fn allow(name: String, source: PodId, destination: PodId) -> Self {
        Self {
            id: PolicyId::new(),
            name,
            source_pod: Some(source),
            destination_pod: Some(destination),
            action: PolicyAction::Allow,
            priority: 0,
            enabled: true,
            conditions: None,
        }
    }

    /// Creates a new deny policy between two pods.
    #[must_use]
    pub fn deny(name: String, source: PodId, destination: PodId) -> Self {
        Self {
            id: PolicyId::new(),
            name,
            source_pod: Some(source),
            destination_pod: Some(destination),
            action: PolicyAction::Deny,
            priority: 0,
            enabled: true,
            conditions: None,
        }
    }

    /// Returns true if this policy allows the connection.
    #[must_use]
    pub fn allows(&self) -> bool {
        self.enabled && self.action == PolicyAction::Allow
    }
}

/// Action to take when a policy matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyAction {
    /// Allow the connection.
    Allow,
    /// Deny the connection.
    Deny,
}

/// Additional conditions for policy evaluation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyConditions {
    /// Time window when the policy is active.
    pub time_window: Option<TimeWindow>,
    /// Required device posture for the policy to apply.
    pub required_posture: Option<RequiredPosture>,
}

/// Time window for policy evaluation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Start hour (0-23).
    pub start_hour: u8,
    /// End hour (0-23).
    pub end_hour: u8,
    /// Days of the week (0 = Sunday, 6 = Saturday).
    pub days_of_week: Vec<u8>,
    /// Timezone for the time window (e.g., "America/New_York").
    pub timezone: String,
}

impl TimeWindow {
    /// Creates a new time window for business hours (9-17, Mon-Fri).
    #[must_use]
    pub fn business_hours(timezone: String) -> Self {
        Self {
            start_hour: 9,
            end_hour: 17,
            days_of_week: vec![1, 2, 3, 4, 5], // Mon-Fri
            timezone,
        }
    }
}

/// Required device posture for policy evaluation.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RequiredPosture {
    /// Whether a firewall must be enabled.
    pub firewall_required: bool,
    /// Whether disk encryption must be enabled.
    pub encryption_required: bool,
    /// Minimum agent version required.
    pub min_agent_version: Option<String>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_policy_id_new() {
        let id1 = PolicyId::new();
        let id2 = PolicyId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_policy_id_from_bytes() {
        let bytes = [1u8; 16];
        let id = PolicyId::from_bytes(&bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn test_policy_allow() {
        let source = PodId::new();
        let dest = PodId::new();
        let policy = Policy::allow("test".to_string(), source, dest);
        assert!(policy.allows());
        assert_eq!(policy.action, PolicyAction::Allow);
    }

    #[test]
    fn test_policy_deny() {
        let source = PodId::new();
        let dest = PodId::new();
        let policy = Policy::deny("test".to_string(), source, dest);
        assert!(!policy.allows());
        assert_eq!(policy.action, PolicyAction::Deny);
    }

    #[test]
    fn test_time_window_business_hours() {
        let window = TimeWindow::business_hours("America/New_York".to_string());
        assert_eq!(window.start_hour, 9);
        assert_eq!(window.end_hour, 17);
        assert_eq!(window.days_of_week, vec![1, 2, 3, 4, 5]);
    }
}
