//! Pod-related types for AVON.
//!
//! Pods are organizational units that group devices together for policy management.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a pod in the AVON network.
///
/// A PodId is a 16-byte UUID that uniquely identifies a pod.
///
/// # Example
///
/// ```
/// use avon_common::pod::PodId;
///
/// let id = PodId::new();
/// let bytes = id.as_bytes();
/// let restored = PodId::from_bytes(bytes);
/// assert_eq!(id, restored);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PodId(pub Uuid);

impl PodId {
    /// Creates a new random PodId.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Creates a PodId from a 16-byte array.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 16]) -> Self {
        Self(Uuid::from_bytes(*bytes))
    }

    /// Returns the PodId as a 16-byte array.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl Default for PodId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for PodId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A pod is an organizational unit that groups devices together.
///
/// Pods can be hierarchical, with a parent pod containing child pods.
/// Policies are applied at the pod level.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pod {
    /// Unique identifier for the pod.
    pub id: PodId,
    /// Human-readable name for the pod.
    pub name: String,
    /// Parent pod ID for hierarchical organization.
    pub parent_id: Option<PodId>,
    /// Optional description of the pod.
    pub description: Option<String>,
}

impl Pod {
    /// Creates a new pod with the given name.
    #[must_use]
    pub fn new(name: String) -> Self {
        Self {
            id: PodId::new(),
            name,
            parent_id: None,
            description: None,
        }
    }

    /// Creates a new pod with a parent.
    #[must_use]
    pub fn with_parent(name: String, parent_id: PodId) -> Self {
        Self {
            id: PodId::new(),
            name,
            parent_id: Some(parent_id),
            description: None,
        }
    }

    /// Returns true if this pod is a root pod (has no parent).
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.parent_id.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pod_id_new() {
        let id1 = PodId::new();
        let id2 = PodId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_pod_id_from_bytes() {
        let bytes = [1u8; 16];
        let id = PodId::from_bytes(&bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn test_pod_new() {
        let pod = Pod::new("engineering".to_string());
        assert_eq!(pod.name, "engineering");
        assert!(pod.is_root());
    }

    #[test]
    fn test_pod_with_parent() {
        let parent = Pod::new("company".to_string());
        let child = Pod::with_parent("engineering".to_string(), parent.id);
        assert_eq!(child.parent_id, Some(parent.id));
        assert!(!child.is_root());
    }
}
