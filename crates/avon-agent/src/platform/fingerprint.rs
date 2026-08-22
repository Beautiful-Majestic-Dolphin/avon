use avon_agent_core::traits::FingerprintProvider;
use avon_protocol::v2::Fingerprint;
use sha2::{Digest, Sha256};

pub struct PlatformFingerprint;

impl FingerprintProvider for PlatformFingerprint {
    fn collect(&self) -> Fingerprint {
        // Stable identifiers: machine-id, DMI UUID, etc.
        // For now, hash the hostname and a few stable files.
        let mut hasher = Sha256::new();
        if let Ok(host) = std::fs::read_to_string("/etc/machine-id") {
            hasher.update(host.trim().as_bytes());
        } else if let Ok(host) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
            hasher.update(host.trim().as_bytes());
        } else {
            hasher.update(b"unknown-machine");
        }
        // Add OS identifier.
        hasher.update(std::env::consts::OS.as_bytes());
        let hash = hasher.finalize().to_vec();
        Fingerprint {
            version: 2,
            hash,
            identifier_kinds: vec!["machine-id".into()],
        }
    }
}
