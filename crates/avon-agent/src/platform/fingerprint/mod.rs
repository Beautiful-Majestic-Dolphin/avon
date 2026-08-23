use avon_agent_core::traits::FingerprintProvider;
use avon_protocol::v2::Fingerprint;
use sha2::{Digest, Sha256};

pub const FINGERPRINT_VERSION: u32 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FingerprintV2 {
    pub hash: [u8; 32],
    pub kinds: Vec<&'static str>,
}

pub fn collect_from(inputs: &[(&'static str, Vec<u8>)]) -> FingerprintV2 {
    let mut sorted = inputs.to_vec();
    sorted.sort_by_key(|(k, _)| *k);
    let kinds = sorted.iter().map(|(k, _)| *k).collect();
    let mut hasher = Sha256::new();
    hasher.update(b"AVON-FP-V2");
    for (kind, value) in &sorted {
        hasher.update((kind.len() as u32).to_be_bytes());
        hasher.update(kind.as_bytes());
        hasher.update((value.len() as u32).to_be_bytes());
        hasher.update(value);
    }
    let hash: [u8; 32] = hasher.finalize().into();
    FingerprintV2 { hash, kinds }
}

pub fn collect() -> FingerprintV2 {
    #[cfg(target_os = "linux")]
    {
        linux::gather()
    }
    #[cfg(target_os = "macos")]
    {
        macos::gather()
    }
    #[cfg(target_os = "windows")]
    {
        windows::gather()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        collect_from(&[])
    }
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

pub struct PlatformFingerprint;

impl FingerprintProvider for PlatformFingerprint {
    fn collect(&self) -> Fingerprint {
        let v2 = collect();
        Fingerprint {
            version: FINGERPRINT_VERSION,
            hash: v2.hash.to_vec(),
            identifier_kinds: v2.kinds.into_iter().map(|s| s.to_string()).collect(),
        }
    }
}
