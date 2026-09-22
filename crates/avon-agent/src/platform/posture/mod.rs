use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use avon_keystore::ProviderKind;
use avon_protocol::v2::DevicePosture;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

/// What a platform probe was able to establish about this device.
///
/// Every signal is `Option`: `None` means the probe could not tell, and is
/// never collapsed into `false` on the way to the wire. A policy that
/// conditions on a signal this device cannot report must not match by
/// accident.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Posture {
    pub os_name: String,
    pub os_version: String,
    pub firewall_enabled: Option<bool>,
    pub disk_encrypted: Option<bool>,
    pub screen_lock_enabled: Option<bool>,
    pub last_update_unix: Option<i64>,
}

/// Probes the device on demand and caches the answer for `ttl`.
///
/// The key provider is fixed for the life of an enrolled device, so the
/// collector is told which one it is at construction rather than guessing
/// per pulse.
pub struct PostureCollector {
    ttl: Duration,
    provider: ProviderKind,
    cached: Mutex<Option<(Instant, DevicePosture)>>,
}

impl PostureCollector {
    pub fn new(ttl: Duration, provider: ProviderKind) -> Self {
        Self {
            ttl,
            provider,
            cached: Mutex::new(None),
        }
    }

    pub async fn collect(&self) -> DevicePosture {
        if let Some(fresh) = self.fresh() {
            return fresh;
        }
        let probed = tokio::task::spawn_blocking(probe).await.unwrap_or_default();
        let posture = DevicePosture {
            os_name: probed.os_name,
            os_version: probed.os_version,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            firewall_enabled: probed.firewall_enabled,
            disk_encrypted: probed.disk_encrypted,
            screen_lock_enabled: probed.screen_lock_enabled,
            last_update_unix: probed.last_update_unix,
            key_provider: self.provider.as_str().to_string(),
            collected_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        };
        if let Ok(mut guard) = self.cached.lock() {
            *guard = Some((Instant::now(), posture.clone()));
        }
        posture
    }

    /// The cached posture, if it is still inside the TTL. A poisoned lock is
    /// treated as a miss: re-probing costs a few file reads, and serving a
    /// stale signal is the thing worth avoiding.
    fn fresh(&self) -> Option<DevicePosture> {
        let guard = self.cached.lock().ok()?;
        let (at, posture) = guard.as_ref()?;
        (at.elapsed() < self.ttl).then(|| posture.clone())
    }
}

#[async_trait::async_trait]
impl avon_agent_core::traits::PostureProvider for PostureCollector {
    async fn collect(&self) -> DevicePosture {
        PostureCollector::collect(self).await
    }
}

fn probe() -> Posture {
    #[cfg(target_os = "linux")]
    {
        linux::probe()
    }
    #[cfg(target_os = "macos")]
    {
        macos::probe()
    }
    #[cfg(target_os = "windows")]
    {
        windows::probe()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Posture::default()
    }
}
