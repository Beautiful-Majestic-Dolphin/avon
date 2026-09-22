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
    probe: fn() -> Posture,
    cached: Mutex<Option<(Instant, DevicePosture)>>,
}

impl PostureCollector {
    pub fn new(ttl: Duration, provider: ProviderKind) -> Self {
        Self::with_probe(ttl, provider, probe)
    }

    /// A collector that runs `probe` in place of the platform's own. Tests use
    /// it to stand in for a probe the host cannot exercise, such as one that
    /// panics.
    pub fn with_probe(ttl: Duration, provider: ProviderKind, probe: fn() -> Posture) -> Self {
        Self {
            ttl,
            provider,
            probe,
            cached: Mutex::new(None),
        }
    }

    pub async fn collect(&self) -> DevicePosture {
        if let Some(fresh) = self.fresh() {
            return fresh;
        }
        match tokio::task::spawn_blocking(self.probe).await {
            Ok(probed) => {
                let posture = self.assemble(probed);
                *lock_recovering(&self.cached) = Some((Instant::now(), posture.clone()));
                posture
            }
            Err(e) => {
                // The probe panicked. Say so, send the little that is known for
                // certain, and leave the cache empty so the next pulse probes
                // again instead of repeating a blank posture for the whole TTL.
                tracing::warn!(error = %e, "posture probe panicked; sending a minimal posture");
                self.assemble(Posture {
                    os_name: std::env::consts::OS.to_string(),
                    os_version: "unknown".to_string(),
                    ..Posture::default()
                })
            }
        }
    }

    /// Stamps a probe result with what the collector knows and the probe does
    /// not: the agent's version, the key provider, and the time.
    fn assemble(&self, probed: Posture) -> DevicePosture {
        DevicePosture {
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
        }
    }

    /// The cached posture, if it is still inside the TTL.
    fn fresh(&self) -> Option<DevicePosture> {
        let guard = lock_recovering(&self.cached);
        let (at, posture) = guard.as_ref()?;
        (at.elapsed() < self.ttl).then(|| posture.clone())
    }
}

/// The cache only ever holds a value that was fully built before the lock was
/// taken, so a poisoned lock means some thread panicked while cloning or
/// storing one, not that the entry is half-written. Recover the guard rather
/// than treating every later pulse as a cache miss.
fn lock_recovering<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
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
