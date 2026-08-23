#![allow(dead_code)]

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use avon_keystore::ProviderKind;
use tokio::sync::Mutex;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Posture {
    pub os_name: String,
    pub os_version: String,
    pub agent_version: &'static str,
    pub firewall_enabled: Option<bool>,
    pub disk_encrypted: Option<bool>,
    pub screen_lock_enabled: Option<bool>,
    pub last_update_unix: Option<i64>,
    pub collected_at_unix: i64,
}

#[allow(dead_code)]
pub struct PostureCollector {
    ttl: Duration,
    cached: Mutex<Option<(Instant, Posture)>>,
}

impl PostureCollector {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            cached: Mutex::new(None),
        }
    }

    pub async fn collect(&self, _provider: ProviderKind) -> Posture {
        {
            let guard = self.cached.lock().await;
            if let Some((at, posture)) = guard.as_ref() {
                if at.elapsed() < self.ttl {
                    return posture.clone();
                }
            }
        }
        let probed = tokio::task::spawn_blocking(probe).await.unwrap_or_default();
        let posture = Posture {
            agent_version: env!("CARGO_PKG_VERSION"),
            collected_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            ..probed
        };
        *self.cached.lock().await = Some((Instant::now(), posture.clone()));
        posture
    }
}

impl avon_agent_core::traits::PostureProvider for PostureCollector {
    fn collect(&self) -> avon_protocol::v2::DevicePosture {
        // Synchronous fallback for trait — use cached or default.
        // The async version is preferred.
        avon_protocol::v2::DevicePosture {
            os_name: std::env::consts::OS.to_string(),
            os_version: sysinfo::System::os_version().unwrap_or_else(|| "unknown".into()),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            firewall_enabled: None,
            disk_encrypted: None,
            screen_lock_enabled: None,
            last_update_unix: None,
            key_provider: "software".into(),
            collected_at_unix: chrono::Utc::now().timestamp(),
        }
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
