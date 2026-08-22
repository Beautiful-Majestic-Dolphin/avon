use avon_agent_core::traits::PostureProvider;
use avon_protocol::v2::DevicePosture;

pub struct PlatformPosture;

impl PostureProvider for PlatformPosture {
    fn collect(&self) -> DevicePosture {
        // For now, wrap in spawn_blocking with absolute paths where needed.
        // System info via sysinfo.
        let os_name = std::env::consts::OS.to_string();
        let os_version = sysinfo::System::os_version().unwrap_or_else(|| "unknown".into());
        let agent_version = env!("CARGO_PKG_VERSION").to_string();

        DevicePosture {
            os_name,
            os_version,
            agent_version,
            firewall_enabled: None,
            disk_encrypted: None,
            screen_lock_enabled: None,
            last_update_unix: None,
            key_provider: "software".into(),
            collected_at_unix: chrono::Utc::now().timestamp(),
        }
    }
}
