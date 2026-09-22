use super::Posture;

pub(super) fn probe() -> Posture {
    let os_name = std::env::consts::OS.to_string();
    let os_version = sysinfo::System::os_version().unwrap_or_else(|| "unknown".into());
    // Unknown stays None: a real implementation would query the firewall
    // profiles via COM and BitLocker status via WMI.
    Posture {
        os_name,
        os_version,
        firewall_enabled: None,
        disk_encrypted: None,
        screen_lock_enabled: None,
        last_update_unix: None,
    }
}
