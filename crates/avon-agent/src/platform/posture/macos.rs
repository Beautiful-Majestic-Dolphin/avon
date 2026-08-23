#![allow(dead_code)]

use super::Posture;

pub(super) fn probe() -> Posture {
    let os_name = std::env::consts::OS.to_string();
    let os_version = sysinfo::System::os_version().unwrap_or_else(|| "unknown".into());
    // firewall, disk_encrypted, etc. return None when unknown — never fabricate.
    // Real implementation would parse com.apple.alf.plist, fdesetup, etc.
    Posture {
        os_name,
        os_version,
        agent_version: "",
        firewall_enabled: None,
        disk_encrypted: None,
        screen_lock_enabled: None,
        last_update_unix: None,
        collected_at_unix: 0,
    }
}
