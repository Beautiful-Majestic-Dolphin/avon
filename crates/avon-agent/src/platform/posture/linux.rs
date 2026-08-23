#![allow(dead_code)]

use super::Posture;
use std::path::Path;

fn root() -> String {
    std::env::var("AVON_TEST_FAKE_ROOT").unwrap_or_default()
}

fn read_under_root(relative: &str) -> Option<String> {
    let r = root();
    let path = if r.is_empty() {
        Path::new(relative).to_path_buf()
    } else {
        Path::new(&r).join(relative.trim_start_matches('/'))
    };
    std::fs::read_to_string(&path).ok()
}

pub(super) fn probe() -> Posture {
    let os_name = read_under_root("/etc/os-release")
        .and_then(|s| {
            for line in s.lines() {
                if let Some(v) = line.strip_prefix("NAME=") {
                    return Some(v.trim_matches('"').to_string());
                }
            }
            None
        })
        .unwrap_or_else(|| std::env::consts::OS.to_string());
    let os_version = read_under_root("/etc/os-release")
        .and_then(|s| {
            for line in s.lines() {
                if let Some(v) = line.strip_prefix("VERSION_ID=") {
                    return Some(v.trim_matches('"').to_string());
                }
            }
            None
        })
        .unwrap_or_else(|| sysinfo::System::os_version().unwrap_or_else(|| "unknown".into()));

    // firewall: netlink query simulation — return None when unavailable, never fabricate.
    let firewall_enabled: Option<bool> = None;

    // disk_encrypted: check /proc/mounts for dm device and uuid prefix CRYPT-LUKS
    let disk_encrypted = {
        let mounts = read_under_root("/proc/mounts").unwrap_or_default();
        if mounts.trim().is_empty() {
            None
        } else if mounts.contains("/dev/mapper/") {
            // Try to find dm uuid
            let r = root();
            let base = if r.is_empty() {
                Path::new("/sys/class/block").to_path_buf()
            } else {
                Path::new(&r).join("sys/class/block")
            };
            let mut encrypted = false;
            if let Ok(entries) = std::fs::read_dir(&base) {
                for entry in entries.flatten() {
                    let dm_uuid = entry.path().join("dm/uuid");
                    if let Ok(content) = std::fs::read_to_string(&dm_uuid) {
                        if content.trim().starts_with("CRYPT-LUKS") {
                            encrypted = true;
                            break;
                        }
                    }
                }
            }
            if encrypted {
                Some(true)
            } else {
                // If we saw a mapper but no LUKS uuid, we cannot conclude — return None to avoid false negative.
                // However spec's test expects None when empty, and Some(true) when LUKS file exists.
                // So when mounts non-empty but no uuid, return None (unknown).
                None
            }
        } else {
            None
        }
    };

    // last_update_unix: newest mtime among dpkg/rpm/pacman/apk dbs
    let last_update_unix = {
        let candidates = [
            "/var/lib/dpkg/status",
            "/var/lib/rpm/rpmdb.sqlite",
            "/var/lib/pacman/local",
            "/var/lib/apk/db/installed",
        ];
        let mut newest: Option<i64> = None;
        for rel in candidates {
            let p = if root().is_empty() {
                Path::new(rel).to_path_buf()
            } else {
                Path::new(&root()).join(rel.trim_start_matches('/'))
            };
            if let Ok(meta) = std::fs::metadata(&p) {
                if let Ok(mtime) = meta.modified() {
                    if let Ok(dur) = mtime.duration_since(std::time::UNIX_EPOCH) {
                        let ts = dur.as_secs() as i64;
                        newest = Some(newest.map_or(ts, |prev: i64| prev.max(ts)));
                    }
                }
            }
        }
        newest
    };

    Posture {
        os_name,
        os_version,
        agent_version: "",
        firewall_enabled,
        disk_encrypted,
        screen_lock_enabled: None,
        last_update_unix,
        collected_at_unix: 0,
    }
}
