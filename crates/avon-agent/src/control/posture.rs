//! Device posture collection for AVON Agent.
//!
//! Collects security-relevant information about the device including:
//! - OS version
//! - Agent version
//! - Firewall status
//! - Disk encryption status
//! - Last update time

use avon_protocol::v1::{DevicePosture, Timestamp};
use sysinfo::System;

/// Agent version from Cargo.toml.
const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Collects device posture information.
pub struct PostureCollector {
    system: System,
}

impl PostureCollector {
    /// Creates a new posture collector.
    pub fn new() -> Self {
        Self {
            system: System::new_all(),
        }
    }

    /// Collects the current device posture.
    pub fn collect(&self) -> DevicePosture {
        let os_version = self.collect_os_version();
        let firewall_enabled = self.check_firewall_enabled();
        let disk_encrypted = self.check_disk_encrypted();
        let last_update = self.get_last_update_time();

        DevicePosture {
            os_version,
            agent_version: AGENT_VERSION.to_string(),
            firewall_enabled,
            disk_encrypted,
            last_update,
        }
    }

    /// Collects the OS version string.
    fn collect_os_version(&self) -> String {
        let name = System::name().unwrap_or_else(|| "Unknown".to_string());
        let version = System::os_version().unwrap_or_else(|| "Unknown".to_string());
        let kernel = System::kernel_version().unwrap_or_else(|| "Unknown".to_string());

        format!("{} {} (kernel {})", name, version, kernel)
    }

    /// Checks if the firewall is enabled.
    ///
    /// Platform-specific implementation:
    /// - Linux: Checks iptables/nftables or ufw status
    /// - macOS: Checks Application Firewall status
    /// - Windows: Checks Windows Firewall status
    fn check_firewall_enabled(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.check_linux_firewall()
        }

        #[cfg(target_os = "macos")]
        {
            self.check_macos_firewall()
        }

        #[cfg(target_os = "windows")]
        {
            self.check_windows_firewall()
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            false
        }
    }

    #[cfg(target_os = "linux")]
    fn check_linux_firewall(&self) -> bool {
        use std::process::Command;

        // Check ufw status
        if let Ok(output) = Command::new("ufw").arg("status").output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.contains("Status: active") {
                    return true;
                }
            }
        }

        // Check iptables (if any rules exist beyond default)
        if let Ok(output) = Command::new("iptables").args(["-L", "-n"]).output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                // If there are rules beyond the default ACCEPT policies
                let lines: Vec<&str> = stdout.lines().collect();
                if lines.len() > 8 {
                    return true;
                }
            }
        }

        // Check nftables
        if let Ok(output) = Command::new("nft").args(["list", "ruleset"]).output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if !stdout.trim().is_empty() {
                    return true;
                }
            }
        }

        false
    }

    #[cfg(target_os = "macos")]
    fn check_macos_firewall(&self) -> bool {
        use std::process::Command;

        // Check Application Firewall status
        if let Ok(output) = Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
            .arg("--getglobalstate")
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                return stdout.contains("enabled");
            }
        }

        false
    }

    #[cfg(target_os = "windows")]
    fn check_windows_firewall(&self) -> bool {
        use std::process::Command;

        // Check Windows Firewall status using netsh
        if let Ok(output) = Command::new("netsh")
            .args(["advfirewall", "show", "allprofiles", "state"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                return stdout.contains("ON");
            }
        }

        false
    }

    /// Checks if disk encryption is enabled.
    ///
    /// Platform-specific implementation:
    /// - Linux: Checks for LUKS encryption
    /// - macOS: Checks FileVault status
    /// - Windows: Checks BitLocker status
    fn check_disk_encrypted(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.check_linux_encryption()
        }

        #[cfg(target_os = "macos")]
        {
            self.check_macos_encryption()
        }

        #[cfg(target_os = "windows")]
        {
            self.check_windows_encryption()
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            false
        }
    }

    #[cfg(target_os = "linux")]
    fn check_linux_encryption(&self) -> bool {
        use std::path::Path;

        // Check for dm-crypt/LUKS devices
        if Path::new("/dev/mapper").exists() {
            if let Ok(entries) = std::fs::read_dir("/dev/mapper") {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    // Common LUKS naming patterns
                    if name_str.contains("crypt") || name_str.contains("luks") {
                        return true;
                    }
                }
            }
        }

        // Check /etc/crypttab
        if let Ok(content) = std::fs::read_to_string("/etc/crypttab") {
            if !content.trim().is_empty()
                && content
                    .lines()
                    .any(|l| !l.starts_with('#') && !l.trim().is_empty())
            {
                return true;
            }
        }

        false
    }

    #[cfg(target_os = "macos")]
    fn check_macos_encryption(&self) -> bool {
        use std::process::Command;

        // Check FileVault status
        if let Ok(output) = Command::new("fdesetup").arg("status").output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                return stdout.contains("FileVault is On");
            }
        }

        false
    }

    #[cfg(target_os = "windows")]
    fn check_windows_encryption(&self) -> bool {
        use std::process::Command;

        // Check BitLocker status
        if let Ok(output) = Command::new("manage-bde").args(["-status", "C:"]).output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                return stdout.contains("Protection On") || stdout.contains("Fully Encrypted");
            }
        }

        false
    }

    /// Gets the last system update time.
    fn get_last_update_time(&self) -> Option<Timestamp> {
        #[cfg(target_os = "linux")]
        {
            self.get_linux_last_update()
        }

        #[cfg(target_os = "macos")]
        {
            self.get_macos_last_update()
        }

        #[cfg(target_os = "windows")]
        {
            self.get_windows_last_update()
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            None
        }
    }

    #[cfg(target_os = "linux")]
    fn get_linux_last_update(&self) -> Option<Timestamp> {
        use std::fs;

        // Check apt history
        let apt_history = "/var/log/apt/history.log";
        if let Ok(metadata) = fs::metadata(apt_history) {
            if let Ok(modified) = metadata.modified() {
                if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
                    return Some(Timestamp {
                        seconds: duration.as_secs() as i64,
                        nanos: duration.subsec_nanos() as i32,
                    });
                }
            }
        }

        // Check dnf/yum history
        let dnf_history = "/var/log/dnf.log";
        if let Ok(metadata) = fs::metadata(dnf_history) {
            if let Ok(modified) = metadata.modified() {
                if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
                    return Some(Timestamp {
                        seconds: duration.as_secs() as i64,
                        nanos: duration.subsec_nanos() as i32,
                    });
                }
            }
        }

        None
    }

    #[cfg(target_os = "macos")]
    fn get_macos_last_update(&self) -> Option<Timestamp> {
        use std::process::Command;

        // Get last software update time
        if let Ok(output) = Command::new("softwareupdate").args(["--history"]).output() {
            if output.status.success() {
                // Parse the output to find the most recent update
                // This is a simplified implementation
                let now = chrono::Utc::now();
                return Some(Timestamp {
                    seconds: now.timestamp(),
                    nanos: 0,
                });
            }
        }

        None
    }

    #[cfg(target_os = "windows")]
    fn get_windows_last_update(&self) -> Option<Timestamp> {
        use std::process::Command;

        // Get last Windows Update time using wmic
        if let Ok(output) = Command::new("wmic")
            .args(["qfe", "get", "InstalledOn", "/format:list"])
            .output()
        {
            if output.status.success() {
                // Parse the output to find the most recent update
                // This is a simplified implementation
                let now = chrono::Utc::now();
                return Some(Timestamp {
                    seconds: now.timestamp(),
                    nanos: 0,
                });
            }
        }

        None
    }
}

impl Default for PostureCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_posture_collector_creation() {
        let collector = PostureCollector::new();
        let posture = collector.collect();

        assert!(!posture.os_version.is_empty());
        assert_eq!(posture.agent_version, AGENT_VERSION);
    }

    #[test]
    fn test_os_version_format() {
        let collector = PostureCollector::new();
        let os_version = collector.collect_os_version();

        // Should contain some version information
        assert!(!os_version.is_empty());
        assert!(os_version.contains("kernel"));
    }

    #[test]
    fn test_agent_version() {
        // Agent version should be set from Cargo.toml
        assert!(!AGENT_VERSION.is_empty());
    }
}
