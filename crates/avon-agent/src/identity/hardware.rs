//! Hardware fingerprint collection for device identity.
//!
//! Collects platform-specific hardware identifiers to create a unique
//! device fingerprint that is used for identity binding.

use serde::{Deserialize, Serialize};
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareFingerprint {
    pub cpu_id: Option<String>,
    pub motherboard_uuid: Option<String>,
    pub disk_serials: Vec<String>,
    pub mac_addresses: Vec<String>,
    pub tpm_ek_hash: Option<[u8; 32]>,
    pub hostname: Option<String>,
    pub os_name: Option<String>,
}

impl HardwareFingerprint {
    pub fn collect() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();

        let cpu_id = Self::collect_cpu_id(&sys);
        let motherboard_uuid = Self::collect_motherboard_uuid();
        let disk_serials = Self::collect_disk_serials();
        let mac_addresses = Self::collect_mac_addresses();
        let tpm_ek_hash = Self::collect_tpm_ek_hash();
        let hostname = System::host_name();
        let os_name = System::name();

        Self {
            cpu_id,
            motherboard_uuid,
            disk_serials,
            mac_addresses,
            tpm_ek_hash,
            hostname,
            os_name,
        }
    }

    pub fn to_hash(&self) -> [u8; 32] {
        use avon_crypto::hmac::hmac_sha256;

        let mut data = Vec::new();

        if let Some(ref cpu_id) = self.cpu_id {
            data.extend_from_slice(cpu_id.as_bytes());
        }
        if let Some(ref uuid) = self.motherboard_uuid {
            data.extend_from_slice(uuid.as_bytes());
        }
        for serial in &self.disk_serials {
            data.extend_from_slice(serial.as_bytes());
        }
        for mac in &self.mac_addresses {
            data.extend_from_slice(mac.as_bytes());
        }
        if let Some(ref hash) = self.tpm_ek_hash {
            data.extend_from_slice(hash);
        }

        let key = b"avon-hardware-fingerprint-v1";
        hmac_sha256(key, &data)
    }

    fn collect_cpu_id(sys: &System) -> Option<String> {
        let cpus = sys.cpus();
        if cpus.is_empty() {
            return None;
        }

        let cpu = &cpus[0];
        Some(format!("{}-{}", cpu.vendor_id(), cpu.brand()))
    }

    #[cfg(target_os = "linux")]
    fn collect_motherboard_uuid() -> Option<String> {
        std::fs::read_to_string("/sys/class/dmi/id/product_uuid")
            .ok()
            .map(|s| s.trim().to_string())
            .or_else(|| {
                std::fs::read_to_string("/etc/machine-id")
                    .ok()
                    .map(|s| s.trim().to_string())
            })
    }

    #[cfg(target_os = "macos")]
    fn collect_motherboard_uuid() -> Option<String> {
        use std::process::Command;

        Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .ok()
            .and_then(|output| {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if line.contains("IOPlatformUUID") {
                        if let Some(uuid) = line.split('"').nth(3) {
                            return Some(uuid.to_string());
                        }
                    }
                }
                None
            })
    }

    #[cfg(target_os = "windows")]
    fn collect_motherboard_uuid() -> Option<String> {
        use std::process::Command;

        Command::new("wmic")
            .args(["csproduct", "get", "UUID"])
            .output()
            .ok()
            .and_then(|output| {
                let stdout = String::from_utf8_lossy(&output.stdout);
                stdout.lines().nth(1).map(|s| s.trim().to_string())
            })
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    fn collect_motherboard_uuid() -> Option<String> {
        None
    }

    #[cfg(target_os = "linux")]
    fn collect_disk_serials() -> Vec<String> {
        let mut serials = Vec::new();

        if let Ok(entries) = std::fs::read_dir("/dev/disk/by-id") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("ata-") || name.starts_with("nvme-") {
                    if !name.contains("-part") {
                        serials.push(name);
                    }
                }
            }
        }

        serials.sort();
        serials.truncate(5);
        serials
    }

    #[cfg(target_os = "macos")]
    fn collect_disk_serials() -> Vec<String> {
        use std::process::Command;

        let mut serials = Vec::new();

        // Try system_profiler for NVMe disk info (JSON output)
        if let Ok(output) = Command::new("system_profiler")
            .args(["SPNVMeDataType", "-json"])
            .output()
        {
            if output.status.success() {
                if let Ok(stdout) = String::from_utf8(output.stdout) {
                    // Parse JSON to extract serial numbers
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                        if let Some(nvme_items) =
                            json.get("SPNVMeDataType").and_then(|v| v.as_array())
                        {
                            for item in nvme_items {
                                if let Some(serial) =
                                    item.get("device_serial").and_then(|v| v.as_str())
                                {
                                    let serial = serial.trim().to_string();
                                    if !serial.is_empty() {
                                        serials.push(format!("nvme-{}", serial));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Also try SATA/ATA disks
        if let Ok(output) = Command::new("system_profiler")
            .args(["SPSerialATADataType", "-json"])
            .output()
        {
            if output.status.success() {
                if let Ok(stdout) = String::from_utf8(output.stdout) {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                        if let Some(sata_items) =
                            json.get("SPSerialATADataType").and_then(|v| v.as_array())
                        {
                            for item in sata_items {
                                if let Some(serial) =
                                    item.get("device_serial").and_then(|v| v.as_str())
                                {
                                    let serial = serial.trim().to_string();
                                    if !serial.is_empty() {
                                        serials.push(format!("ata-{}", serial));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        serials.sort();
        serials.truncate(5);
        serials
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn collect_disk_serials() -> Vec<String> {
        Vec::new()
    }

    fn collect_mac_addresses() -> Vec<String> {
        use sysinfo::Networks;

        let networks = Networks::new_with_refreshed_list();
        let mut macs: Vec<String> = networks
            .iter()
            .filter_map(|(name, _data)| {
                if name.starts_with("lo") || name.starts_with("docker") || name.starts_with("veth")
                {
                    return None;
                }
                Self::get_mac_address(name)
            })
            .collect();

        macs.sort();
        macs.dedup();
        macs.truncate(5);
        macs
    }

    #[cfg(target_os = "linux")]
    fn get_mac_address(interface: &str) -> Option<String> {
        let path = format!("/sys/class/net/{}/address", interface);
        std::fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_uppercase())
            .filter(|mac| mac != "00:00:00:00:00:00")
    }

    #[cfg(target_os = "macos")]
    fn get_mac_address(interface: &str) -> Option<String> {
        use std::process::Command;

        Command::new("ifconfig")
            .arg(interface)
            .output()
            .ok()
            .and_then(|output| {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("ether ") {
                        let mac = trimmed
                            .strip_prefix("ether ")
                            .unwrap_or("")
                            .trim()
                            .to_uppercase();
                        if mac != "00:00:00:00:00:00" && !mac.is_empty() {
                            return Some(mac);
                        }
                    }
                }
                None
            })
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn get_mac_address(_interface: &str) -> Option<String> {
        None
    }

    fn collect_tpm_ek_hash() -> Option<[u8; 32]> {
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            super::tpm::TpmContext::try_open().and_then(|ctx| ctx.get_ek_hash().ok())
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_collection() {
        let fingerprint = HardwareFingerprint::collect();

        assert!(fingerprint.cpu_id.is_some() || fingerprint.hostname.is_some());
    }

    #[test]
    fn test_fingerprint_hash_deterministic() {
        let fingerprint = HardwareFingerprint::collect();

        let hash1 = fingerprint.to_hash();
        let hash2 = fingerprint.to_hash();

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 32]);
    }

    #[test]
    fn test_fingerprint_hash_different_for_different_data() {
        let fp1 = HardwareFingerprint {
            cpu_id: Some("cpu1".to_string()),
            motherboard_uuid: None,
            disk_serials: vec![],
            mac_addresses: vec![],
            tpm_ek_hash: None,
            hostname: None,
            os_name: None,
        };

        let fp2 = HardwareFingerprint {
            cpu_id: Some("cpu2".to_string()),
            motherboard_uuid: None,
            disk_serials: vec![],
            mac_addresses: vec![],
            tpm_ek_hash: None,
            hostname: None,
            os_name: None,
        };

        assert_ne!(fp1.to_hash(), fp2.to_hash());
    }
}
