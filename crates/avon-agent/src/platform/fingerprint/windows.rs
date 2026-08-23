use super::{collect_from, FingerprintV2};

pub(super) fn gather() -> FingerprintV2 {
    let mut inputs: Vec<(&'static str, Vec<u8>)> = Vec::new();

    // MachineGuid from registry HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("C:\\Windows\\System32\\reg.exe")
            .args([
                "query",
                "HKLM\\SOFTWARE\\Microsoft\\Cryptography",
                "/v",
                "MachineGuid",
            ])
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    if line.contains("MachineGuid") {
                        if let Some(val) = line.split_whitespace().last() {
                            inputs.push(("machine-guid", val.as_bytes().to_vec()));
                        }
                    }
                }
            }
        }
        // system-uuid via wmi — use absolute path to wmic if present.
        if let Ok(output) = std::process::Command::new("C:\\Windows\\System32\\wbem\\wmic.exe")
            .args(["csproduct", "get", "UUID", "/value"])
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    if let Some(v) = line.strip_prefix("UUID=") {
                        let v = v.trim();
                        if !v.is_empty() {
                            inputs.push(("system-uuid", v.as_bytes().to_vec()));
                        }
                    }
                }
            }
        }
    }

    collect_from(&inputs)
}
