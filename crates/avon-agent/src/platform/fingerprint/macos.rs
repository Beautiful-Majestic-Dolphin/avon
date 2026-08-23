use super::{collect_from, FingerprintV2};

fn ioreg_value(key: &str) -> Option<Vec<u8>> {
    // Use absolute path as required by Global Constraints.
    let output = std::process::Command::new("/usr/sbin/ioreg")
        .args(["-d2", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if line.contains(key) {
            // Line looks like:   "IOPlatformUUID" = "XXXX-..."
            if let Some(start) = line.find('"') {
                let rest = &line[start + 1..];
                if let Some(end) = rest.find('"') {
                    let _k = &rest[..end];
                    // Find the value quoted string after =
                    if let Some(eq) = line.find('=') {
                        let val_part = &line[eq + 1..];
                        if let Some(s) = val_part.find('"') {
                            let v = &val_part[s + 1..];
                            if let Some(e) = v.find('"') {
                                return Some(v.as_bytes()[..e].to_vec());
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

pub(super) fn gather() -> FingerprintV2 {
    let mut inputs: Vec<(&'static str, Vec<u8>)> = Vec::new();
    if let Some(v) = ioreg_value("IOPlatformUUID") {
        if !v.is_empty() {
            inputs.push(("platform-uuid", v));
        }
    }
    if let Some(v) = ioreg_value("IOPlatformSerialNumber") {
        if !v.is_empty() {
            inputs.push(("platform-serial", v));
        }
    }
    collect_from(&inputs)
}
