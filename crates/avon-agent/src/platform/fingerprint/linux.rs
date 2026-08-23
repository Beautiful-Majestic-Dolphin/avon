use super::collect_from;
use super::FingerprintV2;
use std::path::Path;

fn root() -> String {
    std::env::var("AVON_TEST_FAKE_ROOT").unwrap_or_default()
}

fn read_under_root(relative: &str) -> Option<Vec<u8>> {
    let r = root();
    let path = if r.is_empty() {
        Path::new(relative).to_path_buf()
    } else {
        Path::new(&r).join(relative.trim_start_matches('/'))
    };
    std::fs::read(&path).ok().map(|mut v| {
        // Trim trailing newline and whitespace as per file format.
        while v
            .last()
            .map(|c| *c == b'\n' || *c == b'\r')
            .unwrap_or(false)
        {
            v.pop();
        }
        v
    })
}

fn cpu_model() -> Option<Vec<u8>> {
    let data = read_under_root("/proc/cpuinfo")?;
    let text = String::from_utf8_lossy(&data);
    let mut vendor = String::new();
    let mut family = String::new();
    let mut model = String::new();
    for line in text.lines() {
        let mut parts = line.splitn(2, ':');
        let key = parts.next().unwrap_or("").trim();
        let val = parts.next().unwrap_or("").trim();
        match key {
            "vendor_id" if vendor.is_empty() => vendor = val.to_string(),
            "cpu family" if family.is_empty() => family = val.to_string(),
            "model" if model.is_empty() && !line.contains("model name") => model = val.to_string(),
            _ => {}
        }
    }
    if vendor.is_empty() && family.is_empty() && model.is_empty() {
        return None;
    }
    Some(format!("{vendor}:{family}:{model}").into_bytes())
}

pub(super) fn gather() -> FingerprintV2 {
    let mut inputs: Vec<(&'static str, Vec<u8>)> = Vec::new();

    if let Some(v) = read_under_root("/sys/class/dmi/id/product_uuid") {
        if !v.is_empty() {
            inputs.push(("dmi-product-uuid", v));
        }
    }
    if let Some(v) = read_under_root("/etc/machine-id") {
        if !v.is_empty() {
            inputs.push(("machine-id", v));
        }
    } else if let Some(v) = read_under_root("/var/lib/dbus/machine-id") {
        if !v.is_empty() {
            inputs.push(("machine-id", v));
        }
    }
    if let Some(v) = cpu_model() {
        inputs.push(("cpu-model", v));
    }
    // tpm-ek when TPM provider is active — try to get EK SHA256 if available.
    #[cfg(feature = "tpm2")]
    {
        // Attempt to read EK via Tpm2 provider if available, but don't fail if not.
        // The hash is the SHA256 of the EK public; we simulate by reading from env if present.
        if let Ok(ek) = std::env::var("AVON_TEST_TPM_EK") {
            if let Ok(bytes) = hex::decode(ek.trim()) {
                if bytes.len() == 32 {
                    inputs.push(("tpm-ek", bytes));
                }
            }
        }
    }

    collect_from(&inputs)
}
