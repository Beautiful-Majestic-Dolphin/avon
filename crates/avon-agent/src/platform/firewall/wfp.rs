//! Windows fail-closed enforcement.
//!
//! Windows Firewall evaluates block rules before allow rules, so the WireGuard
//! trick of "permit on the tunnel, block everywhere" cannot be expressed as a
//! pair of rules: a block on a protected prefix would also win over the permit
//! on the tunnel adapter. What *is* expressible — and is what we install — is a
//! block on the protected prefixes bound to every adapter except the tunnel, so
//! packets can only leave through `avon0`. Adapters that appear after the rules
//! are installed are not covered; the agent re-applies on every session change,
//! which closes that window in practice.

use super::FirewallRules;

/// Rules are grouped so `clear` can remove exactly what we installed.
pub const GROUP: &str = "AVON";

/// `powershell.exe`'s absolute path: `PATH` must never decide which binary the
/// privileged helper runs.
pub const POWERSHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Render the PowerShell that installs `rules`. Kept pure so the ruleset is
/// golden-tested on every platform, not just on Windows.
pub fn render(rules: &FirewallRules) -> String {
    let mut out = String::new();
    out.push_str("$ErrorActionPreference = 'Stop'\n");
    out.push_str(&format!(
        "Remove-NetFirewallRule -Group {} -ErrorAction SilentlyContinue\n",
        ps_quote(GROUP)
    ));
    if !rules.block_default {
        // Fail-open: the tunnel is a route, not a jail.
        return out;
    }
    out.push_str(&format!(
        "$outside = @(Get-NetAdapter | Where-Object {{ $_.Name -ne {} }} | Select-Object -ExpandProperty Name)\n",
        ps_quote(&rules.tun_name)
    ));
    out.push_str("if ($outside.Count -gt 0) {\n");
    for cidr in &rules.allow_cidrs {
        out.push_str(&format!(
            "  New-NetFirewallRule -DisplayName {} -Group {} -Direction Outbound -Action Block -RemoteAddress {} -InterfaceAlias $outside | Out-Null\n",
            ps_quote(&format!("AVON block {cidr} off-tunnel")),
            ps_quote(GROUP),
            ps_quote(cidr),
        ));
    }
    out.push_str("}\n");
    out
}

/// Render the PowerShell that removes every rule we installed.
pub fn render_clear() -> String {
    format!(
        "$ErrorActionPreference = 'SilentlyContinue'\nRemove-NetFirewallRule -Group {}\n",
        ps_quote(GROUP)
    )
}

#[cfg(target_os = "windows")]
async fn run(script: &str) -> anyhow::Result<()> {
    use anyhow::Context;
    use tokio::io::AsyncWriteExt;

    let mut child = tokio::process::Command::new(POWERSHELL)
        .args(["-NoProfile", "-NonInteractive", "-Command", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("spawn powershell")?;
    if let Some(mut pipe) = child.stdin.take() {
        pipe.write_all(script.as_bytes()).await?;
        pipe.shutdown().await?;
    }
    let out = child.wait_with_output().await?;
    if !out.status.success() {
        anyhow::bail!(
            "powershell failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub async fn apply(rules: &FirewallRules) -> anyhow::Result<()> {
    run(&render(rules)).await
}

#[cfg(target_os = "windows")]
pub async fn clear() -> anyhow::Result<()> {
    let _ = run(&render_clear()).await;
    Ok(())
}
