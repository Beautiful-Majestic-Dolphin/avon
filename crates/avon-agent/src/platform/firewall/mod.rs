//! Fail-closed firewall integration.
//!
//! The typed [`FirewallRules`] is the only thing that crosses the helper IPC
//! boundary: rule *text* is rendered here, inside the privileged process, so a
//! compromised agent cannot smuggle a ruleset of its own choosing.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use anyhow::Context;
use anyhow::Result;
use serde::{Deserialize, Serialize};

pub mod nftables;
pub mod pf;
pub mod wfp;

#[async_trait::async_trait]
pub trait Firewall: Send + Sync {
    async fn apply(&self, rules: &[String]) -> Result<()>;
    async fn clear(&self) -> Result<()>;
}

/// Intent, not commands: the destinations that must only be reachable through
/// the tunnel, the interface they are allowed to leave by, and whether traffic
/// is dropped when the tunnel is down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallRules {
    pub allow_cidrs: Vec<String>,
    pub tun_name: String,
    pub block_default: bool,
}

pub struct NoopFirewall;

#[async_trait::async_trait]
impl Firewall for NoopFirewall {
    async fn apply(&self, _rules: &[String]) -> Result<()> {
        Ok(())
    }
    async fn clear(&self) -> Result<()> {
        Ok(())
    }
}

/// The first of these that exists is used; absolute paths only, so `PATH` can
/// never redirect the privileged helper to another binary.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn first_existing(candidates: &[&'static str]) -> Option<&'static str> {
    candidates
        .iter()
        .copied()
        .find(|p| std::path::Path::new(p).exists())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn run_with_stdin(program: &str, args: &[&str], stdin: &str) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut child = tokio::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn {program}"))?;
    if let Some(mut pipe) = child.stdin.take() {
        pipe.write_all(stdin.as_bytes()).await?;
        pipe.shutdown().await?;
    }
    let out = child.wait_with_output().await?;
    if !out.status.success() {
        anyhow::bail!(
            "{program} failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Install the rendered ruleset. Called only by the privileged helper.
#[cfg(target_os = "linux")]
pub async fn apply(rules: &FirewallRules) -> Result<()> {
    let nft = first_existing(&["/usr/sbin/nft", "/sbin/nft"])
        .context("nft not found (/usr/sbin/nft, /sbin/nft)")?;
    run_with_stdin(nft, &["-f", "-"], &nftables::render(rules)).await
}

#[cfg(target_os = "linux")]
pub async fn clear() -> Result<()> {
    let nft = first_existing(&["/usr/sbin/nft", "/sbin/nft"])
        .context("nft not found (/usr/sbin/nft, /sbin/nft)")?;
    // Deleting a table that was never created is not an error worth failing on.
    let _ = run_with_stdin(nft, &["-f", "-"], nftables::CLEAR).await;
    Ok(())
}

#[cfg(target_os = "macos")]
pub async fn apply(rules: &FirewallRules) -> Result<()> {
    let pfctl = first_existing(&["/sbin/pfctl"]).context("pfctl not found (/sbin/pfctl)")?;
    run_with_stdin(pfctl, &["-a", pf::ANCHOR, "-f", "-"], &pf::render(rules)).await
}

#[cfg(target_os = "macos")]
pub async fn clear() -> Result<()> {
    let pfctl = first_existing(&["/sbin/pfctl"]).context("pfctl not found (/sbin/pfctl)")?;
    let _ = tokio::process::Command::new(pfctl)
        .args(["-a", pf::ANCHOR, "-F", "all"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;
    Ok(())
}

#[cfg(target_os = "windows")]
pub async fn apply(rules: &FirewallRules) -> Result<()> {
    wfp::apply(rules).await
}

#[cfg(target_os = "windows")]
pub async fn clear() -> Result<()> {
    wfp::clear().await
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub async fn apply(_rules: &FirewallRules) -> Result<()> {
    anyhow::bail!("no firewall backend on this platform")
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub async fn clear() -> Result<()> {
    Ok(())
}
