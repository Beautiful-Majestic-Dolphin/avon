#![allow(dead_code)]

use anyhow::Result;

pub mod nftables;
pub mod pf;
pub mod wfp;

#[async_trait::async_trait]
pub trait Firewall: Send + Sync {
    async fn apply(&self, rules: &[String]) -> Result<()>;
    async fn clear(&self) -> Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
