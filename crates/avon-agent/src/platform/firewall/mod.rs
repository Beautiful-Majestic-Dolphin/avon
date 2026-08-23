use anyhow::Result;

#[async_trait::async_trait]
pub trait Firewall: Send + Sync {
    async fn apply(&self, rules: &[String]) -> Result<()>;
    async fn clear(&self) -> Result<()>;
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
