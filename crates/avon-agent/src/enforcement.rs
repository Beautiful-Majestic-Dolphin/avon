//! Fail-closed enforcement.
//!
//! When a tunnel session comes up the agent installs rules that confine the
//! protected prefixes to the tunnel interface. When the session goes away the
//! rules **stay** — that is the whole point of fail-closed — unless the operator
//! asked for `fail_open`, in which case they are removed and traffic falls back
//! to the normal route.

#[cfg(unix)]
use std::sync::Arc;

use async_trait::async_trait;
use ipnet::IpNet;

#[cfg(unix)]
use crate::helper::HelperTun;
use crate::platform::firewall::FirewallRules;

/// What to do with the installed rules when a session drops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownAction {
    /// Keep the rules: the protected prefixes stay unreachable until the tunnel
    /// is back.
    Keep,
    /// Remove the rules and let traffic take the default path.
    Clear,
}

pub fn down_action(fail_open: bool) -> DownAction {
    if fail_open {
        DownAction::Clear
    } else {
        DownAction::Keep
    }
}

/// The rules a session's routes imply. `block_default` is the fail-closed
/// switch: with it set, anything not permitted through the tunnel is dropped.
pub fn rules_for(tun_name: &str, protected: &[IpNet], fail_open: bool) -> FirewallRules {
    FirewallRules {
        allow_cidrs: protected.iter().map(|r| r.to_string()).collect(),
        tun_name: tun_name.to_string(),
        block_default: !fail_open,
    }
}

/// Applies the rules through the privileged helper when there is one, and
/// directly when the agent is itself privileged (`--no-helper`, used by the e2e
/// containers).
pub struct FirewallEnforcement {
    #[cfg(unix)]
    helper: Option<Arc<HelperTun>>,
    fail_open: bool,
}

impl FirewallEnforcement {
    #[cfg(unix)]
    pub fn new(helper: Option<Arc<HelperTun>>, fail_open: bool) -> Self {
        Self { helper, fail_open }
    }

    #[cfg(not(unix))]
    pub fn new(fail_open: bool) -> Self {
        Self { fail_open }
    }

    async fn apply(&self, rules: &FirewallRules) -> anyhow::Result<()> {
        #[cfg(unix)]
        if let Some(h) = &self.helper {
            return h.apply_firewall(rules).await.map_err(Into::into);
        }
        crate::platform::firewall::apply(rules).await
    }

    async fn clear(&self) -> anyhow::Result<()> {
        #[cfg(unix)]
        if let Some(h) = &self.helper {
            return h.clear_firewall().await.map_err(Into::into);
        }
        crate::platform::firewall::clear().await
    }
}

#[async_trait]
impl avon_agent_core::traits::Enforcement for FirewallEnforcement {
    async fn on_session_up(
        &self,
        tun_name: &str,
        protected: &[IpNet],
    ) -> Result<(), avon_agent_core::AgentError> {
        let rules = rules_for(tun_name, protected, self.fail_open);
        self.apply(&rules)
            .await
            .map_err(|e| avon_agent_core::AgentError::Tun(format!("apply firewall: {e}")))
    }

    async fn on_session_down(&self) -> Result<(), avon_agent_core::AgentError> {
        match down_action(self.fail_open) {
            DownAction::Keep => {
                tracing::warn!("tunnel down; leaving the fail-closed rules in place");
                Ok(())
            }
            DownAction::Clear => self
                .clear()
                .await
                .map_err(|e| avon_agent_core::AgentError::Tun(format!("clear firewall: {e}"))),
        }
    }
}
