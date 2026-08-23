//! The AVON endpoint agent.
//!
//! On Unix the privileged work lives in `avon-agent-helper` and reaches the
//! agent as a file descriptor; on Windows there is no way to hand a WinTun
//! session to another process, so the agent service owns the adapter itself and
//! the helper is not built.

pub mod config;
pub mod enforcement;
#[cfg(unix)]
pub mod helper;
pub mod platform;
pub mod run;
