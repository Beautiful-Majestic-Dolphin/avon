//! Native service integration. Only Windows needs code here: systemd and
//! launchd take unit files, which live under `deploy/`.

#[cfg(target_os = "windows")]
pub mod windows;
