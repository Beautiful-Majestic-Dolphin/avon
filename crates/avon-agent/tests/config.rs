#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::PathBuf;

use avon_agent::config::{AgentConfig, ConfigLoadError};

#[test]
fn loads_partial_toml_with_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.toml");
    std::fs::write(&path, "control_plane = \"control.example.com:443\"\n").unwrap();
    let cfg = AgentConfig::load(Some(&path)).unwrap();
    assert_eq!(cfg.control_plane, "control.example.com:443");
    assert_eq!(cfg.pulse_interval_secs, 30);
    assert_eq!(cfg.tun_name, "avon0");
    assert_eq!(cfg.overlay_mtu, 1280);
}

#[test]
fn syntax_errors_are_reported_not_swallowed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.toml");
    std::fs::write(&path, "control_plane = [unterminated\n").unwrap();
    let err = AgentConfig::load(Some(&path)).unwrap_err();
    assert!(matches!(err, ConfigLoadError::Parse { .. }), "{err:?}");
}

#[test]
fn unknown_keys_are_errors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.toml");
    std::fs::write(&path, "gateway_adress = \"typo:1\"\n").unwrap();
    assert!(AgentConfig::load(Some(&path)).is_err());
}

#[test]
fn pulse_interval_below_five_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.toml");
    std::fs::write(&path, "control_plane = \"c:1\"\npulse_interval_secs = 0\n").unwrap();
    let err = AgentConfig::load(Some(&path)).unwrap_err();
    assert!(
        matches!(
            err,
            ConfigLoadError::Invalid {
                field: "pulse_interval_secs",
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn missing_explicit_path_is_an_error_but_missing_default_path_uses_defaults() {
    let err = AgentConfig::load(Some(&PathBuf::from("/nonexistent/agent.toml"))).unwrap_err();
    assert!(matches!(err, ConfigLoadError::Read { .. }));
    let err = AgentConfig::load(None).unwrap_err();
    assert!(
        matches!(
            err,
            ConfigLoadError::Invalid {
                field: "control_plane",
                ..
            }
        ) || matches!(err, ConfigLoadError::Read { .. })
    );
}
