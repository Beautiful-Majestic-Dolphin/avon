#![allow(clippy::unwrap_used)]
//! The derivation from "these routes are carried by the tunnel" to "these rules
//! are installed" is the part with judgement in it, so it is tested directly;
//! actually driving nft/pf needs root and belongs to the e2e suite.

use avon_agent::enforcement::{down_action, rules_for, DownAction};

#[test]
fn rules_confine_the_carried_routes_to_the_tunnel() {
    let routes = [
        "172.30.0.0/24".parse().unwrap(),
        "10.8.0.0/16".parse().unwrap(),
    ];
    let rules = rules_for("avon0", &routes, false);
    assert_eq!(rules.tun_name, "avon0");
    assert_eq!(rules.allow_cidrs, vec!["172.30.0.0/24", "10.8.0.0/16"]);
    assert!(
        rules.block_default,
        "fail-closed is the default: everything else is dropped"
    );
}

#[test]
fn fail_open_installs_permissive_rules() {
    let routes = ["172.30.0.0/24".parse().unwrap()];
    assert!(!rules_for("avon0", &routes, true).block_default);
}

#[test]
fn a_dropped_session_keeps_the_rules_unless_fail_open() {
    assert_eq!(down_action(false), DownAction::Keep);
    assert_eq!(down_action(true), DownAction::Clear);
}

#[test]
fn a_session_with_no_routes_still_blocks_by_default() {
    let rules = rules_for("avon0", &[], false);
    assert!(rules.allow_cidrs.is_empty());
    assert!(
        rules.block_default,
        "an empty route set must not silently disable enforcement"
    );
}
