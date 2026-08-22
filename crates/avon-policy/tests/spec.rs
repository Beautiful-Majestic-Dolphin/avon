#![allow(clippy::unwrap_used)]
use avon_policy::spec::{Effect, PolicySpec, Protocol, SpecError};

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[test]
fn parses_allow_ssh_fixture() {
    let p: PolicySpec = serde_json::from_str(&fixture("allow_ssh.json")).unwrap();
    p.validate().unwrap();
    assert_eq!(p.effect, Effect::Allow);
    assert_eq!(p.l4.len(), 2);
    assert_eq!(p.l4[0].protocol, Protocol::Tcp);
    assert!(p.l4[0].ports.contains(22));
    assert!(p.l4[0].ports.contains(8050));
    assert!(!p.l4[0].ports.contains(8101));
    assert_eq!(p.destination.cidrs.len(), 1);
}

#[test]
fn rejects_invalid_ports_and_wrong_version() {
    let err = serde_json::from_str::<PolicySpec>(&fixture("invalid_ports.json"))
        .err()
        .map(|e| e.to_string())
        .or_else(|| {
            serde_json::from_str::<PolicySpec>(&fixture("invalid_ports.json"))
                .unwrap()
                .validate()
                .err()
                .map(|e| e.to_string())
        })
        .unwrap();
    assert!(err.contains("port"), "{err}");
    let mut p: PolicySpec = serde_json::from_str(&fixture("allow_ssh.json")).unwrap();
    p.version = 1;
    assert!(matches!(p.validate(), Err(SpecError::Version(1))));
}

#[test]
fn empty_selector_without_any_is_invalid_and_cidrs_only_in_destination() {
    let mut p: PolicySpec = serde_json::from_str(&fixture("allow_ssh.json")).unwrap();
    p.source.pods.clear();
    assert!(matches!(
        p.validate(),
        Err(SpecError::EmptySelector("source"))
    ));
    let mut p: PolicySpec = serde_json::from_str(&fixture("allow_ssh.json")).unwrap();
    p.source.cidrs = vec!["10.0.0.0/8".parse().unwrap()];
    assert!(matches!(p.validate(), Err(SpecError::CidrInSource)));
}

#[test]
fn time_window_requires_valid_timezone_and_times() {
    let p: PolicySpec = serde_json::from_str(&fixture("time_window.json")).unwrap();
    p.validate().unwrap();
    let mut bad = p.clone();
    bad.conditions.time_window.as_mut().unwrap().timezone = "Mars/Olympus".into();
    assert!(matches!(bad.validate(), Err(SpecError::Timezone(_))));
    let mut bad = p;
    bad.conditions.time_window.as_mut().unwrap().start = "25:00".into();
    assert!(matches!(bad.validate(), Err(SpecError::Time(_))));
}

#[test]
fn schema_is_committed_and_current() {
    let committed: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/../../docs/policy-schema.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        committed,
        avon_policy::schema::json_schema(),
        "run `cargo run -p avon-policy -- schema > docs/policy-schema.json`"
    );
}
