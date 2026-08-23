#![allow(clippy::unwrap_used, clippy::panic)]
use avon_policy::spec::PolicySpec;

/// Every fixture the Python admin API posts must parse, validate and compile.
fn policy_fixtures() -> Vec<String> {
    // The Python tests copy crates fixtures into api/admin-api/tests/fixtures/policies/
    let candidates = [
        format!(
            "{}/../../api/admin-api/tests/fixtures/policies",
            env!("CARGO_MANIFEST_DIR")
        ),
        format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR")),
    ];
    let mut fixtures = Vec::new();
    for dir in candidates {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.extension().map(|x| x == "json").unwrap_or(false) {
                    if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                        if name == "invalid_ports.json" {
                            continue;
                        }
                        if let Ok(s) = std::fs::read_to_string(&p) {
                            fixtures.push(s);
                        }
                    }
                }
            }
            if !fixtures.is_empty() {
                break;
            }
        }
    }
    fixtures
}

#[test]
fn every_python_fixture_parses_validates_and_compiles() {
    let fixtures = policy_fixtures();
    assert!(!fixtures.is_empty(), "no fixtures found");
    for raw in fixtures {
        let spec: PolicySpec = serde_json::from_str(&raw).unwrap();
        spec.validate().unwrap();
        let data = avon_policy::entities::SnapshotData {
            tenant_id: uuid::Uuid::new_v4(),
            version: 1,
            generated_at: 0,
            pods: vec![],
            device_classes: vec![],
            devices: vec![],
            policies: vec![avon_policy::entities::PolicyEntry {
                id: uuid::Uuid::new_v4(),
                name: "t".into(),
                spec,
            }],
        };
        let out = avon_policy::compile::compile(&data, 0);
        assert!(out.is_ok(), "compile failed: {:?}", out.err());
    }
}

#[test]
fn invalid_ports_fixture_is_rejected() {
    let raw = std::fs::read_to_string(format!(
        "{}/tests/fixtures/invalid_ports.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    // Either deserialization or validation must fail
    let spec: Result<PolicySpec, _> = serde_json::from_str(&raw);
    if let Ok(p) = spec {
        assert!(p.validate().is_err(), "invalid_ports should not validate");
    } else {
        // deserialization error is also acceptable
    }
}
