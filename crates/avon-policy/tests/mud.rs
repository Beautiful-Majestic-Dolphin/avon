#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use avon_policy::mud::{import, MudError};
use avon_policy::spec::{Effect, Protocol};
use ipnet::IpNet;
use uuid::Uuid;

fn fixture() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/mud-camera.json"
    ))
    .unwrap()
}

fn resolver(name: &str) -> Vec<IpNet> {
    match name {
        "pool.ntp.org" => vec!["192.0.2.0/24".parse().unwrap()],
        "vendor.example.com" => vec!["198.51.100.7/32".parse().unwrap()],
        _ => vec![],
    }
}

#[test]
fn imports_two_allows_and_a_terminal_deny() {
    let class = Uuid::new_v4();
    let result = import(&fixture(), class, &resolver).unwrap();
    assert_eq!(
        result.policies.len(),
        3,
        "two allows plus the implicit deny"
    );

    let (ntp_name, ntp) = &result.policies[0];
    assert!(ntp_name.contains("ntp"), "{ntp_name}");
    assert_eq!(ntp.effect, Effect::Allow);
    assert_eq!(ntp.source.device_classes, vec![class]);
    assert_eq!(
        ntp.destination.cidrs,
        vec!["192.0.2.0/24".parse::<IpNet>().unwrap()]
    );
    assert_eq!(ntp.l4[0].protocol, Protocol::Udp);
    assert!(ntp.l4[0].ports.contains(123));
    assert!(!ntp.l4[0].ports.contains(124));

    let (_, https) = &result.policies[1];
    assert_eq!(
        https.destination.cidrs,
        vec!["198.51.100.7/32".parse::<IpNet>().unwrap()]
    );
    assert!(https.l4[0].ports.contains(443));

    let (deny_name, deny) = &result.policies[2];
    assert_eq!(deny.effect, Effect::Deny);
    assert!(
        deny.destination.any,
        "the terminal rule must match everything: {deny_name}"
    );
    for (_, p) in &result.policies {
        p.validate().unwrap();
    }
}

#[test]
fn to_device_acls_are_skipped_with_a_reason_not_silently_dropped() {
    let result = import(&fixture(), Uuid::new_v4(), &resolver).unwrap();
    assert!(!result.skipped.is_empty());
    assert!(
        result.skipped.iter().any(|s| s.contains("to-device")),
        "{:?}",
        result.skipped
    );
}

#[test]
fn an_unresolvable_name_is_skipped_rather_than_becoming_an_allow_any() {
    let result = import(&fixture(), Uuid::new_v4(), &|_| Vec::new()).unwrap();
    assert!(
        result
            .policies
            .iter()
            .all(|(_, p)| p.effect == Effect::Deny || !p.destination.cidrs.is_empty()),
        "a name that did not resolve must not turn into an unrestricted allow"
    );
    assert!(
        result.skipped.iter().any(|s| s.contains("resolve")),
        "{:?}",
        result.skipped
    );
}

#[test]
fn malformed_documents_are_errors() {
    assert!(matches!(
        import("{", Uuid::new_v4(), &resolver),
        Err(MudError::Json(_))
    ));
    assert!(matches!(
        import("{}", Uuid::new_v4(), &resolver),
        Err(MudError::Empty)
    ));
}
