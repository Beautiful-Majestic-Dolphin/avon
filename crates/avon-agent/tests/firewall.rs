#![allow(clippy::unwrap_used)]
use avon_agent::platform::firewall::{nftables, pf, FirewallRules};

fn rules() -> FirewallRules {
    FirewallRules {
        allow_cidrs: vec!["10.0.0.0/8".into(), "172.16.0.0/12".into()],
        tun_name: "avon0".into(),
        block_default: true,
    }
}

#[test]
fn nftables_golden() {
    let rendered = nftables::render(&rules());
    let golden = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/nftables.txt"
    ))
    .unwrap();
    assert_eq!(rendered, golden);
}

#[test]
fn pf_golden() {
    let rendered = pf::render(&rules());
    let golden =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/pf.txt"))
            .unwrap();
    assert_eq!(rendered, golden);
}
