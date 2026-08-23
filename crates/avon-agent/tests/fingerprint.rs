#![allow(clippy::unwrap_used)]
use avon_agent::platform::fingerprint::{collect, collect_from, FINGERPRINT_VERSION};

#[test]
fn hashing_is_deterministic_order_independent_and_domain_separated() {
    let a = collect_from(&[
        ("machine-id", b"abc".to_vec()),
        ("cpu-model", b"x".to_vec()),
    ]);
    let b = collect_from(&[
        ("cpu-model", b"x".to_vec()),
        ("machine-id", b"abc".to_vec()),
    ]);
    assert_eq!(a, b, "input order must not change the fingerprint");
    assert_eq!(
        a.kinds,
        vec!["cpu-model", "machine-id"],
        "kinds are reported sorted"
    );

    let c = collect_from(&[
        ("machine-id", b"abd".to_vec()),
        ("cpu-model", b"x".to_vec()),
    ]);
    assert_ne!(a.hash, c.hash, "changing an input must change the hash");
}

#[test]
fn fields_are_length_prefixed_so_boundaries_cannot_be_shifted() {
    let a = collect_from(&[("machine-id", b"ab".to_vec()), ("cpu-model", b"c".to_vec())]);
    let b = collect_from(&[("machine-id", b"a".to_vec()), ("cpu-model", b"bc".to_vec())]);
    assert_ne!(a.hash, b.hash);
}

#[test]
fn collect_never_uses_volatile_identifiers() {
    let fp = collect();
    for kind in &fp.kinds {
        assert!(
            !kind.contains("mac")
                && !kind.contains("disk")
                && !kind.contains("host")
                && !kind.contains("ip"),
            "fingerprint input {kind} is not stable enough to be an identity input"
        );
    }
    assert_eq!(FINGERPRINT_VERSION, 2);
}

#[test]
fn collect_is_stable_across_calls() {
    assert_eq!(collect().hash, collect().hash);
}

#[test]
fn an_empty_input_set_still_produces_a_usable_fingerprint() {
    let fp = collect_from(&[]);
    assert_eq!(fp.kinds.len(), 0);
    assert_ne!(fp.hash, [0u8; 32]);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_reads_from_the_injected_root_when_testing() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("sys/class/dmi/id")).unwrap();
    std::fs::create_dir_all(root.path().join("etc")).unwrap();
    std::fs::write(
        root.path().join("sys/class/dmi/id/product_uuid"),
        "11111111-2222-3333-4444-555555555555\n",
    )
    .unwrap();
    std::fs::write(
        root.path().join("etc/machine-id"),
        "0123456789abcdef0123456789abcdef\n",
    )
    .unwrap();
    std::env::set_var("AVON_TEST_FAKE_ROOT", root.path());
    let fp = collect();
    std::env::remove_var("AVON_TEST_FAKE_ROOT");
    assert!(
        fp.kinds.contains(&"dmi-product-uuid"),
        "kinds: {:?}",
        fp.kinds
    );
    assert!(fp.kinds.contains(&"machine-id"));
}
