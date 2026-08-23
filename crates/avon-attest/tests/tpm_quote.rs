#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::time::SystemTime;

use avon_attest::{evidence, verify, AttestationState, Evidence, QuotePolicy};

fn fixture() -> Evidence {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/quote-good.json"
    ))
    .unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let hex = |k: &str| hex::decode(v[k].as_str().unwrap()).unwrap();
    Evidence::Tpm2Quote {
        quote: hex("quote"),
        signature: hex("signature"),
        ak_public: hex("ak_public"),
        pcrs: v["pcrs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                (
                    p["index"].as_u64().unwrap() as u32,
                    hex::decode(p["value"].as_str().unwrap()).unwrap(),
                )
            })
            .collect(),
        nonce: hex("nonce"),
    }
}

fn nonce() -> Vec<u8> {
    let v: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/quote-good.json"
        ))
        .unwrap(),
    )
    .unwrap();
    hex::decode(v["nonce"].as_str().unwrap()).unwrap()
}
fn ak() -> Vec<u8> {
    let v: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/quote-good.json"
        ))
        .unwrap(),
    )
    .unwrap();
    hex::decode(v["ak_public"].as_str().unwrap()).unwrap()
}

#[test]
fn a_good_quote_with_a_known_ak_verifies() {
    let v = verify(
        &fixture(),
        &nonce(),
        Some(&ak()),
        &QuotePolicy::default(),
        SystemTime::now(),
    );
    assert_eq!(v.state, AttestationState::Verified, "{}", v.reason);
    assert_ne!(v.pcr_digest, [0u8; 32]);
}

#[test]
fn an_unknown_ak_is_trust_on_first_use_only_when_the_policy_allows_it() {
    let tofu = verify(
        &fixture(),
        &nonce(),
        None,
        &QuotePolicy::default(),
        SystemTime::now(),
    );
    assert_eq!(tofu.state, AttestationState::Verified);
    assert!(
        tofu.reason.to_lowercase().contains("first use"),
        "{}",
        tofu.reason
    );

    let strict = QuotePolicy {
        allow_unknown_ak: false,
        ..QuotePolicy::default()
    };
    let v = verify(&fixture(), &nonce(), None, &strict, SystemTime::now());
    assert_eq!(v.state, AttestationState::Failed);
}

#[test]
fn a_substituted_ak_fails() {
    let other = {
        let mut a = ak();
        let len = a.len();
        a[len - 1] ^= 0xFF;
        a
    };
    let v = verify(
        &fixture(),
        &nonce(),
        Some(&other),
        &QuotePolicy::default(),
        SystemTime::now(),
    );
    assert_eq!(v.state, AttestationState::Failed);
}

#[test]
fn a_wrong_nonce_fails_so_a_captured_quote_cannot_be_replayed() {
    let v = verify(
        &fixture(),
        &[0x11; 32],
        Some(&ak()),
        &QuotePolicy::default(),
        SystemTime::now(),
    );
    assert_eq!(v.state, AttestationState::Failed);
    assert!(v.reason.to_lowercase().contains("nonce"), "{}", v.reason);
}

#[test]
fn parse_and_encode_roundtrip() {
    let ev = fixture();
    let (fmt, bytes) = evidence::encode(&ev);
    let parsed = evidence::parse(&fmt, &bytes).unwrap();
    assert_eq!(parsed, ev);
}
