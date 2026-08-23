#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Quotes are built here rather than read from a checked-in fixture: the
//! previous fixture carried a timestamp and expired, which made the suite fail
//! for reasons that had nothing to do with the code. The key is fixed and
//! ECDSA over P-256 is deterministic (RFC 6979), so these bytes are the same on
//! every run and on every machine.
//!
//! A quote from a real TPM is checked too, in `avon-keystore`'s swtpm-gated
//! tests: this file proves the parser is right about the structure, that one
//! proves the structure is right about the TPM.

use avon_attest::tpms::{ClockInfo, QuoteAttest};
use avon_attest::{evidence, tpms, verify, AttestationState, Evidence, QuotePolicy};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::EncodePublicKey;
use sha2::{Digest, Sha256};

/// A fixed attestation key. Any 32 bytes below the curve order will do; this
/// one is a constant so the whole fixture is reproducible.
fn ak() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32].into()).unwrap()
}

fn ak_public_der(key: &SigningKey) -> Vec<u8> {
    key.verifying_key().to_public_key_der().unwrap().into_vec()
}

fn pcr_values(indices: &[u32]) -> Vec<(u32, Vec<u8>)> {
    indices
        .iter()
        .map(|i| (*i, Sha256::digest(format!("pcr-{i}").as_bytes()).to_vec()))
        .collect()
}

/// Build the quote a TPM would produce over `pcrs` for `nonce`.
fn quote_for(nonce: &[u8], pcrs: &[(u32, Vec<u8>)], safe: bool) -> Evidence {
    let key = ak();
    let mut hasher = Sha256::new();
    for (_, value) in pcrs {
        hasher.update(value);
    }
    let attest = QuoteAttest {
        qualified_signer: vec![0x00, 0x0b].into_iter().chain([9u8; 32]).collect(),
        extra_data: nonce.to_vec(),
        clock: ClockInfo {
            clock_ms: 1_234_567,
            reset_count: 4,
            restart_count: 0,
            safe,
        },
        firmware_version: 0x0001_0002_0003_0004,
        selected_pcrs: pcrs.iter().map(|(i, _)| *i).collect(),
        pcr_digest: hasher.finalize().to_vec(),
    };
    let blob = tpms::encode_quote(&attest);
    let sig: Signature = key.sign(&blob);
    Evidence::Tpm2Quote {
        quote: blob,
        signature: sig.to_der().as_bytes().to_vec(),
        ak_public: ak_public_der(&key),
        pcrs: pcrs.to_vec(),
        nonce: nonce.to_vec(),
    }
}

fn good() -> (Evidence, Vec<u8>, Vec<u8>) {
    let nonce = vec![0x42; 32];
    let ev = quote_for(&nonce, &pcr_values(&[0, 7]), true);
    let ak = ak_public_der(&ak());
    (ev, nonce, ak)
}

#[test]
fn a_good_quote_with_a_known_ak_verifies() {
    let (ev, nonce, ak) = good();
    let v = verify(&ev, &nonce, Some(&ak), &QuotePolicy::default());
    assert_eq!(v.state, AttestationState::Verified, "{}", v.reason);
    assert_ne!(v.pcr_digest, [0u8; 32]);
    assert_eq!(v.reset_count, 4, "the TPM's reset counter is reported");
    assert_eq!(v.firmware_version, 0x0001_0002_0003_0004);
}

#[test]
fn an_unknown_ak_is_trust_on_first_use_only_when_the_policy_allows_it() {
    let (ev, nonce, _) = good();
    let tofu = verify(&ev, &nonce, None, &QuotePolicy::default());
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
    assert_eq!(
        verify(&ev, &nonce, None, &strict).state,
        AttestationState::Failed
    );
}

#[test]
fn a_substituted_ak_fails() {
    let (ev, nonce, ak) = good();
    let mut other = ak;
    let len = other.len();
    other[len - 1] ^= 0xFF;
    let v = verify(&ev, &nonce, Some(&other), &QuotePolicy::default());
    assert_eq!(v.state, AttestationState::Failed);
}

#[test]
fn a_wrong_nonce_fails_so_a_captured_quote_cannot_be_replayed() {
    let (ev, _, ak) = good();
    let v = verify(&ev, &[0x11; 32], Some(&ak), &QuotePolicy::default());
    assert_eq!(v.state, AttestationState::Failed);
    assert!(v.reason.to_lowercase().contains("nonce"), "{}", v.reason);
}

#[test]
fn pcr_values_that_do_not_match_the_signed_digest_fail() {
    let (ev, nonce, ak) = good();
    let Evidence::Tpm2Quote {
        quote,
        signature,
        ak_public,
        mut pcrs,
        nonce: n,
    } = ev
    else {
        unreachable!()
    };
    // Claim a different PCR 7 while keeping the TPM's signed digest.
    pcrs[1].1 = vec![0xAA; 32];
    let tampered = Evidence::Tpm2Quote {
        quote,
        signature,
        ak_public,
        pcrs,
        nonce: n,
    };
    let v = verify(&tampered, &nonce, Some(&ak), &QuotePolicy::default());
    assert_eq!(v.state, AttestationState::Failed);
    assert!(v.reason.contains("digest"), "{}", v.reason);
}

#[test]
fn a_quote_that_omits_a_required_pcr_fails() {
    let nonce = vec![0x42; 32];
    let ev = quote_for(&nonce, &pcr_values(&[7, 23]), true);
    let ak = ak_public_der(&ak());
    let v = verify(&ev, &nonce, Some(&ak), &QuotePolicy::default());
    assert_eq!(v.state, AttestationState::Failed);
    assert!(v.reason.contains("pcr 0"), "{}", v.reason);
}

#[test]
fn an_unsafe_clock_is_refused_unless_the_policy_allows_it() {
    let nonce = vec![0x42; 32];
    let ev = quote_for(&nonce, &pcr_values(&[0, 7]), false);
    let ak = ak_public_der(&ak());
    assert_eq!(
        verify(&ev, &nonce, Some(&ak), &QuotePolicy::default()).state,
        AttestationState::Failed
    );
    let lenient = QuotePolicy {
        require_safe_clock: false,
        ..QuotePolicy::default()
    };
    assert_eq!(
        verify(&ev, &nonce, Some(&ak), &lenient).state,
        AttestationState::Verified
    );
}

#[test]
fn a_signature_over_other_bytes_fails() {
    let (ev, nonce, ak) = good();
    let Evidence::Tpm2Quote {
        mut quote,
        signature,
        ak_public,
        pcrs,
        nonce: n,
    } = ev
    else {
        unreachable!()
    };
    // Flip a bit in the firmware version: parses, but is no longer what was
    // signed.
    let len = quote.len();
    quote[len - 40] ^= 0x01;
    let tampered = Evidence::Tpm2Quote {
        quote,
        signature,
        ak_public,
        pcrs,
        nonce: n,
    };
    let v = verify(&tampered, &nonce, Some(&ak), &QuotePolicy::default());
    assert_eq!(v.state, AttestationState::Failed);
}

#[test]
fn something_that_is_not_a_tpm_structure_is_rejected_before_anything_else() {
    let (_, nonce, ak) = good();
    for junk in [vec![], vec![0u8; 8], vec![0xFF; 64]] {
        let ev = Evidence::Tpm2Quote {
            quote: junk,
            signature: vec![0; 70],
            ak_public: ak.clone(),
            pcrs: vec![],
            nonce: nonce.clone(),
        };
        assert_eq!(
            verify(&ev, &nonce, Some(&ak), &QuotePolicy::default()).state,
            AttestationState::Failed
        );
    }
}

#[test]
fn no_evidence_is_not_a_failure_it_is_an_absence() {
    let v = verify(&Evidence::None, &[0; 32], None, &QuotePolicy::default());
    assert_eq!(v.state, AttestationState::None);
}

#[test]
fn parse_and_encode_roundtrip() {
    let (ev, _, _) = good();
    let (fmt, bytes) = evidence::encode(&ev);
    let parsed = evidence::parse(&fmt, &bytes).unwrap();
    assert_eq!(parsed, ev);
}

#[test]
fn the_attest_structure_survives_a_round_trip() {
    let (ev, nonce, _) = good();
    let Evidence::Tpm2Quote { quote, .. } = &ev else {
        unreachable!()
    };
    let parsed = tpms::parse_quote(quote).unwrap();
    assert_eq!(parsed.extra_data, nonce);
    assert_eq!(parsed.selected_pcrs, vec![0, 7]);
    assert_eq!(tpms::encode_quote(&parsed), *quote);
}
