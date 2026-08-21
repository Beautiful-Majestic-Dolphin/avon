#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use avon_crypto::aead::Suite;
use avon_crypto::hybrid::kem::combine;
use avon_crypto::hybrid::signature::{framed_message, Domain};
use avon_crypto::session::{SessionKeys, Transcript};
use serde::{Deserialize, Serialize};

fn dir() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors") }

#[derive(Serialize, Deserialize)]
struct CombinerVector { ss_x25519: String, ss_mlkem: String, eph_x25519_pk: String, x25519_pk: String, mlkem_ct: String, mlkem_pk: String, expected: String }

#[derive(Serialize, Deserialize)]
struct KeyScheduleVector { session_id: String, initiator_cert_id: String, responder_cert_id: String, eph_kem_pk: String, ct_e: String, ct_s: String, suite: u8, ss_e: String, ss_s: String, ss_rekey: String, k_i2r: String, k_r2i: String, rekey_secret: String, epoch1_k_i2r: String }

#[derive(Serialize, Deserialize)]
struct FramingVector { domain: String, message: String, expected: String }

fn pattern(len: usize, seed: u8) -> Vec<u8> { (0..len).map(|i| seed.wrapping_add(i as u8)).collect() }

fn compute_combiner() -> CombinerVector {
    let ss_x = pattern(32, 1); let ss_m = pattern(32, 2); let eph = pattern(32, 3); let xpk = pattern(32, 4);
    let ct = pattern(1088, 5); let mpk = pattern(1184, 6);
    let out = combine(ss_x.as_slice().try_into().unwrap(), ss_m.as_slice().try_into().unwrap(), eph.as_slice().try_into().unwrap(), xpk.as_slice().try_into().unwrap(), &ct, &mpk);
    CombinerVector { ss_x25519: hex::encode(ss_x), ss_mlkem: hex::encode(ss_m), eph_x25519_pk: hex::encode(eph), x25519_pk: hex::encode(xpk), mlkem_ct: hex::encode(ct), mlkem_pk: hex::encode(mpk), expected: hex::encode(out) }
}

fn ss(seed: u8) -> avon_crypto::hybrid::kem::HybridSharedSecret {
    avon_crypto::hybrid::kem::HybridSharedSecret::from_bytes_for_tests(pattern(32, seed).as_slice().try_into().unwrap())
}

fn compute_key_schedule() -> KeyScheduleVector {
    let t = Transcript { session_id: [7; 16], initiator_cert_id: [8; 32], responder_cert_id: [9; 32], eph_kem_pk: pattern(1216, 10), ct_e: pattern(1120, 11), ct_s: pattern(1120, 12), suite: Suite::Aes256Gcm };
    let k0 = SessionKeys::derive(&t, &ss(20), &ss(21)).unwrap();
    let k1 = k0.rekey(&ss(22)).unwrap();
    KeyScheduleVector {
        session_id: hex::encode(t.session_id), initiator_cert_id: hex::encode(t.initiator_cert_id), responder_cert_id: hex::encode(t.responder_cert_id),
        eph_kem_pk: hex::encode(&t.eph_kem_pk), ct_e: hex::encode(&t.ct_e), ct_s: hex::encode(&t.ct_s), suite: t.suite.id(),
        ss_e: hex::encode(pattern(32, 20)), ss_s: hex::encode(pattern(32, 21)), ss_rekey: hex::encode(pattern(32, 22)),
        k_i2r: hex::encode(k0.k_i2r), k_r2i: hex::encode(k0.k_r2i), rekey_secret: hex::encode(k0.rekey_secret), epoch1_k_i2r: hex::encode(k1.k_i2r),
    }
}

fn compute_framing() -> Vec<FramingVector> {
    [Domain::Cert, Domain::Csr, Domain::Auth, Domain::Session, Domain::Crl, Domain::Offer].iter().map(|d| FramingVector {
        domain: String::from_utf8(d.label().to_vec()).unwrap(), message: hex::encode(b"vector"), expected: hex::encode(framed_message(*d, b"vector")),
    }).collect()
}

#[test]
fn combiner_vector_matches() {
    let v: CombinerVector = serde_json::from_str(&std::fs::read_to_string(dir().join("combiner.json")).unwrap()).unwrap();
    let c = compute_combiner();
    assert_eq!(c.expected, v.expected);
}

#[test]
fn key_schedule_vector_matches() {
    let v: KeyScheduleVector = serde_json::from_str(&std::fs::read_to_string(dir().join("key_schedule.json")).unwrap()).unwrap();
    let c = compute_key_schedule();
    assert_eq!((c.k_i2r, c.k_r2i, c.rekey_secret, c.epoch1_k_i2r), (v.k_i2r, v.k_r2i, v.rekey_secret, v.epoch1_k_i2r));
}

#[test]
fn framing_vectors_match() {
    let v: Vec<FramingVector> = serde_json::from_str(&std::fs::read_to_string(dir().join("framing.json")).unwrap()).unwrap();
    let c = compute_framing();
    assert_eq!(serde_json::to_string(&c).unwrap(), serde_json::to_string(&v).unwrap());
}

/// Run with `cargo test -p avon-crypto --features test-vectors --test vectors regenerate_vectors -- --ignored`
/// and review the diff before committing.
#[test]
#[ignore]
fn regenerate_vectors() {
    std::fs::create_dir_all(dir()).unwrap();
    std::fs::write(dir().join("combiner.json"), serde_json::to_string_pretty(&compute_combiner()).unwrap()).unwrap();
    std::fs::write(dir().join("key_schedule.json"), serde_json::to_string_pretty(&compute_key_schedule()).unwrap()).unwrap();
    std::fs::write(dir().join("framing.json"), serde_json::to_string_pretty(&compute_framing()).unwrap()).unwrap();
}
