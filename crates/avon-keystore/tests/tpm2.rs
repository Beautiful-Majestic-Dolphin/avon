#![cfg(all(feature = "tpm2", target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Mutex, MutexGuard, OnceLock};

use avon_crypto::hybrid::signature::Domain;
use avon_keystore::{tpm2::Tpm2KeyProvider, verify_binding, KeyProvider, ProviderKind};

/// One TPM, one test at a time.
///
/// A TPM only guarantees three transient object slots, and these tests share a
/// single swtpm, so running them concurrently exhausts it. Two of them also set
/// process-wide environment variables. Serialising is not a workaround for a
/// bug in the provider — it is what a single piece of hardware requires.
fn tpm() -> Option<MutexGuard<'static, ()>> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    if std::env::var("AVON_TEST_TPM").is_err() {
        eprintln!("skipping: set AVON_TEST_TPM=swtpm and AVON_TPM_TCTI to run TPM tests");
        return None;
    }
    assert!(
        Tpm2KeyProvider::available(),
        "AVON_TEST_TPM is set but no TPM is reachable"
    );
    // A test that fails while holding the lock poisons it; the next test still
    // wants to run, and it wants a real failure of its own, not this one.
    Some(
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner()),
    )
}

fn nonce() -> Vec<u8> {
    use rand::RngCore;
    let mut n = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut n);
    n
}

fn evidence(q: &avon_keystore::Quote, n: &[u8]) -> avon_attest::Evidence {
    avon_attest::Evidence::Tpm2Quote {
        quote: q.attest.clone(),
        signature: q.signature.clone(),
        ak_public: q.ak_public.clone(),
        pcrs: q.pcrs.clone(),
        nonce: n.to_vec(),
    }
}

#[test]
fn creates_seals_and_reopens_keys_and_signs_a_binding() {
    let Some(_tpm) = tpm() else { return };
    let dir = tempfile::tempdir().unwrap();
    let p = Tpm2KeyProvider::create(dir.path()).unwrap();
    assert_eq!(p.kind(), ProviderKind::Tpm2);

    let b = p
        .hardware_binding(b"device-hint")
        .unwrap()
        .expect("tpm provider must produce a binding");
    assert_eq!(b.provider, ProviderKind::Tpm2);
    assert_eq!(b.algorithm, "ecdsa-p256-sha256");
    verify_binding(&b, &p.signing_public(), &p.kem_public(), b"device-hint").unwrap();
    assert!(
        b.attestation.is_some(),
        "TPM2_Certify evidence must accompany the binding"
    );

    let reopened = Tpm2KeyProvider::open(dir.path()).unwrap();
    assert_eq!(
        reopened.signing_public().to_bytes(),
        p.signing_public().to_bytes()
    );
    assert_eq!(reopened.kem_public().to_bytes(), p.kem_public().to_bytes());
    let sig = reopened.sign(Domain::Auth, b"message").unwrap();
    p.signing_public()
        .verify(Domain::Auth, b"message", &sig)
        .unwrap();

    let (ct, ss) = p.kem_public().encapsulate().unwrap();
    assert_eq!(reopened.decapsulate(&ct).unwrap().as_bytes(), ss.as_bytes());
}

#[test]
fn sealed_material_is_not_usable_as_a_key_on_disk() {
    let Some(_tpm) = tpm() else { return };
    let dir = tempfile::tempdir().unwrap();
    let _p = Tpm2KeyProvider::create(dir.path()).unwrap();
    let blob = std::fs::read(dir.path().join("tpm-sealed.bin")).unwrap();
    assert!(
        avon_crypto::hybrid::signature::HybridSigningKeyPair::from_secret_bytes(&blob).is_err(),
        "the sealed blob must not be a usable key"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for f in ["tpm-sealed.bin", "tpm-primary.ctx", "provider.json"] {
            let mode = std::fs::metadata(dir.path().join(f))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{f}");
        }
    }
}

#[test]
fn a_copied_directory_is_useless_against_a_different_tpm() {
    let Some(_tpm) = tpm() else { return };
    let dir = tempfile::tempdir().unwrap();
    let _p = Tpm2KeyProvider::create(dir.path()).unwrap();
    let clone = tempfile::tempdir().unwrap();
    for f in [
        "tpm-sealed.bin",
        "tpm-primary.ctx",
        "tpm-public.json",
        "provider.json",
    ] {
        std::fs::copy(dir.path().join(f), clone.path().join(f)).unwrap();
    }
    let Ok(other) = std::env::var("AVON_TEST_TPM_ALT_TCTI") else {
        eprintln!("skipping the clone check: set AVON_TEST_TPM_ALT_TCTI to a second swtpm");
        return;
    };
    let previous = std::env::var("AVON_TPM_TCTI").ok();
    std::env::set_var("AVON_TPM_TCTI", other);
    let result = Tpm2KeyProvider::open(clone.path());
    match previous {
        Some(v) => std::env::set_var("AVON_TPM_TCTI", v),
        None => std::env::remove_var("AVON_TPM_TCTI"),
    }
    assert!(
        result.is_err(),
        "sealed material must not unseal on a different TPM"
    );
}

/// The cross-check that matters: a quote a real TPM produced, checked by the
/// same verifier the control plane runs. If `avon-attest`'s `TPMS_ATTEST`
/// parser and a TPM ever disagree about the layout, this is where it shows.
#[test]
fn a_real_quote_verifies_with_the_control_planes_verifier() {
    let Some(_tpm) = tpm() else { return };
    let dir = tempfile::tempdir().unwrap();
    let p = Tpm2KeyProvider::create(dir.path()).unwrap();

    let n = nonce();
    let quote = p
        .attestation_quote(&n)
        .unwrap()
        .expect("a TPM-backed provider must produce a quote");

    // The PCRs the default policy asks for are the ones the quote covers.
    let quoted: Vec<u32> = quote.pcrs.iter().map(|(i, _)| *i).collect();
    assert_eq!(quoted, vec![0, 7], "the quote must cover PCRs 0 and 7");
    for (index, value) in &quote.pcrs {
        assert_eq!(value.len(), 32, "PCR {index} is not a SHA-256 digest");
    }

    let verified = avon_attest::verify(
        &evidence(&quote, &n),
        &n,
        None,
        &avon_attest::QuotePolicy::default(),
    );
    assert_eq!(
        verified.state,
        avon_attest::AttestationState::Verified,
        "{}",
        verified.reason
    );

    // And the AK the verifier pinned is the one the provider says it has.
    use sha2::{Digest, Sha256};
    let expected: [u8; 32] = Sha256::digest(p.attestation_key_spki()).into();
    assert_eq!(verified.ak_sha256, expected);

    // Pinning works: the same device quoting again against its known AK stays
    // verified rather than being trusted on first use all over again.
    let n2 = nonce();
    let again = p.attestation_quote(&n2).unwrap().unwrap();
    let second = avon_attest::verify(
        &evidence(&again, &n2),
        &n2,
        Some(&quote.ak_public),
        &avon_attest::QuotePolicy::default(),
    );
    assert_eq!(
        second.state,
        avon_attest::AttestationState::Verified,
        "{}",
        second.reason
    );
}

#[test]
fn a_quote_is_rejected_when_it_answers_a_different_challenge() {
    let Some(_tpm) = tpm() else { return };
    let dir = tempfile::tempdir().unwrap();
    let p = Tpm2KeyProvider::create(dir.path()).unwrap();

    let n = nonce();
    let quote = p.attestation_quote(&n).unwrap().unwrap();
    let policy = avon_attest::QuotePolicy::default();

    // Replayed against a challenge it was not made for.
    let other = nonce();
    let replayed = avon_attest::verify(&evidence(&quote, &n), &other, None, &policy);
    assert_eq!(replayed.state, avon_attest::AttestationState::Failed);
    assert!(replayed.reason.contains("nonce"), "{}", replayed.reason);

    // Presented with an attestation key the device did not enrol with.
    let stranger = Tpm2KeyProvider::create(tempfile::tempdir().unwrap().path()).unwrap();
    let wrong_ak = avon_attest::verify(
        &evidence(&quote, &n),
        &n,
        Some(stranger.attestation_key_spki()),
        &policy,
    );
    assert_eq!(wrong_ak.state, avon_attest::AttestationState::Failed);
    assert!(
        wrong_ak.reason.contains("attestation key"),
        "{}",
        wrong_ak.reason
    );

    // With a PCR value edited to something the TPM did not hash.
    let mut tampered = quote.clone();
    tampered.pcrs[0].1[0] ^= 0xff;
    let edited = avon_attest::verify(&evidence(&tampered, &n), &n, None, &policy);
    assert_eq!(edited.state, avon_attest::AttestationState::Failed);
    assert!(edited.reason.contains("digest"), "{}", edited.reason);

    // And with the signature flipped a bit.
    let mut unsigned = quote.clone();
    let last = unsigned.signature.len() - 1;
    unsigned.signature[last] ^= 0x01;
    let broken = avon_attest::verify(&evidence(&unsigned, &n), &n, None, &policy);
    assert_eq!(broken.state, avon_attest::AttestationState::Failed);
    assert!(broken.reason.contains("signature"), "{}", broken.reason);
}

/// Sealing to PCRs is what makes offline tampering visible: change the measured
/// state and the TPM refuses to unseal at all. PCR 16 is the debug PCR, the one
/// a test is allowed to extend.
#[test]
fn sealing_to_pcrs_makes_the_identity_unusable_once_they_change() {
    let Some(_tpm) = tpm() else { return };
    let Ok(tcti) = std::env::var("AVON_TPM_TCTI") else {
        eprintln!("skipping: this test extends a PCR through tpm2_pcrextend, which needs a TCTI");
        return;
    };
    if std::process::Command::new("tpm2_pcrextend")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skipping: tpm2_pcrextend is not installed");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("AVON_TPM_SEAL_PCRS", "16");
    let created = Tpm2KeyProvider::create(dir.path());
    std::env::remove_var("AVON_TPM_SEAL_PCRS");
    let p = created.unwrap();
    let signing_pk = p.signing_public().to_bytes();
    drop(p);

    // While PCR 16 still holds the value the seal was bound to, reopening works.
    let reopened = Tpm2KeyProvider::open(dir.path()).unwrap();
    assert_eq!(reopened.signing_public().to_bytes(), signing_pk);
    drop(reopened);

    let extended = std::process::Command::new("tpm2_pcrextend")
        .args([
            "-T",
            &tcti,
            "16:sha256=0000000000000000000000000000000000000000000000000000000000000001",
        ])
        .output()
        .unwrap();
    assert!(
        extended.status.success(),
        "tpm2_pcrextend failed: {}",
        String::from_utf8_lossy(&extended.stderr)
    );

    let after = Tpm2KeyProvider::open(dir.path());
    assert!(
        after.is_err(),
        "the TPM must refuse to unseal once the sealed PCRs have moved"
    );
}
