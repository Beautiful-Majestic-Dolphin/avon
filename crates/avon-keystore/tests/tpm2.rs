#![cfg(all(feature = "tpm2", any(target_os = "linux", target_os = "windows")))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use avon_crypto::hybrid::signature::Domain;
use avon_keystore::{tpm2::Tpm2KeyProvider, verify_binding, KeyProvider, ProviderKind};

fn tpm() -> bool {
    if std::env::var("AVON_TEST_TPM").is_err() {
        eprintln!("skipping: set AVON_TEST_TPM=swtpm and AVON_TPM_TCTI to run TPM tests");
        return false;
    }
    assert!(
        Tpm2KeyProvider::available(),
        "AVON_TEST_TPM is set but no TPM is reachable"
    );
    true
}

#[test]
fn creates_seals_and_reopens_keys_and_signs_a_binding() {
    if !tpm() {
        return;
    }
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
    if !tpm() {
        return;
    }
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
    if !tpm() {
        return;
    }
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
