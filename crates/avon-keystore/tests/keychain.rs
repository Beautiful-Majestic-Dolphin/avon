#![cfg(all(feature = "keychain", target_os = "macos"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use avon_crypto::hybrid::signature::Domain;
use avon_keystore::{keychain::KeychainKeyProvider, verify_binding, KeyProvider, ProviderKind};

struct TempKeychain {
    path: std::path::PathBuf,
}

impl TempKeychain {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("avon-test-{}.keychain-db", std::process::id()));
        let _ = std::process::Command::new("/usr/bin/security")
            .args(["delete-keychain", path.to_str().unwrap()])
            .status();
        let ok = std::process::Command::new("/usr/bin/security")
            .args(["create-keychain", "-p", "avon-test", path.to_str().unwrap()])
            .status()
            .expect("security create-keychain")
            .success();
        assert!(ok, "could not create a temporary keychain");
        let _ = std::process::Command::new("/usr/bin/security")
            .args(["unlock-keychain", "-p", "avon-test", path.to_str().unwrap()])
            .status();
        std::env::set_var("AVON_MACOS_KEYCHAIN", &path);
        Self { path }
    }
}

impl Drop for TempKeychain {
    fn drop(&mut self) {
        let _ = std::process::Command::new("/usr/bin/security")
            .args(["delete-keychain", self.path.to_str().unwrap()])
            .status();
        std::env::remove_var("AVON_MACOS_KEYCHAIN");
    }
}

#[test]
fn creates_binds_and_reopens() {
    let _kc = TempKeychain::new();
    if !KeychainKeyProvider::available() {
        eprintln!("skipping: keychain unavailable on this runner");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let p = KeychainKeyProvider::create(dir.path()).unwrap();
    assert_eq!(p.kind(), ProviderKind::Keychain);

    let b = p
        .hardware_binding(b"hint")
        .unwrap()
        .expect("keychain provider produces a binding");
    verify_binding(&b, &p.signing_public(), &p.kem_public(), b"hint").unwrap();

    let reopened = KeychainKeyProvider::open(dir.path()).unwrap();
    assert_eq!(
        reopened.signing_public().to_bytes(),
        p.signing_public().to_bytes()
    );
    let sig = reopened.sign(Domain::Auth, b"m").unwrap();
    p.signing_public().verify(Domain::Auth, b"m", &sig).unwrap();
    let (ct, ss) = p.kem_public().encapsulate().unwrap();
    assert_eq!(reopened.decapsulate(&ct).unwrap().as_bytes(), ss.as_bytes());
}

#[test]
fn pq_material_is_not_on_disk_in_the_clear() {
    let _kc = TempKeychain::new();
    if !KeychainKeyProvider::available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let p = KeychainKeyProvider::create(dir.path()).unwrap();
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let path = entry.unwrap().path();
        let bytes = std::fs::read(&path).unwrap_or_default();
        assert!(
            avon_crypto::hybrid::signature::HybridSigningKeyPair::from_secret_bytes(&bytes)
                .is_err(),
            "{} contains usable secret key material",
            path.display()
        );
    }
    drop(p);
}
