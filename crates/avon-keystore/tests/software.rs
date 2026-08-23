#![allow(clippy::unwrap_used)]
use avon_crypto::hybrid::signature::Domain;
use avon_keystore::select::{open_existing, open_or_create, ProviderChoice};
use avon_keystore::{KeyError, KeyProvider, ProviderKind, SoftwareKeyProvider};

#[test]
fn create_persists_0600_files_and_reloads_the_same_keys() {
    let dir = tempfile::tempdir().unwrap();
    let p = SoftwareKeyProvider::create(dir.path()).unwrap();
    assert_eq!(p.kind(), ProviderKind::Software);
    assert!(
        p.hardware_binding(b"hint").unwrap().is_none(),
        "software has no hardware key"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in ["identity.bin", "identity.key", "provider.json"] {
            let mode = std::fs::metadata(dir.path().join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{name}");
        }
        assert_eq!(
            std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    let reopened = open_existing(dir.path()).unwrap();
    assert_eq!(reopened.kind(), ProviderKind::Software);
    assert_eq!(
        reopened.signing_public().to_bytes(),
        p.signing_public().to_bytes()
    );
    assert_eq!(reopened.kem_public().to_bytes(), p.kem_public().to_bytes());

    // Signing and decapsulation still work through the trait after reload.
    let sig = reopened.sign(Domain::Auth, b"m").unwrap();
    p.signing_public().verify(Domain::Auth, b"m", &sig).unwrap();
    let (ct, ss) = p.kem_public().encapsulate().unwrap();
    assert_eq!(reopened.decapsulate(&ct).unwrap().as_bytes(), ss.as_bytes());
    assert!(!reopened.tls_key_pem().is_empty());
}

#[test]
fn create_refuses_to_overwrite_an_existing_identity() {
    let dir = tempfile::tempdir().unwrap();
    SoftwareKeyProvider::create(dir.path()).unwrap();
    assert!(matches!(
        SoftwareKeyProvider::create(dir.path()),
        Err(KeyError::Exists)
    ));
}

#[test]
fn provider_json_records_the_kind() {
    let dir = tempfile::tempdir().unwrap();
    SoftwareKeyProvider::create(dir.path()).unwrap();
    let json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("provider.json")).unwrap()).unwrap();
    assert_eq!(json["kind"], "software");
}

#[test]
fn open_existing_fails_on_an_empty_directory() {
    let dir = tempfile::tempdir().unwrap();
    assert!(open_existing(dir.path()).is_err());
}

#[test]
fn open_or_create_is_stable_across_calls() {
    let dir = tempfile::tempdir().unwrap();
    // Auto on a laptop/CI box without hardware providers must fall back to software
    // (with a WARN naming the reason) instead of failing.
    let first = open_or_create(ProviderChoice::Auto, dir.path()).unwrap();
    let second = open_or_create(ProviderChoice::Auto, dir.path()).unwrap();
    assert_eq!(first.kind(), second.kind());
    assert_eq!(
        first.signing_public().to_bytes(),
        second.signing_public().to_bytes()
    );
    // An explicit choice that contradicts the on-disk provider is a hard error,
    // never a silent re-key.
    if first.kind() == ProviderKind::Software {
        assert!(open_or_create(ProviderChoice::Tpm2, dir.path()).is_err());
    }
}
