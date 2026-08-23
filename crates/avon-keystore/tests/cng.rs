#![cfg(all(feature = "cng", target_os = "windows"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use avon_crypto::hybrid::signature::Domain;
use avon_keystore::{cng::CngKeyProvider, verify_binding, KeyProvider, ProviderKind};

#[test]
fn creates_binds_and_reopens() {
    if !CngKeyProvider::available() {
        eprintln!("skipping: CNG unavailable on this runner");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let p = CngKeyProvider::create(dir.path()).unwrap();
    assert_eq!(p.kind(), ProviderKind::Cng);

    let b = p
        .hardware_binding(b"hint")
        .unwrap()
        .expect("cng provider produces a binding");
    verify_binding(&b, &p.signing_public(), &p.kem_public(), b"hint").unwrap();

    let reopened = CngKeyProvider::open(dir.path()).unwrap();
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
fn pq_material_is_dpapi_wrapped() {
    if !CngKeyProvider::available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let p = CngKeyProvider::create(dir.path()).unwrap();
    let blob = std::fs::read(dir.path().join("cng-sealed.bin")).unwrap();
    assert!(
        avon_crypto::hybrid::signature::HybridSigningKeyPair::from_secret_bytes(&blob).is_err(),
        "the DPAPI-NG blob must not be a usable key"
    );
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("provider.json")).unwrap()).unwrap();
    assert_eq!(meta["kind"], "cng");
    drop(p);
}
