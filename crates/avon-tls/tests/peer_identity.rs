#![allow(clippy::unwrap_used, clippy::expect_used)]
use avon_common::ids::SpiffeKind;
use avon_testkit::pki::TestPki;
use avon_tls::{cert_sha256_from_pem, spiffe_from_cert_der};
use sha2::Digest;

#[test]
fn extracts_spiffe_uri_and_hash_from_leaf() {
    let pki = TestPki::new();
    let id = pki.issue_tls("spiffe://avon/service/control", &["control"]);
    let der = pem::parse(&id.cert_pem).unwrap();
    let spiffe = spiffe_from_cert_der(der.contents()).unwrap().unwrap();
    assert!(matches!(spiffe.kind, SpiffeKind::Service { ref name, .. } if name == "control"));
    let h = cert_sha256_from_pem(id.cert_pem.as_bytes()).unwrap();
    assert_eq!(h, <[u8; 32]>::from(sha2::Sha256::digest(der.contents())));
}
