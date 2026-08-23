#![allow(clippy::unwrap_used)]
use avon_crypto::cert::{Certificate, SubjectKind, TbsCertificate};
use avon_crypto::hybrid::kem::HybridKemKeyPair;
use avon_crypto::hybrid::signature::HybridSigningKeyPair;
use avon_keystore::{binding_message, verify_binding, BindingError, HardwareBinding, ProviderKind};
use p256::ecdsa::{signature::Signer, SigningKey};
use p256::pkcs8::EncodePublicKey;

fn hw_binding(
    signing: &HybridSigningKeyPair,
    kem: &HybridKemKeyPair,
    hint: &[u8],
) -> (SigningKey, HardwareBinding) {
    let hw = SigningKey::random(&mut rand::thread_rng());
    let msg = binding_message(&signing.verifying_key(), &kem.public_key(), hint);
    let sig: p256::ecdsa::Signature = hw.sign(&msg);
    let b = HardwareBinding {
        provider: ProviderKind::Tpm2,
        algorithm: "ecdsa-p256-sha256".into(),
        public_key: hw
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec(),
        signature: sig.to_der().as_bytes().to_vec(),
        attestation: None,
    };
    (hw, b)
}

#[test]
fn ecdsa_binding_verifies_and_is_bound_to_both_keys_and_the_hint() {
    let signing = HybridSigningKeyPair::generate().unwrap();
    let kem = HybridKemKeyPair::generate().unwrap();
    let (_hw, b) = hw_binding(&signing, &kem, b"hint");
    verify_binding(&b, &signing.verifying_key(), &kem.public_key(), b"hint").unwrap();

    // A different KEM key breaks the binding (prevents key-substitution).
    let other_kem = HybridKemKeyPair::generate().unwrap();
    assert!(matches!(
        verify_binding(
            &b,
            &signing.verifying_key(),
            &other_kem.public_key(),
            b"hint"
        ),
        Err(BindingError::Signature)
    ));
    // A different PQ signing key breaks it too.
    let other_sig = HybridSigningKeyPair::generate().unwrap();
    assert!(matches!(
        verify_binding(&b, &other_sig.verifying_key(), &kem.public_key(), b"hint"),
        Err(BindingError::Signature)
    ));
    // A different device hint breaks it.
    assert!(verify_binding(&b, &signing.verifying_key(), &kem.public_key(), b"other").is_err());
}

#[test]
fn binding_message_is_length_prefixed_and_domain_separated() {
    let s = HybridSigningKeyPair::generate().unwrap();
    let k = HybridKemKeyPair::generate().unwrap();
    let m = binding_message(&s.verifying_key(), &k.public_key(), b"x");
    assert!(m.starts_with(b"AVON-HW-BINDING-V2"));
    let m2 = binding_message(&s.verifying_key(), &k.public_key(), b"xx");
    assert_ne!(m, m2);
    // The hint is length-prefixed, so a hint that happens to extend the KEM key
    // bytes cannot collide with a different (kem, hint) split.
    assert_ne!(
        binding_message(&s.verifying_key(), &k.public_key(), b""),
        binding_message(&s.verifying_key(), &k.public_key(), b"\x00")
    );
}

#[test]
fn unsupported_algorithm_and_garbage_spki_are_rejected() {
    let signing = HybridSigningKeyPair::generate().unwrap();
    let kem = HybridKemKeyPair::generate().unwrap();
    let (_hw, mut b) = hw_binding(&signing, &kem, b"h");
    b.algorithm = "ed25519".into();
    assert!(matches!(
        verify_binding(&b, &signing.verifying_key(), &kem.public_key(), b"h"),
        Err(BindingError::UnsupportedAlgorithm(_))
    ));
    let (_hw, mut b) = hw_binding(&signing, &kem, b"h");
    b.public_key = vec![0xAB; 40];
    assert!(matches!(
        verify_binding(&b, &signing.verifying_key(), &kem.public_key(), b"h"),
        Err(BindingError::PublicKey)
    ));
}

#[test]
fn binding_encodes_into_certificates_and_roundtrips() {
    let signing = HybridSigningKeyPair::generate().unwrap();
    let kem = HybridKemKeyPair::generate().unwrap();
    let (_hw, mut b) = hw_binding(&signing, &kem, b"hint");
    b.attestation = Some(vec![0x42; 300]);

    // Standalone blob roundtrip, including the attestation field.
    let decoded = HardwareBinding::decode(&b.encode()).unwrap();
    assert_eq!(decoded, b);

    // Inside a certificate.
    let issuer = HybridSigningKeyPair::generate().unwrap();
    let tbs = TbsCertificate {
        version: 2,
        serial: [7; 16],
        tenant_id: "00000000-0000-0000-0000-000000000001".into(),
        subject_id: [9; 16],
        kind: SubjectKind::Device,
        signing_key: signing.verifying_key(),
        kem_key: Some(kem.public_key()),
        not_before: 0,
        not_after: 4_000_000_000,
        issuer_key_id: issuer.verifying_key().key_id(),
        sans: vec!["spiffe://avon/t/device/x".into()],
        tls_cert_sha256: Some([0x22; 32]),
        hardware_binding: Some(b.clone()),
    };
    let cert = Certificate::sign(tbs, &issuer).unwrap();
    let decoded = Certificate::decode(&cert.encode()).unwrap();
    assert_eq!(decoded, cert);
    assert_eq!(decoded.tbs.hardware_binding.as_ref().unwrap(), &b);

    // None still encodes and decodes as None.
    let mut no_binding = cert.tbs.clone();
    no_binding.hardware_binding = None;
    let cert2 = Certificate::sign(no_binding, &issuer).unwrap();
    assert!(Certificate::decode(&cert2.encode())
        .unwrap()
        .tbs
        .hardware_binding
        .is_none());
}
