#![allow(clippy::unwrap_used, clippy::panic)]
//! An agent answers every challenge it is given — including with "I have
//! nothing", which is the only truthful answer a software-keyed device can
//! give.

use avon_agent_core::attest::answer_challenge;
use avon_keystore::{open_or_create, ProviderChoice};

#[test]
fn a_software_provider_answers_that_it_has_no_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let provider = open_or_create(ProviderChoice::Software, dir.path()).unwrap();
    let nonce = [0x5a; 32];

    let ev = answer_challenge(provider.as_ref(), &nonce);
    assert_eq!(ev.format, "none");
    assert!(ev.evidence.is_empty());
    assert_eq!(ev.nonce, nonce, "the answer names the challenge it answers");

    // And the verifier reads that as an absence, not as a failure or a pass.
    let parsed = avon_attest::evidence::parse(&ev.format, &ev.evidence).unwrap();
    let v = avon_attest::verify(&parsed, &nonce, None, &avon_attest::QuotePolicy::default());
    assert_eq!(v.state, avon_attest::AttestationState::None);
}

#[test]
fn a_quote_is_forwarded_verbatim_so_the_verifier_sees_what_the_tpm_signed() {
    // A stand-in provider that returns a quote: the point is that the bytes
    // reach the wire unchanged, not that these particular bytes verify.
    struct Quoting(Box<dyn avon_keystore::KeyProvider>);
    impl avon_keystore::KeyProvider for Quoting {
        fn kind(&self) -> avon_keystore::ProviderKind {
            self.0.kind()
        }
        fn signing_public(&self) -> avon_crypto::hybrid::signature::HybridVerifyingKey {
            self.0.signing_public()
        }
        fn kem_public(&self) -> avon_crypto::hybrid::kem::HybridKemPublicKey {
            self.0.kem_public()
        }
        fn sign(
            &self,
            domain: avon_crypto::hybrid::signature::Domain,
            msg: &[u8],
        ) -> Result<avon_crypto::hybrid::signature::HybridSignature, avon_keystore::KeyError>
        {
            self.0.sign(domain, msg)
        }
        fn decapsulate(
            &self,
            ct: &avon_crypto::hybrid::kem::HybridKemCiphertext,
        ) -> Result<avon_crypto::hybrid::kem::HybridSharedSecret, avon_keystore::KeyError> {
            self.0.decapsulate(ct)
        }
        fn tls_key_pem(&self) -> &str {
            self.0.tls_key_pem()
        }
        fn rotate_tls_key(&mut self) -> Result<String, avon_keystore::KeyError> {
            unreachable!()
        }
        fn hardware_binding(
            &self,
            hint: &[u8],
        ) -> Result<Option<avon_keystore::HardwareBinding>, avon_keystore::KeyError> {
            self.0.hardware_binding(hint)
        }
        fn attestation_quote(
            &self,
            _nonce: &[u8],
        ) -> Result<Option<avon_keystore::Quote>, avon_keystore::KeyError> {
            Ok(Some(avon_keystore::Quote {
                attest: b"attest-bytes".to_vec(),
                signature: b"sig".to_vec(),
                ak_public: b"ak".to_vec(),
                pcrs: vec![(0, vec![1; 32]), (7, vec![2; 32])],
            }))
        }
        fn persist(&self) -> Result<(), avon_keystore::KeyError> {
            self.0.persist()
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let inner = open_or_create(ProviderChoice::Software, dir.path()).unwrap();
    let provider = Quoting(inner);
    let nonce = [0x11; 32];

    let ev = answer_challenge(&provider, &nonce);
    assert_eq!(ev.format, "tpm2-quote");
    let parsed = avon_attest::evidence::parse(&ev.format, &ev.evidence).unwrap();
    match parsed {
        avon_attest::Evidence::Tpm2Quote {
            quote,
            signature,
            ak_public,
            pcrs,
            nonce: carried,
        } => {
            assert_eq!(quote, b"attest-bytes");
            assert_eq!(signature, b"sig");
            assert_eq!(ak_public, b"ak");
            assert_eq!(pcrs.len(), 2);
            assert_eq!(carried, nonce);
        }
        other => panic!("expected a quote, got {other:?}"),
    }
}
