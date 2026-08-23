//! The device's side of attestation.
//!
//! The control plane sends a nonce; the agent asks its key provider for a quote
//! over it and sends back whatever it gets. A provider with no attestation
//! hardware answers with nothing, and "nothing" is reported as such — an agent
//! that manufactured evidence would be telling the control plane exactly what
//! it wants to hear, which is the one thing attestation exists to prevent.

use avon_keystore::KeyProvider;
use avon_protocol::v2::AttestationEvidence;

/// Answer a challenge. Never fails the caller: a provider that errors is
/// reported as having no evidence, and the control plane decides what that is
/// worth.
pub fn answer_challenge(provider: &dyn KeyProvider, nonce: &[u8]) -> AttestationEvidence {
    let quote = match provider.attestation_quote(nonce) {
        Ok(q) => q,
        Err(e) => {
            tracing::warn!(error = %e, "key provider could not produce an attestation quote");
            None
        }
    };
    match quote {
        Some(q) => {
            let ev = avon_attest::Evidence::Tpm2Quote {
                quote: q.attest,
                signature: q.signature,
                ak_public: q.ak_public,
                pcrs: q.pcrs,
                nonce: nonce.to_vec(),
            };
            let (format, evidence) = avon_attest::evidence::encode(&ev);
            AttestationEvidence {
                format,
                evidence,
                nonce: nonce.to_vec(),
            }
        }
        None => {
            let (format, evidence) = avon_attest::evidence::encode(&avon_attest::Evidence::None);
            AttestationEvidence {
                format,
                evidence,
                nonce: nonce.to_vec(),
            }
        }
    }
}
