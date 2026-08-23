//! Quote verification.
//!
//! What makes a quote convincing is not that it parses, but that four things
//! line up: the TPM signed it (magic plus a signature by the AK), it answers
//! *this* challenge (`extraData` is the nonce we just issued), it covers the
//! PCRs the policy asks for, and the PCR values the agent sent hash to the
//! digest the TPM signed. Freshness comes from the nonce, never from the TPM's
//! clock — that clock counts milliseconds since the TPM was made and says
//! nothing about wall time.

use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};

use crate::evidence::Evidence;
use crate::policy::{AttestationState, QuotePolicy};
use crate::tpms;

#[derive(Clone, Debug)]
pub struct Verified {
    pub state: AttestationState,
    pub pcr_digest: [u8; 32],
    pub ak_sha256: [u8; 32],
    /// The TPM's reset counter: a jump means the machine rebooted, which is
    /// worth recording even when the quote is otherwise fine.
    pub reset_count: u32,
    pub firmware_version: u64,
    pub reason: String,
}

impl Verified {
    fn failed(ak_sha256: [u8; 32], pcr_digest: [u8; 32], reason: impl Into<String>) -> Self {
        Self {
            state: AttestationState::Failed,
            pcr_digest,
            ak_sha256,
            reset_count: 0,
            firmware_version: 0,
            reason: reason.into(),
        }
    }
}

/// Check `ev` against the challenge we issued. `known_ak` is the AK this device
/// used last time, if any; without one the policy decides whether to trust on
/// first use.
pub fn verify(
    ev: &Evidence,
    expected_nonce: &[u8],
    known_ak: Option<&[u8]>,
    policy: &QuotePolicy,
) -> Verified {
    let Evidence::Tpm2Quote {
        quote,
        signature,
        ak_public,
        pcrs,
        nonce: _,
    } = ev
    else {
        return Verified {
            state: AttestationState::None,
            pcr_digest: [0; 32],
            ak_sha256: [0; 32],
            reset_count: 0,
            firmware_version: 0,
            reason: "no evidence".into(),
        };
    };

    let ak_sha256: [u8; 32] = Sha256::digest(ak_public).into();
    let attest = match tpms::parse_quote(quote) {
        Ok(a) => a,
        Err(e) => return Verified::failed(ak_sha256, [0; 32], e.to_string()),
    };
    let mut pcr_digest = [0u8; 32];
    pcr_digest.copy_from_slice(&attest.pcr_digest);

    if attest.extra_data != expected_nonce {
        return Verified::failed(ak_sha256, pcr_digest, "nonce mismatch");
    }
    if policy.require_safe_clock && !attest.clock.safe {
        return Verified::failed(ak_sha256, pcr_digest, "TPM clock is not safe");
    }

    // Every PCR the policy cares about has to be in the selection the TPM
    // signed — a quote over PCR 23 alone must not satisfy a policy about PCR 0.
    for required in &policy.required_pcrs {
        if !attest.selected_pcrs.contains(required) {
            return Verified::failed(ak_sha256, pcr_digest, format!("pcr {required} not quoted"));
        }
    }

    // The values the agent sent must be the values the TPM hashed: recompute
    // the digest over the selection, in the TPM's order.
    let mut hasher = Sha256::new();
    for index in &attest.selected_pcrs {
        match pcrs.iter().find(|(i, _)| i == index) {
            Some((_, value)) => hasher.update(value),
            None => {
                return Verified::failed(
                    ak_sha256,
                    pcr_digest,
                    format!("pcr {index} was quoted but its value was not sent"),
                )
            }
        }
    }
    let computed: [u8; 32] = hasher.finalize().into();
    if computed != pcr_digest {
        return Verified::failed(ak_sha256, pcr_digest, "pcr digest mismatch");
    }

    // The signature is over the attestation blob itself; ECDSA-P256 hashes it
    // with SHA-256, which is the scheme the AK is created with.
    let Ok(vk) = VerifyingKey::from_public_key_der(ak_public) else {
        return Verified::failed(ak_sha256, pcr_digest, "ak public key invalid");
    };
    let Ok(sig) = Signature::from_der(signature) else {
        return Verified::failed(ak_sha256, pcr_digest, "signature malformed");
    };
    if vk.verify(quote, &sig).is_err() {
        return Verified::failed(ak_sha256, pcr_digest, "signature invalid");
    }

    let (state, reason) = match known_ak {
        Some(expected) if expected == ak_public.as_slice() => {
            (AttestationState::Verified, "quote verified".to_string())
        }
        Some(_) => {
            return Verified::failed(
                ak_sha256,
                pcr_digest,
                "attestation key does not match the one this device enrolled with",
            )
        }
        None if policy.allow_unknown_ak => (
            AttestationState::Verified,
            "quote verified; attestation key trusted on first use".to_string(),
        ),
        None => return Verified::failed(ak_sha256, pcr_digest, "attestation key is not known"),
    };

    Verified {
        state,
        pcr_digest,
        ak_sha256,
        reset_count: attest.clock.reset_count,
        firmware_version: attest.firmware_version,
        reason,
    }
}
