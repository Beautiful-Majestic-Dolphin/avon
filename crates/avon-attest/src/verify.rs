#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::SystemTime;

use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};

use crate::evidence::Evidence;
use crate::policy::{AttestationState, QuotePolicy};

pub struct Verified {
    pub state: AttestationState,
    pub pcr_digest: [u8; 32],
    pub ak_sha256: [u8; 32],
    pub reason: String,
}

const MAGIC: u32 = 0xFF544347;
const TYPE_QUOTE: u16 = 0x8018;

pub fn verify(
    ev: &Evidence,
    expected_nonce: &[u8],
    known_ak: Option<&[u8]>,
    policy: &QuotePolicy,
    now: SystemTime,
) -> Verified {
    match ev {
        Evidence::None => Verified {
            state: AttestationState::None,
            pcr_digest: [0; 32],
            ak_sha256: [0; 32],
            reason: "no evidence".into(),
        },
        Evidence::Tpm2Quote {
            quote,
            signature,
            ak_public,
            pcrs,
            nonce: _,
        } => {
            let ak_sha256: [u8; 32] = Sha256::digest(ak_public).into();

            // Parse quote: magic(4)|type(2)|extra_len(2)|extra|pcr_digest(32)|clock(8)|pcrs_digest_check
            if quote.len() < 4 + 2 + 2 + 32 + 8 {
                return Verified {
                    state: AttestationState::Failed,
                    pcr_digest: [0; 32],
                    ak_sha256,
                    reason: "malformed quote".into(),
                };
            }
            let mut pos = 0;
            let magic =
                u32::from_be_bytes([quote[pos], quote[pos + 1], quote[pos + 2], quote[pos + 3]]);
            pos += 4;
            if magic != MAGIC {
                return Verified {
                    state: AttestationState::Failed,
                    pcr_digest: [0; 32],
                    ak_sha256,
                    reason: "bad magic".into(),
                };
            }
            let typ = u16::from_be_bytes([quote[pos], quote[pos + 1]]);
            pos += 2;
            if typ != TYPE_QUOTE {
                return Verified {
                    state: AttestationState::Failed,
                    pcr_digest: [0; 32],
                    ak_sha256,
                    reason: "bad type".into(),
                };
            }
            let extra_len = u16::from_be_bytes([quote[pos], quote[pos + 1]]) as usize;
            pos += 2;
            if pos + extra_len > quote.len() {
                return Verified {
                    state: AttestationState::Failed,
                    pcr_digest: [0; 32],
                    ak_sha256,
                    reason: "truncated extraData".into(),
                };
            }
            let extra = &quote[pos..pos + extra_len];
            pos += extra_len;
            if extra != expected_nonce {
                return Verified {
                    state: AttestationState::Failed,
                    pcr_digest: [0; 32],
                    ak_sha256,
                    reason: "nonce mismatch".into(),
                };
            }
            let pcr_digest: [u8; 32] = quote[pos..pos + 32].try_into().unwrap();
            pos += 32;

            // clockInfo: 8-byte unix timestamp
            if pos + 8 > quote.len() {
                return Verified {
                    state: AttestationState::Failed,
                    pcr_digest,
                    ak_sha256,
                    reason: "truncated clock".into(),
                };
            }
            let clock = u64::from_be_bytes(quote[pos..pos + 8].try_into().unwrap());
            let _ = pos + 8;
            let quote_time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(clock);
            if let Ok(elapsed) = now.duration_since(quote_time) {
                if elapsed > policy.max_age {
                    return Verified {
                        state: AttestationState::Failed,
                        pcr_digest,
                        ak_sha256,
                        reason: "quote too old".into(),
                    };
                }
            } else if let Ok(future) = quote_time.duration_since(now) {
                if future > Duration::from_secs(5) {
                    return Verified {
                        state: AttestationState::Failed,
                        pcr_digest,
                        ak_sha256,
                        reason: "quote in future".into(),
                    };
                }
            }

            // Check PCR coverage and digest.
            let mut pcrs_sorted = pcrs.clone();
            pcrs_sorted.sort_by_key(|(idx, _)| *idx);
            let required = &policy.required_pcrs;
            for r in required {
                if !pcrs_sorted.iter().any(|(idx, _)| idx == r) {
                    return Verified {
                        state: AttestationState::Failed,
                        pcr_digest,
                        ak_sha256,
                        reason: format!("missing pcr {r}"),
                    };
                }
            }
            // Recompute SHA256(concat pcr values in selection order)
            let mut hasher = Sha256::new();
            for idx in required {
                if let Some((_, val)) = pcrs_sorted.iter().find(|(i, _)| i == idx) {
                    hasher.update(val);
                }
            }
            // Also include all pcrs in order for pcrDigest check if required set equals all?
            // For our fixture, pcrDigest is SHA256(concat required pcrs)
            let computed: [u8; 32] = hasher.finalize().into();
            if computed != pcr_digest {
                return Verified {
                    state: AttestationState::Failed,
                    pcr_digest,
                    ak_sha256,
                    reason: "pcr digest mismatch".into(),
                };
            }

            // Verify signature over quote.
            let vk = match VerifyingKey::from_public_key_der(ak_public) {
                Ok(k) => k,
                Err(_) => {
                    return Verified {
                        state: AttestationState::Failed,
                        pcr_digest,
                        ak_sha256,
                        reason: "ak public key invalid".into(),
                    }
                }
            };
            let sig = match Signature::from_der(signature) {
                Ok(s) => s,
                Err(_) => {
                    return Verified {
                        state: AttestationState::Failed,
                        pcr_digest,
                        ak_sha256,
                        reason: "signature malformed".into(),
                    }
                }
            };
            if vk.verify(quote, &sig).is_err() {
                return Verified {
                    state: AttestationState::Failed,
                    pcr_digest,
                    ak_sha256,
                    reason: "signature invalid".into(),
                };
            }

            // AK trust check.
            if let Some(expected) = known_ak {
                if expected != ak_public {
                    return Verified {
                        state: AttestationState::Failed,
                        pcr_digest,
                        ak_sha256,
                        reason: "ak mismatch".into(),
                    };
                }
                Verified {
                    state: AttestationState::Verified,
                    pcr_digest,
                    ak_sha256,
                    reason: "verified with known AK".into(),
                }
            } else if policy.allow_unknown_ak {
                Verified {
                    state: AttestationState::Verified,
                    pcr_digest,
                    ak_sha256,
                    reason: "verified trust on first use".into(),
                }
            } else {
                Verified {
                    state: AttestationState::Failed,
                    pcr_digest,
                    ak_sha256,
                    reason: "unknown AK not allowed".into(),
                }
            }
        }
    }
}

use std::time::Duration;
