//! Session establishment over the authenticated control channel (spec §6.2)
//! and in-tunnel rekey (§6.3). Nothing here runs on unauthenticated UDP.

use avon_common::ids::SessionId;
use avon_crypto::aead::Suite;
use avon_crypto::cert::Certificate;
use avon_crypto::hybrid::kem::{
    HybridKemCiphertext, HybridKemKeyPair, HybridKemPublicKey, HybridSharedSecret,
};
use avon_crypto::hybrid::signature::{Domain, HybridSignature, HybridSigningKeyPair};
use avon_crypto::session::{SessionKeys, Transcript};
use avon_protocol::v2::SessionAnswer;

use crate::TunnelError;

pub struct PendingOffer {
    eph: HybridKemKeyPair,
    pub eph_pk_bytes: Vec<u8>,
    pub suites: Vec<Suite>,
}

pub struct Established {
    pub keys: SessionKeys,
    pub suite: Suite,
    pub transcript_hash: [u8; 32],
}

/// First suite the responder prefers that the initiator also offered.
pub fn choose_suite(offered: &[Suite], preferred: &[Suite]) -> Option<Suite> {
    preferred.iter().copied().find(|p| offered.contains(p))
}

fn suite_from_pb(v: i32) -> Result<Suite, TunnelError> {
    Suite::from_id(u8::try_from(v).map_err(|_| TunnelError::Protocol("suite".into()))?)
        .ok_or_else(|| TunnelError::Protocol("unknown suite".into()))
}

pub struct Initiator;

impl Initiator {
    pub fn offer(suites: &[Suite]) -> Result<PendingOffer, TunnelError> {
        let eph = HybridKemKeyPair::generate()?;
        let eph_pk_bytes = eph.public_key().to_bytes();
        Ok(PendingOffer {
            eph,
            eph_pk_bytes,
            suites: suites.to_vec(),
        })
    }

    /// Verify the responder's signature against its certificate and derive keys.
    pub fn complete(
        pending: PendingOffer,
        answer: &SessionAnswer,
        session_id: SessionId,
        my_cert_id: [u8; 32],
        my_static_kem: &HybridKemKeyPair,
        responder_cert: &Certificate,
    ) -> Result<Established, TunnelError> {
        let suite = suite_from_pb(answer.suite)?;
        if !pending.suites.contains(&suite) {
            return Err(TunnelError::Protocol(
                "responder chose a suite we did not offer".into(),
            ));
        }
        if answer.session_id.as_slice() != session_id.as_bytes() {
            return Err(TunnelError::Protocol("session id mismatch".into()));
        }
        let transcript = Transcript {
            session_id: *session_id.as_bytes(),
            initiator_cert_id: my_cert_id,
            responder_cert_id: responder_cert.id(),
            eph_kem_pk: pending.eph_pk_bytes.clone(),
            ct_e: answer.ct_e.clone(),
            ct_s: answer.ct_s.clone(),
            suite,
        };
        let hash = transcript.hash();
        let sig = HybridSignature::from_bytes(&answer.signature)
            .map_err(|_| TunnelError::Protocol("answer signature".into()))?;
        responder_cert
            .tbs
            .signing_key
            .verify(Domain::Session, &hash, &sig)
            .map_err(|_| TunnelError::Protocol("answer signature invalid".into()))?;

        let ct_e = HybridKemCiphertext::from_bytes(&answer.ct_e)?;
        let ct_s = HybridKemCiphertext::from_bytes(&answer.ct_s)?;
        let ss_e = pending.eph.decapsulate(&ct_e)?;
        let ss_s = my_static_kem.decapsulate(&ct_s)?;
        let keys = SessionKeys::derive(&transcript, &ss_e, &ss_s)?;
        Ok(Established {
            keys,
            suite,
            transcript_hash: hash,
        })
    }

    /// Like [`Self::complete`] but the static KEM private operation is
    /// delegated to `decapsulate_static`, so hardware-backed providers never
    /// expose key bytes.
    pub fn complete_with<F>(
        pending: PendingOffer,
        answer: &SessionAnswer,
        session_id: SessionId,
        my_cert_id: [u8; 32],
        decapsulate_static: F,
        responder_cert: &Certificate,
    ) -> Result<Established, TunnelError>
    where
        F: FnOnce(&HybridKemCiphertext) -> Result<HybridSharedSecret, TunnelError>,
    {
        let suite = suite_from_pb(answer.suite)?;
        if !pending.suites.contains(&suite) {
            return Err(TunnelError::Protocol(
                "responder chose a suite we did not offer".into(),
            ));
        }
        if answer.session_id.as_slice() != session_id.as_bytes() {
            return Err(TunnelError::Protocol("session id mismatch".into()));
        }
        let transcript = Transcript {
            session_id: *session_id.as_bytes(),
            initiator_cert_id: my_cert_id,
            responder_cert_id: responder_cert.id(),
            eph_kem_pk: pending.eph_pk_bytes.clone(),
            ct_e: answer.ct_e.clone(),
            ct_s: answer.ct_s.clone(),
            suite,
        };
        let hash = transcript.hash();
        let sig = HybridSignature::from_bytes(&answer.signature)
            .map_err(|_| TunnelError::Protocol("answer signature".into()))?;
        responder_cert
            .tbs
            .signing_key
            .verify(Domain::Session, &hash, &sig)
            .map_err(|_| TunnelError::Protocol("answer signature invalid".into()))?;

        let ct_e = HybridKemCiphertext::from_bytes(&answer.ct_e)?;
        let ct_s = HybridKemCiphertext::from_bytes(&answer.ct_s)?;
        let ss_e = pending.eph.decapsulate(&ct_e)?;
        let ss_s = decapsulate_static(&ct_s)?;
        let keys = SessionKeys::derive(&transcript, &ss_e, &ss_s)?;
        Ok(Established {
            keys,
            suite,
            transcript_hash: hash,
        })
    }
}

pub struct Responder;

impl Responder {
    /// Gateway/peer side: encapsulate to both the ephemeral and the
    /// certificate's static key, then sign the transcript.
    #[allow(clippy::too_many_arguments)]
    pub fn answer(
        session_id: SessionId,
        initiator_cert: &Certificate,
        eph_pk: &[u8],
        suite: Suite,
        my_cert_id: [u8; 32],
        my_signing: &HybridSigningKeyPair,
        my_index: u32,
        my_endpoint: Option<String>,
    ) -> Result<(SessionAnswer, Established), TunnelError> {
        let eph = HybridKemPublicKey::from_bytes(eph_pk)?;
        let static_pk =
            initiator_cert.tbs.kem_key.as_ref().ok_or_else(|| {
                TunnelError::Protocol("initiator certificate has no kem key".into())
            })?;
        let (ct_e, ss_e) = eph.encapsulate()?;
        let (ct_s, ss_s) = static_pk.encapsulate()?;
        let transcript = Transcript {
            session_id: *session_id.as_bytes(),
            initiator_cert_id: initiator_cert.id(),
            responder_cert_id: my_cert_id,
            eph_kem_pk: eph_pk.to_vec(),
            ct_e: ct_e.to_bytes(),
            ct_s: ct_s.to_bytes(),
            suite,
        };
        let hash = transcript.hash();
        let signature = my_signing.sign(Domain::Session, &hash)?.to_bytes();
        let keys = SessionKeys::derive(&transcript, &ss_e, &ss_s)?;
        let answer = SessionAnswer {
            session_id: session_id.to_vec(),
            ct_e: ct_e.to_bytes(),
            ct_s: ct_s.to_bytes(),
            responder_index: my_index,
            responder_endpoint: my_endpoint.unwrap_or_default(),
            suite: suite.id() as i32,
            signature,
        };
        Ok((
            answer,
            Established {
                keys,
                suite,
                transcript_hash: hash,
            },
        ))
    }

    /// Like [`Self::answer`] but signing is delegated to `sign_fn` so the
    /// hardware signer can hold the private key.
    #[allow(clippy::too_many_arguments)]
    pub fn answer_with<F>(
        session_id: SessionId,
        initiator_cert: &Certificate,
        eph_pk: &[u8],
        suite: Suite,
        my_cert_id: [u8; 32],
        sign_fn: F,
        my_index: u32,
        my_endpoint: Option<String>,
    ) -> Result<(SessionAnswer, Established), TunnelError>
    where
        F: FnOnce(Domain, &[u8]) -> Result<HybridSignature, TunnelError>,
    {
        let eph = HybridKemPublicKey::from_bytes(eph_pk)?;
        let static_pk =
            initiator_cert.tbs.kem_key.as_ref().ok_or_else(|| {
                TunnelError::Protocol("initiator certificate has no kem key".into())
            })?;
        let (ct_e, ss_e) = eph.encapsulate()?;
        let (ct_s, ss_s) = static_pk.encapsulate()?;
        let transcript = Transcript {
            session_id: *session_id.as_bytes(),
            initiator_cert_id: initiator_cert.id(),
            responder_cert_id: my_cert_id,
            eph_kem_pk: eph_pk.to_vec(),
            ct_e: ct_e.to_bytes(),
            ct_s: ct_s.to_bytes(),
            suite,
        };
        let hash = transcript.hash();
        let signature = sign_fn(Domain::Session, &hash)?.to_bytes();
        let keys = SessionKeys::derive(&transcript, &ss_e, &ss_s)?;
        let answer = SessionAnswer {
            session_id: session_id.to_vec(),
            ct_e: ct_e.to_bytes(),
            ct_s: ct_s.to_bytes(),
            responder_index: my_index,
            responder_endpoint: my_endpoint.unwrap_or_default(),
            suite: suite.id() as i32,
            signature,
        };
        Ok((
            answer,
            Established {
                keys,
                suite,
                transcript_hash: hash,
            },
        ))
    }
}

pub fn rekey_offer() -> Result<(HybridKemKeyPair, Vec<u8>), TunnelError> {
    let eph = HybridKemKeyPair::generate()?;
    let pk = eph.public_key().to_bytes();
    Ok((eph, pk))
}

pub fn rekey_answer(
    eph_pk: &[u8],
    current: &SessionKeys,
) -> Result<(Vec<u8>, SessionKeys), TunnelError> {
    let pk = HybridKemPublicKey::from_bytes(eph_pk)?;
    let (ct, ss) = pk.encapsulate()?;
    Ok((ct.to_bytes(), current.rekey(&ss)?))
}

pub fn rekey_complete(
    eph: &HybridKemKeyPair,
    ct: &[u8],
    current: &SessionKeys,
) -> Result<SessionKeys, TunnelError> {
    let ct = HybridKemCiphertext::from_bytes(ct)?;
    let ss = eph.decapsulate(&ct)?;
    Ok(current.rekey(&ss)?)
}
