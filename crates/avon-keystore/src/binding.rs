use avon_crypto::hybrid::kem::HybridKemPublicKey;
use avon_crypto::hybrid::signature::HybridVerifyingKey;

use crate::provider::HardwareBinding;

const LABEL: &[u8] = b"AVON-HW-BINDING-V2";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BindingError {
    #[error("unsupported binding algorithm {0}")]
    UnsupportedAlgorithm(String),
    #[error("hardware public key does not parse")]
    PublicKey,
    #[error("binding signature invalid")]
    Signature,
}

/// Every field is length-prefixed so no two different inputs can produce the
/// same message (a hint that extends the KEM key must not collide).
pub fn binding_message(
    signing: &HybridVerifyingKey,
    kem: &HybridKemPublicKey,
    device_hint: &[u8],
) -> Vec<u8> {
    let s = signing.to_bytes();
    let k = kem.to_bytes();
    let mut out = Vec::with_capacity(LABEL.len() + 12 + s.len() + k.len() + device_hint.len());
    out.extend_from_slice(LABEL);
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(&s);
    out.extend_from_slice(&(k.len() as u32).to_be_bytes());
    out.extend_from_slice(&k);
    out.extend_from_slice(&(device_hint.len() as u32).to_be_bytes());
    out.extend_from_slice(device_hint);
    out
}

pub fn verify_binding(
    b: &HardwareBinding,
    signing: &HybridVerifyingKey,
    kem: &HybridKemPublicKey,
    device_hint: &[u8],
) -> Result<(), BindingError> {
    let msg = binding_message(signing, kem, device_hint);
    match b.algorithm.as_str() {
        "ecdsa-p256-sha256" | "ecdsa-p256-sha256-se" => {
            use p256::ecdsa::signature::Verifier;
            use p256::pkcs8::DecodePublicKey;
            let vk = p256::ecdsa::VerifyingKey::from_public_key_der(&b.public_key)
                .map_err(|_| BindingError::PublicKey)?;
            let sig = p256::ecdsa::Signature::from_der(&b.signature)
                .map_err(|_| BindingError::Signature)?;
            vk.verify(&msg, &sig).map_err(|_| BindingError::Signature)
        }
        "rsa-pss-sha256" => {
            use rsa::pkcs8::DecodePublicKey;
            use rsa::signature::Verifier;
            use sha2::Sha256;
            let vk = rsa::RsaPublicKey::from_public_key_der(&b.public_key)
                .map_err(|_| BindingError::PublicKey)?;
            let verifying = rsa::pss::VerifyingKey::<Sha256>::new(vk);
            let sig = rsa::pss::Signature::try_from(b.signature.as_slice())
                .map_err(|_| BindingError::Signature)?;
            verifying
                .verify(&msg, &sig)
                .map_err(|_| BindingError::Signature)
        }
        other => Err(BindingError::UnsupportedAlgorithm(other.to_string())),
    }
}
