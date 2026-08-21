//! Sealing of control-plane session tokens to a device's static hybrid KEM key.
//!
//! The AEAD key is derived from a shared secret that comes from a fresh
//! encapsulation, so it encrypts exactly one message and a fixed zero nonce is
//! safe. Shared with the agent, which opens the token after decapsulating.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::aead::{AeadKey, Suite};
use crate::error::CryptoError;
use crate::hybrid::kem::HybridSharedSecret;

fn key_from(ss: &HybridSharedSecret) -> Result<[u8; 32], CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, ss.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"AVON-SESSION-TOKEN", &mut key)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    Ok(key)
}

pub fn seal_session_token(
    token: &[u8; 32],
    ss: &HybridSharedSecret,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut key = key_from(ss)?;
    let aead = AeadKey::new(Suite::Aes256Gcm, &key);
    key.zeroize();
    let mut buf = token.to_vec();
    aead.seal_in_place(&[0u8; 12], aad, &mut buf)?;
    Ok(buf)
}

pub fn open_session_token(
    sealed: &[u8],
    ss: &HybridSharedSecret,
    aad: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let mut key = key_from(ss)?;
    let aead = AeadKey::new(Suite::Aes256Gcm, &key);
    key.zeroize();
    let mut buf = sealed.to_vec();
    aead.open_in_place(&[0u8; 12], aad, &mut buf)?;
    buf.as_slice()
        .try_into()
        .map_err(|_| CryptoError::AuthenticationFailed)
}
