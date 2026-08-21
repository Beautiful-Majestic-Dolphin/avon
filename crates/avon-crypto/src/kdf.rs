//! Key Derivation Functions (KDF) for AVON.
//!
//! This module provides HKDF (HMAC-based Key Derivation Function) implementations
//! using SHA-256 and SHA-384 as the underlying hash functions.

use hkdf::Hkdf;
use sha2::{Sha256, Sha384};

use crate::error::CryptoError;

/// Derives key material using HKDF with SHA-256.
///
/// HKDF is a key derivation function based on HMAC, defined in RFC 5869.
/// It takes input keying material (IKM) and derives cryptographically strong
/// output keying material (OKM).
///
/// # Arguments
///
/// * `ikm` - Input keying material (the source key material).
/// * `salt` - Optional salt value. If `None`, a zero-filled salt of the hash
///   length is used.
/// * `info` - Application-specific context information.
/// * `output_len` - The desired length of the output key material in bytes.
///
/// # Returns
///
/// A vector containing the derived key material.
///
/// # Errors
///
/// Returns `CryptoError::KeyDerivationFailed` if the output length is too large
/// (maximum is 255 * hash_length = 8160 bytes for SHA-256).
///
/// # Example
///
/// ```
/// use avon_crypto::kdf::hkdf_sha256;
///
/// let ikm = b"input key material";
/// let salt = Some(b"salt value".as_slice());
/// let info = b"application context";
///
/// let okm = hkdf_sha256(ikm, salt, info, 32).unwrap();
/// assert_eq!(okm.len(), 32);
/// ```
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0u8; output_len];

    hk.expand(info, &mut okm)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    Ok(okm)
}

/// Derives key material using HKDF with SHA-384.
///
/// HKDF is a key derivation function based on HMAC, defined in RFC 5869.
/// It takes input keying material (IKM) and derives cryptographically strong
/// output keying material (OKM).
///
/// # Arguments
///
/// * `ikm` - Input keying material (the source key material).
/// * `salt` - Optional salt value. If `None`, a zero-filled salt of the hash
///   length is used.
/// * `info` - Application-specific context information.
/// * `output_len` - The desired length of the output key material in bytes.
///
/// # Returns
///
/// A vector containing the derived key material.
///
/// # Errors
///
/// Returns `CryptoError::KeyDerivationFailed` if the output length is too large
/// (maximum is 255 * hash_length = 12240 bytes for SHA-384).
///
/// # Example
///
/// ```
/// use avon_crypto::kdf::hkdf_sha384;
///
/// let ikm = b"input key material";
/// let salt = Some(b"salt value".as_slice());
/// let info = b"application context";
///
/// let okm = hkdf_sha384(ikm, salt, info, 48).unwrap();
/// assert_eq!(okm.len(), 48);
/// ```
pub fn hkdf_sha384(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let hk = Hkdf::<Sha384>::new(salt, ikm);
    let mut okm = vec![0u8; output_len];

    hk.expand(info, &mut okm)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    Ok(okm)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_hkdf_sha256_basic() {
        let ikm = b"input key material";
        let salt = Some(b"salt".as_slice());
        let info = b"info";

        let okm = hkdf_sha256(ikm, salt, info, 32).unwrap();
        assert_eq!(okm.len(), 32);
    }

    #[test]
    fn test_hkdf_sha384_basic() {
        let ikm = b"input key material";
        let salt = Some(b"salt".as_slice());
        let info = b"info";

        let okm = hkdf_sha384(ikm, salt, info, 48).unwrap();
        assert_eq!(okm.len(), 48);
    }

    #[test]
    fn test_hkdf_sha256_no_salt() {
        let ikm = b"input key material";
        let info = b"info";

        let okm = hkdf_sha256(ikm, None, info, 32).unwrap();
        assert_eq!(okm.len(), 32);
    }

    #[test]
    fn test_hkdf_deterministic() {
        let ikm = b"input key material";
        let salt = Some(b"salt".as_slice());
        let info = b"info";

        let okm1 = hkdf_sha256(ikm, salt, info, 32).unwrap();
        let okm2 = hkdf_sha256(ikm, salt, info, 32).unwrap();

        assert_eq!(okm1, okm2);
    }
}
