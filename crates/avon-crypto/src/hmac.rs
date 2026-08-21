//! HMAC (Hash-based Message Authentication Code) implementations.
//!
//! This module provides HMAC-SHA256 for message authentication with
//! constant-time verification to prevent timing attacks.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Computes HMAC-SHA256 of the given data with the specified key.
///
/// # Arguments
///
/// * `key` - The secret key for HMAC computation. Can be any length,
///   but keys shorter than 32 bytes are not recommended.
/// * `data` - The data to authenticate.
///
/// # Returns
///
/// A 32-byte authentication tag.
///
/// # Example
///
/// ```
/// use avon_crypto::hmac::hmac_sha256;
///
/// let key = b"secret key";
/// let data = b"message to authenticate";
///
/// let tag = hmac_sha256(key, data);
/// assert_eq!(tag.len(), 32);
/// ```
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        // `Hmac` hashes over-long keys and zero-pads short ones, so this is unreachable.
        unreachable!("HMAC accepts keys of any length")
    };
    mac.update(data);
    let result = mac.finalize();
    result.into_bytes().into()
}

/// Verifies an HMAC-SHA256 tag using constant-time comparison.
///
/// This function uses constant-time comparison to prevent timing attacks
/// that could leak information about the expected tag.
///
/// # Arguments
///
/// * `key` - The secret key used to compute the HMAC.
/// * `data` - The data that was authenticated.
/// * `tag` - The authentication tag to verify.
///
/// # Returns
///
/// `true` if the tag is valid, `false` otherwise.
///
/// # Example
///
/// ```
/// use avon_crypto::hmac::{hmac_sha256, hmac_sha256_verify};
///
/// let key = b"secret key";
/// let data = b"message to authenticate";
///
/// let tag = hmac_sha256(key, data);
/// assert!(hmac_sha256_verify(key, data, &tag));
///
/// // Tampered tag should fail
/// let mut bad_tag = tag;
/// bad_tag[0] ^= 0xff;
/// assert!(!hmac_sha256_verify(key, data, &bad_tag));
/// ```
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        // `Hmac` hashes over-long keys and zero-pads short ones, so this is unreachable.
        unreachable!("HMAC accepts keys of any length")
    };
    mac.update(data);
    mac.verify_slice(tag).is_ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_hmac_sha256_basic() {
        let key = b"key";
        let data = b"data";

        let tag = hmac_sha256(key, data);
        assert_eq!(tag.len(), 32);
    }

    #[test]
    fn test_hmac_sha256_verify_valid() {
        let key = b"key";
        let data = b"data";

        let tag = hmac_sha256(key, data);
        assert!(hmac_sha256_verify(key, data, &tag));
    }

    #[test]
    fn test_hmac_sha256_verify_invalid_tag() {
        let key = b"key";
        let data = b"data";

        let mut tag = hmac_sha256(key, data);
        tag[0] ^= 0xff;
        assert!(!hmac_sha256_verify(key, data, &tag));
    }

    #[test]
    fn test_hmac_sha256_verify_wrong_key() {
        let key1 = b"key1";
        let key2 = b"key2";
        let data = b"data";

        let tag = hmac_sha256(key1, data);
        assert!(!hmac_sha256_verify(key2, data, &tag));
    }

    #[test]
    fn test_hmac_sha256_deterministic() {
        let key = b"key";
        let data = b"data";

        let tag1 = hmac_sha256(key, data);
        let tag2 = hmac_sha256(key, data);
        assert_eq!(tag1, tag2);
    }
}
