//! Secure random number generation for AVON.
//!
//! This module provides cryptographically secure random number generation
//! using the operating system's random number generator.

use rand::{rngs::OsRng, RngCore};

use crate::error::CryptoError;

/// Generates a vector of cryptographically secure random bytes.
///
/// Uses the operating system's cryptographically secure random number
/// generator (CSPRNG) to generate random bytes.
///
/// # Arguments
///
/// * `len` - The number of random bytes to generate.
///
/// # Returns
///
/// A vector containing `len` random bytes.
///
/// # Errors
///
/// Returns `CryptoError::RandomGenerationFailed` if the random number
/// generator fails (which is extremely rare on modern systems).
///
/// # Example
///
/// ```
/// use avon_crypto::random::random_bytes;
///
/// let bytes = random_bytes(32).unwrap();
/// assert_eq!(bytes.len(), 32);
/// ```
pub fn random_bytes(len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = vec![0u8; len];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| CryptoError::RandomGenerationFailed(e.to_string()))?;
    Ok(bytes)
}

/// Generates a fixed-size array of cryptographically secure random bytes.
///
/// Uses the operating system's cryptographically secure random number
/// generator (CSPRNG) to generate random bytes.
///
/// # Type Parameters
///
/// * `N` - The number of random bytes to generate (compile-time constant).
///
/// # Returns
///
/// An array of `N` random bytes.
///
/// # Errors
///
/// Returns `CryptoError::RandomGenerationFailed` if the random number
/// generator fails (which is extremely rare on modern systems).
///
/// # Example
///
/// ```
/// use avon_crypto::random::random_bytes_fixed;
///
/// // Generate a 32-byte key
/// let key: [u8; 32] = random_bytes_fixed().unwrap();
/// assert_eq!(key.len(), 32);
///
/// // Generate a 12-byte nonce
/// let nonce: [u8; 12] = random_bytes_fixed().unwrap();
/// assert_eq!(nonce.len(), 12);
/// ```
pub fn random_bytes_fixed<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0u8; N];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| CryptoError::RandomGenerationFailed(e.to_string()))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes_length() {
        let bytes = random_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_random_bytes_fixed_length() {
        let bytes: [u8; 32] = random_bytes_fixed().unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_random_bytes_unique() {
        let bytes1 = random_bytes(32).unwrap();
        let bytes2 = random_bytes(32).unwrap();
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_random_bytes_fixed_unique() {
        let bytes1: [u8; 32] = random_bytes_fixed().unwrap();
        let bytes2: [u8; 32] = random_bytes_fixed().unwrap();
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_random_bytes_zero_length() {
        let bytes = random_bytes(0).unwrap();
        assert!(bytes.is_empty());
    }
}
