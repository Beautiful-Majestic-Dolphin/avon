//! ML-KEM-768 (FIPS 203) key encapsulation.
//!
//! Backed by PQClean via `pqcrypto-mlkem`. The wrapper owns byte buffers so
//! secret material is zeroized on drop and so that keys can be persisted.

use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

pub const MLKEM768_PUBLIC_KEY_BYTES: usize = 1184;
pub const MLKEM768_SECRET_KEY_BYTES: usize = 2400;
pub const MLKEM768_CIPHERTEXT_BYTES: usize = 1088;
pub const MLKEM768_SHARED_SECRET_BYTES: usize = 32;

/// Offset of the embedded encapsulation key inside an ML-KEM-768 decapsulation key
/// (FIPS 203 §7.3: dk = dk_PKE || ek || H(ek) || z, with |dk_PKE| = 1152).
const EMBEDDED_PK_OFFSET: usize = 1152;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKemPublicKey(Vec<u8>);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKemSecretKey(Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKemCiphertext(Vec<u8>);

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlKemSharedSecret([u8; MLKEM768_SHARED_SECRET_BYTES]);

pub struct MlKemKeyPair {
    public: MlKemPublicKey,
    secret: MlKemSecretKey,
}

fn check_len(expected: usize, actual: usize) -> Result<(), CryptoError> {
    if expected == actual {
        Ok(())
    } else {
        Err(CryptoError::InvalidKeyLength { expected, actual })
    }
}

impl MlKemPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        check_len(MLKEM768_PUBLIC_KEY_BYTES, bytes.len())?;
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    // Compatibility helpers mirroring legacy Kyber API (used by some tests)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn encapsulate(&self) -> Result<(MlKemCiphertext, MlKemSharedSecret), CryptoError> {
        let pk = mlkem768::PublicKey::from_bytes(&self.0)
            .map_err(|_| CryptoError::EncryptionFailed("invalid ML-KEM public key".into()))?;
        let (ss, ct) = mlkem768::encapsulate(&pk);
        let mut out = [0u8; MLKEM768_SHARED_SECRET_BYTES];
        out.copy_from_slice(ss.as_bytes());
        Ok((
            MlKemCiphertext(ct.as_bytes().to_vec()),
            MlKemSharedSecret(out),
        ))
    }
}

impl MlKemSecretKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        check_len(MLKEM768_SECRET_KEY_BYTES, bytes.len())?;
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl MlKemCiphertext {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        check_len(MLKEM768_CIPHERTEXT_BYTES, bytes.len())?;
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl MlKemSharedSecret {
    pub fn as_bytes(&self) -> &[u8; MLKEM768_SHARED_SECRET_BYTES] {
        &self.0
    }
}

impl MlKemKeyPair {
    pub fn generate() -> Result<Self, CryptoError> {
        let (pk, sk) = mlkem768::keypair();
        Ok(Self {
            public: MlKemPublicKey(pk.as_bytes().to_vec()),
            secret: MlKemSecretKey(sk.as_bytes().to_vec()),
        })
    }

    pub fn from_secret_key(secret: MlKemSecretKey) -> Result<Self, CryptoError> {
        if secret.0.len() != MLKEM768_SECRET_KEY_BYTES {
            return Err(CryptoError::InvalidKeyLength {
                expected: MLKEM768_SECRET_KEY_BYTES,
                actual: secret.0.len(),
            });
        }
        let pk_bytes =
            secret.0[EMBEDDED_PK_OFFSET..EMBEDDED_PK_OFFSET + MLKEM768_PUBLIC_KEY_BYTES].to_vec();
        let public = MlKemPublicKey(pk_bytes);
        Ok(Self { public, secret })
    }

    pub fn public_key(&self) -> &MlKemPublicKey {
        &self.public
    }

    pub fn secret_key(&self) -> &MlKemSecretKey {
        &self.secret
    }

    pub fn decapsulate(&self, ct: &MlKemCiphertext) -> Result<MlKemSharedSecret, CryptoError> {
        let sk = mlkem768::SecretKey::from_bytes(&self.secret.0)
            .map_err(|_| CryptoError::DecryptionFailed("invalid ML-KEM secret key".into()))?;
        let ct = mlkem768::Ciphertext::from_bytes(&ct.0)
            .map_err(|_| CryptoError::DecryptionFailed("invalid ML-KEM ciphertext".into()))?;
        let ss = mlkem768::decapsulate(&ct, &sk);
        let mut out = [0u8; MLKEM768_SHARED_SECRET_BYTES];
        out.copy_from_slice(ss.as_bytes());
        Ok(MlKemSharedSecret(out))
    }
}
