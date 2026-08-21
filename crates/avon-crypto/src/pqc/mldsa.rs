//! ML-DSA-65 (FIPS 204) digital signatures via PQClean (`pqcrypto-mldsa`).

use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

pub const MLDSA65_PUBLIC_KEY_BYTES: usize = 1952;
pub const MLDSA65_SECRET_KEY_BYTES: usize = 4032;
pub const MLDSA65_SIGNATURE_BYTES: usize = 3309;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsaVerifyingKey(Vec<u8>);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsaSigningKey(Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsaSignature(Vec<u8>);

pub struct MlDsaKeyPair {
    signing: MlDsaSigningKey,
    verifying: MlDsaVerifyingKey,
}

fn check_len(expected: usize, actual: usize) -> Result<(), CryptoError> {
    if expected == actual {
        Ok(())
    } else {
        Err(CryptoError::InvalidKeyLength { expected, actual })
    }
}

impl MlDsaVerifyingKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        check_len(MLDSA65_PUBLIC_KEY_BYTES, bytes.len())?;
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn verify(&self, message: &[u8], signature: &MlDsaSignature) -> Result<(), CryptoError> {
        let pk =
            mldsa65::PublicKey::from_bytes(&self.0).map_err(|_| CryptoError::InvalidSignature)?;
        let sig = mldsa65::DetachedSignature::from_bytes(&signature.0)
            .map_err(|_| CryptoError::InvalidSignature)?;
        mldsa65::verify_detached_signature(&sig, message, &pk)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

impl MlDsaSigningKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        check_len(MLDSA65_SECRET_KEY_BYTES, bytes.len())?;
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl MlDsaSignature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        check_len(MLDSA65_SIGNATURE_BYTES, bytes.len())?;
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl MlDsaKeyPair {
    pub fn generate() -> Result<Self, CryptoError> {
        let (pk, sk) = mldsa65::keypair();
        Ok(Self {
            signing: MlDsaSigningKey(sk.as_bytes().to_vec()),
            verifying: MlDsaVerifyingKey(pk.as_bytes().to_vec()),
        })
    }

    pub fn from_keys(signing: MlDsaSigningKey, verifying: MlDsaVerifyingKey) -> Self {
        Self { signing, verifying }
    }

    pub fn signing_key(&self) -> &MlDsaSigningKey {
        &self.signing
    }

    pub fn verifying_key(&self) -> &MlDsaVerifyingKey {
        &self.verifying
    }

    pub fn sign(&self, message: &[u8]) -> Result<MlDsaSignature, CryptoError> {
        let sk = mldsa65::SecretKey::from_bytes(&self.signing.0)
            .map_err(|_| CryptoError::EncryptionFailed("invalid ML-DSA secret key".into()))?;
        let sig = mldsa65::detached_sign(message, &sk);
        Ok(MlDsaSignature(sig.as_bytes().to_vec()))
    }
}
