//! Composite Ed25519 + ML-DSA-65 signatures with domain separation (spec §7.3).
//! Each component signs `label || u32be(len(msg)) || msg`; verification
//! requires both components to verify.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::pqc::mldsa::{
    MlDsaKeyPair, MlDsaSignature, MlDsaSigningKey, MlDsaVerifyingKey, MLDSA65_PUBLIC_KEY_BYTES,
    MLDSA65_SECRET_KEY_BYTES, MLDSA65_SIGNATURE_BYTES,
};
use crate::signature::{Ed25519KeyPair, Ed25519Signature, Ed25519VerifyingKey};

pub const HYBRID_SIGNATURE_BYTES: usize = 64 + MLDSA65_SIGNATURE_BYTES;
pub const HYBRID_VERIFYING_KEY_BYTES: usize = 32 + MLDSA65_PUBLIC_KEY_BYTES;
const HYBRID_SECRET_BYTES: usize = 32 + MLDSA65_SECRET_KEY_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Domain {
    Cert,
    Csr,
    Auth,
    Session,
    Crl,
    Offer,
}

impl Domain {
    pub const fn label(self) -> &'static [u8] {
        match self {
            Domain::Cert => b"AVON-CERT-V2",
            Domain::Csr => b"AVON-CSR-V2",
            Domain::Auth => b"AVON-AUTH-V2",
            Domain::Session => b"AVON-SESSION-V2",
            Domain::Crl => b"AVON-CRL-V2",
            Domain::Offer => b"AVON-OFFER-V2",
        }
    }
}

pub fn framed_message(domain: Domain, msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.label().len() + 4 + msg.len());
    out.extend_from_slice(domain.label());
    out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    out.extend_from_slice(msg);
    out
}

pub struct HybridSigningKeyPair {
    ed25519: Ed25519KeyPair,
    mldsa: MlDsaKeyPair,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridVerifyingKey {
    ed25519: Ed25519VerifyingKey,
    mldsa: MlDsaVerifyingKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridSignature {
    ed25519: Ed25519Signature,
    mldsa: MlDsaSignature,
}

impl HybridSigningKeyPair {
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self {
            ed25519: Ed25519KeyPair::generate()?,
            mldsa: MlDsaKeyPair::generate()?,
        })
    }

    pub fn ed25519(&self) -> &Ed25519KeyPair {
        &self.ed25519
    }

    pub fn verifying_key(&self) -> HybridVerifyingKey {
        HybridVerifyingKey {
            ed25519: self.ed25519.verifying_key().clone(),
            mldsa: self.mldsa.verifying_key().clone(),
        }
    }

    pub fn sign(&self, domain: Domain, msg: &[u8]) -> Result<HybridSignature, CryptoError> {
        let framed = framed_message(domain, msg);
        Ok(HybridSignature {
            ed25519: self.ed25519.sign(&framed),
            mldsa: self.mldsa.sign(&framed)?,
        })
    }

    /// Persisted form: `ed25519_seed(32) || mldsa_sk(4032) || mldsa_pk(1952)`.
    pub fn to_secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(HYBRID_SECRET_BYTES + MLDSA65_PUBLIC_KEY_BYTES));
        out.extend_from_slice(self.ed25519.seed());
        out.extend_from_slice(self.mldsa.signing_key().as_bytes());
        out.extend_from_slice(self.mldsa.verifying_key().as_bytes());
        out
    }

    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let expected = HYBRID_SECRET_BYTES + MLDSA65_PUBLIC_KEY_BYTES;
        if bytes.len() != expected {
            return Err(CryptoError::InvalidKeyLength {
                expected,
                actual: bytes.len(),
            });
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[..32]);
        let ed25519 = Ed25519KeyPair::from_seed(&seed)?;
        let signing = MlDsaSigningKey::from_bytes(&bytes[32..32 + MLDSA65_SECRET_KEY_BYTES])?;
        let verifying = MlDsaVerifyingKey::from_bytes(&bytes[32 + MLDSA65_SECRET_KEY_BYTES..])?;
        Ok(Self {
            ed25519,
            mldsa: MlDsaKeyPair::from_keys(signing, verifying),
        })
    }
}

impl HybridVerifyingKey {
    pub fn ed25519(&self) -> &Ed25519VerifyingKey {
        &self.ed25519
    }
    pub fn mldsa(&self) -> &MlDsaVerifyingKey {
        &self.mldsa
    }

    pub fn verify(&self, domain: Domain, msg: &[u8], sig: &HybridSignature) -> Result<(), CryptoError> {
        let framed = framed_message(domain, msg);
        self.ed25519.verify(&framed, &sig.ed25519)?;
        self.mldsa.verify(&framed, &sig.mldsa)?;
        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_VERIFYING_KEY_BYTES);
        out.extend_from_slice(&self.ed25519.to_bytes());
        out.extend_from_slice(self.mldsa.as_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != HYBRID_VERIFYING_KEY_BYTES {
            return Err(CryptoError::InvalidKeyLength {
                expected: HYBRID_VERIFYING_KEY_BYTES,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            ed25519: Ed25519VerifyingKey::from_bytes(&bytes[..32])?,
            mldsa: MlDsaVerifyingKey::from_bytes(&bytes[32..])?,
        })
    }

    /// SHA-256 over the serialized verifying key; used as `issuer_key_id`.
    pub fn key_id(&self) -> [u8; 32] {
        Sha256::digest(self.to_bytes()).into()
    }
}

impl HybridSignature {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_SIGNATURE_BYTES);
        out.extend_from_slice(&self.ed25519.to_bytes());
        out.extend_from_slice(self.mldsa.as_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != HYBRID_SIGNATURE_BYTES {
            return Err(CryptoError::InvalidKeyLength {
                expected: HYBRID_SIGNATURE_BYTES,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            ed25519: Ed25519Signature::from_bytes(&bytes[..64])?,
            mldsa: MlDsaSignature::from_bytes(&bytes[64..])?,
        })
    }

    /// Legacy compatibility: Ed25519 component.
    pub fn classical(&self) -> &Ed25519Signature {
        &self.ed25519
    }

    /// Legacy compatibility: ML-DSA component.
    pub fn pqc(&self) -> &MlDsaSignature {
        &self.mldsa
    }

    /// Access Ed25519 component.
    pub fn ed25519(&self) -> &Ed25519Signature {
        &self.ed25519
    }

    /// Access ML-DSA component.
    pub fn mldsa(&self) -> &MlDsaSignature {
        &self.mldsa
    }
}
