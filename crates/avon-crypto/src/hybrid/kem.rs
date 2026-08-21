//! Hybrid KEM: X25519 + ML-KEM-768 with a combiner that binds both shared
//! secrets, both public keys and both ciphertexts (spec §7.2).

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::ecdh::{X25519KeyPair, X25519PrivateKey, X25519PublicKey};
use crate::error::CryptoError;
use crate::pqc::mlkem::{
    MlKemCiphertext, MlKemKeyPair, MlKemPublicKey, MlKemSecretKey, MLKEM768_CIPHERTEXT_BYTES,
    MLKEM768_PUBLIC_KEY_BYTES, MLKEM768_SECRET_KEY_BYTES,
};

pub const HYBRID_KEM_PUBLIC_KEY_BYTES: usize = 32 + MLKEM768_PUBLIC_KEY_BYTES;
pub const HYBRID_KEM_CIPHERTEXT_BYTES: usize = 32 + MLKEM768_CIPHERTEXT_BYTES;
const HYBRID_KEM_SECRET_BYTES: usize = 32 + MLKEM768_SECRET_KEY_BYTES;
const LABEL: &[u8] = b"AVON-HYBRID-KEM-V2";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridKemPublicKey {
    x25519: X25519PublicKey,
    mlkem: MlKemPublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridKemCiphertext {
    eph_x25519: X25519PublicKey,
    mlkem: MlKemCiphertext,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridSharedSecret([u8; 32]);

impl HybridSharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[cfg(feature = "test-vectors")]
    pub fn from_bytes_for_tests(bytes: &[u8; 32]) -> Self {
        Self(*bytes)
    }
}

pub struct HybridKemKeyPair {
    x25519: X25519KeyPair,
    mlkem: MlKemKeyPair,
}

/// The combiner. Public for test vectors; callers use encapsulate/decapsulate.
pub fn combine(
    ss_x25519: &[u8; 32],
    ss_mlkem: &[u8; 32],
    eph_x25519_pk: &[u8; 32],
    x25519_pk: &[u8; 32],
    mlkem_ct: &[u8],
    mlkem_pk: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LABEL);
    h.update(ss_x25519);
    h.update(ss_mlkem);
    h.update(eph_x25519_pk);
    h.update(x25519_pk);
    h.update(mlkem_ct);
    h.update(mlkem_pk);
    h.finalize().into()
}

impl HybridKemPublicKey {
    pub fn x25519(&self) -> &[u8; 32] {
        self.x25519.as_array()
    }
    pub fn mlkem(&self) -> &MlKemPublicKey {
        &self.mlkem
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_KEM_PUBLIC_KEY_BYTES);
        out.extend_from_slice(&self.x25519.to_bytes());
        out.extend_from_slice(self.mlkem.as_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != HYBRID_KEM_PUBLIC_KEY_BYTES {
            return Err(CryptoError::InvalidKeyLength {
                expected: HYBRID_KEM_PUBLIC_KEY_BYTES,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            x25519: X25519PublicKey::from_bytes(&bytes[..32])?,
            mlkem: MlKemPublicKey::from_bytes(&bytes[32..])?,
        })
    }

    pub fn encapsulate(&self) -> Result<(HybridKemCiphertext, HybridSharedSecret), CryptoError> {
        let eph = X25519KeyPair::generate()?;
        let ss_x = eph.diffie_hellman(&self.x25519)?;
        let (ct_m, ss_m) = self.mlkem.encapsulate()?;
        let ss = combine(
            ss_x.as_bytes(),
            ss_m.as_bytes(),
            eph.public_key().as_array(),
            self.x25519.as_array(),
            ct_m.as_bytes(),
            self.mlkem.as_bytes(),
        );
        Ok((
            HybridKemCiphertext {
                eph_x25519: eph.public_key().clone(),
                mlkem: ct_m,
            },
            HybridSharedSecret(ss),
        ))
    }
}

impl HybridKemCiphertext {
    pub fn eph_x25519(&self) -> &X25519PublicKey {
        &self.eph_x25519
    }
    pub fn mlkem(&self) -> &MlKemCiphertext {
        &self.mlkem
    }

    // Compatibility aliases for legacy code
    pub fn classical_public(&self) -> &X25519PublicKey {
        &self.eph_x25519
    }
    pub fn pqc_ciphertext(&self) -> &MlKemCiphertext {
        &self.mlkem
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_KEM_CIPHERTEXT_BYTES);
        out.extend_from_slice(&self.eph_x25519.to_bytes());
        out.extend_from_slice(self.mlkem.as_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != HYBRID_KEM_CIPHERTEXT_BYTES {
            return Err(CryptoError::InvalidKeyLength {
                expected: HYBRID_KEM_CIPHERTEXT_BYTES,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            eph_x25519: X25519PublicKey::from_bytes(&bytes[..32])?,
            mlkem: MlKemCiphertext::from_bytes(&bytes[32..])?,
        })
    }
}

impl HybridKemKeyPair {
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self {
            x25519: X25519KeyPair::generate()?,
            mlkem: MlKemKeyPair::generate()?,
        })
    }

    pub fn public_key(&self) -> HybridKemPublicKey {
        HybridKemPublicKey {
            x25519: self.x25519.public_key().clone(),
            mlkem: self.mlkem.public_key().clone(),
        }
    }

    pub fn decapsulate(&self, ct: &HybridKemCiphertext) -> Result<HybridSharedSecret, CryptoError> {
        let ss_x = self.x25519.diffie_hellman(&ct.eph_x25519)?;
        let ss_m = self.mlkem.decapsulate(&ct.mlkem)?;
        let pk = self.public_key();
        Ok(HybridSharedSecret(combine(
            ss_x.as_bytes(),
            ss_m.as_bytes(),
            ct.eph_x25519.as_array(),
            pk.x25519.as_array(),
            ct.mlkem.as_bytes(),
            pk.mlkem.as_bytes(),
        )))
    }

    /// `x25519_sk(32) || mlkem_sk(2400)`, zeroized on drop.
    pub fn to_secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(HYBRID_KEM_SECRET_BYTES));
        out.extend_from_slice(self.x25519.private_key().as_bytes());
        out.extend_from_slice(self.mlkem.secret_key().as_bytes());
        out
    }

    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != HYBRID_KEM_SECRET_BYTES {
            return Err(CryptoError::InvalidKeyLength {
                expected: HYBRID_KEM_SECRET_BYTES,
                actual: bytes.len(),
            });
        }
        let mut x = [0u8; 32];
        x.copy_from_slice(&bytes[..32]);
        let x25519 = X25519KeyPair::from_private_key(X25519PrivateKey::from_bytes(x));
        let mlkem = MlKemKeyPair::from_secret_key(MlKemSecretKey::from_bytes(&bytes[32..])?)?;
        Ok(Self { x25519, mlkem })
    }
}
