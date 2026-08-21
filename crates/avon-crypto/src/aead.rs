//! AEAD suites for the data plane: AES-256-GCM (hardware-accelerated CPUs)
//! and ChaCha20-Poly1305 (everything else). In-place APIs avoid per-packet
//! allocation.

use aes_gcm::aead::{Aead, AeadInPlace, KeyInit};
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;
use chacha20poly1305::ChaCha20Poly1305;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Suite {
    Aes256Gcm = 1,
    ChaCha20Poly1305 = 2,
}

impl Suite {
    pub const TAG_LEN: usize = 16;
    pub const NONCE_LEN: usize = 12;

    pub const fn id(self) -> u8 {
        self as u8
    }
    pub const fn key_len(self) -> usize {
        32
    }

    pub fn from_id(id: u8) -> Option<Suite> {
        match id {
            1 => Some(Suite::Aes256Gcm),
            2 => Some(Suite::ChaCha20Poly1305),
            _ => None,
        }
    }
}

enum Inner {
    Aes(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

/// A suite-tagged AEAD key. Key material inside the cipher state is zeroized
/// by the underlying crates on drop.
pub struct AeadKey {
    suite: Suite,
    inner: Inner,
    raw: [u8; 32],
}

impl Drop for AeadKey {
    fn drop(&mut self) {
        self.raw.zeroize();
    }
}

impl ZeroizeOnDrop for AeadKey {}

impl AeadKey {
    pub fn new(suite: Suite, key: &[u8; 32]) -> Self {
        let inner = match suite {
            Suite::Aes256Gcm => Inner::Aes(Box::new(Aes256Gcm::new(key.into()))),
            Suite::ChaCha20Poly1305 => Inner::ChaCha(Box::new(ChaCha20Poly1305::new(key.into()))),
        };
        Self {
            suite,
            inner,
            raw: *key,
        }
    }

    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// Encrypts `buf` in place and appends the 16-byte tag.
    pub fn seal_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        let result = match &self.inner {
            Inner::Aes(c) => c.encrypt_in_place(nonce.into(), aad, buf),
            Inner::ChaCha(c) => c.encrypt_in_place(nonce.into(), aad, buf),
        };
        result.map_err(|_| CryptoError::EncryptionFailed("aead seal".into()))
    }

    /// Verifies the tag, decrypts in place and removes the tag.
    pub fn open_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        if buf.len() < Suite::TAG_LEN {
            return Err(CryptoError::AuthenticationFailed);
        }
        let result = match &self.inner {
            Inner::Aes(c) => c.decrypt_in_place(nonce.into(), aad, buf),
            Inner::ChaCha(c) => c.decrypt_in_place(nonce.into(), aad, buf),
        };
        result.map_err(|_| CryptoError::AuthenticationFailed)
    }
}

// ---------------------------------------------------------------------------
// Legacy Aes256GcmCipher for backwards compatibility (avon-agent, tests)
// ---------------------------------------------------------------------------

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Aes256GcmCipher {
    key: [u8; 32],
}

impl Aes256GcmCipher {
    pub const KEY_LENGTH: usize = 32;
    pub const NONCE_LENGTH: usize = 12;
    pub const TAG_LENGTH: usize = 16;

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != Self::KEY_LENGTH {
            return Err(CryptoError::InvalidKeyLength {
                expected: Self::KEY_LENGTH,
                actual: key.len(),
            });
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key);
        Ok(Self { key: key_array })
    }

    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        let nonce = Nonce::from_slice(nonce);
        cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))
    }

    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        let nonce = Nonce::from_slice(nonce);
        cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }
}
