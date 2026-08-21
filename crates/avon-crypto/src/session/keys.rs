use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::aead::Suite;
use crate::error::CryptoError;
use crate::hybrid::kem::HybridSharedSecret;

const LABEL: &[u8] = b"AVON-ATP2";

/// Everything both parties saw during session establishment, in a fixed order.
#[derive(Clone, Debug)]
pub struct Transcript {
    pub session_id: [u8; 16],
    pub initiator_cert_id: [u8; 32],
    pub responder_cert_id: [u8; 32],
    pub eph_kem_pk: Vec<u8>,
    pub ct_e: Vec<u8>,
    pub ct_s: Vec<u8>,
    pub suite: Suite,
}

impl Transcript {
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(LABEL);
        h.update(self.session_id);
        h.update(self.initiator_cert_id);
        h.update(self.responder_cert_id);
        h.update((self.eph_kem_pk.len() as u32).to_be_bytes());
        h.update(&self.eph_kem_pk);
        h.update((self.ct_e.len() as u32).to_be_bytes());
        h.update(&self.ct_e);
        h.update((self.ct_s.len() as u32).to_be_bytes());
        h.update(&self.ct_s);
        h.update([self.suite.id()]);
        h.finalize().into()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    pub k_i2r: [u8; 32],
    pub k_r2i: [u8; 32],
    pub rekey_secret: [u8; 32],
    #[zeroize(skip)]
    pub epoch: u32,
}

fn expand(prk: &Hkdf<Sha256>, label: &[u8], epoch: u32) -> Result<[u8; 32], CryptoError> {
    let mut info = Vec::with_capacity(label.len() + 4);
    info.extend_from_slice(label);
    info.extend_from_slice(&epoch.to_be_bytes());
    let mut out = [0u8; 32];
    prk.expand(&info, &mut out).map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    Ok(out)
}

impl SessionKeys {
    fn from_prk(prk: &Hkdf<Sha256>, epoch: u32) -> Result<Self, CryptoError> {
        Ok(Self {
            k_i2r: expand(prk, b"i2r", epoch)?,
            k_r2i: expand(prk, b"r2i", epoch)?,
            rekey_secret: expand(prk, b"rekey", epoch)?,
            epoch,
        })
    }

    pub fn derive(transcript: &Transcript, ss_e: &HybridSharedSecret, ss_s: &HybridSharedSecret) -> Result<Self, CryptoError> {
        let salt = transcript.hash();
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(ss_e.as_bytes());
        ikm[32..].copy_from_slice(ss_s.as_bytes());
        let prk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        ikm.zeroize();
        Self::from_prk(&prk, 0)
    }

    pub fn rekey(&self, ss_new: &HybridSharedSecret) -> Result<Self, CryptoError> {
        let prk = Hkdf::<Sha256>::new(Some(&self.rekey_secret), ss_new.as_bytes());
        Self::from_prk(&prk, self.epoch + 1)
    }
}
