//! Composite-signed certificate revocation lists. Kept in `avon-crypto` so a
//! gateway can verify a CRL without depending on the CA crate.

use crate::error::CryptoError;
use crate::hybrid::signature::{Domain, HybridSignature, HybridSigningKeyPair, HybridVerifyingKey};

use super::CertError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Crl {
    pub version: u64,
    pub issued_at: i64,
    pub serials: Vec<[u8; 16]>,
}

const MAX_SERIALS: usize = 1_000_000;

impl Crl {
    pub fn encode_tbs(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(20 + self.serials.len() * 16);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&(self.serials.len() as u32).to_be_bytes());
        for s in &self.serials {
            out.extend_from_slice(s);
        }
        out
    }

    pub fn decode_tbs(bytes: &[u8]) -> Result<Self, CertError> {
        if bytes.len() < 20 {
            return Err(CertError::Encoding("crl truncated".into()));
        }
        let version = u64::from_be_bytes(
            bytes[0..8]
                .try_into()
                .map_err(|_| CertError::Encoding("crl".into()))?,
        );
        let issued_at = i64::from_be_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| CertError::Encoding("crl".into()))?,
        );
        let count = u32::from_be_bytes(
            bytes[16..20]
                .try_into()
                .map_err(|_| CertError::Encoding("crl".into()))?,
        ) as usize;
        if count > MAX_SERIALS || bytes.len() != 20 + count * 16 {
            return Err(CertError::Encoding("crl length".into()));
        }
        let serials = bytes[20..]
            .chunks_exact(16)
            .map(|c| {
                let mut a = [0u8; 16];
                a.copy_from_slice(c);
                a
            })
            .collect();
        Ok(Self {
            version,
            issued_at,
            serials,
        })
    }

    pub fn sign(&self, issuer: &HybridSigningKeyPair) -> Result<Vec<u8>, CryptoError> {
        Ok(issuer.sign(Domain::Crl, &self.encode_tbs())?.to_bytes())
    }

    pub fn verify(
        tbs: &[u8],
        signature: &[u8],
        issuer: &HybridVerifyingKey,
    ) -> Result<Self, CertError> {
        let sig = HybridSignature::from_bytes(signature).map_err(|_| CertError::Signature)?;
        issuer
            .verify(Domain::Crl, tbs, &sig)
            .map_err(|_| CertError::Signature)?;
        Self::decode_tbs(tbs)
    }

    pub fn contains(&self, serial: &[u8; 16]) -> bool {
        self.serials.iter().any(|s| s == serial)
    }
}
