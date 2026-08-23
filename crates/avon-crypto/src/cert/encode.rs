use sha2::{Digest, Sha256};

use super::binding::HardwareBinding;
use super::CertError;
use crate::error::CryptoError;
use crate::hybrid::kem::{HybridKemPublicKey, HYBRID_KEM_PUBLIC_KEY_BYTES};
use crate::hybrid::signature::{
    Domain, HybridSignature, HybridSigningKeyPair, HybridVerifyingKey, HYBRID_SIGNATURE_BYTES,
    HYBRID_VERIFYING_KEY_BYTES,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SubjectKind {
    RootCa = 1,
    IssuingCa = 2,
    Device = 3,
    Gateway = 4,
    Service = 5,
}

impl SubjectKind {
    fn from_u8(v: u8) -> Result<Self, CertError> {
        Ok(match v {
            1 => Self::RootCa,
            2 => Self::IssuingCa,
            3 => Self::Device,
            4 => Self::Gateway,
            5 => Self::Service,
            other => return Err(CertError::Encoding(format!("unknown subject kind {other}"))),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TbsCertificate {
    pub version: u8,
    pub serial: [u8; 16],
    pub tenant_id: String,
    pub subject_id: [u8; 16],
    pub kind: SubjectKind,
    pub signing_key: HybridVerifyingKey,
    pub kem_key: Option<HybridKemPublicKey>,
    pub not_before: i64,
    pub not_after: i64,
    pub issuer_key_id: [u8; 32],
    pub sans: Vec<String>,
    pub tls_cert_sha256: Option<[u8; 32]>,
    pub hardware_binding: Option<HardwareBinding>,
}

const MAX_TBS_LEN: usize = 16 * 1024;
const MAX_SANS: usize = 32;
const MAX_STRING: usize = 512;

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CertError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| CertError::Encoding("overflow".into()))?;
        if end > self.buf.len() {
            return Err(CertError::Encoding("truncated".into()));
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, CertError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, CertError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn i64(&mut self) -> Result<i64, CertError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(i64::from_be_bytes(a))
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], CertError> {
        let b = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(b);
        Ok(a)
    }
    fn bytes16(&mut self, max: usize) -> Result<&'a [u8], CertError> {
        let len = self.u16()? as usize;
        if len > max {
            return Err(CertError::Encoding(format!("field too long: {len}")));
        }
        self.take(len)
    }
    fn string16(&mut self) -> Result<String, CertError> {
        let b = self.bytes16(MAX_STRING)?;
        String::from_utf8(b.to_vec()).map_err(|_| CertError::Encoding("invalid utf-8".into()))
    }
    fn done(&self) -> Result<(), CertError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(CertError::Encoding("trailing bytes".into()))
        }
    }
}

fn put16(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

impl TbsCertificate {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2300);
        out.push(self.version);
        out.extend_from_slice(&self.serial);
        put16(&mut out, self.tenant_id.as_bytes());
        out.extend_from_slice(&self.subject_id);
        out.push(self.kind as u8);
        out.extend_from_slice(&self.signing_key.to_bytes());
        match &self.kem_key {
            Some(k) => put16(&mut out, &k.to_bytes()),
            None => put16(&mut out, &[]),
        }
        out.extend_from_slice(&self.not_before.to_be_bytes());
        out.extend_from_slice(&self.not_after.to_be_bytes());
        out.extend_from_slice(&self.issuer_key_id);
        out.extend_from_slice(&(self.sans.len() as u16).to_be_bytes());
        for san in &self.sans {
            put16(&mut out, san.as_bytes());
        }
        match &self.tls_cert_sha256 {
            Some(h) => put16(&mut out, h),
            None => put16(&mut out, &[]),
        }
        match &self.hardware_binding {
            Some(b) => put16(&mut out, &b.encode()),
            None => put16(&mut out, &[]),
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CertError> {
        if bytes.len() > MAX_TBS_LEN {
            return Err(CertError::Encoding("tbs too large".into()));
        }
        let mut r = Reader { buf: bytes, pos: 0 };
        let version = r.u8()?;
        if version != 2 {
            return Err(CertError::Encoding(format!(
                "unsupported version {version}"
            )));
        }
        let serial = r.array::<16>()?;
        let tenant_id = r.string16()?;
        let subject_id = r.array::<16>()?;
        let kind = SubjectKind::from_u8(r.u8()?)?;
        let signing_key = HybridVerifyingKey::from_bytes(r.take(HYBRID_VERIFYING_KEY_BYTES)?)
            .map_err(|e| CertError::Encoding(e.to_string()))?;
        let kem_bytes = r.bytes16(HYBRID_KEM_PUBLIC_KEY_BYTES)?;
        let kem_key = match kem_bytes.len() {
            0 => None,
            HYBRID_KEM_PUBLIC_KEY_BYTES => Some(
                HybridKemPublicKey::from_bytes(kem_bytes)
                    .map_err(|e| CertError::Encoding(e.to_string()))?,
            ),
            n => return Err(CertError::Encoding(format!("bad kem key length {n}"))),
        };
        let not_before = r.i64()?;
        let not_after = r.i64()?;
        let issuer_key_id = r.array::<32>()?;
        let n_sans = r.u16()? as usize;
        if n_sans > MAX_SANS {
            return Err(CertError::Encoding("too many sans".into()));
        }
        let mut sans = Vec::with_capacity(n_sans);
        for _ in 0..n_sans {
            sans.push(r.string16()?);
        }
        let tls = r.bytes16(32)?;
        let tls_cert_sha256 = match tls.len() {
            0 => None,
            32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(tls);
                Some(a)
            }
            n => return Err(CertError::Encoding(format!("bad tls hash length {n}"))),
        };
        let hw_bytes = r.bytes16(crate::cert::binding::MAX_BINDING_BYTES)?;
        let hardware_binding = if hw_bytes.is_empty() {
            None
        } else {
            Some(HardwareBinding::decode(hw_bytes)?)
        };
        r.done()?;
        Ok(Self {
            version,
            serial,
            tenant_id,
            subject_id,
            kind,
            signing_key,
            kem_key,
            not_before,
            not_after,
            issuer_key_id,
            sans,
            tls_cert_sha256,
            hardware_binding,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub tbs: TbsCertificate,
    pub signature: HybridSignature,
}

impl Certificate {
    pub fn sign(tbs: TbsCertificate, issuer: &HybridSigningKeyPair) -> Result<Self, CryptoError> {
        let signature = issuer.sign(Domain::Cert, &tbs.encode())?;
        Ok(Self { tbs, signature })
    }

    pub fn encode(&self) -> Vec<u8> {
        let tbs = self.tbs.encode();
        let mut out = Vec::with_capacity(4 + tbs.len() + HYBRID_SIGNATURE_BYTES);
        out.extend_from_slice(&(tbs.len() as u32).to_be_bytes());
        out.extend_from_slice(&tbs);
        out.extend_from_slice(&self.signature.to_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CertError> {
        if bytes.len() < 4 {
            return Err(CertError::Encoding("truncated".into()));
        }
        let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if len > MAX_TBS_LEN || bytes.len() != 4 + len + HYBRID_SIGNATURE_BYTES {
            return Err(CertError::Encoding("bad length".into()));
        }
        let tbs = TbsCertificate::decode(&bytes[4..4 + len])?;
        let signature = HybridSignature::from_bytes(&bytes[4 + len..])
            .map_err(|e| CertError::Encoding(e.to_string()))?;
        Ok(Self { tbs, signature })
    }

    pub fn id(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }

    pub fn verify_signature(&self, issuer: &HybridVerifyingKey) -> Result<(), CertError> {
        issuer
            .verify(Domain::Cert, &self.tbs.encode(), &self.signature)
            .map_err(|_| CertError::Signature)
    }

    pub fn is_valid_at(&self, now: i64) -> bool {
        self.tbs.not_before <= now && now <= self.tbs.not_after
    }
}
