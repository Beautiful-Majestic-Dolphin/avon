use serde::{Deserialize, Serialize};

use super::CertError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum ProviderKind {
    Software = 1,
    Tpm2 = 2,
    Keychain = 3,
    Cng = 4,
}

impl ProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Software => "software",
            Self::Tpm2 => "tpm2",
            Self::Keychain => "keychain",
            Self::Cng => "cng",
        }
    }
    pub fn is_hardware(self) -> bool {
        !matches!(self, Self::Software)
    }
    fn from_u8(v: u8) -> Result<Self, CertError> {
        Ok(match v {
            1 => Self::Software,
            2 => Self::Tpm2,
            3 => Self::Keychain,
            4 => Self::Cng,
            _ => return Err(CertError::Encoding(format!("unknown provider {v}"))),
        })
    }
    fn from_str(s: &str) -> Result<Self, String> {
        Ok(match s {
            "software" => Self::Software,
            "tpm2" => Self::Tpm2,
            "keychain" => Self::Keychain,
            "cng" => Self::Cng,
            _ => return Err(format!("unknown provider {s}")),
        })
    }
}

impl std::str::FromStr for ProviderKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str(s)
    }
}

pub const MAX_BINDING_BYTES: usize = 12 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareBinding {
    pub provider: ProviderKind,
    pub algorithm: String,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub attestation: Option<Vec<u8>>,
}

impl HardwareBinding {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.provider as u8);
        put16(&mut out, self.algorithm.as_bytes());
        put16(&mut out, &self.public_key);
        put16(&mut out, &self.signature);
        match &self.attestation {
            Some(a) => put16(&mut out, a),
            None => put16(&mut out, &[]),
        }
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, CertError> {
        if bytes.len() > MAX_BINDING_BYTES {
            return Err(CertError::Encoding("binding too large".into()));
        }
        if bytes.is_empty() {
            return Err(CertError::Encoding("empty binding".into()));
        }
        let mut pos = 0;
        let provider = ProviderKind::from_u8(bytes[pos])?;
        pos += 1;
        let (algorithm, n) = take16(bytes, pos)?;
        pos += n;
        let algorithm = String::from_utf8(algorithm.to_vec())
            .map_err(|_| CertError::Encoding("invalid utf-8 algorithm".into()))?;
        let (public_key, n) = take16(bytes, pos)?;
        pos += n;
        let (signature, n) = take16(bytes, pos)?;
        pos += n;
        let (attestation_bytes, n) = take16(bytes, pos)?;
        pos += n;
        if pos != bytes.len() {
            return Err(CertError::Encoding("trailing bytes in binding".into()));
        }
        let attestation = if attestation_bytes.is_empty() {
            None
        } else {
            Some(attestation_bytes.to_vec())
        };
        Ok(Self {
            provider,
            algorithm,
            public_key: public_key.to_vec(),
            signature: signature.to_vec(),
            attestation,
        })
    }
}

fn put16(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}
fn take16(buf: &[u8], pos: usize) -> Result<(&[u8], usize), CertError> {
    if pos + 2 > buf.len() {
        return Err(CertError::Encoding("truncated binding".into()));
    }
    let len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    if pos + 2 + len > buf.len() {
        return Err(CertError::Encoding("truncated binding".into()));
    }
    Ok((&buf[pos + 2..pos + 2 + len], 2 + len))
}
