#[derive(Debug, thiserror::Error)]
pub enum AttestError {
    #[error("encoding: {0}")]
    Encoding(&'static str),
    #[error("unknown format {0}")]
    UnknownFormat(String),
    #[error("signature invalid")]
    Signature,
    #[error("malformed: {0}")]
    Malformed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evidence {
    Tpm2Quote {
        quote: Vec<u8>,
        signature: Vec<u8>,
        ak_public: Vec<u8>,
        pcrs: Vec<(u32, Vec<u8>)>,
        nonce: Vec<u8>,
    },
    None,
}

pub fn parse(format: &str, bytes: &[u8]) -> Result<Evidence, AttestError> {
    match format {
        "tpm2-quote" => {
            // Length-prefixed cbor-free blob: quote_len(2)|quote|sig_len(2)|sig|ak_len(2)|ak|pcrs_len(2)|pcrs…|nonce_len(2)|nonce
            let mut pos = 0;
            let take = |b: &[u8], p: &mut usize| -> Result<Vec<u8>, AttestError> {
                if *p + 2 > b.len() {
                    return Err(AttestError::Encoding("truncated evidence"));
                }
                let len = u16::from_be_bytes([b[*p], b[*p + 1]]) as usize;
                *p += 2;
                if *p + len > b.len() {
                    return Err(AttestError::Encoding("truncated evidence"));
                }
                let out = b[*p..*p + len].to_vec();
                *p += len;
                Ok(out)
            };
            let quote = take(bytes, &mut pos)?;
            let signature = take(bytes, &mut pos)?;
            let ak_public = take(bytes, &mut pos)?;
            // pcrs: count(2) then each index(4)|len(2)|value
            if pos + 2 > bytes.len() {
                return Err(AttestError::Encoding("truncated pcrs"));
            }
            let count = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
            pos += 2;
            let mut pcrs = Vec::new();
            for _ in 0..count {
                if pos + 6 > bytes.len() {
                    return Err(AttestError::Encoding("truncated pcr"));
                }
                let idx = u32::from_be_bytes([
                    bytes[pos],
                    bytes[pos + 1],
                    bytes[pos + 2],
                    bytes[pos + 3],
                ]);
                pos += 4;
                let len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
                pos += 2;
                if pos + len > bytes.len() {
                    return Err(AttestError::Encoding("truncated pcr value"));
                }
                let val = bytes[pos..pos + len].to_vec();
                pos += len;
                pcrs.push((idx, val));
            }
            let nonce = take(bytes, &mut pos)?;
            if pos != bytes.len() {
                return Err(AttestError::Encoding("trailing bytes"));
            }
            Ok(Evidence::Tpm2Quote {
                quote,
                signature,
                ak_public,
                pcrs,
                nonce,
            })
        }
        "none" => Ok(Evidence::None),
        other => Err(AttestError::UnknownFormat(other.to_string())),
    }
}

pub fn encode(ev: &Evidence) -> (String, Vec<u8>) {
    match ev {
        Evidence::Tpm2Quote {
            quote,
            signature,
            ak_public,
            pcrs,
            nonce,
        } => {
            let mut out = Vec::new();
            out.extend_from_slice(&(quote.len() as u16).to_be_bytes());
            out.extend_from_slice(quote);
            out.extend_from_slice(&(signature.len() as u16).to_be_bytes());
            out.extend_from_slice(signature);
            out.extend_from_slice(&(ak_public.len() as u16).to_be_bytes());
            out.extend_from_slice(ak_public);
            out.extend_from_slice(&(pcrs.len() as u16).to_be_bytes());
            for (idx, val) in pcrs {
                out.extend_from_slice(&idx.to_be_bytes());
                out.extend_from_slice(&(val.len() as u16).to_be_bytes());
                out.extend_from_slice(val);
            }
            out.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
            out.extend_from_slice(nonce);
            ("tpm2-quote".to_string(), out)
        }
        Evidence::None => ("none".to_string(), vec![]),
    }
}
