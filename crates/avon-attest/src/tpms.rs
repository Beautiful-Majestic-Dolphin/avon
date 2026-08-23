//! Just enough of the TPM 2.0 structures to check a quote.
//!
//! A quote is only worth anything if the bytes we check are the bytes the TPM
//! signed, so this parses the real `TPMS_ATTEST` — magic, attest type, the
//! nonce the caller put in `extraData`, the clock the TPM keeps, and the PCR
//! selection with its digest — rather than a convenient re-encoding of it.
//! Spec references are to TPM 2.0 Part 2, revision 1.59.

use crate::evidence::AttestError;

/// `TPM_GENERATED_VALUE`: present on everything the TPM signs, and on nothing a
/// caller can ask it to sign, which is what stops a quote being forged out of
/// an ordinary signing operation.
pub const TPM_GENERATED_VALUE: u32 = 0xFF54_4347;
/// `TPM_ST_ATTEST_QUOTE`.
pub const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;
/// `TPM_ALG_SHA256`.
pub const TPM_ALG_SHA256: u16 = 0x000B;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClockInfo {
    /// Milliseconds since the TPM was created — not a wall clock, so it says
    /// nothing about when the quote was made. Freshness comes from the nonce.
    pub clock_ms: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    /// False means the TPM's clock may have gone backwards, which makes any
    /// time-based reasoning on it worthless.
    pub safe: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuoteAttest {
    pub qualified_signer: Vec<u8>,
    /// The nonce the verifier asked for.
    pub extra_data: Vec<u8>,
    pub clock: ClockInfo,
    pub firmware_version: u64,
    /// PCR indices the TPM says it hashed, in ascending order, for the SHA-256
    /// bank. Selections in other banks are parsed and ignored.
    pub selected_pcrs: Vec<u32>,
    /// The TPM's digest over those PCR values.
    pub pcr_digest: Vec<u8>,
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], AttestError> {
        if self.pos + n > self.b.len() {
            return Err(AttestError::Malformed(format!(
                "truncated at {} (wanted {n})",
                self.pos
            )));
        }
        let out = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, AttestError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, AttestError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, AttestError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, AttestError> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// A `TPM2B_*`: a 16-bit size followed by that many bytes.
    fn tpm2b(&mut self) -> Result<Vec<u8>, AttestError> {
        let len = self.u16()? as usize;
        Ok(self.take(len)?.to_vec())
    }
}

/// Parse a `TPMS_ATTEST` that must be a quote.
pub fn parse_quote(bytes: &[u8]) -> Result<QuoteAttest, AttestError> {
    let mut r = Reader::new(bytes);
    let magic = r.u32()?;
    if magic != TPM_GENERATED_VALUE {
        return Err(AttestError::Malformed(format!(
            "magic {magic:#010x} is not TPM_GENERATED_VALUE"
        )));
    }
    let attest_type = r.u16()?;
    if attest_type != TPM_ST_ATTEST_QUOTE {
        return Err(AttestError::Malformed(format!(
            "attest type {attest_type:#06x} is not a quote"
        )));
    }
    let qualified_signer = r.tpm2b()?;
    let extra_data = r.tpm2b()?;
    let clock = ClockInfo {
        clock_ms: r.u64()?,
        reset_count: r.u32()?,
        restart_count: r.u32()?,
        safe: r.u8()? != 0,
    };
    let firmware_version = r.u64()?;

    // TPMS_QUOTE_INFO: TPML_PCR_SELECTION then TPM2B_DIGEST.
    let count = r.u32()?;
    if count > 8 {
        return Err(AttestError::Malformed(format!(
            "{count} PCR selections is not plausible"
        )));
    }
    let mut selected_pcrs = Vec::new();
    for _ in 0..count {
        let alg = r.u16()?;
        let size_of_select = r.u8()? as usize;
        if size_of_select > 8 {
            return Err(AttestError::Malformed("pcr selection too wide".into()));
        }
        let bitmap = r.take(size_of_select)?;
        if alg != TPM_ALG_SHA256 {
            continue; // other banks are not what we check against
        }
        for (byte_index, byte) in bitmap.iter().enumerate() {
            for bit in 0..8u32 {
                if byte & (1 << bit) != 0 {
                    selected_pcrs.push(byte_index as u32 * 8 + bit);
                }
            }
        }
    }
    selected_pcrs.sort_unstable();
    let pcr_digest = r.tpm2b()?;
    if pcr_digest.len() != 32 {
        return Err(AttestError::Malformed(format!(
            "pcr digest is {} bytes, expected a SHA-256",
            pcr_digest.len()
        )));
    }

    Ok(QuoteAttest {
        qualified_signer,
        extra_data,
        clock,
        firmware_version,
        selected_pcrs,
        pcr_digest,
    })
}

/// Build a `TPMS_ATTEST` quote. Only tests and the swtpm fixture generator use
/// this — a real quote is produced inside the TPM — but it lives here so the
/// encoder and the parser cannot drift apart.
pub fn encode_quote(q: &QuoteAttest) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes());
    out.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes());
    let tpm2b = |v: &[u8], out: &mut Vec<u8>| {
        out.extend_from_slice(&(v.len() as u16).to_be_bytes());
        out.extend_from_slice(v);
    };
    tpm2b(&q.qualified_signer, &mut out);
    tpm2b(&q.extra_data, &mut out);
    out.extend_from_slice(&q.clock.clock_ms.to_be_bytes());
    out.extend_from_slice(&q.clock.reset_count.to_be_bytes());
    out.extend_from_slice(&q.clock.restart_count.to_be_bytes());
    out.push(u8::from(q.clock.safe));
    out.extend_from_slice(&q.firmware_version.to_be_bytes());

    out.extend_from_slice(&1u32.to_be_bytes()); // one selection: the SHA-256 bank
    out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    let width = q
        .selected_pcrs
        .iter()
        .map(|p| (p / 8 + 1) as usize)
        .max()
        .unwrap_or(3)
        .max(3);
    out.push(width as u8);
    let mut bitmap = vec![0u8; width];
    for p in &q.selected_pcrs {
        bitmap[(p / 8) as usize] |= 1 << (p % 8);
    }
    out.extend_from_slice(&bitmap);
    tpm2b(&q.pcr_digest, &mut out);
    out
}
