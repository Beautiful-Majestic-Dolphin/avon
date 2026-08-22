use crate::TunnelError;

pub const HEADER_LEN: usize = 16;
pub const TYPE_DATA: u8 = 0x01;
pub const FLAG_EPOCH_OVERLAP: u8 = 0b0000_0001;
const TAG_LEN: usize = 16;

/// Spec §6.1: `type(1) || flags(1) || reserved(2) || receiver_index(4) || counter(8)`,
/// all big-endian. Everything after it is AEAD ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: u8,
    pub flags: u8,
    pub receiver_index: u32,
    pub counter: u64,
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0] = self.kind;
        b[1] = self.flags;
        b[4..8].copy_from_slice(&self.receiver_index.to_be_bytes());
        b[8..16].copy_from_slice(&self.counter.to_be_bytes());
        b
    }

    /// Parse the header; returns the remaining body. Drops anything that is
    /// not a well-formed data packet before any cryptography runs.
    pub fn decode(bytes: &[u8]) -> Result<(Header, &[u8]), TunnelError> {
        if bytes.len() < HEADER_LEN {
            return Err(TunnelError::Short);
        }
        if bytes[0] != TYPE_DATA {
            return Err(TunnelError::BadType(bytes[0]));
        }
        if bytes[2] != 0 || bytes[3] != 0 || bytes[1] & !FLAG_EPOCH_OVERLAP != 0 {
            return Err(TunnelError::Protocol("reserved bits set".into()));
        }
        let receiver_index = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let counter = u64::from_be_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        Ok((
            Header {
                kind: bytes[0],
                flags: bytes[1],
                receiver_index,
                counter,
            },
            &bytes[HEADER_LEN..],
        ))
    }
}

/// Largest UDP payload an overlay packet can produce: header, inner type byte,
/// the packet itself and the AEAD tag.
pub fn max_udp_payload(overlay_mtu: u16) -> usize {
    HEADER_LEN + 1 + overlay_mtu as usize + TAG_LEN
}
