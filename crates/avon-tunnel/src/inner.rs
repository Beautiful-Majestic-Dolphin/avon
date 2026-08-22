use crate::TunnelError;

/// The plaintext inside a data packet: `inner_type(1) || payload`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inner<'a> {
    Ip(&'a [u8]),
    Control(&'a [u8]),
    Keepalive,
}

impl Inner<'_> {
    pub const IP: u8 = 0;
    pub const CONTROL: u8 = 1;
    pub const KEEPALIVE: u8 = 2;

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Inner::Ip(p) => {
                out.push(Self::IP);
                out.extend_from_slice(p);
            }
            Inner::Control(f) => {
                out.push(Self::CONTROL);
                out.extend_from_slice(f);
            }
            Inner::Keepalive => out.push(Self::KEEPALIVE),
        }
    }

    pub fn decode(plaintext: &[u8]) -> Result<Inner<'_>, TunnelError> {
        let (&t, rest) = plaintext.split_first().ok_or(TunnelError::Short)?;
        match t {
            Self::IP => Ok(Inner::Ip(rest)),
            Self::CONTROL => Ok(Inner::Control(rest)),
            Self::KEEPALIVE => Ok(Inner::Keepalive),
            other => Err(TunnelError::BadInner(other)),
        }
    }
}
