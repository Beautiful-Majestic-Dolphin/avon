//! Where flow authorization plugs in. Phase 3 ships `AllowAll`; phase 4
//! replaces it with the Cedar engine without touching the data plane.

use std::net::IpAddr;

use avon_common::ids::SessionId;

#[derive(Clone, Debug)]
pub struct Flow {
    pub session: SessionId,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub dst_port: Option<u16>,
}

#[derive(Clone, Copy, Debug)]
pub struct Decision {
    pub allow: bool,
    pub reason: &'static str,
}

pub trait FlowPolicy: Send + Sync {
    fn allow(&self, flow: &Flow) -> Decision;
}

/// Phase-3 default. Replaced by the Cedar engine in phase 4.
pub struct AllowAll;

impl FlowPolicy for AllowAll {
    fn allow(&self, _flow: &Flow) -> Decision {
        Decision {
            allow: true,
            reason: "allow-all",
        }
    }
}

/// Version, addresses, protocol and — for TCP/UDP — the destination port.
/// Returns `None` for anything that is not a well-formed IPv4/IPv6 packet, so
/// the caller drops it rather than guessing.
pub fn parse_flow(session: SessionId, packet: &[u8]) -> Option<Flow> {
    let version = packet.first()? >> 4;
    match version {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let ihl = (packet[0] & 0x0f) as usize * 4;
            if ihl < 20 || packet.len() < ihl {
                return None;
            }
            let protocol = packet[9];
            let src = IpAddr::from([packet[12], packet[13], packet[14], packet[15]]);
            let dst = IpAddr::from([packet[16], packet[17], packet[18], packet[19]]);
            let dst_port = match protocol {
                6 | 17 if packet.len() >= ihl + 4 => {
                    Some(u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]))
                }
                _ => None,
            };
            Some(Flow {
                session,
                src,
                dst,
                protocol,
                dst_port,
            })
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            // Next-header only; extension headers are not walked, so a flow
            // carrying them is treated as portless rather than misparsed.
            let protocol = packet[6];
            let mut s = [0u8; 16];
            s.copy_from_slice(&packet[8..24]);
            let mut d = [0u8; 16];
            d.copy_from_slice(&packet[24..40]);
            let dst_port = match protocol {
                6 | 17 if packet.len() >= 44 => Some(u16::from_be_bytes([packet[42], packet[43]])),
                _ => None,
            };
            Some(Flow {
                session,
                src: IpAddr::from(s),
                dst: IpAddr::from(d),
                protocol,
                dst_port,
            })
        }
        _ => None,
    }
}
