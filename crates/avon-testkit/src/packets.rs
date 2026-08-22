use std::net::Ipv4Addr;

/// Build a minimal IPv4 UDP packet: 20-byte header + 8-byte UDP + payload.
/// No checksum, no options. `src_port` is chosen as 12345.
pub fn udp_v4(src: Ipv4Addr, dst: Ipv4Addr, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let src_port: u16 = 12345;
    let total_len = 20 + 8 + payload.len();
    let mut pkt = Vec::with_capacity(total_len);
    // IPv4 header
    pkt.push(0x45); // version 4, IHL 5
    pkt.push(0x00); // DSCP/ECN
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // identification
    pkt.extend_from_slice(&[0x00, 0x00]); // flags/fragment
    pkt.push(64); // TTL
    pkt.push(17); // protocol UDP
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum (zero)
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&dst.octets());
    // UDP header
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    let udp_len = (8 + payload.len()) as u16;
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum zero
    pkt.extend_from_slice(payload);
    pkt
}
