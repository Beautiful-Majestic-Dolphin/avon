/// Fix IPv4 header and ICMP checksums in place for the loopback ping test.
pub fn fix_ipv4_and_icmp(packet: &mut [u8]) {
    if packet.len() < 20 {
        return;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if ihl < 20 || packet.len() < ihl {
        return;
    }
    // Zero checksums.
    packet[10] = 0;
    packet[11] = 0;
    if packet.len() >= ihl + 4 {
        // ICMP checksum is at icmp header + 2.
        packet[ihl + 2] = 0;
        packet[ihl + 3] = 0;
    }

    // IPv4 header checksum.
    let csum = checksum(&packet[..ihl]);
    packet[10] = (csum >> 8) as u8;
    packet[11] = (csum & 0xff) as u8;

    // ICMP checksum if protocol is ICMP (1).
    if packet[9] == 1 && packet.len() >= ihl + 4 {
        let icmp_len = packet.len() - ihl;
        let csum = checksum(&packet[ihl..ihl + icmp_len]);
        packet[ihl + 2] = (csum >> 8) as u8;
        packet[ihl + 3] = (csum & 0xff) as u8;
    }
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
