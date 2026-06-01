//! Minimal network protocol helpers — the start of the IPv4/IPv6 stack.
//!
//! This module is pure (no hardware): it builds and parses frames. The e1000
//! driver does the actual transmit/receive. Today it covers ARP (IPv4 address
//! resolution) — enough to prove the NIC's TX+RX path works end-to-end by
//! resolving the gateway's MAC. IPv4/ICMP/UDP/IPv6/TCP build on the same shape.

pub mod icmp;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod tcp_connection;
pub mod udp;

/// Ethernet header length.
pub const ETHERNET_HEADER_LENGTH: usize = 14;
/// EtherType for ARP.
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// Length of an Ethernet+ARP frame for IPv4 over Ethernet.
pub const ARP_FRAME_LENGTH: usize = 42;

const ARP_HARDWARE_TYPE_ETHERNET: u16 = 0x0001;
const ARP_PROTOCOL_TYPE_IPV4: u16 = 0x0800;
const ARP_HARDWARE_LENGTH: u8 = 6;
const ARP_PROTOCOL_LENGTH: u8 = 4;
const ARP_OPERATION_REQUEST: u16 = 0x0001;
const ARP_OPERATION_REPLY: u16 = 0x0002;

const BROADCAST_MAC: [u8; 6] = [0xFF; 6];

/// Total length of an Ethernet+IPv4+ICMP echo frame.
pub const ICMP_PING_FRAME_LENGTH: usize =
    ETHERNET_HEADER_LENGTH + ipv4::IPV4_HEADER_LENGTH + icmp::ICMP_ECHO_LENGTH;

/// Writes a 14-byte Ethernet header into `out`.
fn write_ethernet_header(out: &mut [u8], destination_mac: [u8; 6], source_mac: [u8; 6], ethertype: u16) {
    out[0..6].copy_from_slice(&destination_mac);
    out[6..12].copy_from_slice(&source_mac);
    out[12..14].copy_from_slice(&ethertype.to_be_bytes());
}

/// Assembles a complete Ethernet+IPv4+ICMP echo-request ("ping") frame into
/// `out` (must be >= ICMP_PING_FRAME_LENGTH). Returns the frame length.
pub fn build_icmp_ping_frame(
    destination_mac: [u8; 6],
    source_mac: [u8; 6],
    source_ipv4: [u8; 4],
    destination_ipv4: [u8; 4],
    identifier: u16,
    sequence: u16,
    out: &mut [u8],
) -> usize {
    write_ethernet_header(out, destination_mac, source_mac, ipv4::ETHERTYPE_IPV4);
    let header = ipv4::build_header(
        source_ipv4,
        destination_ipv4,
        ipv4::IP_PROTOCOL_ICMP,
        icmp::ICMP_ECHO_LENGTH as u16,
        identifier,
    );
    let ip_start = ETHERNET_HEADER_LENGTH;
    out[ip_start..ip_start + ipv4::IPV4_HEADER_LENGTH].copy_from_slice(&header);
    let echo = icmp::build_echo_request(identifier, sequence);
    let icmp_start = ip_start + ipv4::IPV4_HEADER_LENGTH;
    out[icmp_start..icmp_start + icmp::ICMP_ECHO_LENGTH].copy_from_slice(&echo);
    ICMP_PING_FRAME_LENGTH
}

/// Assembles an Ethernet+IPv4+UDP frame carrying `payload` into `out`. Returns
/// the frame length.
pub fn build_udp_ipv4_frame(
    destination_mac: [u8; 6],
    source_mac: [u8; 6],
    source_ipv4: [u8; 4],
    destination_ipv4: [u8; 4],
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
    out: &mut [u8],
) -> usize {
    write_ethernet_header(out, destination_mac, source_mac, ipv4::ETHERTYPE_IPV4);
    let mut datagram = [0u8; 512];
    let datagram_length = udp::build_datagram(
        source_ipv4,
        destination_ipv4,
        source_port,
        destination_port,
        payload,
        &mut datagram,
    );
    let header = ipv4::build_header(
        source_ipv4,
        destination_ipv4,
        udp::IP_PROTOCOL_UDP,
        datagram_length as u16,
        source_port, // reuse the ephemeral port as the IP id; uniqueness suffices
    );
    let ip_start = ETHERNET_HEADER_LENGTH;
    out[ip_start..ip_start + ipv4::IPV4_HEADER_LENGTH].copy_from_slice(&header);
    let udp_start = ip_start + ipv4::IPV4_HEADER_LENGTH;
    out[udp_start..udp_start + datagram_length].copy_from_slice(&datagram[..datagram_length]);
    udp_start + datagram_length
}

/// Wraps an already-built L4 segment (`l4_payload`, e.g. a TCP segment with its
/// own checksum) in an Ethernet + IPv4 frame. Returns the frame length.
pub fn build_ipv4_frame(
    destination_mac: [u8; 6],
    source_mac: [u8; 6],
    source_ipv4: [u8; 4],
    destination_ipv4: [u8; 4],
    protocol: u8,
    l4_payload: &[u8],
    out: &mut [u8],
) -> usize {
    write_ethernet_header(out, destination_mac, source_mac, ipv4::ETHERTYPE_IPV4);
    let header = ipv4::build_header(
        source_ipv4,
        destination_ipv4,
        protocol,
        l4_payload.len() as u16,
        // IP id: low 16 bits of the payload length is fine for our traffic.
        l4_payload.len() as u16,
    );
    let ip_start = ETHERNET_HEADER_LENGTH;
    out[ip_start..ip_start + ipv4::IPV4_HEADER_LENGTH].copy_from_slice(&header);
    let l4_start = ip_start + ipv4::IPV4_HEADER_LENGTH;
    out[l4_start..l4_start + l4_payload.len()].copy_from_slice(l4_payload);
    l4_start + l4_payload.len()
}

/// If `frame` is an Ethernet/IPv4/TCP frame addressed to `local_ipv4`, returns
/// (peer MAC, peer IPv4, byte range of the TCP segment within `frame`).
pub fn extract_ipv4_tcp(
    frame: &[u8],
    local_ipv4: [u8; 4],
) -> Option<([u8; 6], [u8; 4], core::ops::Range<usize>)> {
    if frame.len() < ETHERNET_HEADER_LENGTH + ipv4::IPV4_HEADER_LENGTH {
        return None;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != ipv4::ETHERTYPE_IPV4 {
        return None;
    }
    let ip = ETHERNET_HEADER_LENGTH;
    if frame[ip] >> 4 != 4 {
        return None;
    }
    let ihl = ((frame[ip] & 0x0F) as usize) * 4;
    if ihl < ipv4::IPV4_HEADER_LENGTH || frame.len() < ip + ihl {
        return None;
    }
    if frame[ip + 9] != tcp::IP_PROTOCOL_TCP {
        return None;
    }
    let mut destination = [0u8; 4];
    destination.copy_from_slice(&frame[ip + 16..ip + 20]);
    if destination != local_ipv4 {
        return None;
    }
    let mut peer_mac = [0u8; 6];
    peer_mac.copy_from_slice(&frame[6..12]);
    let mut peer_ipv4 = [0u8; 4];
    peer_ipv4.copy_from_slice(&frame[ip + 12..ip + 16]);
    // Use the IPv4 total_length to find the real end of the segment — small
    // frames are zero-padded to the 60-byte Ethernet minimum, and that padding
    // must NOT be treated as TCP payload.
    let ip_total_length = u16::from_be_bytes([frame[ip + 2], frame[ip + 3]]) as usize;
    let segment_end = (ip + ip_total_length).min(frame.len());
    if segment_end < ip + ihl {
        return None;
    }
    Some((peer_mac, peer_ipv4, (ip + ihl)..segment_end))
}

/// Assembles an Ethernet+IPv4+TCP SYN frame into `out`. Returns the frame length.
pub fn build_tcp_syn_frame(
    destination_mac: [u8; 6],
    source_mac: [u8; 6],
    source_ipv4: [u8; 4],
    destination_ipv4: [u8; 4],
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    out: &mut [u8],
) -> usize {
    write_ethernet_header(out, destination_mac, source_mac, ipv4::ETHERTYPE_IPV4);
    let mut segment = [0u8; tcp::TCP_HEADER_LENGTH];
    let segment_length = tcp::build_syn(
        source_ipv4,
        destination_ipv4,
        source_port,
        destination_port,
        sequence_number,
        &mut segment,
    );
    let header = ipv4::build_header(
        source_ipv4,
        destination_ipv4,
        tcp::IP_PROTOCOL_TCP,
        segment_length as u16,
        source_port,
    );
    let ip_start = ETHERNET_HEADER_LENGTH;
    out[ip_start..ip_start + ipv4::IPV4_HEADER_LENGTH].copy_from_slice(&header);
    let tcp_start = ip_start + ipv4::IPV4_HEADER_LENGTH;
    out[tcp_start..tcp_start + segment_length].copy_from_slice(&segment[..segment_length]);
    tcp_start + segment_length
}

/// Classifies a received frame as a TCP handshake response from
/// `expected_source_ipv4` on the given ports (SYN-ACK, RST, or Other).
pub fn classify_tcp_response(
    frame: &[u8],
    expected_source_ipv4: [u8; 4],
    expected_source_port: u16,
    expected_destination_port: u16,
) -> tcp::HandshakeResponse {
    if frame.len() < ETHERNET_HEADER_LENGTH {
        return tcp::HandshakeResponse::Other;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != ipv4::ETHERTYPE_IPV4 {
        return tcp::HandshakeResponse::Other;
    }
    let ip_packet = &frame[ETHERNET_HEADER_LENGTH..];
    let payload_offset =
        match ipv4::parse_payload_offset(ip_packet, tcp::IP_PROTOCOL_TCP, expected_source_ipv4) {
            Some(offset) => offset,
            None => return tcp::HandshakeResponse::Other,
        };
    tcp::classify_handshake_response(
        &ip_packet[payload_offset..],
        expected_source_port,
        expected_destination_port,
    )
}

/// True if `frame` is an Ethernet/IPv4/UDP datagram from `expected_source_ipv4`
/// with the given source/destination ports.
pub fn is_udp_response(
    frame: &[u8],
    expected_source_ipv4: [u8; 4],
    expected_source_port: u16,
    expected_destination_port: u16,
) -> bool {
    if frame.len() < ETHERNET_HEADER_LENGTH {
        return false;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != ipv4::ETHERTYPE_IPV4 {
        return false;
    }
    let ip_packet = &frame[ETHERNET_HEADER_LENGTH..];
    let payload_offset =
        match ipv4::parse_payload_offset(ip_packet, udp::IP_PROTOCOL_UDP, expected_source_ipv4) {
            Some(offset) => offset,
            None => return false,
        };
    udp::is_response_from_port(
        &ip_packet[payload_offset..],
        expected_source_port,
        expected_destination_port,
    )
}

/// True if `frame` is an Ethernet/IPv4/ICMP echo reply from `expected_src_ipv4`
/// matching `identifier`/`sequence`.
pub fn is_icmp_echo_reply(
    frame: &[u8],
    expected_source_ipv4: [u8; 4],
    identifier: u16,
    sequence: u16,
) -> bool {
    if frame.len() < ETHERNET_HEADER_LENGTH {
        return false;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ipv4::ETHERTYPE_IPV4 {
        return false;
    }
    let ip_packet = &frame[ETHERNET_HEADER_LENGTH..];
    let payload_offset =
        match ipv4::parse_payload_offset(ip_packet, ipv4::IP_PROTOCOL_ICMP, expected_source_ipv4) {
            Some(offset) => offset,
            None => return false,
        };
    icmp::is_matching_echo_reply(&ip_packet[payload_offset..], identifier, sequence)
}

/// Builds a broadcast ARP request asking "who has `target_ipv4`?" from
/// `sender_mac`/`sender_ipv4`.
pub fn build_arp_request(
    sender_mac: [u8; 6],
    sender_ipv4: [u8; 4],
    target_ipv4: [u8; 4],
) -> [u8; ARP_FRAME_LENGTH] {
    let mut frame = [0u8; ARP_FRAME_LENGTH];
    frame[0..6].copy_from_slice(&BROADCAST_MAC);
    frame[6..12].copy_from_slice(&sender_mac);
    frame[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    frame[14..16].copy_from_slice(&ARP_HARDWARE_TYPE_ETHERNET.to_be_bytes());
    frame[16..18].copy_from_slice(&ARP_PROTOCOL_TYPE_IPV4.to_be_bytes());
    frame[18] = ARP_HARDWARE_LENGTH;
    frame[19] = ARP_PROTOCOL_LENGTH;
    frame[20..22].copy_from_slice(&ARP_OPERATION_REQUEST.to_be_bytes());
    frame[22..28].copy_from_slice(&sender_mac);
    frame[28..32].copy_from_slice(&sender_ipv4);
    // target MAC left zero
    frame[38..42].copy_from_slice(&target_ipv4);
    frame
}

/// If `frame` is an ARP reply announcing `expected_ipv4`, returns the sender's
/// MAC address. Returns `None` for anything else (wrong type, op, or IP).
pub fn parse_arp_reply(frame: &[u8], expected_ipv4: [u8; 4]) -> Option<[u8; 6]> {
    if frame.len() < ARP_FRAME_LENGTH {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ETHERTYPE_ARP {
        return None;
    }
    let operation = u16::from_be_bytes([frame[20], frame[21]]);
    if operation != ARP_OPERATION_REPLY {
        return None;
    }
    if frame[28..32] != expected_ipv4 {
        return None;
    }
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&frame[22..28]);
    Some(sender_mac)
}

#[cfg(test)]
mod tests {
    use super::{build_arp_request, parse_arp_reply, ARP_FRAME_LENGTH, ETHERTYPE_ARP};

    const OUR_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    const OUR_IP: [u8; 4] = [10, 0, 2, 15];
    const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];
    const GATEWAY_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];

    #[test]
    fn test_arp_request_layout() {
        let frame = build_arp_request(OUR_MAC, OUR_IP, GATEWAY_IP);
        assert_eq!(frame.len(), ARP_FRAME_LENGTH);
        assert_eq!(&frame[0..6], &[0xFF; 6]); // broadcast
        assert_eq!(&frame[6..12], &OUR_MAC);
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), ETHERTYPE_ARP);
        assert_eq!(u16::from_be_bytes([frame[20], frame[21]]), 1); // request
        assert_eq!(&frame[38..42], &GATEWAY_IP);
    }

    #[test]
    fn test_parse_arp_reply_extracts_sender_mac() {
        // Craft a reply from the gateway.
        let mut reply = [0u8; ARP_FRAME_LENGTH];
        reply[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        reply[20..22].copy_from_slice(&2u16.to_be_bytes()); // reply
        reply[22..28].copy_from_slice(&GATEWAY_MAC);
        reply[28..32].copy_from_slice(&GATEWAY_IP);
        assert_eq!(parse_arp_reply(&reply, GATEWAY_IP), Some(GATEWAY_MAC));
    }

    #[test]
    fn test_parse_rejects_non_arp_and_wrong_ip() {
        let request = build_arp_request(OUR_MAC, OUR_IP, GATEWAY_IP);
        // A request (op 1), not a reply.
        assert_eq!(parse_arp_reply(&request, GATEWAY_IP), None);
        // A reply from a different IP.
        let mut reply = [0u8; ARP_FRAME_LENGTH];
        reply[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        reply[20..22].copy_from_slice(&2u16.to_be_bytes());
        reply[28..32].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(parse_arp_reply(&reply, GATEWAY_IP), None);
    }
}
