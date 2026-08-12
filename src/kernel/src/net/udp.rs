//! Minimal UDP over IPv4: datagram build with pseudo-header checksum, plus a
//! tiny DNS query builder used to prove the UDP datapath against slirp's DNS
//! server (10.0.2.3:53).

use crate::net::ipv4::internet_checksum;

/// UDP header length.
pub const UDP_HEADER_LENGTH: usize = 8;
/// IP protocol number for UDP.
pub const IP_PROTOCOL_UDP: u8 = 17;

/// Builds a UDP datagram (header + payload) into `out`, computing the checksum
/// over the IPv4 pseudo-header + UDP header + payload. Returns the datagram
/// length. `out` must be >= UDP_HEADER_LENGTH + payload.len().
pub fn build_datagram(
    source_ipv4: [u8; 4],
    destination_ipv4: [u8; 4],
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
    out: &mut [u8],
) -> usize {
    let datagram_length = UDP_HEADER_LENGTH + payload.len();
    out[0..2].copy_from_slice(&source_port.to_be_bytes());
    out[2..4].copy_from_slice(&destination_port.to_be_bytes());
    out[4..6].copy_from_slice(&(datagram_length as u16).to_be_bytes());
    out[6..8].copy_from_slice(&[0, 0]); // checksum zero for computation
    out[UDP_HEADER_LENGTH..datagram_length].copy_from_slice(payload);

    let checksum = udp_checksum(source_ipv4, destination_ipv4, &out[..datagram_length]);
    // A computed 0 is transmitted as 0xFFFF (0 means "no checksum" in UDP).
    let checksum = if checksum == 0 { 0xFFFF } else { checksum };
    out[6..8].copy_from_slice(&checksum.to_be_bytes());
    datagram_length
}

/// UDP checksum over the IPv4 pseudo-header followed by the UDP datagram.
fn udp_checksum(source_ipv4: [u8; 4], destination_ipv4: [u8; 4], datagram: &[u8]) -> u16 {
    let mut buffer = [0u8; 12 + 1500];
    buffer[0..4].copy_from_slice(&source_ipv4);
    buffer[4..8].copy_from_slice(&destination_ipv4);
    buffer[8] = 0;
    buffer[9] = IP_PROTOCOL_UDP;
    buffer[10..12].copy_from_slice(&(datagram.len() as u16).to_be_bytes());
    let total = 12 + datagram.len();
    buffer[12..total].copy_from_slice(datagram);
    internet_checksum(&buffer[..total])
}

/// True if `datagram` is a UDP datagram whose source port is `expected_source_port`
/// and destination port is `expected_destination_port`.
pub fn is_response_from_port(
    datagram: &[u8],
    expected_source_port: u16,
    expected_destination_port: u16,
) -> bool {
    if datagram.len() < UDP_HEADER_LENGTH {
        return false;
    }
    u16::from_be_bytes([datagram[0], datagram[1]]) == expected_source_port
        && u16::from_be_bytes([datagram[2], datagram[3]]) == expected_destination_port
}

/// Builds a minimal DNS A-record query for `question_name` (already in DNS
/// label form, e.g. b"\x07example\x03com\x00") with the given `query_id`, into
/// `out`. Returns the query length.
pub fn build_dns_query(query_id: u16, question_name: &[u8], out: &mut [u8]) -> usize {
    out[0..2].copy_from_slice(&query_id.to_be_bytes());
    out[2..4].copy_from_slice(&0x0100u16.to_be_bytes()); // recursion desired
    out[4..6].copy_from_slice(&1u16.to_be_bytes()); // qdcount
    out[6..8].copy_from_slice(&[0, 0]); // ancount
    out[8..10].copy_from_slice(&[0, 0]); // nscount
    out[10..12].copy_from_slice(&[0, 0]); // arcount
    let name_end = 12 + question_name.len();
    out[12..name_end].copy_from_slice(question_name);
    out[name_end..name_end + 2].copy_from_slice(&1u16.to_be_bytes()); // QTYPE A
    out[name_end + 2..name_end + 4].copy_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    name_end + 4
}

#[cfg(test)]
mod tests {
    use super::{build_datagram, build_dns_query, is_response_from_port, UDP_HEADER_LENGTH};

    #[test]
    fn test_udp_datagram_header() {
        let mut out = [0u8; 64];
        let length = build_datagram([10, 0, 2, 15], [10, 0, 2, 3], 40000, 53, b"hello", &mut out);
        assert_eq!(length, UDP_HEADER_LENGTH + 5);
        assert_eq!(u16::from_be_bytes([out[0], out[1]]), 40000);
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), 53);
        assert_eq!(u16::from_be_bytes([out[4], out[5]]), 13);
        assert_ne!(u16::from_be_bytes([out[6], out[7]]), 0); // checksum present
    }

    #[test]
    fn test_is_response_from_port() {
        let mut out = [0u8; 64];
        let length = build_datagram([10, 0, 2, 3], [10, 0, 2, 15], 53, 40000, b"x", &mut out);
        assert!(is_response_from_port(&out[..length], 53, 40000));
        assert!(!is_response_from_port(&out[..length], 99, 40000));
    }

    #[test]
    fn test_dns_query_layout() {
        let mut out = [0u8; 64];
        let length = build_dns_query(0xBEEF, b"\x03foo\x00", &mut out);
        assert_eq!(u16::from_be_bytes([out[0], out[1]]), 0xBEEF);
        assert_eq!(u16::from_be_bytes([out[4], out[5]]), 1); // qdcount
                                                             // name (5) + qtype(2) + qclass(2) after the 12-byte header
        assert_eq!(length, 12 + 5 + 4);
    }
}
