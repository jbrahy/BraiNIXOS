//! Minimal IPv4: header build/parse and the Internet checksum.

/// IPv4 header length with no options.
pub const IPV4_HEADER_LENGTH: usize = 20;
/// EtherType for IPv4.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// IP protocol number for ICMP.
pub const IP_PROTOCOL_ICMP: u8 = 1;

/// The one's-complement Internet checksum (RFC 1071) over `bytes`.
pub fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut index = 0;
    while index + 1 < bytes.len() {
        sum += u32::from(u16::from_be_bytes([bytes[index], bytes[index + 1]]));
        index += 2;
    }
    if index < bytes.len() {
        sum += u32::from(bytes[index]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Builds a 20-byte IPv4 header (no options) for `payload_length` bytes of
/// `protocol` from `source` to `destination`, with `identification`. The header
/// checksum is computed over the header.
pub fn build_header(
    source: [u8; 4],
    destination: [u8; 4],
    protocol: u8,
    payload_length: u16,
    identification: u16,
) -> [u8; IPV4_HEADER_LENGTH] {
    let mut header = [0u8; IPV4_HEADER_LENGTH];
    header[0] = 0x45; // version 4, IHL 5 (20 bytes)
    header[1] = 0x00; // DSCP/ECN
    let total_length = IPV4_HEADER_LENGTH as u16 + payload_length;
    header[2..4].copy_from_slice(&total_length.to_be_bytes());
    header[4..6].copy_from_slice(&identification.to_be_bytes());
    header[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    header[8] = 64; // TTL
    header[9] = protocol;
    // checksum (10..12) left zero for the computation
    header[12..16].copy_from_slice(&source);
    header[16..20].copy_from_slice(&destination);
    let checksum = internet_checksum(&header);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());
    header
}

/// If `packet` is an IPv4 packet of `protocol` from `expected_source`, returns
/// the offset where its payload begins. Returns `None` otherwise.
pub fn parse_payload_offset(
    packet: &[u8],
    protocol: u8,
    expected_source: [u8; 4],
) -> Option<usize> {
    if packet.len() < IPV4_HEADER_LENGTH {
        return None;
    }
    if packet[0] >> 4 != 4 {
        return None;
    }
    let header_length = ((packet[0] & 0x0F) as usize) * 4;
    if header_length < IPV4_HEADER_LENGTH || packet.len() < header_length {
        return None;
    }
    if packet[9] != protocol {
        return None;
    }
    if packet[12..16] != expected_source {
        return None;
    }
    Some(header_length)
}

#[cfg(test)]
mod tests {
    use super::{build_header, internet_checksum, parse_payload_offset, IP_PROTOCOL_ICMP};

    #[test]
    fn test_internet_checksum_known_vector() {
        // RFC 1071 worked example block sums to checksum 0x432B's complement;
        // here just verify a header checksums to zero when its own field is included.
        let header = build_header([10, 0, 2, 15], [10, 0, 2, 2], IP_PROTOCOL_ICMP, 8, 1);
        // Verifying a header (checksum field included) yields 0.
        assert_eq!(internet_checksum(&header), 0);
    }

    #[test]
    fn test_build_header_fields() {
        let header = build_header([10, 0, 2, 15], [10, 0, 2, 2], IP_PROTOCOL_ICMP, 8, 7);
        assert_eq!(header[0], 0x45);
        assert_eq!(u16::from_be_bytes([header[2], header[3]]), 28); // 20 + 8
        assert_eq!(header[9], IP_PROTOCOL_ICMP);
        assert_eq!(&header[12..16], &[10, 0, 2, 15]);
        assert_eq!(&header[16..20], &[10, 0, 2, 2]);
    }

    #[test]
    fn test_parse_payload_offset() {
        let header = build_header([10, 0, 2, 2], [10, 0, 2, 15], IP_PROTOCOL_ICMP, 8, 1);
        assert_eq!(
            parse_payload_offset(&header, IP_PROTOCOL_ICMP, [10, 0, 2, 2]),
            Some(20)
        );
        // Wrong source / protocol rejected.
        assert_eq!(parse_payload_offset(&header, 6, [10, 0, 2, 2]), None);
        assert_eq!(
            parse_payload_offset(&header, IP_PROTOCOL_ICMP, [1, 2, 3, 4]),
            None
        );
    }
}
