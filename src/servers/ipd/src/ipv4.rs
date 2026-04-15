//! IPv4 header parsing for Phase 9 network stack decomposition.
//!
//! Parses IPv4 headers from raw byte slices and returns a typed view of the
//! addressing and protocol fields. No heap allocation — all results are
//! stack-resident value types.

/// Minimum length in bytes of an IPv4 header (no options).
pub const IPV4_MINIMUM_HEADER_LENGTH: usize = 20;

/// IP protocol number for ICMP.
pub const IP_PROTOCOL_ICMP: u8 = 1;

/// IPv4 version number.
pub const IPV4_VERSION: u8 = 4;

/// Parsed view of an IPv4 header.
///
/// Carries the fields required for transport-layer dispatch: source address,
/// destination address, protocol number, and payload location.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ParsedIpv4Header {
    /// Source IPv4 address in network byte order.
    pub source_address: u32,
    /// Destination IPv4 address in network byte order.
    pub destination_address: u32,
    /// IP protocol number identifying the transport-layer protocol.
    pub protocol: u8,
    /// Byte offset from the start of the packet where the payload begins.
    pub payload_offset: usize,
    /// Length in bytes of the transport-layer payload.
    pub payload_length: usize,
}

/// Errors returned when IPv4 header parsing fails.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Ipv4ParseError {
    /// The packet is shorter than the minimum IPv4 header length.
    TooShort,
    /// The IPv4 header checksum does not match the computed value.
    InvalidChecksum,
    /// The protocol field does not identify a supported transport protocol.
    UnsupportedProtocol,
}

/// Parses the IPv4 header from a raw byte slice.
///
/// Returns a ParsedIpv4Header on success, or an Ipv4ParseError if the
/// packet is too short, has an invalid checksum, or carries an unsupported
/// transport protocol.
///
/// Verified by: fuzz_ipd_ingress_with_adversarial_ip_packets
pub fn parse_ipv4_header(packet_bytes: &[u8]) -> Result<ParsedIpv4Header, Ipv4ParseError> {
    validate_minimum_ipv4_length(packet_bytes)?;
    let header_length = extract_header_length_in_bytes(packet_bytes);
    validate_ipv4_header_checksum(packet_bytes, header_length)?;
    let protocol = extract_protocol_field(packet_bytes);
    validate_protocol_is_icmp(protocol)?;
    build_parsed_ipv4_header(packet_bytes, header_length, protocol)
}

/// Returns Err(TooShort) if the packet is shorter than the minimum IPv4 header length.
fn validate_minimum_ipv4_length(packet_bytes: &[u8]) -> Result<(), Ipv4ParseError> {
    if packet_bytes.len() < IPV4_MINIMUM_HEADER_LENGTH {
        return Err(Ipv4ParseError::TooShort);
    }
    Ok(())
}

/// Extracts the Internet Header Length field and converts it to bytes.
fn extract_header_length_in_bytes(packet_bytes: &[u8]) -> usize {
    let internet_header_length_in_words = (packet_bytes[0] & 0x0F) as usize;
    internet_header_length_in_words * 4
}

/// Returns Err(InvalidChecksum) if the IPv4 header checksum is not valid.
fn validate_ipv4_header_checksum(
    packet_bytes: &[u8],
    header_length: usize,
) -> Result<(), Ipv4ParseError> {
    let checksum_result = compute_ipv4_header_checksum(packet_bytes, header_length);
    if checksum_result != 0 {
        return Err(Ipv4ParseError::InvalidChecksum);
    }
    Ok(())
}

/// Computes the one's complement checksum over the IPv4 header words.
///
/// For a valid header (checksum field correctly set), this returns 0.
/// Used both for validation and for constructing test headers.
pub fn compute_ipv4_header_checksum(header_bytes: &[u8], header_length: usize) -> u16 {
    let mut accumulator: u32 = 0;
    let mut word_index = 0;
    while word_index < header_length {
        let high_byte = u16::from(header_bytes[word_index]);
        let low_byte = u16::from(header_bytes[word_index + 1]);
        let word = (high_byte << 8) | low_byte;
        accumulator += u32::from(word);
        word_index += 2;
    }
    while accumulator > 0xFFFF {
        accumulator = (accumulator & 0xFFFF) + (accumulator >> 16);
    }
    !(accumulator as u16)
}

/// Extracts the protocol field from byte 9 of the IPv4 header.
fn extract_protocol_field(packet_bytes: &[u8]) -> u8 {
    packet_bytes[9]
}

/// Returns Err(UnsupportedProtocol) if the protocol is not ICMP.
fn validate_protocol_is_icmp(protocol: u8) -> Result<(), Ipv4ParseError> {
    if protocol != IP_PROTOCOL_ICMP {
        return Err(Ipv4ParseError::UnsupportedProtocol);
    }
    Ok(())
}

/// Extracts the source IPv4 address from bytes 12–15 (big-endian).
fn extract_source_address(packet_bytes: &[u8]) -> u32 {
    let byte_a = u32::from(packet_bytes[12]);
    let byte_b = u32::from(packet_bytes[13]);
    let byte_c = u32::from(packet_bytes[14]);
    let byte_d = u32::from(packet_bytes[15]);
    (byte_a << 24) | (byte_b << 16) | (byte_c << 8) | byte_d
}

/// Extracts the destination IPv4 address from bytes 16–19 (big-endian).
fn extract_destination_address(packet_bytes: &[u8]) -> u32 {
    let byte_a = u32::from(packet_bytes[16]);
    let byte_b = u32::from(packet_bytes[17]);
    let byte_c = u32::from(packet_bytes[18]);
    let byte_d = u32::from(packet_bytes[19]);
    (byte_a << 24) | (byte_b << 16) | (byte_c << 8) | byte_d
}

/// Constructs a ParsedIpv4Header from the validated packet fields.
fn build_parsed_ipv4_header(
    packet_bytes: &[u8],
    header_length: usize,
    protocol: u8,
) -> Result<ParsedIpv4Header, Ipv4ParseError> {
    let source_address = extract_source_address(packet_bytes);
    let destination_address = extract_destination_address(packet_bytes);
    let payload_offset = header_length;
    let payload_length = packet_bytes.len() - header_length;
    Ok(ParsedIpv4Header {
        source_address,
        destination_address,
        protocol,
        payload_offset,
        payload_length,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constructs a minimal valid 20-byte IPv4 ICMP packet with correct checksum.
    ///
    /// Header fields:
    ///   - Version=4, IHL=5 (byte 0: 0x45)
    ///   - DSCP/ECN=0 (byte 1: 0x00)
    ///   - Total length=20 (bytes 2-3: 0x00 0x14)
    ///   - Identification=0 (bytes 4-5: 0x00 0x00)
    ///   - Flags/Fragment offset=0 (bytes 6-7: 0x00 0x00)
    ///   - TTL=64 (byte 8: 0x40)
    ///   - Protocol=1 ICMP (byte 9: 0x01)
    ///   - Checksum=0xF4CE (bytes 10-11: computed with checksum=0 first)
    ///   - Source 192.168.1.1 (bytes 12-15: 0xC0 0xA8 0x01 0x01)
    ///   - Destination 10.0.0.1 (bytes 16-19: 0x0A 0x00 0x00 0x01)
    fn build_valid_icmp_ipv4_packet() -> [u8; 20] {
        let mut header = [
            0x45u8, 0x00, 0x00, 0x14, // version/IHL, DSCP, total length
            0x00, 0x00, 0x00, 0x00, // identification, flags/fragment offset
            0x40, 0x01, 0x00, 0x00, // TTL=64, protocol=ICMP, checksum=0 (placeholder)
            0xC0, 0xA8, 0x01, 0x01, // source 192.168.1.1
            0x0A, 0x00, 0x00, 0x01, // destination 10.0.0.1
        ];
        let computed_checksum = compute_ipv4_header_checksum(&header, 20);
        header[10] = (computed_checksum >> 8) as u8;
        header[11] = (computed_checksum & 0xFF) as u8;
        header
    }

    #[test]
    fn packet_shorter_than_20_bytes_returns_too_short() {
        let short_packet = [0u8; 19];
        let parse_result = parse_ipv4_header(&short_packet);
        assert_eq!(parse_result, Err(Ipv4ParseError::TooShort));
    }

    #[test]
    fn empty_packet_returns_too_short() {
        let empty_packet: [u8; 0] = [];
        let parse_result = parse_ipv4_header(&empty_packet);
        assert_eq!(parse_result, Err(Ipv4ParseError::TooShort));
    }

    #[test]
    fn valid_icmp_packet_with_correct_checksum_returns_parsed_header() {
        let valid_packet = build_valid_icmp_ipv4_packet();
        let parse_result = parse_ipv4_header(&valid_packet);
        assert!(parse_result.is_ok());
        let parsed_header = parse_result.unwrap();
        assert_eq!(parsed_header.protocol, IP_PROTOCOL_ICMP);
        assert_eq!(parsed_header.source_address, 0xC0A80101u32);
        assert_eq!(parsed_header.destination_address, 0x0A000001u32);
        assert_eq!(parsed_header.payload_offset, 20);
        assert_eq!(parsed_header.payload_length, 0);
    }

    #[test]
    fn valid_packet_with_incorrect_checksum_returns_invalid_checksum() {
        let mut corrupted_packet = build_valid_icmp_ipv4_packet();
        corrupted_packet[10] ^= 0xFF;
        let parse_result = parse_ipv4_header(&corrupted_packet);
        assert_eq!(parse_result, Err(Ipv4ParseError::InvalidChecksum));
    }

    #[test]
    fn valid_packet_with_non_icmp_protocol_returns_unsupported_protocol() {
        let mut tcp_packet = build_valid_icmp_ipv4_packet();
        tcp_packet[9] = 0x06; // TCP protocol number
        // Recompute checksum with zero checksum field first
        tcp_packet[10] = 0x00;
        tcp_packet[11] = 0x00;
        let new_checksum = compute_ipv4_header_checksum(&tcp_packet, 20);
        tcp_packet[10] = (new_checksum >> 8) as u8;
        tcp_packet[11] = (new_checksum & 0xFF) as u8;
        let parse_result = parse_ipv4_header(&tcp_packet);
        assert_eq!(parse_result, Err(Ipv4ParseError::UnsupportedProtocol));
    }

    #[test]
    fn ihl_of_5_extracts_payload_at_offset_20() {
        let valid_packet = build_valid_icmp_ipv4_packet();
        let parse_result = parse_ipv4_header(&valid_packet).unwrap();
        assert_eq!(parse_result.payload_offset, 20);
    }

    #[test]
    fn compute_checksum_returns_zero_for_valid_header() {
        let valid_packet = build_valid_icmp_ipv4_packet();
        let checksum_validation_result = compute_ipv4_header_checksum(&valid_packet, 20);
        assert_eq!(checksum_validation_result, 0);
    }

    #[test]
    fn ipv4_version_constant_is_four() {
        assert_eq!(IPV4_VERSION, 4);
    }
}
