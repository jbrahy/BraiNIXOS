//! Ethernet frame parsing for Phase 9 network stack decomposition.
//!
//! Parses IEEE 802.3 Ethernet frame headers and returns a typed view of the
//! payload location and EtherType. No heap allocation — all results are
//! stack-resident value types.

/// Length in bytes of a standard Ethernet frame header (destination MAC + source MAC + EtherType).
pub const ETHERNET_HEADER_LENGTH: usize = 14;

/// EtherType value identifying an IPv4 payload.
pub const ETHER_TYPE_IPV4: u16 = 0x0800;

/// Parsed view of an Ethernet frame header.
///
/// Carries only the fields required for forwarding: EtherType, payload start
/// offset, and payload length. MAC addresses are intentionally omitted —
/// linkd does not perform MAC-based routing decisions.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ParsedEthernetFrame {
    /// EtherType field identifying the network-layer protocol of the payload.
    pub ether_type: u16,
    /// Byte offset from the start of the frame where the payload begins.
    pub payload_offset: usize,
    /// Length in bytes of the frame payload.
    pub payload_length: usize,
}

/// Errors returned when Ethernet frame parsing fails.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EthernetParseError {
    /// The frame is shorter than the minimum Ethernet header length.
    TooShort,
    /// The EtherType field does not identify a supported network-layer protocol.
    UnsupportedEtherType,
}

/// Returns Err(TooShort) if the frame byte slice is shorter than the Ethernet header.
///
/// Enforces the minimum frame length required before any field extraction.
fn validate_minimum_ethernet_length(frame_bytes: &[u8]) -> Result<(), EthernetParseError> {
    if frame_bytes.len() < ETHERNET_HEADER_LENGTH {
        return Err(EthernetParseError::TooShort);
    }
    Ok(())
}

/// Extracts the EtherType field from bytes 12 and 13 of the frame header.
///
/// Caller must have already validated that frame_bytes is at least ETHERNET_HEADER_LENGTH bytes.
fn extract_ether_type_from_header(frame_bytes: &[u8]) -> u16 {
    let high_byte = u16::from(frame_bytes[12]);
    let low_byte = u16::from(frame_bytes[13]);
    (high_byte << 8) | low_byte
}

/// Returns Err(UnsupportedEtherType) if the EtherType is not IPv4 (0x0800).
///
/// linkd only forwards IPv4 payloads in Phase 9. All other EtherTypes are rejected.
fn validate_ether_type_is_ipv4(ether_type: u16) -> Result<(), EthernetParseError> {
    if ether_type != ETHER_TYPE_IPV4 {
        return Err(EthernetParseError::UnsupportedEtherType);
    }
    Ok(())
}

/// Computes the payload length by subtracting the header length from the total frame length.
///
/// Caller must have already validated that frame_bytes is at least ETHERNET_HEADER_LENGTH bytes.
fn compute_ethernet_payload_length(frame_bytes: &[u8]) -> usize {
    frame_bytes.len() - ETHERNET_HEADER_LENGTH
}

/// Constructs a ParsedEthernetFrame from the validated EtherType and payload length.
///
/// The payload offset is always ETHERNET_HEADER_LENGTH for standard Ethernet frames.
fn build_parsed_ethernet_frame(ether_type: u16, payload_length: usize) -> ParsedEthernetFrame {
    ParsedEthernetFrame {
        ether_type,
        payload_offset: ETHERNET_HEADER_LENGTH,
        payload_length,
    }
}

/// Parses the Ethernet frame header from a raw byte slice.
///
/// Returns a ParsedEthernetFrame on success, or an EthernetParseError if
/// the frame is too short or carries an unsupported EtherType.
///
/// Verified by: fuzz_linkd_ingress_with_adversarial_ethernet_frames
pub fn parse_ethernet_frame(frame_bytes: &[u8]) -> Result<ParsedEthernetFrame, EthernetParseError> {
    validate_minimum_ethernet_length(frame_bytes)?;
    let ether_type = extract_ether_type_from_header(frame_bytes);
    validate_ether_type_is_ipv4(ether_type)?;
    let payload_length = compute_ethernet_payload_length(frame_bytes);
    Ok(build_parsed_ethernet_frame(ether_type, payload_length))
}

#[cfg(test)]
mod tests {
    use super::{
        EthernetParseError, ParsedEthernetFrame, ETHERNET_HEADER_LENGTH, ETHER_TYPE_IPV4,
        parse_ethernet_frame,
    };

    /// Builds a minimal 14-byte Ethernet frame with EtherType 0x0800 (IPv4) and no payload.
    fn build_minimum_ipv4_frame() -> [u8; ETHERNET_HEADER_LENGTH] {
        let mut frame = [0u8; ETHERNET_HEADER_LENGTH];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame
    }

    /// Builds a 17-byte Ethernet frame with EtherType 0x0800 (IPv4) and 3 payload bytes.
    fn build_ipv4_frame_with_three_payload_bytes() -> [u8; ETHERNET_HEADER_LENGTH + 3] {
        let mut frame = [0u8; ETHERNET_HEADER_LENGTH + 3];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[ETHERNET_HEADER_LENGTH] = 0xAA;
        frame[ETHERNET_HEADER_LENGTH + 1] = 0xBB;
        frame[ETHERNET_HEADER_LENGTH + 2] = 0xCC;
        frame
    }

    #[test]
    fn frame_shorter_than_fourteen_bytes_returns_too_short() {
        let short_frame = [0u8; 13];
        let parse_result = parse_ethernet_frame(&short_frame);
        assert_eq!(parse_result, Err(EthernetParseError::TooShort));
    }

    #[test]
    fn empty_frame_returns_too_short() {
        let empty_frame: &[u8] = &[];
        let parse_result = parse_ethernet_frame(empty_frame);
        assert_eq!(parse_result, Err(EthernetParseError::TooShort));
    }

    #[test]
    fn valid_ipv4_frame_returns_parsed_frame_with_correct_fields() {
        let frame = build_ipv4_frame_with_three_payload_bytes();
        let parse_result = parse_ethernet_frame(&frame);
        let expected = ParsedEthernetFrame {
            ether_type: ETHER_TYPE_IPV4,
            payload_offset: ETHERNET_HEADER_LENGTH,
            payload_length: 3,
        };
        assert_eq!(parse_result, Ok(expected));
    }

    #[test]
    fn frame_with_ipv6_ether_type_returns_unsupported_ether_type() {
        let mut frame = [0u8; ETHERNET_HEADER_LENGTH + 4];
        frame[12] = 0x86;
        frame[13] = 0xDD;
        let parse_result = parse_ethernet_frame(&frame);
        assert_eq!(parse_result, Err(EthernetParseError::UnsupportedEtherType));
    }

    #[test]
    fn frame_with_arp_ether_type_returns_unsupported_ether_type() {
        let mut frame = [0u8; ETHERNET_HEADER_LENGTH + 4];
        frame[12] = 0x08;
        frame[13] = 0x06;
        let parse_result = parse_ethernet_frame(&frame);
        assert_eq!(parse_result, Err(EthernetParseError::UnsupportedEtherType));
    }

    #[test]
    fn minimum_valid_frame_exactly_fourteen_bytes_returns_zero_payload_length() {
        let frame = build_minimum_ipv4_frame();
        let parse_result = parse_ethernet_frame(&frame);
        let expected = ParsedEthernetFrame {
            ether_type: ETHER_TYPE_IPV4,
            payload_offset: ETHERNET_HEADER_LENGTH,
            payload_length: 0,
        };
        assert_eq!(parse_result, Ok(expected));
    }
}
