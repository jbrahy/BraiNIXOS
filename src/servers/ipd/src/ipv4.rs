//! IPv4 header parsing for Phase 9 network stack decomposition.
//!
//! Parses IPv4 headers from raw byte slices and returns a typed view of the
//! addressing and protocol fields. No heap allocation — all results are
//! stack-resident value types.

/// Minimum length in bytes of an IPv4 header (no options).
pub const IPV4_MINIMUM_HEADER_LENGTH: usize = 20;

/// IP protocol number for ICMP.
pub const IP_PROTOCOL_ICMP: u8 = 1;

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
pub fn parse_ipv4_header(_packet_bytes: &[u8]) -> Result<ParsedIpv4Header, Ipv4ParseError> {
    todo!("Phase 9: IPv4 parsing")
}
