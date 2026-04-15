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

/// Parses the Ethernet frame header from a raw byte slice.
///
/// Returns a ParsedEthernetFrame on success, or an EthernetParseError if
/// the frame is too short or carries an unsupported EtherType.
///
/// Verified by: fuzz_linkd_ingress_with_adversarial_ethernet_frames
pub fn parse_ethernet_frame(
    _frame_bytes: &[u8],
) -> Result<ParsedEthernetFrame, EthernetParseError> {
    todo!("Phase 9: Ethernet parsing")
}
