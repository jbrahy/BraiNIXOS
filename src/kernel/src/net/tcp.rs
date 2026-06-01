//! Minimal TCP over IPv4: build a SYN segment and recognize the peer's
//! SYN-ACK (or RST), enough to prove the TCP datapath and the start of the
//! 3-way handshake.

use crate::net::ipv4::internet_checksum;

/// TCP header length with no options.
pub const TCP_HEADER_LENGTH: usize = 20;
/// IP protocol number for TCP.
pub const IP_PROTOCOL_TCP: u8 = 6;

// TCP flag bits.
const TCP_FLAG_SYN: u8 = 1 << 1;
const TCP_FLAG_RST: u8 = 1 << 2;
const TCP_FLAG_ACK: u8 = 1 << 4;

/// Builds a bare SYN segment (no options) into `out`, with the pseudo-header
/// checksum. Returns the segment length (20).
pub fn build_syn(
    source_ipv4: [u8; 4],
    destination_ipv4: [u8; 4],
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    out: &mut [u8],
) -> usize {
    out[0..2].copy_from_slice(&source_port.to_be_bytes());
    out[2..4].copy_from_slice(&destination_port.to_be_bytes());
    out[4..8].copy_from_slice(&sequence_number.to_be_bytes());
    out[8..12].copy_from_slice(&0u32.to_be_bytes()); // ack number
    out[12] = (5 << 4) | 0; // data offset = 5 words (20 bytes)
    out[13] = TCP_FLAG_SYN;
    out[14..16].copy_from_slice(&64240u16.to_be_bytes()); // window
    out[16..18].copy_from_slice(&[0, 0]); // checksum zero for computation
    out[18..20].copy_from_slice(&[0, 0]); // urgent pointer

    let checksum = tcp_checksum(source_ipv4, destination_ipv4, &out[..TCP_HEADER_LENGTH]);
    out[16..18].copy_from_slice(&checksum.to_be_bytes());
    TCP_HEADER_LENGTH
}

/// TCP checksum over the IPv4 pseudo-header + the TCP segment.
fn tcp_checksum(source_ipv4: [u8; 4], destination_ipv4: [u8; 4], segment: &[u8]) -> u16 {
    let mut buffer = [0u8; 12 + 1500];
    buffer[0..4].copy_from_slice(&source_ipv4);
    buffer[4..8].copy_from_slice(&destination_ipv4);
    buffer[8] = 0;
    buffer[9] = IP_PROTOCOL_TCP;
    buffer[10..12].copy_from_slice(&(segment.len() as u16).to_be_bytes());
    let total = 12 + segment.len();
    buffer[12..total].copy_from_slice(segment);
    internet_checksum(&buffer[..total])
}

/// Classifies a TCP segment that is a response to our SYN on the given ports.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HandshakeResponse {
    /// SYN-ACK: the peer accepted the connection (handshake can complete).
    SynAck,
    /// RST: the peer refused — still proves the TCP datapath round-trip.
    Reset,
    /// Not a recognized response to our SYN.
    Other,
}

/// Classifies `segment` as a response to our SYN, matching the ports.
pub fn classify_handshake_response(
    segment: &[u8],
    expected_source_port: u16,
    expected_destination_port: u16,
) -> HandshakeResponse {
    if segment.len() < TCP_HEADER_LENGTH {
        return HandshakeResponse::Other;
    }
    let source_port = u16::from_be_bytes([segment[0], segment[1]]);
    let destination_port = u16::from_be_bytes([segment[2], segment[3]]);
    if source_port != expected_source_port || destination_port != expected_destination_port {
        return HandshakeResponse::Other;
    }
    let flags = segment[13];
    if flags & TCP_FLAG_RST != 0 {
        return HandshakeResponse::Reset;
    }
    if flags & TCP_FLAG_SYN != 0 && flags & TCP_FLAG_ACK != 0 {
        return HandshakeResponse::SynAck;
    }
    HandshakeResponse::Other
}

#[cfg(test)]
mod tests {
    use super::{build_syn, classify_handshake_response, HandshakeResponse, TCP_HEADER_LENGTH};

    #[test]
    fn test_syn_segment() {
        let mut out = [0u8; 32];
        let length = build_syn([10, 0, 2, 15], [1, 1, 1, 1], 50000, 53, 0x11223344, &mut out);
        assert_eq!(length, TCP_HEADER_LENGTH);
        assert_eq!(u16::from_be_bytes([out[0], out[1]]), 50000);
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), 53);
        assert_eq!(out[13], 0x02); // SYN only
        assert_ne!(u16::from_be_bytes([out[16], out[17]]), 0); // checksum set
    }

    #[test]
    fn test_classify_responses() {
        // Build a SYN, then mutate ports/flags to synthesize peer responses.
        let mut synack = [0u8; TCP_HEADER_LENGTH];
        synack[0..2].copy_from_slice(&53u16.to_be_bytes()); // from server port
        synack[2..4].copy_from_slice(&50000u16.to_be_bytes()); // to our port
        synack[13] = 0x12; // SYN+ACK
        assert_eq!(
            classify_handshake_response(&synack, 53, 50000),
            HandshakeResponse::SynAck
        );
        let mut reset = synack;
        reset[13] = 0x04; // RST
        assert_eq!(
            classify_handshake_response(&reset, 53, 50000),
            HandshakeResponse::Reset
        );
        // Wrong ports -> Other.
        assert_eq!(
            classify_handshake_response(&synack, 99, 50000),
            HandshakeResponse::Other
        );
    }
}
