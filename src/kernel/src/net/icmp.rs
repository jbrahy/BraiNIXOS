//! Minimal ICMP: echo request build + echo reply parse (ping).

use crate::net::ipv4::internet_checksum;

/// ICMP echo message length (8-byte header, no payload).
pub const ICMP_ECHO_LENGTH: usize = 8;

const ICMP_TYPE_ECHO_REQUEST: u8 = 8;
const ICMP_TYPE_ECHO_REPLY: u8 = 0;

/// Builds an 8-byte ICMP echo request with the given identifier and sequence.
pub fn build_echo_request(identifier: u16, sequence: u16) -> [u8; ICMP_ECHO_LENGTH] {
    let mut message = [0u8; ICMP_ECHO_LENGTH];
    message[0] = ICMP_TYPE_ECHO_REQUEST;
    message[1] = 0; // code
                    // checksum (2..4) zero for computation
    message[4..6].copy_from_slice(&identifier.to_be_bytes());
    message[6..8].copy_from_slice(&sequence.to_be_bytes());
    let checksum = internet_checksum(&message);
    message[2..4].copy_from_slice(&checksum.to_be_bytes());
    message
}

/// True if `message` is an ICMP echo reply matching `identifier`/`sequence`.
pub fn is_matching_echo_reply(message: &[u8], identifier: u16, sequence: u16) -> bool {
    if message.len() < ICMP_ECHO_LENGTH {
        return false;
    }
    message[0] == ICMP_TYPE_ECHO_REPLY
        && message[4..6] == identifier.to_be_bytes()
        && message[6..8] == sequence.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::{build_echo_request, is_matching_echo_reply, ICMP_TYPE_ECHO_REPLY};
    use crate::net::ipv4::internet_checksum;

    #[test]
    fn test_echo_request_checksums_to_zero() {
        let request = build_echo_request(0x1234, 1);
        assert_eq!(request[0], 8);
        assert_eq!(internet_checksum(&request), 0);
    }

    #[test]
    fn test_matching_echo_reply() {
        // Synthesize a reply: type 0, same id/seq.
        let mut reply = build_echo_request(0xABCD, 5);
        reply[0] = ICMP_TYPE_ECHO_REPLY;
        assert!(is_matching_echo_reply(&reply, 0xABCD, 5));
        assert!(!is_matching_echo_reply(&reply, 0xABCD, 6));
        assert!(!is_matching_echo_reply(&reply, 0x0000, 5));
    }
}
