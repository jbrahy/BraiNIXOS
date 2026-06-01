//! Minimal network protocol helpers — the start of the IPv4/IPv6 stack.
//!
//! This module is pure (no hardware): it builds and parses frames. The e1000
//! driver does the actual transmit/receive. Today it covers ARP (IPv4 address
//! resolution) — enough to prove the NIC's TX+RX path works end-to-end by
//! resolving the gateway's MAC. IPv4/ICMP/UDP/IPv6/TCP build on the same shape.

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
