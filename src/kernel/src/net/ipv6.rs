//! Minimal IPv6 + ICMPv6: enough to send a Router Solicitation and recognize a
//! Router Advertisement, proving the IPv6 datapath + NDP over the e1000.

use crate::net::ipv4::internet_checksum;
use crate::net::ETHERNET_HEADER_LENGTH;

/// EtherType for IPv6.
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
/// IPv6 next-header value for ICMPv6.
pub const NEXT_HEADER_ICMPV6: u8 = 58;
/// IPv6 fixed header length.
pub const IPV6_HEADER_LENGTH: usize = 40;

const ICMPV6_TYPE_ROUTER_SOLICITATION: u8 = 133;
const ICMPV6_TYPE_ROUTER_ADVERTISEMENT: u8 = 134;

/// All-routers multicast address ff02::2 and its Ethernet multicast MAC.
const ALL_ROUTERS_IPV6: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
const ALL_ROUTERS_MAC: [u8; 6] = [0x33, 0x33, 0x00, 0x00, 0x00, 0x02];

/// Derives the IPv6 link-local address (fe80::/64 + modified EUI-64) from a MAC.
pub fn link_local_address(mac: [u8; 6]) -> [u8; 16] {
    [
        0xfe, 0x80, 0, 0, 0, 0, 0, 0,
        mac[0] ^ 0x02, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5],
    ]
}

/// Computes the ICMPv6 checksum over the IPv6 pseudo-header + the ICMPv6 message.
fn icmpv6_checksum(source: [u8; 16], destination: [u8; 16], message: &[u8]) -> u16 {
    let mut buffer = [0u8; 40 + 256];
    buffer[0..16].copy_from_slice(&source);
    buffer[16..32].copy_from_slice(&destination);
    buffer[32..36].copy_from_slice(&(message.len() as u32).to_be_bytes());
    buffer[36..39].copy_from_slice(&[0, 0, 0]);
    buffer[39] = NEXT_HEADER_ICMPV6;
    let total = 40 + message.len();
    buffer[40..total].copy_from_slice(message);
    internet_checksum(&buffer[..total])
}

/// Builds a full Ethernet+IPv6+ICMPv6 Router Solicitation frame into `out` from
/// `source_mac` (its link-local address is derived), sent to the all-routers
/// multicast. Returns the frame length.
pub fn build_router_solicitation_frame(source_mac: [u8; 6], out: &mut [u8]) -> usize {
    let source_address = link_local_address(source_mac);

    // ICMPv6 Router Solicitation: type, code, checksum, 4 reserved bytes.
    let mut message = [0u8; 8];
    message[0] = ICMPV6_TYPE_ROUTER_SOLICITATION;
    let checksum = icmpv6_checksum(source_address, ALL_ROUTERS_IPV6, &message);
    message[2..4].copy_from_slice(&checksum.to_be_bytes());

    // Ethernet header.
    out[0..6].copy_from_slice(&ALL_ROUTERS_MAC);
    out[6..12].copy_from_slice(&source_mac);
    out[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());

    // IPv6 header.
    let ip = ETHERNET_HEADER_LENGTH;
    out[ip] = 0x60; // version 6
    out[ip + 1] = 0;
    out[ip + 2] = 0;
    out[ip + 3] = 0;
    out[ip + 4..ip + 6].copy_from_slice(&(message.len() as u16).to_be_bytes());
    out[ip + 6] = NEXT_HEADER_ICMPV6;
    out[ip + 7] = 255; // hop limit (required 255 for NDP)
    out[ip + 8..ip + 24].copy_from_slice(&source_address);
    out[ip + 24..ip + 40].copy_from_slice(&ALL_ROUTERS_IPV6);

    let icmp = ip + IPV6_HEADER_LENGTH;
    out[icmp..icmp + message.len()].copy_from_slice(&message);
    icmp + message.len()
}

/// True if `frame` is an Ethernet/IPv6/ICMPv6 Router Advertisement.
pub fn is_router_advertisement(frame: &[u8]) -> bool {
    is_icmpv6_of_type(frame, ICMPV6_TYPE_ROUTER_ADVERTISEMENT)
}

fn is_icmpv6_of_type(frame: &[u8], icmpv6_type: u8) -> bool {
    if frame.len() < ETHERNET_HEADER_LENGTH + IPV6_HEADER_LENGTH + 1 {
        return false;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != ETHERTYPE_IPV6 {
        return false;
    }
    let ip = ETHERNET_HEADER_LENGTH;
    if frame[ip] >> 4 != 6 {
        return false;
    }
    if frame[ip + 6] != NEXT_HEADER_ICMPV6 {
        return false;
    }
    frame[ip + IPV6_HEADER_LENGTH] == icmpv6_type
}

#[cfg(test)]
mod tests {
    use super::{
        build_router_solicitation_frame, icmpv6_checksum, is_router_advertisement,
        link_local_address, ETHERTYPE_IPV6, NEXT_HEADER_ICMPV6,
    };
    use crate::net::ETHERNET_HEADER_LENGTH;

    const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    #[test]
    fn test_link_local_eui64() {
        let address = link_local_address(MAC);
        assert_eq!(&address[0..2], &[0xfe, 0x80]);
        // U/L bit of the first MAC octet flipped: 0x52 -> 0x50.
        assert_eq!(address[8], 0x50);
        assert_eq!(&address[11..13], &[0xff, 0xfe]);
        assert_eq!(&address[13..16], &[0x12, 0x34, 0x56]);
    }

    #[test]
    fn test_router_solicitation_frame() {
        let mut out = [0u8; 128];
        let length = build_router_solicitation_frame(MAC, &mut out);
        assert_eq!(length, ETHERNET_HEADER_LENGTH + 40 + 8);
        assert_eq!(&out[0..6], &[0x33, 0x33, 0, 0, 0, 2]); // all-routers MAC
        assert_eq!(u16::from_be_bytes([out[12], out[13]]), ETHERTYPE_IPV6);
        assert_eq!(out[ETHERNET_HEADER_LENGTH] >> 4, 6); // IPv6
        assert_eq!(out[ETHERNET_HEADER_LENGTH + 6], NEXT_HEADER_ICMPV6);
        assert_eq!(out[ETHERNET_HEADER_LENGTH + 7], 255); // hop limit
        assert_eq!(out[ETHERNET_HEADER_LENGTH + 40], 133); // RS type
    }

    #[test]
    fn test_recognize_router_advertisement() {
        // Build an RS then flip the type to RA (134) to exercise the matcher.
        let mut out = [0u8; 128];
        build_router_solicitation_frame(MAC, &mut out);
        assert!(!is_router_advertisement(&out)); // it's an RS (133)
        out[ETHERNET_HEADER_LENGTH + 40] = 134;
        assert!(is_router_advertisement(&out));
    }

    #[test]
    fn test_icmpv6_checksum_nonzero() {
        let message = [133u8, 0, 0, 0, 0, 0, 0, 0];
        let checksum = icmpv6_checksum(link_local_address(MAC), [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2], &message);
        assert_ne!(checksum, 0);
    }
}
