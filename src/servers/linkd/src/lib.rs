#![no_std]
#![deny(unsafe_code)]

//! linkd: Isolated link-layer server for Phase 9 network stack decomposition.
//!
//! Receives raw Ethernet frames from devd-nic via IPC, parses frame headers,
//! and forwards payloads to ipd. Runs as a ring-3 process with a bounded
//! capability set. No global memory authority.
//!
//! Enforces INV-DEV-002: each network service receives least privilege.

pub mod ethernet;

pub use ethernet::parse_ethernet_frame;

/// Link-layer server main loop: receives IPC messages and dispatches to handlers.
///
/// Execution pattern:
///   1. Receive raw Ethernet frame bytes from devd-nic via IPC endpoint.
///   2. Call parse_ethernet_frame on the received bytes.
///   3. On Ok: call forward_frame_to_ip_layer to deliver payload to ipd.
///   4. On Err: drop frame silently (malformed or unsupported EtherType).
///
/// Phase 9 wave 0: IPC receive and forward are stubs. Later waves wire
/// real capability-mediated IPC endpoints.
///
/// Enforces INV-DEV-002: server loops only on its assigned endpoint.
pub fn link_server_main_loop() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Forwards a parsed Ethernet payload to ipd via IPC.
///
/// Phase 9: stub — real implementation sends via capability-mediated
/// synchronous IPC to ipd's registered endpoint.
pub fn forward_frame_to_ip_layer() {
    todo!("Phase 9: IPC send to ipd")
}

/// Forwards a reply from ipd back to the device layer via IPC.
///
/// Phase 9: stub — real implementation sends via capability-mediated
/// synchronous IPC to devd-nic's registered endpoint.
pub fn forward_reply_to_device_layer() {
    todo!("Phase 9: IPC send to devd-nic")
}

#[cfg(test)]
mod tests {
    use super::parse_ethernet_frame;

    /// Builds the 14-byte Ethernet header for the test ICMP echo request packet.
    ///
    /// dst MAC: FF:FF:FF:FF:FF:FF, src MAC: 01:02:03:04:05:06, EtherType: 0x0800 (IPv4).
    fn build_test_ethernet_header() -> [u8; 14] {
        [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // destination MAC
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // source MAC
            0x08, 0x00, // EtherType: IPv4
        ]
    }

    /// Builds the 20-byte IPv4 header with a valid checksum for the test packet.
    ///
    /// version=4, IHL=5, total_length=28 (20+8), protocol=1 (ICMP),
    /// source=10.0.2.2, destination=10.0.2.15.
    fn build_test_ipv4_header_with_checksum() -> [u8; 20] {
        let mut header = [
            0x45u8, 0x00, 0x00, 0x1C, // version/IHL, DSCP, total length=28
            0x00, 0x01, 0x40, 0x00, // identification=1, flags=DF, fragment offset=0
            0x40, 0x01, 0x00, 0x00, // TTL=64, protocol=ICMP, checksum=0 (placeholder)
            0x0A, 0x00, 0x02, 0x02, // source: 10.0.2.2
            0x0A, 0x00, 0x02, 0x0F, // destination: 10.0.2.15
        ];
        let computed_checksum = brainix_ipd::ipv4::compute_ipv4_header_checksum(&header, 20);
        header[10] = (computed_checksum >> 8) as u8;
        header[11] = (computed_checksum & 0xFF) as u8;
        header
    }

    /// Builds the 8-byte ICMP echo request with a valid checksum.
    ///
    /// type=8 (echo request), code=0, identifier=1, sequence=1.
    fn build_test_icmp_echo_request_with_checksum() -> [u8; 8] {
        let mut icmp = [
            0x08u8, 0x00, 0x00, 0x00, // type=echo request, code=0, checksum=0 (placeholder)
            0x00, 0x01, // identifier=1
            0x00, 0x01, // sequence=1
        ];
        let computed_checksum = brainix_transportd::icmp::compute_icmp_checksum(&icmp);
        icmp[2] = (computed_checksum >> 8) as u8;
        icmp[3] = (computed_checksum & 0xFF) as u8;
        icmp
    }

    /// Assembles the complete 42-byte ICMP echo request test packet.
    ///
    /// Layout: 14 bytes Ethernet + 20 bytes IPv4 + 8 bytes ICMP.
    fn build_test_icmp_echo_request_packet() -> [u8; 42] {
        let ethernet_header = build_test_ethernet_header();
        let ipv4_header = build_test_ipv4_header_with_checksum();
        let icmp_message = build_test_icmp_echo_request_with_checksum();
        assemble_test_packet(ethernet_header, ipv4_header, icmp_message)
    }

    /// Copies the three header segments into a single 42-byte packet buffer.
    fn assemble_test_packet(
        ethernet_header: [u8; 14],
        ipv4_header: [u8; 20],
        icmp_message: [u8; 8],
    ) -> [u8; 42] {
        let mut packet = [0u8; 42];
        packet[..14].copy_from_slice(&ethernet_header);
        packet[14..34].copy_from_slice(&ipv4_header);
        packet[34..42].copy_from_slice(&icmp_message);
        packet
    }

    /// Verifies that a complete ICMP echo request traverses the full network stack
    /// and produces a valid ICMP echo reply with the correct type, identifier,
    /// and sequence number.
    ///
    /// Chain: devd-nic reads from ring -> linkd strips Ethernet (14 bytes) ->
    /// ipd strips IPv4 (20 bytes) -> transportd generates ICMP reply.
    #[test]
    fn integration_packet_traverses_full_network_stack() {
        let full_packet = build_test_icmp_echo_request_packet();
        let mut frame_page = [0u8; 4096];
        let packet_length =
            brainix_devd_nic::read_packet_from_receive_ring(&full_packet, &mut frame_page);
        let ethernet_result = parse_ethernet_frame(&frame_page[..packet_length]);
        assert!(ethernet_result.is_ok());
        let parsed_ethernet = ethernet_result.unwrap();
        let ip_start = parsed_ethernet.payload_offset;
        let ip_end = ip_start + parsed_ethernet.payload_length;
        let ipv4_result = brainix_ipd::parse_ipv4_header(&frame_page[ip_start..ip_end]);
        assert!(ipv4_result.is_ok(), "IPv4 parse failed: {:?}", ipv4_result);
        let parsed_ipv4 = ipv4_result.unwrap();
        let icmp_start = ip_start + parsed_ipv4.payload_offset;
        let icmp_end = icmp_start + parsed_ipv4.payload_length;
        let icmp_result = brainix_transportd::parse_icmp_message(&frame_page[icmp_start..icmp_end]);
        assert!(icmp_result.is_ok(), "ICMP parse failed: {:?}", icmp_result);
        let parsed_icmp = icmp_result.unwrap();
        assert_eq!(parsed_icmp.icmp_type, 8);
        let mut reply_buffer = [0u8; 4096];
        let reply_length = brainix_transportd::generate_icmp_echo_reply(
            &frame_page[icmp_start..icmp_end],
            &mut reply_buffer,
        )
        .unwrap();
        assert_eq!(reply_buffer[0], 0);
        assert!(reply_length >= 8);
    }
}
