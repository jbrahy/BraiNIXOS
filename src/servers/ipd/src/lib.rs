#![no_std]
#![deny(unsafe_code)]

//! ipd: Isolated network-layer server for Phase 9 network stack decomposition.
//!
//! Receives Ethernet payloads from linkd via IPC, parses IPv4 headers, and
//! forwards transport-layer payloads to transportd. Runs as a ring-3 process
//! with a bounded capability set. No global memory authority.
//!
//! Enforces INV-DEV-002: each network service receives least privilege.

pub mod ipv4;

pub use ipv4::parse_ipv4_header;

/// Network-layer server main loop: receives IPC messages and dispatches to handlers.
///
/// In Phase 9 wave 0 this is a stub. Later waves wire real IPC receive and
/// IPv4 header parsing with forwarding to transportd.
///
/// Enforces INV-DEV-002: server loops only on its assigned endpoint.
pub fn network_server_main_loop() -> ! {
    loop {
        // Phase 9: IPC receive from linkd endpoint
        // Phase 9: parse_ipv4_header on received payload
        // Phase 9: forward to transportd or reply to linkd
        core::hint::spin_loop();
    }
}

/// Forwards a parsed transport-layer payload to transportd via IPC.
///
/// Phase 9 stub — real IPC send to transportd endpoint wired in a later wave.
pub fn forward_packet_to_transport_layer() {
    todo!("Phase 9: IPC send to transportd")
}

/// Forwards a reply payload back to linkd via IPC.
///
/// Phase 9 stub — real IPC send to linkd endpoint wired in a later wave.
pub fn forward_reply_to_link_layer() {
    todo!("Phase 9: IPC send to linkd")
}
