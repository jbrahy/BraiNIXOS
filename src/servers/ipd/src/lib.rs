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
        core::hint::spin_loop();
    }
}
