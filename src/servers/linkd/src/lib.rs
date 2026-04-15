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
/// In Phase 9 wave 0 this is a stub. Later waves wire real IPC receive and
/// Ethernet frame forwarding to ipd.
///
/// Enforces INV-DEV-002: server loops only on its assigned endpoint.
pub fn link_server_main_loop() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    /// Verifies that a packet traverses the full network stack without error.
    ///
    /// Phase 9 wave 0 stub — wired in a later wave once all servers are implemented.
    #[test]
    fn integration_packet_traverses_full_network_stack() {
        todo!("Phase 9: end-to-end packet traversal")
    }
}
