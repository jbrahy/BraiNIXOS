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
    /// Verifies that a packet traverses the full network stack without error.
    ///
    /// Phase 9 wave 0 stub — wired in a later wave once all servers are implemented.
    #[test]
    fn integration_packet_traverses_full_network_stack() {
        todo!("Phase 9: end-to-end packet traversal")
    }
}
