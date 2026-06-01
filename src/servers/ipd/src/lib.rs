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
/// This function is a documented no-op stub. Real IPC forwarding requires
/// a `syscall_ipc_send` wrapper in `brainix-libsyscall` which does not yet
/// exist; until that wrapper lands (tracked separately), this function
/// intentionally does nothing when invoked. Fails closed: no traffic leaves
/// ipd through this path, which is strictly safe.
///
/// Enforces INV-DEV-002: network servers hold least privilege. The future
/// real implementation will send via a capability-mediated synchronous IPC
/// to transportd's registered endpoint — no ambient authority.
pub fn forward_packet_to_transport_layer() {}

/// Forwards a reply payload back to linkd via IPC.
///
/// Documented no-op stub; see `forward_packet_to_transport_layer` for the
/// full rationale. Real IPC wrapper in libsyscall is the blocker.
pub fn forward_reply_to_link_layer() {}
