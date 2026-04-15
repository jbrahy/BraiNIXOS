#![no_std]
#![deny(unsafe_code)]

//! transportd: Isolated transport-layer server for Phase 9 network stack decomposition.
//!
//! Receives IPv4 payloads from ipd via IPC, parses ICMP messages, and generates
//! ICMP echo replies. Runs as a ring-3 process with a bounded capability set.
//! No global memory authority.
//!
//! Enforces INV-DEV-002: each network service receives least privilege.

pub mod icmp;

pub use icmp::generate_icmp_echo_reply;
pub use icmp::parse_icmp_message;

/// Transport-layer server main loop: receives IPC messages and dispatches to handlers.
///
/// In Phase 9 wave 0 this is a stub. Later waves wire real IPC receive and
/// ICMP message handling with echo reply generation.
///
/// Enforces INV-DEV-002: server loops only on its assigned endpoint.
///
/// transportd has ONLY CapEndpoint to ipd — no CapDevice, no CapIrq (D-03).
pub fn transport_server_main_loop() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    /// Verifies that a compromised transportd process cannot reach devd-nic directly.
    ///
    /// Phase 9 wave 0 stub — containment proof wired in a later wave once
    /// capability enforcement for network servers is fully implemented.
    #[test]
    fn integration_compromised_transportd_cannot_reach_devd_nic() {
        todo!("Phase 9: containment proof")
    }
}
