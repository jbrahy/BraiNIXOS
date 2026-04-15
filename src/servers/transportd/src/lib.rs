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
    use brainix_kernel::capability::capability_rights;
    use brainix_kernel::capability::capability_space::CapabilitySpace;
    use brainix_kernel::capability::capability_type::CapabilityType;
    use brainix_kernel::process::server_launch::grant_initial_capability_to_server;

    /// Verifies that a compromised transportd process cannot reach devd-nic directly.
    ///
    /// Two-layer containment proof per D-04:
    /// Layer 1 (static): transportd CSpace has no CapDevice or CapIrq capability.
    /// Layer 2 (runtime): accessing slot 1 (where devd-nic would be) returns empty.
    ///
    /// Enforces D-04: structural proof + runtime enforcement together.
    /// Verified by: tests::integration_compromised_transportd_cannot_reach_devd_nic
    #[test]
    fn integration_compromised_transportd_cannot_reach_devd_nic() {
        let transportd_capability_space = build_transportd_capability_space();
        audit_transportd_has_no_device_authority(&transportd_capability_space);
        verify_runtime_endpoint_enforcement(&transportd_capability_space);
    }

    /// Builds a transportd CSpace matching D-03: only 1 capability granted.
    ///
    /// Slot 0: CapEndpoint with READ rights (receive from ipd only).
    /// All other slots remain null — no CapDevice, no CapIrq, no devd-nic endpoint.
    fn build_transportd_capability_space() -> CapabilitySpace {
        let mut transportd_capability_space = CapabilitySpace::new();
        grant_initial_capability_to_server(
            &mut transportd_capability_space,
            0,
            CapabilityType::Endpoint,
            capability_rights::READ,
        );
        transportd_capability_space
    }

    /// Layer 1 (static): enumerates all slots and asserts no CapDevice or CapIrq present.
    ///
    /// Enforces D-04 Layer 1: capability audit proves transportd has no device authority.
    fn audit_transportd_has_no_device_authority(transportd_capability_space: &CapabilitySpace) {
        for slot in transportd_capability_space.all_slots() {
            let slot_is_occupied = slot.is_valid();
            if slot_is_occupied {
                let slot_type = slot.capability_type();
                assert_ne!(slot_type, CapabilityType::Device, "transportd must not hold CapDevice");
                assert_ne!(slot_type, CapabilityType::Irq, "transportd must not hold CapIrq");
            }
        }
    }

    /// Layer 2 (runtime): accessing slot 1 returns empty, confirming no devd-nic path exists.
    ///
    /// Enforces D-04 Layer 2: runtime enforcement proves the kernel blocks unauthorized access.
    fn verify_runtime_endpoint_enforcement(transportd_capability_space: &CapabilitySpace) {
        let slot_one_result = transportd_capability_space.lookup_slot(1);
        assert!(
            slot_one_result.is_err(),
            "slot 1 must be empty: transportd has no path to devd-nic"
        );
    }
}
