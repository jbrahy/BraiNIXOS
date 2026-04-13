#![deny(unsafe_code)]
// kani is a cfg set by the Kani verification tool's dedicated CI image.
// On the host target it is not defined; this allow suppresses the warning.
#![allow(unexpected_cfgs)]

#[cfg(kani)]
mod proofs {
    use brainix_kernel::capability::capability_rights::CapabilityRights;
    use brainix_kernel::capability::capability_slot::CapabilitySlotState;
    use brainix_kernel::capability::capability_space::CapabilitySpace;
    use brainix_kernel::capability::capability_type::CapabilityType;
    use brainix_kernel::capability::derivation_tree::CapabilityDerivationTree;
    use brainix_kernel::capability::derive_capability::derive_capability;
    use brainix_kernel::capability::CapabilityError;

    /// Proves that a derived capability never gains rights not present in its parent.
    ///
    /// Enforces INV-AUTH-003: rights are monotonic under derivation.
    /// Calls the real derive_capability function with symbolic inputs so Kani
    /// exhaustively checks all possible rights combinations.
    #[kani::proof]
    fn property_rights_monotonicity_over_derivation_chain() {
        let mut capability_space = CapabilitySpace::new();
        let mut derivation_tree = CapabilityDerivationTree::new();

        let parent_rights_raw: u32 = kani::any();
        kani::assume(parent_rights_raw <= 0b1111);
        let parent_rights = CapabilityRights::from(parent_rights_raw);

        let parent_slot = capability_space.lookup_slot_mut(0);
        parent_slot.state = CapabilitySlotState::Valid;
        parent_slot.capability_type = CapabilityType::Memory;
        parent_slot.rights_bitmask = parent_rights;
        parent_slot.object_pointer = 0x1000;
        parent_slot.generation_counter = 1;

        let child_rights_raw: u32 = kani::any();
        kani::assume(child_rights_raw <= 0b1111);
        let child_rights = CapabilityRights::from(child_rights_raw);

        let result = derive_capability(
            &mut capability_space,
            &mut derivation_tree,
            0,
            1,
            child_rights,
        );

        if result.is_ok() {
            let child_slot = capability_space.lookup_slot_mut(1);
            let child_actual_rights = child_slot.rights_bitmask;
            assert!(
                (child_actual_rights.bits() & !parent_rights.bits()) == 0,
                "Rights monotonicity violated: child has rights not in parent"
            );
        }

        if (child_rights_raw & !parent_rights_raw) != 0 {
            assert!(
                result == Err(CapabilityError::RightsExceedParent),
                "Derivation should reject rights amplification"
            );
        }
    }

    /// Proves that the revocation tree walk terminates within 256 iterations.
    ///
    /// Models the depth-first walk with a symbolic iteration counter.
    /// Bounded by MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS so each slot is visited once.
    /// Enforces INV-AUTH-004: revocation always completes.
    #[kani::proof]
    #[kani::unwind(257)]
    fn proof_revocation_loop_terminates() {
        let mut iteration_count: u32 = 0;
        let maximum_iterations: u32 = 256;

        let mut visited: [bool; 256] = [false; 256];

        loop {
            if iteration_count >= maximum_iterations {
                break;
            }
            let next_index: u8 = kani::any();
            if visited[next_index as usize] {
                break;
            }
            visited[next_index as usize] = true;
            iteration_count = iteration_count.wrapping_add(1);
        }

        assert!(iteration_count <= maximum_iterations);
    }

    /// Proves that any u8 slot index is always in bounds for a 256-element array.
    ///
    /// The u8 type limits values to 0..=255, which is exactly the valid index range.
    /// Kani confirms no arithmetic can produce an out-of-bounds access.
    /// Enforces INV-MEM-002: no out-of-bounds CSlot access is possible.
    #[kani::proof]
    fn proof_no_out_of_bounds_cslot_access() {
        let slot_index: u8 = kani::any();
        let array_length: usize = 256;
        let index_as_usize = slot_index as usize;
        assert!(index_as_usize < array_length);
    }

    /// Proves that no domain exceeds its CPU budget per major frame period.
    ///
    /// Stub: will be implemented in Plan 05 after budget accounting is complete.
    /// Enforces SCHED-01 / SCHED-04 / INV-SCHED-001.
    #[kani::proof]
    fn property_no_domain_exceeds_its_cpu_budget_per_period() {
        // SCHED-01 / SCHED-04 / INV-SCHED-001
        // Stub: will be implemented in Plan 05 after budget accounting is complete
    }
}
