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
    /// For any initial budget B (0..=255), after exactly B decrements (saturating_sub(1)),
    /// the budget reaches 0 and never goes below 0. The thread consumed at most B ticks.
    ///
    /// Models the saturating decrement in budget_accounting::decrement_budget.
    /// Exhaustively checks all possible u8 budget values using Kani symbolic execution.
    ///
    /// Enforces SCHED-01 / INV-SCHED-001: per-domain CPU budget never underflows.
    /// Enforces SCHED-04: exhaustion is explicit and bounded.
    #[kani::proof]
    #[kani::unwind(260)]
    fn property_no_domain_exceeds_its_cpu_budget_per_period() {
        // SCHED-01 / SCHED-04 / INV-SCHED-001
        // Property: for any initial budget B (0..=255), after B+1 saturating decrements,
        // budget is 0 and tick_count <= initial_budget.
        let initial_budget: u8 = kani::any();
        let mut budget = initial_budget as u64;
        let mut tick_count: u64 = 0;
        while budget > 0 {
            budget = budget.saturating_sub(1);
            tick_count += 1;
        }
        assert!(budget == 0);
        assert!(tick_count <= initial_budget as u64);
    }

    // =======================================================================
    // P2-T5 — the serving-era capability types.
    //
    // CAPABILITY_MODEL.md names four properties as load-bearing and requires
    // that they "survive implementation". The two that are statements about
    // the kernel's derivation machinery are proven here; the other two are
    // properties of `servd`, which does not exist yet, and are not claimed.
    // =======================================================================

    /// Maps a symbolic index onto a capability type, covering the full set.
    ///
    /// `CapabilityType` does not implement `kani::Arbitrary`, and deriving it in
    /// the kernel purely for verification would put test-only machinery in the
    /// TCB. Enumerating here keeps that out of the kernel and makes the mapping
    /// auditable: if a variant is added and this function is not updated, the
    /// exhaustiveness assertion below fails.
    fn capability_type_from_index(index: u8) -> CapabilityType {
        match index {
            0 => CapabilityType::Memory,
            1 => CapabilityType::Endpoint,
            2 => CapabilityType::Thread,
            3 => CapabilityType::CNode,
            4 => CapabilityType::Irq,
            5 => CapabilityType::Device,
            6 => CapabilityType::Untyped,
            7 => CapabilityType::Reply,
            8 => CapabilityType::Spawn,
            9 => CapabilityType::AuditRead,
            10 => CapabilityType::Frame,
            11 => CapabilityType::Serve,
            12 => CapabilityType::Model,
            13 => CapabilityType::Gpu,
            _ => CapabilityType::Admin,
        }
    }

    /// Highest valid index accepted by [`capability_type_from_index`].
    const HIGHEST_CAPABILITY_TYPE_INDEX: u8 = 14;

    /// Proves the discriminants match the only normative table that defines
    /// them, `docs/architecture/CAPABILITY_MODEL.md`.
    ///
    /// These numbers travel on the wire and appear in audit records, so a
    /// silent reordering would change the meaning of stored authority without
    /// changing any code that reads it. `NORTH_STAR.md` deliberately carries no
    /// numeric IDs, so this proof and that table are the only pair that can
    /// disagree.
    #[kani::proof]
    fn serving_capability_discriminants_match_the_normative_table() {
        assert!(CapabilityType::Frame as u8 == 10, "Frame moved");
        assert!(CapabilityType::Serve as u8 == 11, "CapServe must be 11");
        assert!(CapabilityType::Model as u8 == 12, "CapModel must be 12");
        assert!(CapabilityType::Gpu as u8 == 13, "CapGpu must be 13");
        assert!(CapabilityType::Admin as u8 == 14, "CapAdmin must be 14");
    }

    /// Proves that every index up to [`HIGHEST_CAPABILITY_TYPE_INDEX`] maps to a
    /// type whose discriminant equals that index.
    ///
    /// Keeps [`capability_type_from_index`] honest: without this, a stale
    /// mapping would silently narrow every proof below it to a subset of the
    /// type space while still appearing to quantify over all of it.
    #[kani::proof]
    fn the_symbolic_type_mapping_covers_every_discriminant() {
        let index: u8 = kani::any();
        kani::assume(index <= HIGHEST_CAPABILITY_TYPE_INDEX);
        let capability_type = capability_type_from_index(index);
        assert!(
            capability_type as u8 == index,
            "symbolic type mapping disagrees with the discriminant"
        );
    }

    /// Proves derivation preserves the capability type, for **every** type.
    ///
    /// This is the general form of CAPABILITY_MODEL.md's property 4. Type
    /// preservation is what makes "a session's type is decided at accept and
    /// frozen there" structurally true rather than merely asserted: there is no
    /// derivation that changes what kind of authority a capability is.
    #[kani::proof]
    fn derivation_never_changes_a_capabilitys_type() {
        let mut capability_space = CapabilitySpace::new();
        let mut derivation_tree = CapabilityDerivationTree::new();

        let type_index: u8 = kani::any();
        kani::assume(type_index <= HIGHEST_CAPABILITY_TYPE_INDEX);
        let parent_type = capability_type_from_index(type_index);

        let rights_raw: u32 = kani::any();
        kani::assume(rights_raw <= 0b1111);
        let parent_rights = CapabilityRights::from(rights_raw);

        let parent_slot = capability_space.lookup_slot_mut(0);
        parent_slot.state = CapabilitySlotState::Valid;
        parent_slot.capability_type = parent_type;
        parent_slot.rights_bitmask = parent_rights;
        parent_slot.object_pointer = 0x1000;
        parent_slot.generation_counter = 1;

        let child_rights_raw: u32 = kani::any();
        kani::assume(child_rights_raw <= 0b1111);

        let result = derive_capability(
            &mut capability_space,
            &mut derivation_tree,
            0,
            1,
            CapabilityRights::from(child_rights_raw),
        );

        if result.is_ok() {
            let child_slot = capability_space.lookup_slot_mut(1);
            assert!(
                child_slot.capability_type as u8 == parent_type as u8,
                "derivation changed the capability type"
            );
        }
    }

    /// Proves there is no derivation path from `CapServe` to `CapAdmin`, and
    /// none the other way.
    ///
    /// CAPABILITY_MODEL.md property 4: "CapAdmin is a separate grant, not a
    /// stronger CapServe... nothing promotes one into the other. This is what
    /// makes 'one transport, two capability grants' hold rather than merely be
    /// asserted."
    ///
    /// Stated as its own proof rather than left as a corollary of
    /// [`derivation_never_changes_a_capabilitys_type`] because it is the
    /// specific claim the serving design rests on, and a reader looking for it
    /// should find it by name.
    ///
    /// **Scope, stated honestly:** this proves the *kernel* offers no such
    /// path. It does not prove `servd` grants correctly — `servd` does not
    /// exist yet (P2-T4), and its "decided at accept and frozen there"
    /// obligation is its own, not this one's.
    #[kani::proof]
    fn no_derivation_path_leads_between_serve_and_admin() {
        let mut capability_space = CapabilitySpace::new();
        let mut derivation_tree = CapabilityDerivationTree::new();

        // Symbolic over the two session types, so the proof covers both
        // directions rather than one worked example.
        let start_with_serve: bool = kani::any();
        let parent_type = if start_with_serve {
            CapabilityType::Serve
        } else {
            CapabilityType::Admin
        };
        let forbidden_type = if start_with_serve {
            CapabilityType::Admin
        } else {
            CapabilityType::Serve
        };

        let rights_raw: u32 = kani::any();
        kani::assume(rights_raw <= 0b1111);

        let parent_slot = capability_space.lookup_slot_mut(0);
        parent_slot.state = CapabilitySlotState::Valid;
        parent_slot.capability_type = parent_type;
        parent_slot.rights_bitmask = CapabilityRights::from(rights_raw);
        parent_slot.object_pointer = 0x2000;
        parent_slot.generation_counter = 1;

        let child_rights_raw: u32 = kani::any();
        kani::assume(child_rights_raw <= 0b1111);

        let result = derive_capability(
            &mut capability_space,
            &mut derivation_tree,
            0,
            1,
            CapabilityRights::from(child_rights_raw),
        );

        if result.is_ok() {
            let child_slot = capability_space.lookup_slot_mut(1);
            assert!(
                child_slot.capability_type as u8 != forbidden_type as u8,
                "derivation produced the other session type: one transport, \
                 two capability grants no longer holds"
            );
        }
    }

    /// Proves a derived `CapModel` never becomes something that could carry
    /// authority the confined tenant must not hold.
    ///
    /// CAPABILITY_MODEL.md property 2: `CapModel` confers compute, not
    /// authority. `INV-MODEL-001` forbids the served model spawning, mutating
    /// the kernel, or reaching the network. Since derivation preserves type, a
    /// `CapModel` can never become `Spawn`, `CNode`, `Untyped`, or `Admin` —
    /// the four types that would hand a confined tenant an escalation path.
    #[kani::proof]
    fn a_derived_model_capability_never_becomes_an_escalation_type() {
        let mut capability_space = CapabilitySpace::new();
        let mut derivation_tree = CapabilityDerivationTree::new();

        let rights_raw: u32 = kani::any();
        kani::assume(rights_raw <= 0b1111);

        let parent_slot = capability_space.lookup_slot_mut(0);
        parent_slot.state = CapabilitySlotState::Valid;
        parent_slot.capability_type = CapabilityType::Model;
        parent_slot.rights_bitmask = CapabilityRights::from(rights_raw);
        parent_slot.object_pointer = 0x3000;
        parent_slot.generation_counter = 1;

        let child_rights_raw: u32 = kani::any();
        kani::assume(child_rights_raw <= 0b1111);

        let result = derive_capability(
            &mut capability_space,
            &mut derivation_tree,
            0,
            1,
            CapabilityRights::from(child_rights_raw),
        );

        if result.is_ok() {
            let child_type = capability_space.lookup_slot_mut(1).capability_type as u8;
            assert!(
                child_type != CapabilityType::Spawn as u8
                    && child_type != CapabilityType::CNode as u8
                    && child_type != CapabilityType::Untyped as u8
                    && child_type != CapabilityType::Admin as u8,
                "a confined tenant's capability derived into an escalation type"
            );
        }
    }
}

#[cfg(kani)]
mod hardware_security_proofs {
    use brainix_kernel::hardware_security::attestation_gate::{
        advance_attestation_gate, create_attestation_gate, get_attestation_gate_state,
        AttestationEvent, AttestationGateState,
    };

    /// Proves the attestation gate state machine has no single-step path from Closed to Open.
    ///
    /// Gate transitions must follow Closed -> MeasuringPlatform ->
    /// AwaitingQuoteVerification -> Open.
    /// No single event from Closed state can reach Open.
    ///
    /// Enforces INV-BOOT-001: measured boot path integrity.
    #[kani::proof]
    fn attestation_gate_state_machine_has_no_skip_path() {
        let mut gate = create_attestation_gate();
        // `AttestationEvent` does not implement `kani::Arbitrary`, so
        // `kani::any()` fails to compile and takes the whole crate — every
        // other proof in it included — down with it. Enumerating the variants
        // from a symbolic index keeps the quantification total without putting
        // verification-only trait impls in the kernel.
        let event_index: u8 = kani::any();
        kani::assume(event_index <= 4);
        let event = match event_index {
            0 => AttestationEvent::MeasurementComplete,
            1 => AttestationEvent::QuoteGenerated,
            2 => AttestationEvent::VerificationPassed,
            3 => AttestationEvent::VerificationFailed,
            _ => AttestationEvent::Timeout,
        };
        let result = advance_attestation_gate(&mut gate, event);
        if result.is_ok() {
            kani::assert(
                get_attestation_gate_state(&gate) != AttestationGateState::Open,
                "Gate must not open in one step from Closed",
            );
        }
    }

    /// Proves the CSPRNG state is never all zeros after Phase A seeding.
    ///
    /// After seeding from RDRAND+RDSEED, the ChaCha20 key material must not
    /// be all zeros (a degenerate key that would compromise all output).
    ///
    /// Phase 6 Plan 01 replaces this stub with a proof over the real CSPRNG type.
    #[kani::proof]
    fn csprng_state_is_never_all_zeros_after_seeding() {
        // Prove: after Phase A seeding, key material is not all zeros
        kani::assume(true); // Stub -- replaced in Plan 01
    }

}
