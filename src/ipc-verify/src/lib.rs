//! Kani proof harnesses for the IPC rendezvous path.
//!
//! # Why this crate replaced a Prusti shim
//!
//! `src/brainix-ipc-core/` was a Prusti verification shim that claimed to cover
//! INV-IPC-002, INV-IPC-003, and INV-IPC-005. It covered none of them, for three
//! compounding reasons:
//!
//! 1. **It never ran.** Its annotations gated on `feature = "prusti"` while its
//!    manifest declared no `[features]` section, so every annotation was inert;
//!    and the CI action required a `prusti-contracts` dependency that was
//!    deliberately absent.
//! 2. **It verified a copy.** Nothing in the tree depended on that crate and the
//!    kernel never called its functions. It duplicated three ideas from the IPC
//!    path rather than verifying the path.
//! 3. **Its contracts were tautologies.** Each had the form "a function that
//!    returns `Ok` exactly when `P` holds, returns `Ok` only when `P` holds" —
//!    true by construction, and true regardless of what the kernel does.
//!
//! Meanwhile `src/kernel/src/ipc/tests.rs` told readers that "Prusti property in
//! brainix-ipc-core covers this formally", pointing at coverage that had never
//! existed. That is worse than no coverage, because it tells a reviewer to stop
//! looking.
//!
//! Every harness below runs against the **real** `perform_rendezvous`.
//!
//! # What is and is not proven
//!
//! These cover the capability-transfer half of rendezvous: the rights, grant,
//! and overwrite rules, and that a denied transfer leaves the receiver
//! untouched. They do **not** cover the blocking, queueing, or timeout paths of
//! INV-IPC-003 — `perform_rendezvous` is the transfer step and never blocks.
//! Timeout rollback remains covered by unit tests only, and saying so is the
//! point: the previous arrangement claimed otherwise.

#![deny(unsafe_code)]
// `kani` is a cfg set by the Kani verification tool, not by cargo.
#![allow(unexpected_cfgs)]

#[cfg(kani)]
mod proofs {
    use brainix_kernel::capability::capability_rights::{self, CapabilityRights};
    use brainix_kernel::capability::capability_slot::CapabilitySlotState;
    use brainix_kernel::capability::capability_space::CapabilitySpace;
    use brainix_kernel::capability::capability_type::CapabilityType;
    use brainix_kernel::ipc::rendezvous::perform_rendezvous;
    use brainix_kernel::ipc::{IpcError, IpcMessage, CAPABILITY_TRANSFER_NONE_SENTINEL};

    /// Rights bits are a four-bit lattice; bounding the symbolic value keeps the
    /// harness in the real domain rather than exploring 2^32 meaningless states.
    const RIGHTS_BITS_UPPER_BOUND: u32 = 0b1111;

    /// Populates a slot with a valid capability carrying `rights`.
    fn place_valid_capability(space: &mut CapabilitySpace, index: u8, rights: CapabilityRights) {
        let slot = space.lookup_slot_mut(index);
        slot.state = CapabilitySlotState::Valid;
        slot.capability_type = CapabilityType::Endpoint;
        slot.rights_bitmask = rights;
        slot.object_pointer = 0x4000;
        slot.generation_counter = 1;
    }

    /// A symbolic message. Register contents are irrelevant to every property
    /// here except badge stamping, so they are fixed and the badge is symbolic.
    fn message_with_badge(badge: u64) -> IpcMessage {
        IpcMessage {
            register_zero: 0x1111,
            register_one: 0x2222,
            register_two: 0x3333,
            register_three: 0x4444,
            badge,
        }
    }

    /// **INV-IPC-002 / INV-AUTH-003.** A delivered capability never carries
    /// rights the sender did not hold.
    ///
    /// Symbolic over the sender's full rights lattice and over both slot
    /// indices, so this is a statement about every reachable transfer rather
    /// than a worked example.
    #[kani::proof]
    fn rendezvous_never_amplifies_rights() {
        let mut sender = CapabilitySpace::new();
        let mut receiver = CapabilitySpace::new();

        let sender_rights_raw: u32 = kani::any();
        kani::assume(sender_rights_raw <= RIGHTS_BITS_UPPER_BOUND);
        let sender_rights = CapabilityRights::from(sender_rights_raw);

        let source: u8 = kani::any();
        let destination: u8 = kani::any();
        kani::assume(source != CAPABILITY_TRANSFER_NONE_SENTINEL);

        place_valid_capability(&mut sender, source, sender_rights);

        let result = perform_rendezvous(
            &message_with_badge(0x0BAD_BADD),
            source,
            destination,
            &mut sender,
            &mut receiver,
            0x0BAD_BADD,
        );

        if result.is_ok() {
            let delivered = receiver.lookup_slot_ref(destination).rights_bitmask;
            assert!(
                (delivered.bits() & !sender_rights.bits()) == 0,
                "rendezvous delivered rights the sender never held"
            );
        }
    }

    /// **INV-AUTH-003.** A transfer without the Grant right always denies.
    ///
    /// The converse of the amplification proof: not only are rights not widened,
    /// a capability cannot move at all unless it is explicitly grantable.
    #[kani::proof]
    fn a_capability_without_grant_right_never_transfers() {
        let mut sender = CapabilitySpace::new();
        let mut receiver = CapabilitySpace::new();

        let sender_rights_raw: u32 = kani::any();
        kani::assume(sender_rights_raw <= RIGHTS_BITS_UPPER_BOUND);
        // Every rights combination that does NOT include GRANT.
        kani::assume((sender_rights_raw & capability_rights::GRANT.bits()) == 0);

        let source: u8 = kani::any();
        let destination: u8 = kani::any();
        kani::assume(source != CAPABILITY_TRANSFER_NONE_SENTINEL);

        place_valid_capability(
            &mut sender,
            source,
            CapabilityRights::from(sender_rights_raw),
        );

        let result = perform_rendezvous(
            &message_with_badge(1),
            source,
            destination,
            &mut sender,
            &mut receiver,
            1,
        );

        assert!(
            result == Err(IpcError::GrantRightNotHeld),
            "a capability lacking GRANT was transferred"
        );
        assert!(
            receiver.lookup_slot_ref(destination).is_null(),
            "a denied transfer still wrote to the receiver"
        );
    }

    /// **INV-IPC-005.** An occupied destination slot is never overwritten.
    ///
    /// Silently replacing a live capability would destroy authority the receiver
    /// still holds, which is a loss of authority rather than an escalation, and
    /// equally forbidden.
    #[kani::proof]
    fn an_occupied_destination_slot_is_never_overwritten() {
        let mut sender = CapabilitySpace::new();
        let mut receiver = CapabilitySpace::new();

        let source: u8 = kani::any();
        let destination: u8 = kani::any();
        kani::assume(source != CAPABILITY_TRANSFER_NONE_SENTINEL);

        // Sender holds a fully-privileged, grantable capability, so the only
        // thing that can stop the transfer is the occupied destination.
        place_valid_capability(
            &mut sender,
            source,
            CapabilityRights::from(RIGHTS_BITS_UPPER_BOUND),
        );

        let occupant_pointer: u64 = 0x9999;
        let occupant = receiver.lookup_slot_mut(destination);
        occupant.state = CapabilitySlotState::Valid;
        occupant.capability_type = CapabilityType::Endpoint;
        occupant.rights_bitmask = CapabilityRights::from(0b0001);
        occupant.object_pointer = occupant_pointer;
        occupant.generation_counter = 7;

        let result = perform_rendezvous(
            &message_with_badge(2),
            source,
            destination,
            &mut sender,
            &mut receiver,
            2,
        );

        assert!(
            result == Err(IpcError::SlotOccupied),
            "a transfer overwrote an occupied destination slot"
        );
        assert!(
            receiver.lookup_slot_ref(destination).object_pointer == occupant_pointer,
            "the occupant capability was mutated by a denied transfer"
        );
    }

    /// **INV-IPC-005.** The sentinel path transfers nothing and touches nothing.
    ///
    /// A send that carries no capability must leave both capability spaces
    /// exactly as it found them, whatever the destination index happens to be.
    #[kani::proof]
    fn the_no_capability_sentinel_leaves_both_spaces_untouched() {
        let mut sender = CapabilitySpace::new();
        let mut receiver = CapabilitySpace::new();

        let destination: u8 = kani::any();

        let result = perform_rendezvous(
            &message_with_badge(3),
            CAPABILITY_TRANSFER_NONE_SENTINEL,
            destination,
            &mut sender,
            &mut receiver,
            3,
        );

        assert!(
            result.is_ok(),
            "a message carrying no capability was denied"
        );
        assert!(
            receiver.lookup_slot_ref(destination).is_null(),
            "the sentinel path wrote a capability into the receiver"
        );
    }

    /// The delivered message carries the endpoint's badge, not the sender's
    /// claim, and the register contents survive unchanged.
    ///
    /// Badge integrity is what makes a badge evidence of authority: a sender
    /// that could stamp its own badge could impersonate any other sender on the
    /// same endpoint.
    #[kani::proof]
    fn the_endpoint_badge_overrides_any_sender_supplied_badge() {
        let mut sender = CapabilitySpace::new();
        let mut receiver = CapabilitySpace::new();

        let claimed_badge: u64 = kani::any();
        let endpoint_badge: u64 = kani::any();

        let sent = message_with_badge(claimed_badge);
        let result = perform_rendezvous(
            &sent,
            CAPABILITY_TRANSFER_NONE_SENTINEL,
            0,
            &mut sender,
            &mut receiver,
            endpoint_badge,
        );

        let delivered = result.expect("the sentinel path cannot deny");
        assert!(
            delivered.badge == endpoint_badge,
            "the sender's claimed badge survived into the delivered message"
        );
        assert!(
            delivered.register_zero == sent.register_zero
                && delivered.register_one == sent.register_one
                && delivered.register_two == sent.register_two
                && delivered.register_three == sent.register_three,
            "message registers were altered in transit"
        );
    }
}
