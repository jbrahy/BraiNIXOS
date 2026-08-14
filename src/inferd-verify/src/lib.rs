//! Kani proof harnesses for the confined tenant's KV binding.
//!
//! `INV-MODEL-001`'s reason for existing is that confinement must be
//! **structural, not behavioural** — and the structural claim in
//! `brainix-inferd` is that a session's KV partition is *derived from its own
//! slot* rather than chosen, so no call can be handed another client's cache.
//!
//! The tests in that crate check that claim at all eight admissible slots,
//! which is every slot the server can admit. These harnesses check it over a
//! **symbolic** `usize`, which is every value the type can hold — including the
//! ones an admission bug, an arithmetic slip, or a future `MAX_SESSIONS` could
//! produce. The difference matters here more than it usually does: the failure
//! mode is one tenant reading another's KV cache (`INV-SERVE-001`), and a test
//! over the values we expect is exactly the instrument that cannot see a value
//! we did not expect.
//!
//! Cheap by construction: the model is integer comparison, with no buffer, no
//! loop, and no hash. Every harness here verifies in seconds, which is why none
//! of them is behind `long-proofs`.

#![deny(unsafe_code)]
// kani is a cfg set by the Kani verification tool's dedicated CI image.
#![allow(unexpected_cfgs)]

#[cfg(kani)]
mod proofs {
    use brainix_bsp::MAX_SESSIONS;
    use brainix_inferd::{teardown, BindingError, KvBinding};

    /// **A session reaches its own partition and no other — unbounded.**
    ///
    /// Over every `usize` the slot could be. For an admissible slot the
    /// partition index equals the slot; for any other value the binding denies
    /// rather than resolving to something.
    #[kani::proof]
    fn inferd_model_binds_each_session_to_its_own_partition() {
        let slot: usize = kani::any();
        match KvBinding::for_session(slot) {
            Ok(binding) => {
                kani::assert(
                    slot < MAX_SESSIONS,
                    "a binding was made for an inadmissible slot",
                );
                kani::assert(
                    binding.partition_index() == slot,
                    "a session was bound to a partition that is not its own",
                );
                kani::assert(
                    binding.session_slot() == slot,
                    "a binding forgot which session it belongs to",
                );
            }
            Err(error) => {
                kani::assert(
                    slot >= MAX_SESSIONS,
                    "an admissible slot was refused a binding",
                );
                kani::assert(
                    matches!(error, BindingError::NoSuchSession),
                    "a binding failed for a reason the model does not name",
                );
            }
        }
    }

    /// **No two sessions share a partition — unbounded over both slots.**
    ///
    /// The cross-tenant property in its sharpest form: two bindings share a
    /// partition **exactly when they are the same session**. A `true` here for
    /// two different sessions is one client reading another's KV cache.
    #[kani::proof]
    fn inferd_model_never_binds_two_sessions_to_one_partition() {
        let left: usize = kani::any();
        let right: usize = kani::any();
        let (Ok(first), Ok(second)) = (KvBinding::for_session(left), KvBinding::for_session(right))
        else {
            return;
        };
        kani::assert(
            first.shares_partition_with(&second) == (left == right),
            "two distinct sessions share a KV partition, or one session does not share its own",
        );
    }

    /// **Teardown names the partition the session actually held — unbounded.**
    ///
    /// `INV-SERVE-004` zeroizes on teardown. Zeroizing the *wrong* partition is
    /// two failures at once: the departing tenant's residue survives for the
    /// next occupant, and a live tenant's cache is destroyed under it.
    #[kani::proof]
    fn inferd_model_teardown_names_the_partition_the_session_held() {
        let slot: usize = kani::any();
        let Ok(binding) = KvBinding::for_session(slot) else {
            return;
        };
        let duty = teardown(binding);
        kani::assert(
            duty.partition_index == binding.partition_index(),
            "teardown named a partition the session did not hold",
        );
        kani::assert(
            duty.partition_index < MAX_SESSIONS,
            "teardown named a partition outside the region",
        );
    }
}
