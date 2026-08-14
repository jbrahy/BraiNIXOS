//! `INV-SERVE-003`, proved: no sequence of admissions exceeds the ceilings.
//!
//! The tests in `brainix-servd` walk the ceilings deliberately — fill the pool,
//! then ask for one more. That checks the paths a person thought of. These
//! harnesses check the property against **an arbitrary sequence of arbitrary
//! operations**, which is what an unauthenticated peer actually generates: it
//! does not take turns politely, and it does not stop at the boundary a test
//! author had in mind.
//!
//! The three ceilings are `const` and the pool is fixed, so the interesting
//! question is not whether one `acquire` respects them — it is whether any
//! interleaving of acquire, release and expire can leave the pool in a state
//! that violates them. Fixed-size pools make that provable rather than
//! argued: the state space is eight slots.
//!
//! Bounded by construction, and honest about it: each harness drives a fixed
//! number of operations over symbolic arguments, so the claim is "no sequence
//! of *this length*". The pool has eight slots and the per-credential ceiling
//! is two, so a sequence long enough to fill the pool twice over is long enough
//! to reach every boundary the ceilings describe.
//!
//! The unwind bound is **18**, and the number came from Kani rather than from
//! reasoning. The first draft used one past the harness's operation count; the
//! second used one past the pool's eight-slot walks. Both were rejected, and
//! the loop that actually needs the room is `memcmp`: comparing two sixteen-byte
//! credential handles, which `live_for_credential` does once per slot. The
//! longest loop in the model was neither the harness's nor the pool's — it was
//! inside an equality operator nobody wrote.

#![deny(unsafe_code)]
// kani is a cfg set by the Kani verification tool's dedicated CI image.
#![allow(unexpected_cfgs)]

#[cfg(kani)]
mod proofs {
    use brainix_bsp::{SessionType, MAX_ADMIN_SESSIONS, MAX_SESSIONS, MAX_SESSIONS_PER_CREDENTIAL};
    use brainix_servd::{CredentialHandle, SessionSlots, Tick};

    /// How many operations each harness drives.
    ///
    /// Ten: enough to fill an eight-slot pool and keep going.
    const OPERATIONS: usize = 10;

    /// One of a small set of credentials, so that the per-credential ceiling is
    /// reachable at all — with 2^128 distinct handles it never would be.
    fn any_credential() -> CredentialHandle {
        let which: u8 = kani::any();
        kani::assume(which < 3);
        CredentialHandle::new([which; 16])
    }

    fn any_session_type() -> SessionType {
        if kani::any() {
            SessionType::Client
        } else {
            SessionType::Admin
        }
    }

    /// **No interleaving of operations exceeds the pool or admin ceilings.**
    ///
    /// Ten arbitrary operations over arbitrary arguments, with the ceilings
    /// checked after **every** one rather than at the end: a pool that exceeds
    /// a ceiling transiently has already admitted the session that did it.
    ///
    /// The per-credential ceiling is deliberately *not* checked here — see
    /// [`servd_admission_never_exceeds_the_per_credential_ceiling`] for why it
    /// needs its own, shorter harness.
    #[kani::proof]
    #[kani::unwind(18)]
    fn servd_admission_never_exceeds_the_pool_or_admin_ceiling() {
        let mut slots = SessionSlots::new();
        let mut handles: [Option<_>; OPERATIONS] = [None; OPERATIONS];

        let mut index: usize = 0;
        while index < OPERATIONS {
            let choice: u8 = kani::any();
            match choice % 3 {
                0 => {
                    // A distinct, **concrete** credential per operation. Two
                    // reasons, and the second is why it is concrete rather than
                    // symbolic: distinct credentials let the pool fill to
                    // MAX_SESSIONS without the per-credential ceiling
                    // intervening, which is the boundary this harness is about;
                    // and `acquire` compares handles internally, so a symbolic
                    // one puts a symbolic sixteen-byte memcmp inside every slot
                    // walk of every operation. That is what made the first
                    // version of this harness not finish.
                    let credential = CredentialHandle::new([index as u8; 16]);
                    if let Ok(handle) = slots.acquire(
                        credential,
                        any_session_type(),
                        Tick::from_seconds(kani::any()),
                    ) {
                        handles[index] = Some(handle);
                    }
                }
                1 => {
                    let which: usize = kani::any();
                    if which < OPERATIONS {
                        if let Some(handle) = handles[which] {
                            let _ = slots.release(handle);
                        }
                    }
                }
                _ => {
                    let _ = slots.expire(Tick::from_seconds(kani::any()));
                }
            }

            kani::assert(
                slots.live() <= MAX_SESSIONS,
                "the pool holds more sessions than it has slots",
            );
            kani::assert(
                slots.live_of_type(SessionType::Admin) <= MAX_ADMIN_SESSIONS,
                "more admin sessions are live than the ceiling permits",
            );

            index = index.saturating_add(1);
        }
    }

    /// **No sequence exceeds the per-credential ceiling.**
    ///
    /// Four operations rather than ten, and one credential rather than three,
    /// because this is the expensive property to prove and the reason is
    /// specific: `live_for_credential` compares sixteen-byte handles, so every
    /// check instantiates a `memcmp` loop **per slot**, and the cost is the
    /// product of the sequence length and that. Four operations against a
    /// two-slot ceiling still reaches the boundary and crosses it, which is
    /// what the property is about; ten did not finish in ten minutes.
    #[kani::proof]
    #[kani::unwind(18)]
    fn servd_admission_never_exceeds_the_per_credential_ceiling() {
        let credential = CredentialHandle::new([7u8; 16]);
        let mut slots = SessionSlots::new();
        let mut last: Option<_> = None;

        let mut index: usize = 0;
        while index < 4 {
            let choice: u8 = kani::any();
            if choice % 2 == 0 {
                if let Ok(handle) = slots.acquire(
                    credential,
                    any_session_type(),
                    Tick::from_seconds(kani::any()),
                ) {
                    last = Some(handle);
                }
            } else if let Some(handle) = last.take() {
                let _ = slots.release(handle);
            }

            kani::assert(
                slots.live_for_credential(credential) <= MAX_SESSIONS_PER_CREDENTIAL,
                "a credential holds more slots than the ceiling permits",
            );

            index = index.saturating_add(1);
        }
    }

    /// **A released handle never resolves again, whatever happens next.**
    ///
    /// Slot reuse is where cross-tenant reads would come from: the same index
    /// belongs to somebody else afterwards. The tests check one reuse; this
    /// checks that no sequence of later operations makes a released handle
    /// resolve, including the sequence that puts a new session in that exact
    /// slot.
    #[kani::proof]
    #[kani::unwind(18)]
    fn servd_admission_a_released_handle_never_resolves_again() {
        let mut slots = SessionSlots::new();
        let Ok(handle) = slots.acquire(
            any_credential(),
            any_session_type(),
            Tick::from_seconds(kani::any()),
        ) else {
            return;
        };
        let Ok(()) = slots.release(handle) else {
            return;
        };

        let mut index: usize = 0;
        while index < 5 {
            let choice: u8 = kani::any();
            if choice % 2 == 0 {
                let _ = slots.acquire(
                    any_credential(),
                    any_session_type(),
                    Tick::from_seconds(kani::any()),
                );
            } else {
                let _ = slots.expire(Tick::from_seconds(kani::any()));
            }

            kani::assert(
                slots.session_type(handle).is_err(),
                "a released handle named a session type after the slot was reused",
            );
            index = index.saturating_add(1);
        }
    }

    /// **Expiry reclaims only what is due — over an arbitrary clock.**
    ///
    /// A clock reading before the deadline must reclaim nothing. The failure
    /// this excludes is an expiry that tears down live sessions early, which an
    /// attacker able to influence the clock would use as a remote teardown.
    #[kani::proof]
    #[kani::unwind(18)]
    fn servd_admission_expiry_reclaims_nothing_before_a_deadline() {
        let mut slots = SessionSlots::new();
        let acquired: u64 = kani::any();
        let Ok(handle) = slots.acquire(
            any_credential(),
            any_session_type(),
            Tick::from_seconds(acquired),
        ) else {
            return;
        };
        let Ok(deadline) = slots.deadline(handle) else {
            return;
        };

        let now: u64 = kani::any();
        kani::assume(now < deadline.seconds());
        kani::assert(
            slots.expire(Tick::from_seconds(now)) == 0,
            "expiry reclaimed a slot before its deadline",
        );
        kani::assert(
            slots.credential(handle).is_ok(),
            "a slot was reclaimed before its deadline",
        );
    }
}
