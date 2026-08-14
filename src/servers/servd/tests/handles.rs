//! Handle discipline: a released slot is unreachable, permanently.
//!
//! The property under test is `INV-SERVE`'s: no client can name another
//! client's session. Slot reuse is where that could fail without anyone
//! writing a line of wrong-looking code — hold a handle across a teardown, and
//! the same index now belongs to someone else.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
#![allow(clippy::cognitive_complexity)]

use brainix_bsp::{SessionType, MAX_SESSIONS, MAX_SESSIONS_PER_CREDENTIAL};
use brainix_servd::{CredentialHandle, SessionSlots, SlotError};

fn credential(n: u8) -> CredentialHandle {
    CredentialHandle::new([n; 16])
}

#[test]
fn a_released_handle_resolves_to_nothing_through_every_accessor() {
    let mut slots = SessionSlots::new();
    let handle = slots
        .acquire(credential(1), SessionType::Client)
        .expect("acquired");
    slots.release(handle).expect("released");

    assert_eq!(slots.session(handle).err(), Some(SlotError::Stale));
    assert_eq!(slots.session_mut(handle).err(), Some(SlotError::Stale));
    assert_eq!(slots.session_type(handle), Err(SlotError::Stale));
    assert_eq!(slots.credential(handle), Err(SlotError::Stale));
    assert_eq!(slots.release(handle), Err(SlotError::Stale));
    assert_eq!(slots.live(), 0);
}

#[test]
fn a_stale_handle_cannot_read_the_client_that_took_its_slot() {
    let mut slots = SessionSlots::new();
    let first = slots
        .acquire(credential(1), SessionType::Client)
        .expect("first client");
    slots.release(first).expect("released");

    // The pool is empty, so the next acquire takes the same index. Only the
    // generation distinguishes them, which is the whole reason it exists.
    let second = slots
        .acquire(credential(2), SessionType::Admin)
        .expect("second client");

    assert_eq!(slots.credential(first), Err(SlotError::Stale));
    assert_eq!(slots.session_type(first), Err(SlotError::Stale));
    assert_eq!(slots.credential(second), Ok(credential(2)));
    assert_eq!(slots.session_type(second), Ok(SessionType::Admin));
}

#[test]
fn a_reused_slot_starts_from_a_fresh_protocol_state() {
    let mut slots = SessionSlots::new();
    let first = slots
        .acquire(credential(1), SessionType::Client)
        .expect("first");

    // Drive the first session off its initial state, then tear it down.
    let session = slots.session_mut(first).expect("live");
    assert!(session.accept_client_hello(&[0u8; 8]).is_err());
    slots.release(first).expect("released");

    let second = slots
        .acquire(credential(2), SessionType::Client)
        .expect("second");
    assert_eq!(
        slots.session(second).expect("live").state(),
        brainix_bsp::SessionState::WaitHello
    );
    assert_eq!(
        slots.session(second).expect("live").request_phase(),
        brainix_bsp::RequestPhase::Idle
    );
    assert_eq!(slots.session(second).expect("live").session_type(), None);
}

#[test]
fn the_session_state_machine_is_reachable_and_writable_through_its_handle() {
    let mut slots = SessionSlots::new();
    let handle = slots
        .acquire(credential(9), SessionType::Client)
        .expect("acquired");

    // A malformed ClientHello is refused by the protocol state machine, not by
    // this crate: servd owns the slot, `brainix-bsp` owns the wire rules.
    let session = slots.session_mut(handle).expect("live");
    assert!(session.accept_client_hello(&[]).is_err());

    // The slot is still live and still this credential's after that refusal.
    assert_eq!(slots.credential(handle), Ok(credential(9)));
    assert_eq!(slots.live(), 1);
}

#[test]
fn every_slot_in_a_full_pool_is_independently_addressable() {
    let mut slots = SessionSlots::new();
    let mut handles = [None; MAX_SESSIONS];
    for (n, entry) in handles.iter_mut().enumerate() {
        let cred = credential((n / MAX_SESSIONS_PER_CREDENTIAL) as u8);
        *entry = Some(slots.acquire(cred, SessionType::Client).expect("within"));
    }

    // Each handle resolves to its own credential, and no two handles are equal.
    for (n, entry) in handles.iter().enumerate() {
        let handle = entry.expect("acquired");
        let expected = credential((n / MAX_SESSIONS_PER_CREDENTIAL) as u8);
        assert_eq!(slots.credential(handle), Ok(expected));
    }
    for (n, left) in handles.iter().enumerate() {
        for right in handles.iter().skip(n + 1) {
            assert_ne!(left, right);
        }
    }
}

#[test]
fn releasing_the_middle_of_a_full_pool_frees_exactly_one_slot() {
    let mut slots = SessionSlots::new();
    let mut handles = [None; MAX_SESSIONS];
    for (n, entry) in handles.iter_mut().enumerate() {
        let cred = credential((n / MAX_SESSIONS_PER_CREDENTIAL) as u8);
        *entry = Some(slots.acquire(cred, SessionType::Client).expect("within"));
    }
    assert_eq!(slots.live(), MAX_SESSIONS);

    let middle = handles[MAX_SESSIONS / 2].expect("acquired");
    slots.release(middle).expect("released");
    assert_eq!(slots.live(), MAX_SESSIONS - 1);

    // The freed slot is the one that gets reused, and every other handle is
    // untouched by its neighbour's teardown.
    let replacement = slots
        .acquire(credential(200), SessionType::Client)
        .expect("one slot free");
    assert_eq!(slots.credential(replacement), Ok(credential(200)));
    for (n, entry) in handles.iter().enumerate() {
        if n == MAX_SESSIONS / 2 {
            continue;
        }
        let handle = entry.expect("acquired");
        assert!(slots.credential(handle).is_ok());
    }
}

#[test]
fn a_handle_survives_being_copied_and_both_copies_go_stale_together() {
    let mut slots = SessionSlots::new();
    let handle = slots
        .acquire(credential(4), SessionType::Client)
        .expect("acquired");
    let copy = handle;

    slots.release(handle).expect("released");

    assert_eq!(slots.credential(copy), Err(SlotError::Stale));
}
