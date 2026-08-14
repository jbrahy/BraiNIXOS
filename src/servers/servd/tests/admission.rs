//! Admission control: the three `const` ceilings of `INV-SERVE-003`.
//!
//! Every limit here counts half-open handshakes, because a slot is acquired
//! before the client has authenticated (BSP v2 §9.1). These tests never
//! authenticate anything, which is the point: an unauthenticated peer holding
//! slots is the case the limits exist for.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
#![allow(clippy::cognitive_complexity)]

use brainix_bsp::{SessionType, MAX_ADMIN_SESSIONS, MAX_SESSIONS, MAX_SESSIONS_PER_CREDENTIAL};
use brainix_servd::{AdmissionDenied, CredentialHandle, SessionSlots};

fn credential(n: u8) -> CredentialHandle {
    CredentialHandle::new([n; 16])
}

#[test]
fn a_fresh_pool_holds_nothing() {
    let slots = SessionSlots::new();
    assert_eq!(slots.live(), 0);
    assert_eq!(slots.live_for_credential(credential(1)), 0);
    assert_eq!(slots.live_of_type(SessionType::Client), 0);
    assert_eq!(slots.live_of_type(SessionType::Admin), 0);
}

#[test]
fn the_default_pool_is_the_empty_pool() {
    let slots = SessionSlots::default();
    assert_eq!(slots.live(), 0);
}

#[test]
fn an_admitted_session_starts_at_the_beginning_of_the_handshake() {
    let mut slots = SessionSlots::new();
    let handle = slots
        .acquire(credential(1), SessionType::Client)
        .expect("the first acquire on an empty pool cannot be denied");

    assert_eq!(slots.live(), 1);
    assert_eq!(slots.live_for_credential(credential(1)), 1);
    assert_eq!(slots.live_of_type(SessionType::Client), 1);
    assert_eq!(slots.credential(handle), Ok(credential(1)));
    assert_eq!(slots.session_type(handle), Ok(SessionType::Client));
    assert_eq!(
        slots
            .session(handle)
            .expect("a live handle resolves")
            .state(),
        brainix_bsp::SessionState::WaitHello
    );
}

#[test]
fn a_credential_is_refused_its_third_concurrent_slot() {
    let mut slots = SessionSlots::new();
    for _ in 0..MAX_SESSIONS_PER_CREDENTIAL {
        slots
            .acquire(credential(7), SessionType::Client)
            .expect("within the per-credential limit");
    }

    assert_eq!(
        slots.acquire(credential(7), SessionType::Client),
        Err(AdmissionDenied::CredentialLimitReached)
    );
    // The refusal is about that credential and nothing else: the pool has
    // six free slots and another client is admitted immediately.
    assert!(slots.acquire(credential(8), SessionType::Client).is_ok());
}

#[test]
fn releasing_a_slot_returns_the_credential_its_admission_budget() {
    let mut slots = SessionSlots::new();
    let first = slots
        .acquire(credential(3), SessionType::Client)
        .expect("first");
    slots
        .acquire(credential(3), SessionType::Client)
        .expect("second");
    assert_eq!(
        slots.acquire(credential(3), SessionType::Client),
        Err(AdmissionDenied::CredentialLimitReached)
    );

    slots.release(first).expect("a live handle releases");

    assert!(slots.acquire(credential(3), SessionType::Client).is_ok());
}

#[test]
fn a_second_admin_session_is_refused_even_under_a_different_credential() {
    let mut slots = SessionSlots::new();
    slots
        .acquire(credential(1), SessionType::Admin)
        .expect("the first admin session");
    assert_eq!(slots.live_of_type(SessionType::Admin), MAX_ADMIN_SESSIONS);

    assert_eq!(
        slots.acquire(credential(2), SessionType::Admin),
        Err(AdmissionDenied::AdminLimitReached)
    );
    // The admin ceiling constrains admin sessions only.
    assert!(slots.acquire(credential(2), SessionType::Client).is_ok());
}

#[test]
fn an_admin_slot_frees_the_admin_ceiling_when_it_is_released() {
    let mut slots = SessionSlots::new();
    let admin = slots
        .acquire(credential(1), SessionType::Admin)
        .expect("first admin");
    assert_eq!(
        slots.acquire(credential(2), SessionType::Admin),
        Err(AdmissionDenied::AdminLimitReached)
    );

    slots.release(admin).expect("live");

    assert!(slots.acquire(credential(2), SessionType::Admin).is_ok());
}

#[test]
fn the_pool_denies_rather_than_grows() {
    let mut slots = SessionSlots::new();
    // Four credentials at two slots each exactly fills the eight-slot pool
    // without any of them reaching the per-credential ceiling.
    for n in 0..(MAX_SESSIONS / MAX_SESSIONS_PER_CREDENTIAL) {
        for _ in 0..MAX_SESSIONS_PER_CREDENTIAL {
            slots
                .acquire(credential(n as u8), SessionType::Client)
                .expect("within both ceilings");
        }
    }
    assert_eq!(slots.live(), MAX_SESSIONS);

    assert_eq!(
        slots.acquire(credential(200), SessionType::Client),
        Err(AdmissionDenied::PoolFull)
    );
    assert_eq!(slots.live(), MAX_SESSIONS);
}

#[test]
fn a_credential_at_its_limit_is_refused_for_that_reason_even_when_the_pool_is_full() {
    let mut slots = SessionSlots::new();
    for n in 0..(MAX_SESSIONS / MAX_SESSIONS_PER_CREDENTIAL) {
        for _ in 0..MAX_SESSIONS_PER_CREDENTIAL {
            slots
                .acquire(credential(n as u8), SessionType::Client)
                .expect("within both ceilings");
        }
    }

    // Credential 0 holds two slots and the pool is full. The denial names the
    // credential's ceiling, not the server's load, so an operator reading it
    // learns something that does not change with unrelated traffic.
    assert_eq!(
        slots.acquire(credential(0), SessionType::Client),
        Err(AdmissionDenied::CredentialLimitReached)
    );
}

#[test]
fn an_admin_at_its_credential_limit_is_refused_before_the_admin_ceiling_is_consulted() {
    let mut slots = SessionSlots::new();
    slots
        .acquire(credential(5), SessionType::Client)
        .expect("first");
    slots
        .acquire(credential(5), SessionType::Client)
        .expect("second");

    // No admin session is live, so the admin ceiling would admit this. The
    // per-credential ceiling is checked first and denies it.
    assert_eq!(
        slots.acquire(credential(5), SessionType::Admin),
        Err(AdmissionDenied::CredentialLimitReached)
    );
}

#[test]
fn a_credential_handle_is_readable_for_audit_and_compares_by_value() {
    let handle = credential(42);
    assert_eq!(handle.as_bytes(), &[42u8; 16]);
    assert_eq!(handle, CredentialHandle::new([42u8; 16]));
    assert_ne!(handle, credential(43));
}
