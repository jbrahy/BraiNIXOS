//! §6 — chain advance, zeroization, the monotonic commit, catch-up, and
//! desynchronization.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cognitive_complexity,
    clippy::useless_vec
)]

mod common;

use brainix_bsp::{CredentialRole, MAX_CHAIN_CATCHUP};
use brainix_transport_crypto::{
    advance_key, ChainState, ClientHandshake, Credential, Secret, ServerHandshake,
    TransportCryptoError,
};

/// A chain state at position `counter` derived from a fixed seed.
fn chain_at(counter: u64) -> ChainState {
    ChainState::at(Secret::from_bytes([0x21u8; 32]), counter)
}

#[test]
fn an_advance_produces_a_different_key() {
    let start = Secret::<32>::from_bytes([0x21u8; 32]);
    let next = advance_key(&start);
    assert_ne!(next.expose(), start.expose());
    // And it is deterministic, or the two ends could never agree.
    assert_eq!(advance_key(&start).expose(), next.expose());
}

/// §6.1's `zeroize(CK_n)`. The buffer the ratchet advanced past comes back
/// **all zeros** — that is the entire forward-secrecy claim, made observable.
#[test]
fn the_chain_key_an_advance_walks_past_is_zeroized() {
    let mut scratch = chain_at(0).scratch();
    let before = *scratch.key().expose();
    let retired = scratch.advance();
    assert_ne!(before, [0u8; 32], "the fixture must not start at zero");
    assert_eq!(
        retired.expose(),
        &[0u8; 32],
        "the key advanced past must not remain in memory"
    );
    assert_ne!(scratch.key().expose(), &before);
}

/// Ten successive advances all differ — the chain does not cycle or fix-point.
#[test]
fn successive_advances_never_repeat_a_key() {
    let mut scratch = chain_at(0).scratch();
    let mut seen = vec![*scratch.key().expose()];
    for _ in 0..10 {
        let _retired = scratch.advance();
        let key = *scratch.key().expose();
        assert!(!seen.contains(&key), "the chain repeated a key");
        seen.push(key);
    }
    assert_eq!(scratch.counter(), 10);
}

/// §6.3 row: `n == s` is the normal case and costs no advance.
#[test]
fn resolving_the_persisted_position_costs_no_advance() {
    let state = chain_at(4);
    let scratch = state.resolve(4).expect("the normal case resolves");
    assert_eq!(scratch.counter(), 4);
    assert_eq!(scratch.key().expose(), state.key().expose());
}

/// §6.3 row: `s < n ≤ s + MAX_CHAIN_CATCHUP` walks forward in scratch.
#[test]
fn catch_up_walks_forward_and_lands_on_the_expected_key() {
    let state = chain_at(0);
    let scratch = state.resolve(3).expect("three steps is within the bound");
    assert_eq!(scratch.counter(), 3);
    let mut expected = Secret::<32>::from_bytes([0x21u8; 32]);
    for _ in 0..3 {
        expected = advance_key(&expected);
    }
    assert_eq!(scratch.key().expose(), expected.expose());
    // The persisted state is untouched: resolution is uncommitted (§6.2).
    assert_eq!(state.counter(), 0);
}

/// §6.3 row K4 — catch-up is bounded, and the bound is exact.
#[test]
fn catch_up_is_bounded_at_exactly_max_chain_catchup() {
    let state = chain_at(0);
    assert!(state.resolve(MAX_CHAIN_CATCHUP).is_ok());
    assert_eq!(
        state.resolve(MAX_CHAIN_CATCHUP + 1).err(),
        Some(TransportCryptoError::ChainCounterTooFarAhead)
    );
}

/// §6.3 row K3 / §6.4 — a client behind the server is a desynchronization, and
/// it fails closed. There is no fallback to an un-ratcheted key.
#[test]
fn a_client_behind_the_server_is_denied_rather_than_accommodated() {
    let state = chain_at(9);
    for behind in 0..9u64 {
        assert_eq!(
            state.resolve(behind).err(),
            Some(TransportCryptoError::ChainDesynchronized),
            "counter {behind}"
        );
    }
}

/// §6.2 — the commit installs `(CK_{m+1}, m+1)`.
#[test]
fn a_commit_installs_the_next_position() {
    let mut state = chain_at(0);
    let expected = advance_key(&advance_key(state.key()));
    let scratch = state.resolve(1).expect("one step ahead");
    assert!(state.commit(scratch));
    assert_eq!(state.counter(), 2);
    assert_eq!(state.key().expose(), expected.expose());
}

/// §6.2 — the commit is a **monotonic compare-and-swap**. Two handshakes may
/// resolve from different positions and complete in either order; the later
/// one must not move the persisted counter backwards and reinstate a chain key
/// the server had already advanced past.
#[test]
fn a_stale_commit_does_not_move_the_chain_backwards() {
    let mut state = chain_at(0);
    let early = state
        .resolve(0)
        .expect("resolves at the persisted position");
    let late = state.resolve(3).expect("resolves ahead");

    assert!(state.commit(late), "the forward commit wins");
    assert_eq!(state.counter(), 4);
    let after = *state.key().expose();

    assert!(!state.commit(early), "the stale commit is refused");
    assert_eq!(state.counter(), 4, "the counter did not move backwards");
    assert_eq!(state.key().expose(), &after, "the key was not reinstated");
}

/// An explicit teardown zeroizes the persisted key (§9.4).
#[test]
fn zeroizing_a_chain_state_clears_its_key() {
    let mut state = chain_at(2);
    state.zeroize();
    assert_eq!(state.key().expose(), &[0u8; 32]);
}

/// Revoking a credential destroys everything secret in the slot.
#[test]
fn revoking_a_credential_clears_its_chain_and_frees_the_slot() {
    let mut credential = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Client, 0);
    assert!(credential.is_occupied());
    credential.revoke();
    assert!(!credential.is_occupied());
    assert_eq!(credential.handle(), &[0u8; 16]);
}

// ---------------------------------------------------------------------------
// End-to-end: the ratchet as the handshake drives it
// ---------------------------------------------------------------------------

/// A completed handshake advances **both** ends by exactly one.
#[test]
fn a_completed_handshake_advances_both_ends() {
    let session = common::handshake();
    assert_eq!(session.credential.chain_counter(), 1, "the client advanced");
    let slot = session.table.slot(0).expect("slot 0 holds the credential");
    assert_eq!(slot.chain_counter(), 1, "the server advanced");
}

/// A handshake that fails at row H5 commits **no** chain advance (§6.2): an
/// unauthenticated peer must not be able to push the server's chain forward.
#[test]
fn a_failed_client_auth_commits_no_chain_advance() {
    let mut table = common::table_with_one_client();
    let mut credential = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Client, 0);
    let (mut client, hello) = ClientHandshake::start(&credential, &common::CLIENT_NONCE);
    let mut server = ServerHandshake::new();
    let matched = server.identify(&hello, &table).expect("identifies");
    let server_hello = server
        .derive(matched, &common::SERVER_NONCE)
        .expect("derives");
    let (mut auth, _session) = client
        .accept_server_hello(&server_hello, &mut credential)
        .expect("the client accepts");

    auth[0] ^= 0x01;
    assert_eq!(
        server.accept_client_auth(&auth, &mut table).err(),
        Some(TransportCryptoError::AuthenticationFailed)
    );
    assert_eq!(
        table.slot(0).expect("slot 0").chain_counter(),
        0,
        "a failed handshake must not advance the persisted chain"
    );
}

/// §6.3's stated resynchronization: the client's `ClientAuth` is lost, so the
/// client is at `s + 1` while the server is still at `s`, and the next
/// connection resynchronizes with a single catch-up step.
#[test]
fn a_lost_client_auth_resynchronizes_on_the_next_connection() {
    let mut table = common::table_with_one_client();
    let mut credential = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Client, 0);

    // First connection: the client accepts, then its ClientAuth is lost.
    let (mut client, hello) = ClientHandshake::start(&credential, &common::CLIENT_NONCE);
    let mut server = ServerHandshake::new();
    let matched = server.identify(&hello, &table).expect("identifies");
    let server_hello = server
        .derive(matched, &common::SERVER_NONCE)
        .expect("derives");
    let (_auth, _session) = client
        .accept_server_hello(&server_hello, &mut credential)
        .expect("the client accepts");
    assert_eq!(credential.chain_counter(), 1);
    assert_eq!(table.slot(0).expect("slot 0").chain_counter(), 0);

    // Second connection: one catch-up step, and it completes.
    let (mut client, hello) = ClientHandshake::start(&credential, &[0x5cu8; 32]);
    let mut server = ServerHandshake::new();
    let matched = server.identify(&hello, &table).expect("identifies");
    let server_hello = server.derive(matched, &[0xa3u8; 32]).expect("derives");
    let (auth, _session) = client
        .accept_server_hello(&server_hello, &mut credential)
        .expect("the client accepts");
    server
        .accept_client_auth(&auth, &mut table)
        .expect("the server accepts");
    assert_eq!(table.slot(0).expect("slot 0").chain_counter(), 2);
    assert_eq!(credential.chain_counter(), 2);
}

/// A client whose store was restored from an older state is locked out — §6.4's
/// availability failure, which is not a confidentiality failure and has no
/// fallback.
#[test]
fn a_client_restored_from_an_older_state_is_locked_out() {
    let mut table = common::table_with_one_client();
    let stale = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Client, 0);

    // Push the server forward two positions.
    let slot = table.slot_mut(0).expect("slot 0");
    let scratch = slot.chain_mut().resolve(2).expect("resolves ahead");
    assert!(slot.chain_mut().commit(scratch));
    assert_eq!(table.slot(0).expect("slot 0").chain_counter(), 3);

    let (_client, hello) = ClientHandshake::start(&stale, &common::CLIENT_NONCE);
    let mut server = ServerHandshake::new();
    let matched = server.identify(&hello, &table).expect("still identified");
    assert_eq!(
        server.derive(matched, &common::SERVER_NONCE).err(),
        Some(TransportCryptoError::ChainDesynchronized),
        "the chain is one-way; the server cannot go back"
    );
}

/// §5.3: identification is independent of chain *state*, so a desynchronized
/// client is still **identified** and its failure is reported as a
/// desynchronization rather than as an unknown peer.
#[test]
fn a_desynchronized_client_is_identified_before_it_is_refused() {
    let mut table = common::table_with_one_client();
    let stale = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Client, 0);
    let slot = table.slot_mut(0).expect("slot 0");
    let scratch = slot.chain_mut().resolve(5).expect("resolves ahead");
    assert!(slot.chain_mut().commit(scratch));

    let (_client, hello) = ClientHandshake::start(&stale, &common::CLIENT_NONCE);
    let mut server = ServerHandshake::new();
    let matched = server
        .identify(&hello, &table)
        .expect("identification does not consult chain position");
    assert_eq!(matched.slot, 0);
}

/// A credential enrolled twice from the same material is the same credential:
/// the derivation is deterministic, which is what lets both ends run §5.2
/// independently and arrive at the same state.
#[test]
fn enrollment_is_deterministic_across_the_two_ends() {
    let left = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Client, 0);
    let right = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Client, 0);
    assert_eq!(left.handle(), right.handle());
    assert_eq!(
        left.candidate_selector(0, &common::CLIENT_NONCE).expose(),
        right.candidate_selector(0, &common::CLIENT_NONCE).expose()
    );
}

/// §5.2 — `role` is bound into all three expansions, so the same 32 bytes
/// enrolled as a client and as an admin are two unrelated credentials.
#[test]
fn the_role_byte_separates_two_credentials_from_the_same_material() {
    let client = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Client, 0);
    let admin = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Admin, 0);
    assert_ne!(client.handle(), admin.handle());
    assert_ne!(
        client.candidate_selector(0, &common::CLIENT_NONCE).expose(),
        admin.candidate_selector(0, &common::CLIENT_NONCE).expose()
    );
}

/// §5.2 — the enrolled key material is destroyed by the enrollment that
/// consumed it. The caller cannot opt out: the parameter is `&mut`.
#[test]
fn enrollment_destroys_the_key_material_it_consumed() {
    let mut material = common::ENROLLED_MATERIAL;
    let _credential = Credential::enroll(&mut material, CredentialRole::Client, 0);
    assert_eq!(material, [0u8; 32]);
}

// -------------------------------------------- replay guard, found by coverage
//
// `commit` is §6.2's monotonic compare-and-swap. Its REJECTION arm had never
// executed, which means the property that makes the ratchet a ratchet — that it
// never moves backwards — was asserted in prose and nowhere else. A chain that
// accepts a stale scratch re-derives a key an attacker has already seen the
// traffic for, which is the exact thing forward secrecy is supposed to prevent.

#[test]
fn a_commit_at_or_behind_the_persisted_position_is_refused() {
    // Persisted at 5; a scratch resolved from an earlier position must lose.
    for stale in 0..=4u64 {
        let mut state = chain_at(5);
        let before = *state.key().expose();
        let scratch = chain_at(stale).scratch();

        assert!(
            !state.commit(scratch),
            "a scratch at {stale} must not overwrite a chain already at 5"
        );
        assert_eq!(
            *state.key().expose(),
            before,
            "a refused commit must leave the persisted key untouched"
        );
        assert_eq!(
            state.counter(),
            5,
            "a refused commit must not move the counter"
        );
    }
}

#[test]
fn a_commit_at_exactly_the_persisted_position_is_refused() {
    // The boundary: equal is not ahead. Accepting it would let the same
    // position be committed twice, which is a replay by another name.
    let mut state = chain_at(7);
    let scratch = chain_at(6).scratch();
    let before = *state.key().expose();

    assert!(!state.commit(scratch));
    assert_eq!(*state.key().expose(), before);
    assert_eq!(state.counter(), 7);
}

#[test]
fn a_commit_strictly_ahead_is_accepted_and_moves_the_chain() {
    let mut state = chain_at(5);
    let before = *state.key().expose();
    let scratch = chain_at(5).scratch();

    assert!(state.commit(scratch), "a scratch one ahead must win");
    assert_eq!(state.counter(), 6);
    assert_ne!(
        *state.key().expose(),
        before,
        "the persisted key must actually advance"
    );
}

#[test]
fn a_scratch_at_the_counter_ceiling_cannot_commit() {
    // `counter + 1` overflowing is refused rather than wrapped: wrapping would
    // send the chain back to zero and re-issue every key it ever derived.
    let mut state = chain_at(u64::MAX);
    let scratch = ChainState::at(Secret::from_bytes([0x21u8; 32]), u64::MAX).scratch();
    assert!(!state.commit(scratch));
    assert_eq!(state.counter(), u64::MAX);
}

/// `ct_eq` is the constant-time comparison every secret comparison routes
/// through. Coverage showed it had never been called directly, so its
/// correctness rested entirely on callers exercising it incidentally.
#[test]
fn constant_time_equality_agrees_with_ordinary_equality() {
    let a = Secret::<32>::from_bytes([0x11u8; 32]);
    let same = Secret::<32>::from_bytes([0x11u8; 32]);
    assert!(a.ct_eq(&same));
    assert!(a.ct_eq(&a));

    // A difference in any single byte, at either end or the middle, must be
    // detected — an early-exit comparison would pass the first case and leak
    // the position of the first differing byte through timing.
    for index in [0usize, 1, 15, 30, 31] {
        let mut bytes = [0x11u8; 32];
        bytes[index] ^= 0x01;
        assert!(
            !a.ct_eq(&Secret::<32>::from_bytes(bytes)),
            "a difference at byte {index} was reported equal"
        );
    }
}
