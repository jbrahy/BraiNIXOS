//! §5.3–§5.5 — mutual authentication, the constant-work selector scan, and
//! every §12 K- and H-row this crate owns.

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

use brainix_bsp::{
    ClientHello, CredentialRole, LEN_CLIENT_HELLO, LEN_SERVER_HELLO, MAX_ENROLLED_KEYS,
};
use brainix_transport_crypto::{
    transcript_two, ClientHandshake, ServerHandshake, TransportCryptoError, FLAG_BREAK_GLASS,
};

// ---------------------------------------------------------------------------
// The honest exchange
// ---------------------------------------------------------------------------

/// Both ends reach the same `session_id`, which §5.4 fixes as `TH_2`.
#[test]
fn an_honest_handshake_agrees_on_the_session_id() {
    let session = common::handshake();
    assert_eq!(session.client.session_id, session.server.session_id);
    assert_ne!(session.client.session_id, [0u8; 32]);
}

/// `session_id` really is `TH_2` — SHA-256 over the two message images.
#[test]
fn the_session_id_is_the_second_transcript_hash() {
    let mut table = common::table_with_one_client();
    let mut credential = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Client, 0);
    let (mut client, hello) = ClientHandshake::start(&credential, &common::CLIENT_NONCE);
    let mut server = ServerHandshake::new();
    let matched = server.identify(&hello, &table).expect("identifies");
    let server_hello = server
        .derive(matched, &common::SERVER_NONCE)
        .expect("derives");

    let mut server_confirm = [0u8; 32];
    server_confirm.copy_from_slice(&server_hello[32..64]);
    let expected = transcript_two(&hello, &common::SERVER_NONCE, &server_confirm);

    let (auth, client_session) = client
        .accept_server_hello(&server_hello, &mut credential)
        .expect("the client accepts");
    let server_session = server
        .accept_client_auth(&auth, &mut table)
        .expect("the server accepts");
    assert_eq!(client_session.session_id, expected);
    assert_eq!(server_session.session_id, expected);
}

/// The role is carried across from the credential record, never from the wire
/// (§7.1): there is no session-type field in any handshake message.
#[test]
fn the_granted_role_comes_from_the_credential_record() {
    let mut table = common::empty_table();
    table
        .insert(common::enroll(
            &common::ENROLLED_MATERIAL,
            CredentialRole::Admin,
            0,
        ))
        .expect("room");
    let mut credential = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Admin, 0);
    let (mut client, hello) = ClientHandshake::start(&credential, &common::CLIENT_NONCE);
    let mut server = ServerHandshake::new();
    let matched = server.identify(&hello, &table).expect("identifies");
    let server_hello = server
        .derive(matched, &common::SERVER_NONCE)
        .expect("derives");
    let (auth, _client_session) = client
        .accept_server_hello(&server_hello, &mut credential)
        .expect("the client accepts");
    let server_session = server
        .accept_client_auth(&auth, &mut table)
        .expect("the server accepts");
    assert_eq!(server_session.role, CredentialRole::Admin);
    assert_eq!(&server_session.handle, credential.handle());
}

/// The `ClientHello` this crate encodes is the one P2-T3 decodes.
#[test]
fn a_client_hello_this_crate_encodes_decodes_back_identically() {
    let credential = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Client, 0);
    let (_client, wire) = ClientHandshake::start(&credential, &common::CLIENT_NONCE);
    assert_eq!(wire.len(), LEN_CLIENT_HELLO);
    let decoded = ClientHello::decode(&wire).expect("P2-T3 accepts what this crate encoded");
    assert_eq!(decoded.chain_counter, 0);
    assert_eq!(decoded.client_nonce, common::CLIENT_NONCE);
    assert_eq!(
        decoded.key_selector,
        *credential
            .candidate_selector(0, &common::CLIENT_NONCE)
            .expose()
    );
}

/// Two connections under one credential are cryptographically distinct,
/// because `PRK_session` incorporates two fresh nonces (§9.2).
#[test]
fn two_sessions_under_one_credential_have_different_keys() {
    let alpha = common::handshake();
    let beta = common::handshake_with(&common::ENROLLED_MATERIAL, &[0x01u8; 32], &[0x02u8; 32])
        .expect("a second honest handshake");
    assert_ne!(alpha.client.session_id, beta.client.session_id);
}

// ---------------------------------------------------------------------------
// Mutual authentication
// ---------------------------------------------------------------------------

/// §12 row K1 — a peer that does not possess the PSK matches no credential and
/// never reaches a chain resolution, let alone a session.
#[test]
fn a_peer_without_the_psk_cannot_complete_the_handshake() {
    assert_eq!(
        common::handshake_with(
            &common::IMPOSTOR_MATERIAL,
            &common::CLIENT_NONCE,
            &common::SERVER_NONCE
        )
        .err(),
        Some(TransportCryptoError::NoCredentialMatch)
    );
}

/// §12 row H5 — every single-bit corruption of `ClientAuth` denies, with the
/// one indistinguishable variant.
#[test]
fn every_corruption_of_client_auth_denies_identically() {
    for position in 0..32usize {
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
        auth[position] ^= 0x80;
        assert_eq!(
            server.accept_client_auth(&auth, &mut table).err(),
            Some(TransportCryptoError::AuthenticationFailed),
            "byte {position}"
        );
    }
}

/// §12 row H6 — the client refuses a `ServerHello` whose `server_confirm` is
/// wrong, and aborts without sending anything further.
#[test]
fn every_corruption_of_server_confirm_denies_on_the_client() {
    for position in 32..LEN_SERVER_HELLO {
        let table = common::table_with_one_client();
        let mut credential = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Client, 0);
        let (mut client, hello) = ClientHandshake::start(&credential, &common::CLIENT_NONCE);
        let mut server = ServerHandshake::new();
        let matched = server.identify(&hello, &table).expect("identifies");
        let mut server_hello = server
            .derive(matched, &common::SERVER_NONCE)
            .expect("derives");
        server_hello[position] ^= 0x40;
        assert_eq!(
            client
                .accept_server_hello(&server_hello, &mut credential)
                .err(),
            Some(TransportCryptoError::AuthenticationFailed),
            "byte {position}"
        );
        assert_eq!(
            credential.chain_counter(),
            0,
            "a refused ServerHello must not advance the client's chain"
        );
    }
}

/// §5.6b — a transcript mismatch denies. The server's nonce is altered in
/// flight, so the client derives a different `TH_1` and an unrelated
/// `server_confirm`.
#[test]
fn a_transcript_mismatch_in_the_server_nonce_denies() {
    let table = common::table_with_one_client();
    let mut credential = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Client, 0);
    let (mut client, hello) = ClientHandshake::start(&credential, &common::CLIENT_NONCE);
    let mut server = ServerHandshake::new();
    let matched = server.identify(&hello, &table).expect("identifies");
    let mut server_hello = server
        .derive(matched, &common::SERVER_NONCE)
        .expect("derives");
    server_hello[0] ^= 0x01;
    assert_eq!(
        client
            .accept_server_hello(&server_hello, &mut credential)
            .err(),
        Some(TransportCryptoError::AuthenticationFailed)
    );
}

/// §5.6c — a replayed `ClientHello` reaches a server that generates a fresh
/// `server_nonce`, so the recorded `client_confirm` no longer verifies.
#[test]
fn a_replayed_client_hello_with_a_recorded_client_auth_denies() {
    let mut table = common::table_with_one_client();
    let mut credential = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Client, 0);
    let (mut client, hello) = ClientHandshake::start(&credential, &common::CLIENT_NONCE);
    let mut server = ServerHandshake::new();
    let matched = server.identify(&hello, &table).expect("identifies");
    let server_hello = server
        .derive(matched, &common::SERVER_NONCE)
        .expect("derives");
    let (recorded_auth, _session) = client
        .accept_server_hello(&server_hello, &mut credential)
        .expect("the client accepts");
    server
        .accept_client_auth(&recorded_auth, &mut table)
        .expect("the honest exchange completes");

    // The attacker replays the same 64 bytes at a server still at the recorded
    // chain position. It gets a *fresh* server_nonce, so TH_1 differs,
    // PRK_session differs, and the recorded client_confirm no longer verifies.
    let mut fresh_table = common::table_with_one_client();
    let mut replay = ServerHandshake::new();
    let matched = replay
        .identify(&hello, &fresh_table)
        .expect("still identified");
    let _server_hello = replay
        .derive(matched, &[0xfeu8; 32])
        .expect("a fresh nonce derives");
    assert_eq!(
        replay
            .accept_client_auth(&recorded_auth, &mut fresh_table)
            .err(),
        Some(TransportCryptoError::AuthenticationFailed)
    );
}

/// §5.3's second half of the replay story: once the server has advanced past
/// the recorded position, the replay "costs **zero** chain advances, because
/// row K3 rejects it on a comparison" — before any derivation runs.
#[test]
fn a_replay_against_an_advanced_server_costs_no_chain_work() {
    let mut table = common::table_with_one_client();
    let mut credential = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Client, 0);
    let (mut client, hello) = ClientHandshake::start(&credential, &common::CLIENT_NONCE);
    let mut server = ServerHandshake::new();
    let matched = server.identify(&hello, &table).expect("identifies");
    let server_hello = server
        .derive(matched, &common::SERVER_NONCE)
        .expect("derives");
    let (auth, _session) = client
        .accept_server_hello(&server_hello, &mut credential)
        .expect("the client accepts");
    server
        .accept_client_auth(&auth, &mut table)
        .expect("the honest exchange completes");

    let mut replay = ServerHandshake::new();
    let matched = replay.identify(&hello, &table).expect("still identified");
    assert_eq!(
        replay.derive(matched, &[0xfeu8; 32]).err(),
        Some(TransportCryptoError::ChainDesynchronized)
    );
}

/// §5.6d — the two confirmations use distinct labels, so neither can be
/// reflected back at its sender as the other's proof.
#[test]
fn a_reflected_server_confirm_is_not_a_valid_client_auth() {
    let mut table = common::table_with_one_client();
    let credential = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Client, 0);
    let (_client, hello) = ClientHandshake::start(&credential, &common::CLIENT_NONCE);
    let mut server = ServerHandshake::new();
    let matched = server.identify(&hello, &table).expect("identifies");
    let server_hello = server
        .derive(matched, &common::SERVER_NONCE)
        .expect("derives");
    let reflected = &server_hello[32..64];
    assert_eq!(
        server.accept_client_auth(reflected, &mut table).err(),
        Some(TransportCryptoError::AuthenticationFailed)
    );
}

// ---------------------------------------------------------------------------
// §5.3 — the selector scan
// ---------------------------------------------------------------------------

/// §5.3 — the selector is per-connection: the same credential produces a
/// different selector on every `ClientHello`, so it does not link sessions.
#[test]
fn the_selector_differs_on_every_connection() {
    let credential = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Client, 0);
    let first = credential.candidate_selector(0, &[0x01u8; 32]);
    let second = credential.candidate_selector(0, &[0x02u8; 32]);
    assert_ne!(first.expose(), second.expose());
}

/// §5.3 — `chain_counter` is bound into the selector, so a counter the sender
/// did not derive over matches no credential at all (§12 row K1). This is what
/// stops an attacker choosing how much chain work a `ClientHello` costs.
#[test]
fn a_forged_chain_counter_matches_no_credential() {
    let table = common::table_with_one_client();
    let credential = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Client, 0);
    let (_client, hello) = ClientHandshake::start(&credential, &common::CLIENT_NONCE);

    let mut forged = hello;
    forged[15] = 0x20; // chain_counter's low byte -> an arbitrary position
    let mut server = ServerHandshake::new();
    assert_eq!(
        server.identify(&forged, &table).err(),
        Some(TransportCryptoError::NoCredentialMatch)
    );
}

/// §12 row K2 — two credentials matching one selector is treated as an attack,
/// not resolved by an arbitrary choice.
#[test]
fn two_matching_credentials_deny() {
    let mut table = common::empty_table();
    table
        .insert(common::enroll(
            &common::ENROLLED_MATERIAL,
            CredentialRole::Client,
            0,
        ))
        .expect("room");
    table
        .insert(common::enroll(
            &common::ENROLLED_MATERIAL,
            CredentialRole::Client,
            0,
        ))
        .expect("room");
    let credential = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Client, 0);
    let (_client, hello) = ClientHandshake::start(&credential, &common::CLIENT_NONCE);
    let mut server = ServerHandshake::new();
    assert_eq!(
        server.identify(&hello, &table).err(),
        Some(TransportCryptoError::AmbiguousCredentialMatch)
    );
}

/// §12 row K5 — the break-glass credential is refused on this transport
/// unconditionally, before any chain resolution.
#[test]
fn a_break_glass_credential_is_refused_on_this_transport() {
    let mut table = common::empty_table();
    table
        .insert(common::enroll(
            &common::ENROLLED_MATERIAL,
            CredentialRole::Admin,
            FLAG_BREAK_GLASS,
        ))
        .expect("room");
    let credential = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Admin, 0);
    let (_client, hello) = ClientHandshake::start(&credential, &common::CLIENT_NONCE);
    let mut server = ServerHandshake::new();
    assert_eq!(
        server.identify(&hello, &table).err(),
        Some(TransportCryptoError::BreakGlassCredentialRefused)
    );
}

/// The scan finds a credential in any slot, including the last, because it
/// never breaks early.
#[test]
fn the_scan_finds_a_credential_in_the_last_slot() {
    let mut table = common::empty_table();
    for filler in 0..(MAX_ENROLLED_KEYS - 1) {
        let mut material = [0u8; 32];
        material.fill(filler as u8 + 1);
        table
            .insert(brainix_transport_crypto::Credential::enroll(
                &mut material,
                CredentialRole::Client,
                0,
            ))
            .expect("room");
    }
    table
        .insert(common::enroll(
            &common::ENROLLED_MATERIAL,
            CredentialRole::Client,
            0,
        ))
        .expect("the last slot");
    let credential = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Client, 0);
    let (_client, hello) = ClientHandshake::start(&credential, &common::CLIENT_NONCE);
    let mut server = ServerHandshake::new();
    let matched = server.identify(&hello, &table).expect("identifies");
    assert_eq!(matched.slot, MAX_ENROLLED_KEYS - 1);
}

/// §12 row A2 — the credential table is a fixed pool and refuses to grow.
#[test]
fn the_credential_table_refuses_to_grow() {
    let mut table = common::empty_table();
    for index in 0..MAX_ENROLLED_KEYS {
        let mut material = [0u8; 32];
        material.fill(index as u8);
        table
            .insert(brainix_transport_crypto::Credential::enroll(
                &mut material,
                CredentialRole::Client,
                0,
            ))
            .expect("room");
    }
    let mut overflow = [0xffu8; 32];
    assert_eq!(
        table
            .insert(brainix_transport_crypto::Credential::enroll(
                &mut overflow,
                CredentialRole::Client,
                0,
            ))
            .err(),
        Some(TransportCryptoError::CredentialTableFull)
    );
}

/// An empty table denies every `ClientHello`, and denies it as row K1 rather
/// than by any shortcut — the empty slots' per-boot filler makes them
/// indistinguishable from occupied ones.
#[test]
fn an_empty_table_denies_as_a_no_match() {
    let table = common::empty_table();
    let credential = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Client, 0);
    let (_client, hello) = ClientHandshake::start(&credential, &common::CLIENT_NONCE);
    let mut server = ServerHandshake::new();
    assert_eq!(
        server.identify(&hello, &table).err(),
        Some(TransportCryptoError::NoCredentialMatch)
    );
}

// ---------------------------------------------------------------------------
// State guards
// ---------------------------------------------------------------------------

/// The three §5.5 steps happen in order, or not at all.
#[test]
fn the_server_refuses_every_step_taken_out_of_order() {
    let mut table = common::table_with_one_client();
    let credential = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Client, 0);
    let (_client, hello) = ClientHandshake::start(&credential, &common::CLIENT_NONCE);

    let mut server = ServerHandshake::new();
    assert_eq!(
        server.accept_client_auth(&[0u8; 32], &mut table).err(),
        Some(TransportCryptoError::WrongState),
        "ClientAuth before ServerHello"
    );

    let matched = server.identify(&hello, &table).expect("identifies");
    let mut second = ServerHandshake::new();
    assert!(second.identify(&hello, &table).is_ok());
    assert!(
        server.identify(&hello, &table).is_err(),
        "a second ClientHello on the same handshake denies"
    );

    let _server_hello = server
        .derive(matched, &common::SERVER_NONCE)
        .expect("derives");
    let stale = second.identify(&hello, &table);
    assert!(stale.is_err(), "identify is not repeatable either");
}

/// After a handshake aborts, nothing further is accepted on it.
#[test]
fn an_aborted_handshake_accepts_nothing_further() {
    let mut table = common::table_with_one_client();
    let credential = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Client, 0);
    let (_client, hello) = ClientHandshake::start(&credential, &common::CLIENT_NONCE);
    let mut server = ServerHandshake::new();
    let _matched = server.identify(&hello, &table).expect("identifies");
    server.abort();
    assert_eq!(
        server.identify(&hello, &table).err(),
        Some(TransportCryptoError::WrongState)
    );
    assert_eq!(
        server.accept_client_auth(&[0u8; 32], &mut table).err(),
        Some(TransportCryptoError::WrongState)
    );
}

/// A `ClientHello` of any other length is P2-T3's row H1, surfaced here as a
/// `Wire` failure rather than as an authentication outcome — the bytes never
/// reached key material.
#[test]
fn a_client_hello_of_the_wrong_length_is_a_structural_denial() {
    let table = common::table_with_one_client();
    let mut server = ServerHandshake::new();
    let outcome = server.identify(&[0u8; 63], &table);
    assert!(matches!(outcome, Err(TransportCryptoError::Wire(_))));
}

// ------------------------------------------- teardown, found by coverage
//
// §9.4's teardown obligation had NEVER been executed by a test. In a crypto
// crate, `zeroize` is not housekeeping: it is the whole of the claim that a
// torn-down session leaves no key material behind, and an untested erase is an
// erase nobody has watched happen.

#[test]
fn teardown_destroys_the_session_id_and_both_directions_of_keys() {
    let mut session = common::handshake();

    assert_ne!(
        session.server.session_id, [0u8; 32],
        "the fixture must start with a live session_id"
    );

    session.server.zeroize();

    assert_eq!(
        session.server.session_id, [0u8; 32],
        "§9.4: teardown must destroy the session_id"
    );

    // The client half is independent: tearing one side down must not reach
    // across and mutate the other, or a server teardown would silently break a
    // peer that is still live.
    assert_ne!(
        session.client.session_id, [0u8; 32],
        "tearing down one side must not touch the other"
    );

    session.client.zeroize();
    assert_eq!(session.client.session_id, [0u8; 32]);
}

#[test]
fn teardown_is_idempotent() {
    let mut session = common::handshake();
    session.server.zeroize();
    // A second teardown must not panic or resurrect state: `servd` may unwind a
    // session through more than one path.
    session.server.zeroize();
    assert_eq!(session.server.session_id, [0u8; 32]);
}

#[test]
fn a_default_server_handshake_is_a_new_one() {
    let mut from_default = ServerHandshake::default();
    let mut from_new = ServerHandshake::new();
    assert_eq!(from_default.matched_slot(), from_new.matched_slot());
    assert_eq!(
        from_default.matched_slot(),
        None,
        "a fresh handshake has matched no credential slot yet"
    );

    // And the accessor reports a real slot once the scan has matched one.
    let table = common::table_with_one_client();
    let credential = common::enroll(&common::ENROLLED_MATERIAL, CredentialRole::Client, 0);
    let (_, hello) = ClientHandshake::start(&credential, &common::CLIENT_NONCE);
    let matched = from_new.identify(&hello, &table).expect("identifies");
    from_new
        .derive(matched, &common::SERVER_NONCE)
        .expect("derives");
    assert_eq!(
        from_new.matched_slot(),
        Some(0),
        "the slot is recorded at derive, not at identify"
    );
}
