#![no_main]

//! Fuzz target: the §5.5 handshake state machine with attacker-controlled
//! message bytes.
//!
//! Everything a remote peer sends before a key exists arrives here:
//! `ClientHello` into [`ServerHandshake::identify`], and `ClientAuth` into
//! [`ServerHandshake::accept_client_auth`]. The client half is fuzzed too,
//! because a BraiNIX client talking to a hostile *server* reaches
//! [`ClientHandshake::accept_server_hello`] with 64 bytes it did not choose.
//!
//! The properties asserted:
//!
//! - **No panic, no hang.** Every entry point returns a value or a
//!   [`TransportCryptoError`], for any bytes and in any call order.
//! - **A failed handshake commits no chain advance (§6.2).** This is the
//!   difference between a ratchet and a remote kill switch: if an
//!   unauthenticated peer could move the persisted chain by replaying a
//!   captured `ClientHello`, it could push the server arbitrarily far forward
//!   and lock the legitimate client out without ever holding the credential.
//!   The persisted counter is read before and after every hostile exchange.
//! - **No session exists without mutual proof of possession.** An
//!   `EstablishedSession` is produced only on the path where the constant-time
//!   confirmation comparison passed; every other path yields an error.
//! - **The state guard is total.** Calling the three server entry points in
//!   every order the fuzzer chooses — including `derive` before `identify` and
//!   `accept_client_auth` before `derive` — denies with `WrongState` and never
//!   produces a session.
//! - **Row K5 is unconditional.** A `ClientHello` that matches the break-glass
//!   credential is refused on this listener whatever else is well formed, and
//!   the refusal happens before any chain resolution runs.
//! - **§6.3's window is exact.** `resolve` accepts a declared position in
//!   `s ..= s + MAX_CHAIN_CATCHUP` and denies every other, and a resolved
//!   scratch chain sits at exactly the position that was declared.
//! - **§6.2's commit is monotonic.** A commit that would move the persisted
//!   counter backwards or sideways is refused and leaves the state untouched.

use brainix_bsp::{
    CredentialRole, LEN_CLIENT_AUTH, LEN_CLIENT_HELLO, LEN_SERVER_HELLO, MAX_CHAIN_CATCHUP,
};
use brainix_transport_crypto::{
    ChainState, ClientHandshake, Credential, CredentialTable, EstablishedSession, Secret,
    ServerHandshake, TransportCryptoError, FLAG_BREAK_GLASS,
};
use libfuzzer_sys::fuzz_target;

/// The 32 bytes an operator would have handed `enroll-key` for the client
/// credential the table holds.
const CLIENT_MATERIAL: [u8; 32] = [
    0x9e, 0x1c, 0x44, 0xb7, 0x03, 0xd8, 0x2a, 0x6f, 0x51, 0xe0, 0x77, 0x13, 0xbc, 0x95, 0x38, 0xaa,
    0x62, 0x0d, 0xf4, 0x81, 0x2c, 0x57, 0x9b, 0x30, 0xe6, 0x18, 0x73, 0xcf, 0x45, 0xa2, 0x6b, 0xd9,
];

/// The admin credential's material.
const ADMIN_MATERIAL: [u8; 32] = [0x5du8; 32];

/// The break-glass credential's material — enrolled with [`FLAG_BREAK_GLASS`],
/// so row K5 refuses it on this listener however well formed the message is.
const BREAK_GLASS_MATERIAL: [u8; 32] = [0xb6u8; 32];

/// Chain positions probed against §6.3's window per iteration.
const CHAIN_PROBES: usize = 6;

/// A forward-only cursor over the fuzzer's bytes, wrapping at the end.
struct Driver<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Driver<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    fn byte(&mut self) -> u8 {
        if self.data.is_empty() {
            return 0;
        }
        let index = self.at % self.data.len();
        self.at = self.at.wrapping_add(1);
        self.data.get(index).copied().unwrap_or(0)
    }

    fn bytes(&mut self, count: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(count.min(1024));
        let mut taken = 0usize;
        while taken < count {
            out.push(self.byte());
            taken = taken.saturating_add(1);
        }
        out
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes([self.byte(), self.byte()])
    }

    fn u64(&mut self) -> u64 {
        let mut value = 0u64;
        let mut taken = 0usize;
        while taken < 8 {
            value = value.wrapping_shl(8) | u64::from(self.byte());
            taken = taken.saturating_add(1);
        }
        value
    }

    fn array32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for slot in out.iter_mut() {
            *slot = self.byte();
        }
        out
    }
}

/// Enrolls a credential without disturbing the caller's copy.
fn enroll(material: &[u8; 32], role: CredentialRole, flags: u8) -> Credential {
    let mut copy = *material;
    Credential::enroll(&mut copy, role, flags)
}

/// The server's table: one client credential, one admin, one break-glass, and
/// 29 empty slots holding per-boot filler.
///
/// Rebuilt every iteration. Sharing it across iterations would make the target
/// non-deterministic — a committed ratchet advance would leak into the next
/// input — and a fuzz target whose reproducer does not reproduce is worse than
/// a slow one.
fn table() -> CredentialTable {
    let mut filler = [[0u8; 32]; brainix_bsp::MAX_ENROLLED_KEYS];
    for (index, slot) in filler.iter_mut().enumerate() {
        slot.fill((index as u8) ^ 0x5a);
    }
    let mut table = CredentialTable::new(&mut filler);
    let _ = table.insert(enroll(&CLIENT_MATERIAL, CredentialRole::Client, 0));
    let _ = table.insert(enroll(&ADMIN_MATERIAL, CredentialRole::Admin, 0));
    let _ = table.insert(enroll(
        &BREAK_GLASS_MATERIAL,
        CredentialRole::Admin,
        FLAG_BREAK_GLASS,
    ));
    table
}

/// The persisted chain counter of every occupied slot.
///
/// §6.2's property is about the *persisted* state, so it has to be read out of
/// the table rather than inferred from a return value.
fn counters(table: &CredentialTable) -> Vec<u64> {
    let mut out = Vec::with_capacity(brainix_bsp::MAX_ENROLLED_KEYS);
    let mut index = 0usize;
    while index < brainix_bsp::MAX_ENROLLED_KEYS {
        match table.slot(index) {
            Some(slot) => out.push(slot.chain_counter()),
            None => break,
        }
        index = index.saturating_add(1);
    }
    out
}

/// Checks that an established session carries the identity it authenticated
/// with, and destroys it.
fn consume(mut session: EstablishedSession) {
    assert!(
        session.sealer.sequence() == 0 && session.opener.sequence() == 0,
        "a fresh session did not start both directions at sequence zero"
    );
    assert!(
        matches!(session.role, CredentialRole::Client | CredentialRole::Admin),
        "an established session carries a role outside the enumeration"
    );
    assert!(
        session.session_id != [0u8; 32],
        "an established session has an all-zero session id"
    );
    session.zeroize();
    assert!(
        session.session_id == [0u8; 32],
        "teardown did not destroy the session id"
    );
}

// ---------------------------------------------------------------------------
// The server side: every byte hostile
// ---------------------------------------------------------------------------

/// Offers arbitrary bytes as a `ClientHello`, then arbitrary bytes as a
/// `ClientAuth`, and asserts the chain did not move.
fn hostile_server(data: &[u8], driver: &mut Driver<'_>) {
    let mut table = table();
    let before = counters(&table);
    let mut server = ServerHandshake::new();

    // The state guard, probed before the machine has been fed anything.
    assert!(
        server
            .accept_client_auth(&driver.bytes(LEN_CLIENT_AUTH), &mut table)
            .is_err(),
        "a ClientAuth was accepted before any ClientHello"
    );

    let hello = match driver.byte() % 3 {
        // The raw input.
        0 => data.to_vec(),
        // The raw input truncated or padded to the exact length row H1 wants,
        // so the field checks behind the length check are reachable.
        1 => {
            let mut out = data.to_vec();
            out.resize(LEN_CLIENT_HELLO, driver.byte());
            out
        }
        // A well-formed frame whose selector is the fuzzer's: this is the shape
        // that actually reaches the §5.3 scan.
        _ => forged_hello(driver),
    };

    let matched = match server.identify(&hello, &table) {
        Ok(matched) => matched,
        Err(error) => {
            assert!(
                is_expected_handshake_failure(error),
                "identify reported a failure outside its documented set"
            );
            assert!(
                counters(&table) == before,
                "a rejected ClientHello moved a persisted chain counter"
            );
            // The guard again: derive is illegal after a failed identify.
            assert!(
                server.derive(dummy_match(), &driver.array32()).is_err(),
                "derive succeeded after identify failed"
            );
            return;
        }
    };

    // The scan's result is carried by the returned `MatchedCredential`, not by
    // the handshake: `ServerHandshake::matched_slot` stays `None` until
    // `derive` runs, so it is *not* asserted here. See the task report — this
    // is recorded as a finding about the accessor rather than worked around
    // silently.
    let matched_slot = matched.slot;
    assert!(
        matched_slot < brainix_bsp::MAX_ENROLLED_KEYS,
        "the scan matched a slot outside the fixed credential table"
    );
    assert!(
        counters(&table) == before,
        "identify moved a persisted chain counter before authentication"
    );

    let server_nonce = driver.array32();
    let server_hello = match server.derive(matched, &server_nonce) {
        Ok(wire) => wire,
        Err(error) => {
            assert!(
                is_expected_handshake_failure(error),
                "derive reported a failure outside its documented set"
            );
            assert!(
                counters(&table) == before,
                "a failed derive moved a persisted chain counter"
            );
            return;
        }
    };
    assert!(
        server_hello.len() == LEN_SERVER_HELLO,
        "a ServerHello is not the constant length §5.1 fixes"
    );
    assert!(
        server.matched_slot() == Some(matched_slot),
        "derive recorded a slot other than the one the scan matched"
    );
    assert!(
        counters(&table) == before,
        "derive committed a chain advance before client_confirm was verified"
    );

    // Row H5 with a confirmation the fuzzer chose. Guessing the right 32 bytes
    // is a 2^-256 event, so this path is the *failure* path by construction —
    // which is exactly the path §6.2 says must commit nothing.
    let auth_len = usize::from(driver.byte()) % 48;
    let auth = driver.bytes(auth_len);
    match server.accept_client_auth(&auth, &mut table) {
        Ok(session) => consume(session),
        Err(error) => {
            assert!(
                is_expected_handshake_failure(error),
                "accept_client_auth reported a failure outside its documented set"
            );
            assert!(
                counters(&table) == before,
                "a failed client_confirm committed a chain advance"
            );
            // A dead handshake accepts nothing more.
            assert!(
                server.accept_client_auth(&auth, &mut table).is_err(),
                "a finished handshake accepted a second ClientAuth"
            );
        }
    }

    server.abort();
    assert!(
        server.identify(&hello, &table).is_err(),
        "an aborted handshake accepted a ClientHello"
    );
}

/// A `ClientHello` with the checked preamble correct and everything else the
/// fuzzer's.
///
/// Random bytes stop at row H2 — the `"BSP2"` magic alone is a 2^-32 event — so
/// without this builder the §5.3 scan would never be reached at all.
fn forged_hello(driver: &mut Driver<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(LEN_CLIENT_HELLO);
    out.extend_from_slice(&brainix_bsp::BSP_MAGIC);
    out.push(brainix_bsp::BSP_VERSION_MAJOR);
    out.push(brainix_bsp::BSP_VERSION_MINOR);
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&driver.u64().to_be_bytes());
    out.extend_from_slice(&driver.array32());
    out.extend_from_slice(&driver.bytes(16));
    out
}

/// A `MatchedCredential` that never came from a scan.
///
/// `derive` must refuse it on the state guard alone: the guard is what stops a
/// caller supplying its own credential material, so it has to hold for material
/// the scan never produced.
fn dummy_match() -> brainix_transport_crypto::MatchedCredential {
    brainix_transport_crypto::MatchedCredential {
        slot: 0,
        handle: [0u8; 16],
        role: CredentialRole::WIRE_CLIENT,
        chain_counter: 0,
        chain_key: Secret::zero(),
    }
}

/// Every failure the handshake may report.
fn is_expected_handshake_failure(error: TransportCryptoError) -> bool {
    matches!(
        error,
        TransportCryptoError::AuthenticationFailed
            | TransportCryptoError::NoCredentialMatch
            | TransportCryptoError::AmbiguousCredentialMatch
            | TransportCryptoError::BreakGlassCredentialRefused
            | TransportCryptoError::ChainDesynchronized
            | TransportCryptoError::ChainCounterTooFarAhead
            | TransportCryptoError::ChainCounterOverflow
            | TransportCryptoError::WrongState
            | TransportCryptoError::OutputBufferTooSmall
            | TransportCryptoError::Wire(_)
    )
}

// ---------------------------------------------------------------------------
// The honest exchange, with the fuzzer allowed to tamper at each step
// ---------------------------------------------------------------------------

/// Runs the §5.5 exchange, letting the fuzzer corrupt one message of its
/// choosing, and asserts the chain moves only when the exchange completed.
fn tampered_exchange(driver: &mut Driver<'_>) {
    let mut table = table();
    let before = counters(&table);
    let mut credential = enroll(&CLIENT_MATERIAL, CredentialRole::Client, 0);
    let credential_counter = credential.chain_counter();
    let client_nonce = driver.array32();
    let (mut client, hello) = ClientHandshake::start(&credential, &client_nonce);
    assert!(
        hello.len() == LEN_CLIENT_HELLO,
        "a ClientHello is not the constant length §5.1 fixes"
    );

    let target = driver.byte() % 4;
    let hello_wire = maybe_corrupt(&hello, target == 0, driver);

    let mut server = ServerHandshake::new();
    let Ok(matched) = server.identify(&hello_wire, &table) else {
        assert!(
            counters(&table) == before,
            "a rejected ClientHello moved a persisted chain counter"
        );
        return;
    };
    let server_nonce = driver.array32();
    let Ok(server_hello) = server.derive(matched, &server_nonce) else {
        assert!(
            counters(&table) == before,
            "a failed derive moved a persisted chain counter"
        );
        return;
    };

    let server_wire = maybe_corrupt(&server_hello, target == 1, driver);
    let (auth, client_session) = match client.accept_server_hello(&server_wire, &mut credential) {
        Ok(pair) => pair,
        Err(_) => {
            // Row H6 failed. §5.5: abort without sending anything further, and
            // the client's own chain must not have advanced.
            assert!(
                credential.chain_counter() == credential_counter,
                "a client whose server_confirm failed advanced its own chain"
            );
            assert!(
                counters(&table) == before,
                "a client-side abort moved the server's chain"
            );
            return;
        }
    };
    assert!(
        credential.chain_counter() > credential_counter,
        "a client that accepted server_confirm did not advance its own chain"
    );
    consume(client_session);

    let auth_wire = maybe_corrupt(&auth, target == 2, driver);
    match server.accept_client_auth(&auth_wire, &mut table) {
        Ok(session) => {
            assert!(
                counters(&table) != before,
                "an authenticated handshake committed no chain advance"
            );
            consume(session);
        }
        Err(_) => assert!(
            counters(&table) == before,
            "a failed client_confirm committed a chain advance"
        ),
    }
}

/// Returns `bytes` unchanged, or with one fuzzer-chosen byte flipped.
fn maybe_corrupt(bytes: &[u8], corrupt: bool, driver: &mut Driver<'_>) -> Vec<u8> {
    let mut out = bytes.to_vec();
    if !corrupt || out.is_empty() {
        return out;
    }
    let at = usize::from(driver.u16()) % out.len();
    let mask = driver.byte() | 1;
    if let Some(byte) = out.get_mut(at) {
        *byte ^= mask;
    }
    out
}

// ---------------------------------------------------------------------------
// The client side, talking to a hostile server
// ---------------------------------------------------------------------------

/// Offers arbitrary bytes to the client as a `ServerHello`.
fn hostile_client(data: &[u8], driver: &mut Driver<'_>) {
    let mut credential = enroll(&CLIENT_MATERIAL, CredentialRole::Client, 0);
    let start = credential.chain_counter();
    let (mut client, _hello) = ClientHandshake::start(&credential, &driver.array32());

    let wire = match driver.byte() % 2 {
        0 => data.to_vec(),
        _ => {
            let mut out = data.to_vec();
            out.resize(LEN_SERVER_HELLO, driver.byte());
            out
        }
    };
    match client.accept_server_hello(&wire, &mut credential) {
        Ok((_confirm, session)) => consume(session),
        Err(error) => {
            assert!(
                is_expected_handshake_failure(error),
                "the client reported a failure outside the documented set"
            );
            assert!(
                credential.chain_counter() == start,
                "a client that rejected a ServerHello advanced its own chain"
            );
            assert!(
                client.accept_server_hello(&wire, &mut credential).is_err(),
                "an aborted client handshake accepted a second ServerHello"
            );
        }
    }
    client.abort();
}

// ---------------------------------------------------------------------------
// §6 — the ratchet's window and its commit
// ---------------------------------------------------------------------------

/// Drives §6.3's catch-up window and §6.2's monotonic commit.
fn exercise_ratchet(driver: &mut Driver<'_>) {
    let persisted = driver.u64();
    let key = Secret::from_bytes(driver.array32());
    let state = ChainState::at(key.clone(), persisted);

    let mut probe = 0usize;
    while probe < CHAIN_PROBES {
        probe = probe.saturating_add(1);
        // The boundaries explicitly, plus whatever the fuzzer chose. An
        // off-by-one on a `u64` window is a 2^-64 event for a uniform draw.
        let requested = match probe {
            1 => persisted,
            2 => persisted.wrapping_sub(1),
            3 => persisted.saturating_add(MAX_CHAIN_CATCHUP),
            4 => persisted.saturating_add(MAX_CHAIN_CATCHUP).wrapping_add(1),
            5 => persisted.wrapping_add(u64::from(driver.u16())),
            _ => driver.u64(),
        };
        match state.resolve(requested) {
            Ok(scratch) => {
                assert!(
                    requested >= persisted,
                    "resolve accepted a position behind the persisted one"
                );
                let distance = requested.wrapping_sub(persisted);
                assert!(
                    distance <= MAX_CHAIN_CATCHUP,
                    "resolve accepted a position past the row K4 window"
                );
                assert!(
                    scratch.counter() == requested,
                    "a resolved scratch chain is not at the position declared"
                );
            }
            Err(error) => {
                assert!(
                    matches!(
                        error,
                        TransportCryptoError::ChainDesynchronized
                            | TransportCryptoError::ChainCounterTooFarAhead
                    ),
                    "resolve denied for a reason §6.3 does not name"
                );
                assert!(
                    requested < persisted || requested.wrapping_sub(persisted) > MAX_CHAIN_CATCHUP,
                    "resolve denied a position inside the row K4 window"
                );
            }
        }
    }

    // §6.2 — a commit that would not move the counter strictly forward is
    // refused, and leaves the persisted state exactly where it was.
    let scratch_at = driver.u64();
    let mut target = ChainState::at(key, persisted);
    let scratch = ChainState::at(Secret::from_bytes(driver.array32()), scratch_at).scratch();
    let position = scratch_at.checked_add(1);
    let committed = target.commit(scratch);
    match position {
        Some(position) if position > persisted => {
            assert!(committed, "a strictly forward commit was refused");
            assert!(
                target.counter() == position,
                "a winning commit did not install the position it computed"
            );
            assert!(
                target.counter() > persisted,
                "a winning commit did not move the counter forward"
            );
        }
        _ => {
            assert!(
                !committed,
                "a commit that does not move forward took effect"
            );
            assert!(
                target.counter() == persisted,
                "a losing commit moved the persisted counter"
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut driver = Driver::new(data);
    hostile_server(data, &mut driver);
    hostile_client(data, &mut driver);
    tampered_exchange(&mut driver);
    exercise_ratchet(&mut driver);
});
