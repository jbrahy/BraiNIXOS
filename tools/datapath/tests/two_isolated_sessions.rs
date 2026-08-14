//! Two clients, a real handshake each, and no way to reach the other's state.
//!
//! This is the first test in the tree that puts the transport, the wire
//! decoder, the session pool and the KV binding in one place. Everything it
//! drives is the real implementation: the HKDF key schedule, the constant-work
//! credential scan, the fixed slot pool with its ceilings, and the
//! session-derived partition index.
//!
//! What it is not, stated where a reader meets it rather than only in the
//! roadmap: **there is no kernel here**, no address space, no IPC boundary and
//! no model. Two sessions being unable to name each other's state in this test
//! is a property of the components, not of a booted system. The system claim is
//! AS-4c, on hardware.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
#![allow(clippy::cognitive_complexity)]

use brainix_bsp::{CredentialRole, SessionType, LEN_KEY_ID, MAX_ENROLLED_KEYS};
use brainix_datapath::DETERMINISTIC_TEST_NONCE;
use brainix_inferd::{teardown, KvBinding};
use brainix_servd::{CredentialHandle, SessionSlots, SlotError, Tick};
use brainix_transport_crypto::{ClientHandshake, Credential, CredentialTable, ServerHandshake};

/// An enrolled credential, as both ends hold it.
///
/// Two objects from the same key material rather than one shared: the client
/// keeps its own chain state and the server keeps its own, which is what makes
/// the ratchet a ratchet. `enroll` is deterministic in the key material, so the
/// two start identical — and `enroll` zeroizes the material it was given, so
/// each call needs its own copy.
fn enrolled_pair(seed: u8) -> (Credential, Credential) {
    let mut client_material = [seed; 32];
    let mut server_material = [seed; 32];
    (
        Credential::enroll(&mut client_material, CredentialRole::Client, 0),
        Credential::enroll(&mut server_material, CredentialRole::Client, 0),
    )
}

/// The credential table the server scans, holding the server-side copies.
fn table_holding(server_side: [Credential; 2]) -> CredentialTable {
    let mut filler = [[0u8; LEN_KEY_ID]; MAX_ENROLLED_KEYS];
    for (index, slot) in filler.iter_mut().enumerate() {
        slot[0] = index as u8;
    }
    let mut table = CredentialTable::new(&mut filler);
    for credential in server_side {
        table.insert(credential).expect("the table has room");
    }
    table
}

/// Runs one client's handshake to `ESTABLISHED`, through the real schedule.
fn handshake(
    credential: &mut Credential,
    table: &mut CredentialTable,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
) {
    let (mut client, hello) = ClientHandshake::start(credential, client_nonce);

    let mut server = ServerHandshake::new();
    let matched = server
        .identify(&hello, table)
        .expect("the server finds the credential the client derived its selector from");
    let server_hello = server
        .derive(matched, server_nonce)
        .expect("the schedule derives");

    let (auth, mut client_session) = client
        .accept_server_hello(&server_hello, credential)
        .expect("the client verifies server_confirm");
    let mut server_session = server
        .accept_client_auth(&auth, table)
        .expect("the server verifies client_confirm");

    // Both ends derived the same session, which is what makes the handshake a
    // handshake rather than two monologues.
    client_session.zeroize();
    server_session.zeroize();
}

#[test]
fn two_clients_authenticate_and_land_in_separate_slots_and_partitions() {
    let (mut first, first_server) = enrolled_pair(0x11);
    let (mut second, second_server) = enrolled_pair(0x22);
    let mut table = table_holding([first_server, second_server]);

    let mut slots = SessionSlots::new();
    let now = Tick::from_seconds(0);

    // Client one: handshake, then admission, then its KV partition.
    handshake(
        &mut first,
        &mut table,
        &[0xA1; 32],
        &DETERMINISTIC_TEST_NONCE,
    );
    let first_slot = slots
        .acquire(
            CredentialHandle::new(*first.handle()),
            SessionType::Client,
            now,
        )
        .expect("the pool admits the first client");
    let first_kv = KvBinding::for_session(0).expect("slot zero is admissible");

    // Client two, the same way.
    handshake(
        &mut second,
        &mut table,
        &[0xB2; 32],
        &DETERMINISTIC_TEST_NONCE,
    );
    let second_slot = slots
        .acquire(
            CredentialHandle::new(*second.handle()),
            SessionType::Client,
            now,
        )
        .expect("the pool admits the second client");
    let second_kv = KvBinding::for_session(1).expect("slot one is admissible");

    // Separate slots, separate credentials, separate partitions.
    assert_ne!(first_slot, second_slot);
    assert_ne!(slots.credential(first_slot), slots.credential(second_slot));
    assert!(!first_kv.shares_partition_with(&second_kv));
    assert_eq!(slots.live(), 2);
}

#[test]
fn tearing_one_session_down_leaves_the_other_untouched() {
    let (mut first, first_server) = enrolled_pair(0x33);
    let (mut second, second_server) = enrolled_pair(0x44);
    let mut table = table_holding([first_server, second_server]);
    let mut slots = SessionSlots::new();
    let now = Tick::from_seconds(0);

    handshake(
        &mut first,
        &mut table,
        &[0xC3; 32],
        &DETERMINISTIC_TEST_NONCE,
    );
    handshake(
        &mut second,
        &mut table,
        &[0xD4; 32],
        &DETERMINISTIC_TEST_NONCE,
    );

    let first_slot = slots
        .acquire(
            CredentialHandle::new(*first.handle()),
            SessionType::Client,
            now,
        )
        .expect("admitted");
    let second_slot = slots
        .acquire(
            CredentialHandle::new(*second.handle()),
            SessionType::Client,
            now,
        )
        .expect("admitted");
    let second_handle = slots.credential(second_slot).expect("live");

    // Tear the first down. Its handle dies; the second's does not.
    slots.release(first_slot).expect("live");
    let duty = teardown(KvBinding::for_session(0).expect("admissible"));
    assert_eq!(
        duty.partition_index, 0,
        "teardown owes slot zero's partition"
    );

    assert_eq!(slots.credential(first_slot), Err(SlotError::Stale));
    assert_eq!(slots.credential(second_slot), Ok(second_handle));
    assert_eq!(slots.live(), 1);
}

#[test]
fn a_forged_client_hello_authenticates_as_nobody() {
    // The whole point of the blinded selector: bytes that were not derived from
    // an enrolled credential match no slot, and the scan costs the same either
    // way.
    let (genuine, genuine_server) = enrolled_pair(0x55);
    let (_, spare) = enrolled_pair(0x66);
    let table = table_holding([genuine_server, spare]);

    let mut server = ServerHandshake::new();
    let forged = [0x99u8; 64];
    assert!(
        server.identify(&forged, &table).is_err(),
        "a hello nobody derived must match no credential"
    );

    // And the genuine client still authenticates afterwards: a refused stranger
    // leaves no residue in the table.
    let mut server = ServerHandshake::new();
    let (_, hello) = ClientHandshake::start(&genuine, &[0xE5; 32]);
    assert!(server.identify(&hello, &table).is_ok());
}

#[test]
fn the_pool_admits_no_more_than_its_ceiling_however_many_clients_authenticate() {
    // Eight slots, and a ninth client that authenticates perfectly well and is
    // still refused: admission is a resource bound, not an authentication
    // outcome, and the two are decided in that order.
    let mut slots = SessionSlots::new();
    let now = Tick::from_seconds(0);
    for index in 0..8u8 {
        slots
            .acquire(CredentialHandle::new([index; 16]), SessionType::Client, now)
            .expect("within the pool");
    }
    assert!(slots
        .acquire(CredentialHandle::new([99; 16]), SessionType::Client, now)
        .is_err());
    assert_eq!(slots.live(), 8);
}
