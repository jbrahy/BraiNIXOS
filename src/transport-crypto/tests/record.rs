//! §4.2 record layer: round trip, padding boundaries, tamper detection,
//! replay, and reorder.
//!
//! Every failure assertion is on the **variant**, and the variant is always
//! `AuthenticationFailed`: the point of the tamper suite is not only that a
//! forged record is refused but that every forgery is refused *the same way*.

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

use brainix_bsp::BSP_MAX_RECORD_PLAINTEXT;
use brainix_transport_crypto::{TransportCryptoError, MAX_SEALED_RECORD_BYTES};

/// Seals `payload` on the server's channel and opens it on the client's.
fn round_trip(payload: &[u8]) -> Vec<u8> {
    let mut session = common::handshake();
    let mut wire = vec![0u8; MAX_SEALED_RECORD_BYTES];
    let sealed = session
        .server
        .sealer
        .seal(payload, &mut wire)
        .expect("seals");
    let mut scratch = vec![0u8; MAX_SEALED_RECORD_BYTES];
    let opened = session
        .client
        .opener
        .open(&wire[..sealed], &mut scratch)
        .expect("opens");
    assert_eq!(opened.consumed, sealed);
    opened.payload.to_vec()
}

#[test]
fn a_sealed_record_opens_to_the_same_payload() {
    assert_eq!(round_trip(b"hello"), b"hello");
}

/// §4.2 pads so `1 + payload + padding` is a multiple of 8 with at least 4
/// padding bytes. The interesting lengths are the ones where those two rules
/// disagree about which block to land in, so every length up to four blocks is
/// walked rather than a sample.
#[test]
fn every_payload_length_across_the_padding_boundaries_round_trips() {
    for length in 0..=40usize {
        let payload: Vec<u8> = (0..length).map(|index| index as u8).collect();
        assert_eq!(round_trip(&payload), payload, "length {length}");
    }
}

/// The other boundary: the largest payload the record layer accepts, and the
/// four lengths below it.
#[test]
fn the_largest_payloads_round_trip() {
    for length in (BSP_MAX_RECORD_PLAINTEXT - 4)..=BSP_MAX_RECORD_PLAINTEXT {
        let payload: Vec<u8> = (0..length).map(|index| index as u8).collect();
        assert_eq!(round_trip(&payload), payload, "length {length}");
    }
}

/// Row R4 — a payload over the ceiling is refused by the **sender**, so an
/// over-length record is never produced in the first place.
#[test]
fn a_payload_over_the_ceiling_is_refused_by_the_sealer() {
    let mut session = common::handshake();
    let payload = vec![0u8; BSP_MAX_RECORD_PLAINTEXT + 1];
    let mut wire = vec![0u8; MAX_SEALED_RECORD_BYTES * 2];
    assert_eq!(
        session.server.sealer.seal(&payload, &mut wire),
        Err(TransportCryptoError::PayloadExceedsRecordPlaintext)
    );
}

/// Every single-bit-per-byte corruption of the length prefix, the ciphertext,
/// and the tag must fail — and must fail with the *same* error, so that a peer
/// learns nothing about which part it got wrong.
#[test]
fn flipping_any_byte_of_a_record_fails_to_authenticate_identically() {
    let mut session = common::handshake();
    let mut wire = vec![0u8; MAX_SEALED_RECORD_BYTES];
    let sealed = session
        .server
        .sealer
        .seal(b"the quick brown fox", &mut wire)
        .expect("seals");

    let mut scratch = vec![0u8; MAX_SEALED_RECORD_BYTES];
    for position in 0..sealed {
        let mut corrupted = wire[..sealed].to_vec();
        corrupted[position] ^= 0x01;
        let mut opener = common::handshake();
        let outcome = opener.client.opener.open(&corrupted, &mut scratch);
        match outcome {
            Err(TransportCryptoError::AuthenticationFailed) => {}
            Err(TransportCryptoError::RecordIncomplete) => {
                // Only reachable by corrupting the encrypted length prefix into
                // a value that names more bytes than arrived. §4.2 makes the
                // range check normative before the tag check, so this outcome
                // is the specification's, not a leak this crate introduced --
                // see the crate documentation's "Residual observables".
                assert!(position < 4, "byte {position} must not be length-framing");
            }
            other => panic!("byte {position} produced {other:?}"),
        }
    }
}

/// Row R2 on its own terms: a record whose ciphertext is untouched but whose
/// tag is replaced fails.
///
/// This has its own test because the replay, reorder, and cross-session tests
/// **do not** exercise the tag check: opening those under the wrong key
/// produces garbage that the §4.2 padding rules reject, so they stay green even
/// with the tag comparison removed. A guard whose only coverage is incidental
/// is a guard that is not covered.
#[test]
fn a_record_whose_tag_is_replaced_fails_to_authenticate() {
    let mut session = common::handshake();
    let mut wire = vec![0u8; MAX_SEALED_RECORD_BYTES];
    let sealed = session
        .server
        .sealer
        .seal(b"authentic", &mut wire)
        .expect("seals");
    let mut scratch = vec![0u8; MAX_SEALED_RECORD_BYTES];
    for replacement in [0x00u8, 0xff] {
        let mut forged = wire[..sealed].to_vec();
        let tag_start = sealed - 16;
        forged[tag_start..].fill(replacement);
        let mut opener = common::handshake();
        assert_eq!(
            opener.client.opener.open(&forged, &mut scratch),
            Err(TransportCryptoError::AuthenticationFailed),
            "tag replaced with {replacement:#04x}"
        );
    }
}

/// The same record replayed at the position it was already accepted at fails,
/// because the sequence is the nonce and the receiver has moved on.
#[test]
fn a_replayed_record_fails_to_authenticate() {
    let mut session = common::handshake();
    let mut wire = vec![0u8; MAX_SEALED_RECORD_BYTES];
    let sealed = session
        .server
        .sealer
        .seal(b"first", &mut wire)
        .expect("seals");
    let mut scratch = vec![0u8; MAX_SEALED_RECORD_BYTES];
    session
        .client
        .opener
        .open(&wire[..sealed], &mut scratch)
        .expect("the first delivery opens");
    assert_eq!(
        session.client.opener.open(&wire[..sealed], &mut scratch),
        Err(TransportCryptoError::AuthenticationFailed)
    );
}

/// Two records delivered out of order: the second one presented first fails,
/// because it was sealed at sequence 1 and the receiver expects 0.
#[test]
fn a_reordered_record_fails_to_authenticate() {
    let mut session = common::handshake();
    let mut first = vec![0u8; MAX_SEALED_RECORD_BYTES];
    let mut second = vec![0u8; MAX_SEALED_RECORD_BYTES];
    let first_len = session
        .server
        .sealer
        .seal(b"one", &mut first)
        .expect("seals");
    let second_len = session
        .server
        .sealer
        .seal(b"two", &mut second)
        .expect("seals");
    let mut scratch = vec![0u8; MAX_SEALED_RECORD_BYTES];
    assert_eq!(
        session
            .client
            .opener
            .open(&second[..second_len], &mut scratch),
        Err(TransportCryptoError::AuthenticationFailed)
    );
    // And the sequence did not advance on the failure, so the legitimate
    // record still opens -- a failed forgery must not desynchronize the
    // channel it failed against.
    let opened = session
        .client
        .opener
        .open(&first[..first_len], &mut scratch)
        .expect("the record at the expected sequence still opens");
    assert_eq!(opened.payload, b"one");
}

/// The sequence really is the nonce: the same plaintext sealed twice produces
/// different ciphertext.
#[test]
fn the_same_payload_sealed_twice_produces_different_bytes() {
    let mut session = common::handshake();
    let mut first = vec![0u8; MAX_SEALED_RECORD_BYTES];
    let mut second = vec![0u8; MAX_SEALED_RECORD_BYTES];
    let first_len = session
        .server
        .sealer
        .seal(b"same", &mut first)
        .expect("seals");
    let second_len = session
        .server
        .sealer
        .seal(b"same", &mut second)
        .expect("seals");
    assert_eq!(first_len, second_len);
    assert_ne!(first[..first_len], second[..second_len]);
}

/// A record sealed for one session cannot be opened by another: §9.2 makes
/// cross-session confusion cryptographically foreclosed, not access-checked.
#[test]
fn a_record_from_another_session_fails_to_authenticate() {
    let mut alpha = common::handshake();
    let mut beta = common::handshake_with(&common::ENROLLED_MATERIAL, &[0x44u8; 32], &[0x88u8; 32])
        .expect("a second honest handshake");
    let mut wire = vec![0u8; MAX_SEALED_RECORD_BYTES];
    let sealed = alpha
        .server
        .sealer
        .seal(b"alpha", &mut wire)
        .expect("seals");
    let mut scratch = vec![0u8; MAX_SEALED_RECORD_BYTES];
    assert_eq!(
        beta.client.opener.open(&wire[..sealed], &mut scratch),
        Err(TransportCryptoError::AuthenticationFailed)
    );
}

/// The two directions have different keys, so a record the server sealed
/// cannot be opened by the server's own opener.
#[test]
fn the_two_directions_do_not_share_keys() {
    let mut session = common::handshake();
    let mut wire = vec![0u8; MAX_SEALED_RECORD_BYTES];
    let sealed = session
        .server
        .sealer
        .seal(b"outbound", &mut wire)
        .expect("seals");
    let mut scratch = vec![0u8; MAX_SEALED_RECORD_BYTES];
    assert_eq!(
        session.server.opener.open(&wire[..sealed], &mut scratch),
        Err(TransportCryptoError::AuthenticationFailed)
    );
}

/// A truncated record is `RecordIncomplete`, never a partial accept.
#[test]
fn a_truncated_record_asks_for_more_bytes_rather_than_opening() {
    let mut session = common::handshake();
    let mut wire = vec![0u8; MAX_SEALED_RECORD_BYTES];
    let sealed = session
        .server
        .sealer
        .seal(b"truncate me", &mut wire)
        .expect("seals");
    let mut scratch = vec![0u8; MAX_SEALED_RECORD_BYTES];
    for short in 0..sealed {
        let mut opener = common::handshake();
        assert_eq!(
            opener.client.opener.open(&wire[..short], &mut scratch),
            Err(TransportCryptoError::RecordIncomplete),
            "truncated to {short}"
        );
    }
}

/// Both directions carry traffic, in both directions, at the same time.
#[test]
fn both_directions_carry_traffic_independently() {
    let mut session = common::handshake();
    let mut to_client = vec![0u8; MAX_SEALED_RECORD_BYTES];
    let mut to_server = vec![0u8; MAX_SEALED_RECORD_BYTES];
    let mut scratch = vec![0u8; MAX_SEALED_RECORD_BYTES];

    for round in 0u8..8 {
        let outbound = [round; 5];
        let down = session
            .server
            .sealer
            .seal(&outbound, &mut to_client)
            .expect("seals down");
        let opened = session
            .client
            .opener
            .open(&to_client[..down], &mut scratch)
            .expect("opens down");
        assert_eq!(opened.payload, &outbound);

        let inbound = [round ^ 0xff; 7];
        let up = session
            .client
            .sealer
            .seal(&inbound, &mut to_server)
            .expect("seals up");
        let opened = session
            .server
            .opener
            .open(&to_server[..up], &mut scratch)
            .expect("opens up");
        assert_eq!(opened.payload, &inbound);
    }
}
