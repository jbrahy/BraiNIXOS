//! Well-formed inputs decode to exactly the values the specification's tables
//! say they carry.
//!
//! These tests pin the **offsets**. A decoder that reads the right number of
//! bytes from the wrong place still passes every adversarial test in the suite
//! next door, so the field values are asserted individually and against
//! fixtures whose bytes were laid out from §5.1, §10.2, and §10.4 by hand.

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

use brainix_bsp::record::{
    decode_record_plaintext, encode_record_plaintext, split_data_record, MAX_PACKET_LENGTH,
    MIN_PACKET_LENGTH, RECORD_LENGTH_PREFIX_BYTES, RECORD_TAG_BYTES,
};
use brainix_bsp::{
    AdminResponse, AdminVerb, ClientAuth, ClientHello, ClientRequest, ClientResponse,
    CredentialRole, FinishReason, InboundMessage, InferBegin, PacketLength, RequestPhase,
    RestartTarget, SequenceCounter, ServerHello, Session, SessionState, SessionType,
    LEN_CLIENT_AUTH, LEN_CLIENT_HELLO, LEN_SERVER_HELLO, MAX_AUDIT_CHUNK, MAX_PROMPT_BYTES,
    MAX_PROMPT_CHUNK, MAX_TOKENS_REQUESTED, MAX_TOKEN_CHUNK,
};
use common::{
    all_six_verbs, cancel, client_auth, client_hello, close, enroll_key, established, infer_begin,
    infer_commit, load_weights, nonce, prompt_chunk, read_audit_log, reboot, record_plaintext,
    restart_server, revoke_key, server_hello, sixteen,
};

// ---------------------------------------------------------------------------
// §8 — the const table matches the specification
// ---------------------------------------------------------------------------

#[test]
fn the_const_table_matches_the_specification() {
    assert_eq!(LEN_CLIENT_HELLO, 64);
    assert_eq!(LEN_SERVER_HELLO, 64);
    assert_eq!(LEN_CLIENT_AUTH, 32);
    assert_eq!(MAX_PROMPT_BYTES, 16384);
    assert_eq!(MAX_PROMPT_CHUNK, 4032);
    assert_eq!(MAX_TOKEN_CHUNK, 512);
    assert_eq!(MAX_TOKENS_REQUESTED, 4096);
    assert_eq!(MAX_AUDIT_CHUNK, 1024);
    assert_eq!(MIN_PACKET_LENGTH, 2);
    assert_eq!(MAX_PACKET_LENGTH, 35000);
}

#[test]
fn a_prompt_chunk_fits_one_record_with_room_for_its_header() {
    // §8: MAX_PROMPT_CHUNK ≤ BSP_MAX_RECORD_PLAINTEXT − header, where the
    // header is tag[1] + request_id[4] + len[2].
    let framed = 1 + 4 + 2 + MAX_PROMPT_CHUNK;
    assert!(framed <= brainix_bsp::BSP_MAX_RECORD_PLAINTEXT);
}

// ---------------------------------------------------------------------------
// §5.1 — handshake field offsets
// ---------------------------------------------------------------------------

#[test]
fn a_client_hello_decodes_every_field_at_its_specified_offset() {
    let client_nonce = nonce(0xa1);
    let selector = sixteen(0x30);
    let bytes = client_hello(0x0123_4567_89ab_cdef, client_nonce, selector);

    // Offsets, re-derived from §5.1 rather than trusted from the builder.
    assert_eq!(&bytes[0..4], b"BSP2");
    assert_eq!(bytes[4], 2);
    assert_eq!(bytes[5], 0);
    assert_eq!(&bytes[6..8], &[0, 0]);

    let decoded = ClientHello::decode(&bytes).unwrap();
    assert_eq!(decoded.chain_counter, 0x0123_4567_89ab_cdef);
    assert_eq!(decoded.client_nonce, client_nonce);
    assert_eq!(decoded.key_selector, selector);
}

#[test]
fn a_chain_counter_is_decoded_big_endian_and_never_bounded_here() {
    // §6.3's comparison is against persisted state this crate cannot see, so
    // every 64-bit value decodes. u64::MAX included.
    for counter in [0, 1, u64::MAX, u64::from(u32::MAX)] {
        let bytes = client_hello(counter, nonce(1), sixteen(1));
        assert_eq!(ClientHello::decode(&bytes).unwrap().chain_counter, counter);
    }
}

#[test]
fn a_server_hello_round_trips_through_the_encoder() {
    let server_nonce = nonce(0x5a);
    let server_confirm = nonce(0x77);
    let expected = server_hello(server_nonce, server_confirm);

    let message = ServerHello {
        server_nonce,
        server_confirm,
    };
    let mut out = [0u8; LEN_SERVER_HELLO];
    assert_eq!(message.encode(&mut out).unwrap(), LEN_SERVER_HELLO);
    assert_eq!(&out[..], &expected[..]);
    assert_eq!(ServerHello::decode(&out).unwrap(), message);
}

#[test]
fn a_client_auth_decodes_its_confirmation_value() {
    let confirm = nonce(0xc3);
    let decoded = ClientAuth::decode(&client_auth(confirm)).unwrap();
    assert_eq!(decoded.client_confirm, confirm);
}

// ---------------------------------------------------------------------------
// §10.2 — client-session message shapes
// ---------------------------------------------------------------------------

#[test]
fn an_infer_begin_decodes_all_five_fields() {
    let bytes = infer_begin(0x1122_3344, 4096, 700, 950, 16384);
    let decoded = ClientRequest::decode(&bytes).unwrap();
    assert_eq!(
        decoded,
        ClientRequest::InferBegin(InferBegin {
            request_id: 0x1122_3344,
            max_tokens: 4096,
            temperature: 700,
            top_p: 950,
            prompt_total_length: 16384,
        })
    );
}

#[test]
fn a_prompt_chunk_borrows_its_bytes_without_copying_them() {
    let payload = prompt_chunk(9, b"hello world");
    match ClientRequest::decode(&payload).unwrap() {
        ClientRequest::PromptChunk { request_id, chunk } => {
            assert_eq!(request_id, 9);
            assert_eq!(chunk, b"hello world");
            // The borrow points into the caller's buffer, not into a copy.
            assert_eq!(chunk.as_ptr(), payload[7..].as_ptr());
        }
        other => panic!("expected PromptChunk, got {other:?}"),
    }
}

#[test]
fn a_prompt_chunk_of_exactly_the_maximum_length_is_accepted() {
    let chunk = vec![0x5au8; MAX_PROMPT_CHUNK];
    let payload = prompt_chunk(1, &chunk);
    match ClientRequest::decode(&payload).unwrap() {
        ClientRequest::PromptChunk { chunk: decoded, .. } => {
            assert_eq!(decoded.len(), MAX_PROMPT_CHUNK);
        }
        other => panic!("expected PromptChunk, got {other:?}"),
    }
}

#[test]
fn a_zero_length_prompt_chunk_is_a_legal_var_bytes_field() {
    // §3 form 3 bounds `len` above and not below; a zero-length chunk is
    // structurally fine and is refused, if at all, by the reassembly guard.
    match ClientRequest::decode(&prompt_chunk(1, b"")).unwrap() {
        ClientRequest::PromptChunk { chunk, .. } => assert!(chunk.is_empty()),
        other => panic!("expected PromptChunk, got {other:?}"),
    }
}

#[test]
fn the_remaining_client_messages_decode_to_their_specified_shapes() {
    assert_eq!(
        ClientRequest::decode(&infer_commit(5)).unwrap(),
        ClientRequest::InferCommit { request_id: 5 }
    );
    assert_eq!(
        ClientRequest::decode(&cancel(5)).unwrap(),
        ClientRequest::Cancel { request_id: 5 }
    );
    assert_eq!(
        ClientRequest::decode(&close()).unwrap(),
        ClientRequest::Close
    );
}

#[test]
fn a_request_id_at_both_boundary_values_round_trips() {
    // §10.1 defines request_id as opaque and peer-chosen, so no value is
    // reserved. 0 in particular must not be read as "absent".
    for request_id in [0u32, 1, u32::MAX - 1, u32::MAX] {
        assert_eq!(
            ClientRequest::decode(&infer_commit(request_id))
                .unwrap()
                .request_id(),
            Some(request_id)
        );
        assert_eq!(
            AdminVerb::decode(&reboot(request_id)).unwrap().request_id(),
            request_id
        );
    }
}

// ---------------------------------------------------------------------------
// §10.4 — all six verbs, and only six
// ---------------------------------------------------------------------------

#[test]
fn all_six_admin_verbs_decode() {
    let decoded: Vec<AdminVerb> = all_six_verbs()
        .iter()
        .map(|bytes| AdminVerb::decode(bytes).unwrap())
        .collect();
    assert_eq!(decoded.len(), 6);
    assert!(matches!(decoded[0], AdminVerb::EnrollKey { .. }));
    assert!(matches!(decoded[1], AdminVerb::RevokeKey { .. }));
    assert!(matches!(decoded[2], AdminVerb::LoadWeights { .. }));
    assert!(matches!(decoded[3], AdminVerb::ReadAuditLog { .. }));
    assert!(matches!(decoded[4], AdminVerb::RestartServer { .. }));
    assert!(matches!(decoded[5], AdminVerb::Reboot { .. }));
}

#[test]
fn an_enroll_key_decodes_its_role_and_its_key_material() {
    let material = nonce(0x11);
    for (wire, role) in [
        (0x01u8, CredentialRole::Client),
        (0x02, CredentialRole::Admin),
    ] {
        let decoded = AdminVerb::decode(&enroll_key(42, wire, material)).unwrap();
        assert_eq!(
            decoded,
            AdminVerb::EnrollKey {
                request_id: 42,
                role,
                key_material: material,
            }
        );
        assert_eq!(role.to_wire(), wire);
    }
}

#[test]
fn a_revoke_key_decodes_its_sixteen_byte_handle() {
    let handle = sixteen(0x22);
    assert_eq!(
        AdminVerb::decode(&revoke_key(7, handle)).unwrap(),
        AdminVerb::RevokeKey {
            request_id: 7,
            handle,
        }
    );
}

#[test]
fn a_load_weights_decodes_a_digest_and_names_no_path() {
    let digest = nonce(0x33);
    assert_eq!(
        AdminVerb::decode(&load_weights(8, digest)).unwrap(),
        AdminVerb::LoadWeights {
            request_id: 8,
            weights_digest: digest,
        }
    );
}

#[test]
fn a_read_audit_log_decodes_at_exactly_the_record_ceiling() {
    assert_eq!(
        AdminVerb::decode(&read_audit_log(9, u64::MAX, 64)).unwrap(),
        AdminVerb::ReadAuditLog {
            request_id: 9,
            cursor: u64::MAX,
            max_records: 64,
        }
    );
}

#[test]
fn every_restart_target_decodes_to_its_enumerated_identity() {
    for (wire, target) in [
        (0x01u8, RestartTarget::Servd),
        (0x02, RestartTarget::Inferd),
        (0x03, RestartTarget::Auditd),
        (0x04, RestartTarget::Gpud),
    ] {
        assert_eq!(
            AdminVerb::decode(&restart_server(10, wire)).unwrap(),
            AdminVerb::RestartServer {
                request_id: 10,
                target,
            }
        );
        assert_eq!(target.to_wire(), wire);
    }
}

// ---------------------------------------------------------------------------
// §4.2 — record framing
// ---------------------------------------------------------------------------

#[test]
fn a_packet_length_at_both_bounds_is_accepted() {
    for value in [MIN_PACKET_LENGTH, 4096, MAX_PACKET_LENGTH] {
        let decoded = PacketLength::decode(value.to_be_bytes()).unwrap();
        assert_eq!(decoded.value(), value);
        assert_eq!(
            decoded.record_length().unwrap(),
            RECORD_LENGTH_PREFIX_BYTES + value as usize + RECORD_TAG_BYTES
        );
    }
}

#[test]
fn a_data_record_splits_into_ciphertext_and_tag_without_copying() {
    let stream = common::data_record(64);
    let length = PacketLength::decode(64u32.to_be_bytes()).unwrap();
    let record = split_data_record(&stream, length).unwrap();
    assert_eq!(record.ciphertext.len(), 64);
    assert_eq!(record.tag.len(), RECORD_TAG_BYTES);
    assert_eq!(record.total_length, 4 + 64 + 16);
    assert_eq!(record.ciphertext.as_ptr(), stream[4..].as_ptr());
}

#[test]
fn a_record_plaintext_round_trips_through_both_directions() {
    for payload_length in [0usize, 1, 7, 8, 100, 4095, 4096] {
        let payload = vec![0x5au8; payload_length];
        let mut framed = [0u8; 4112];
        let written = encode_record_plaintext(&payload, &mut framed).unwrap();

        assert_eq!(written % 8, 0, "§4.2 multiple of 8");
        assert!(framed[0] >= 4, "§4.2 at least 4 padding bytes");

        let length = PacketLength::decode((written as u32).to_be_bytes()).unwrap();
        let recovered = decode_record_plaintext(&framed[..written], length).unwrap();
        assert_eq!(recovered, &payload[..], "payload {payload_length}");
    }
}

#[test]
fn the_hand_built_plaintext_fixture_agrees_with_the_encoder() {
    let payload = b"the fixture and the encoder must not diverge";
    let expected = record_plaintext(payload);
    let mut framed = [0u8; 128];
    let written = encode_record_plaintext(payload, &mut framed).unwrap();
    assert_eq!(&framed[..written], &expected[..]);
}

#[test]
fn a_sequence_counter_starts_at_zero_and_its_nonce_is_big_endian() {
    let counter = SequenceCounter::new();
    assert_eq!(counter.value(), 0);
    assert_eq!(counter.nonce(), [0u8; 8]);

    let mut advanced = counter;
    advanced.advance().unwrap();
    assert_eq!(advanced.value(), 1);
    assert_eq!(advanced.nonce(), [0, 0, 0, 0, 0, 0, 0, 1]);
    assert!(!advanced.is_exhausted());
}

// ---------------------------------------------------------------------------
// §10.3 and §10.5 — responses
// ---------------------------------------------------------------------------

#[test]
fn every_client_response_encodes_to_its_specified_image() {
    let cases: Vec<(ClientResponse<'_>, Vec<u8>)> = vec![
        (
            ClientResponse::Accepted { request_id: 3 },
            common::tagged_request_id(0x81, 3),
        ),
        (
            ClientResponse::StreamEnd {
                request_id: 3,
                finish_reason: FinishReason::Cancelled,
            },
            {
                let mut out = common::tagged_request_id(0x83, 3);
                out.push(2);
                out
            },
        ),
        (
            ClientResponse::Error {
                request_id: 0,
                error_code: 0x0002,
            },
            {
                let mut out = common::tagged_request_id(0x8e, 0);
                out.extend_from_slice(&0x0002u16.to_be_bytes());
                out
            },
        ),
        (ClientResponse::Bye, vec![0x8f]),
    ];
    for (response, expected) in cases {
        let mut out = [0u8; 64];
        let written = response.encode(&mut out).unwrap();
        assert_eq!(&out[..written], &expected[..], "{response:?}");
    }
}

#[test]
fn a_token_chunk_encodes_a_bounded_var_bytes_field() {
    let tokens = vec![0x7fu8; MAX_TOKEN_CHUNK];
    let response = ClientResponse::TokenChunk {
        request_id: 0xffff_ffff,
        tokens: &tokens,
    };
    let mut out = [0u8; 1024];
    let written = response.encode(&mut out).unwrap();
    assert_eq!(written, 1 + 4 + 2 + MAX_TOKEN_CHUNK);
    assert_eq!(out[0], 0x82);
    assert_eq!(&out[1..5], &0xffff_ffffu32.to_be_bytes());
    assert_eq!(&out[5..7], &(MAX_TOKEN_CHUNK as u16).to_be_bytes());
}

#[test]
fn every_admin_response_encodes_to_its_specified_image() {
    let handle = sixteen(0x44);
    let records = vec![0x11u8; MAX_AUDIT_CHUNK];
    let cases: Vec<(AdminResponse<'_>, usize, u8)> = vec![
        (
            AdminResponse::Ok {
                request_id: 1,
                status: 0x0001,
            },
            1 + 4 + 2,
            0x90,
        ),
        (
            AdminResponse::KeyEnrolled {
                request_id: 1,
                handle,
            },
            1 + 4 + 16,
            0x91,
        ),
        (
            AdminResponse::AuditChunk {
                request_id: 1,
                next_cursor: 0x0102_0304_0506_0708,
                records: &records,
            },
            1 + 4 + 8 + 2 + MAX_AUDIT_CHUNK,
            0x92,
        ),
        (
            AdminResponse::Error {
                request_id: 1,
                error_code: 9,
            },
            1 + 4 + 2,
            0x9e,
        ),
        (AdminResponse::Bye, 1, 0x9f),
    ];
    for (response, expected_length, expected_tag) in cases {
        let mut out = [0u8; 2048];
        let written = response.encode(&mut out).unwrap();
        assert_eq!(written, expected_length, "{response:?}");
        assert_eq!(out[0], expected_tag, "{response:?}");
    }
}

// ---------------------------------------------------------------------------
// The happy path, end to end
// ---------------------------------------------------------------------------

#[test]
fn a_whole_client_session_walks_from_wait_hello_to_streaming_and_back() {
    let mut session = Session::new();
    assert_eq!(session.state(), SessionState::WaitHello);

    session
        .accept_client_hello(&common::valid_client_hello())
        .unwrap();
    assert_eq!(session.state(), SessionState::WaitClientAuth);

    session
        .accept_client_auth(&common::valid_client_auth())
        .unwrap();
    assert_eq!(session.state(), SessionState::AuthPending);

    session.establish(SessionType::Client).unwrap();
    assert_eq!(session.state(), SessionState::Established);
    assert_eq!(session.session_type(), Some(SessionType::Client));
    assert_eq!(session.request_phase(), RequestPhase::Idle);

    session
        .accept_message(&infer_begin(77, 128, 700, 900, 8))
        .unwrap();
    assert_eq!(
        session.request_phase(),
        RequestPhase::Collecting {
            request_id: 77,
            declared_length: 8,
            accumulated_length: 0,
        }
    );

    session.accept_message(&prompt_chunk(77, b"abcd")).unwrap();
    session.accept_message(&prompt_chunk(77, b"efgh")).unwrap();
    assert_eq!(
        session.request_phase(),
        RequestPhase::Collecting {
            request_id: 77,
            declared_length: 8,
            accumulated_length: 8,
        }
    );

    session.accept_message(&infer_commit(77)).unwrap();
    assert_eq!(
        session.request_phase(),
        RequestPhase::Streaming { request_id: 77 }
    );

    session.accept_message(&cancel(77)).unwrap();
    assert_eq!(session.request_phase(), RequestPhase::Idle);

    session.accept_message(&close()).unwrap();
    assert_eq!(session.state(), SessionState::Closed);
}

#[test]
fn a_full_length_prompt_reassembles_across_five_chunks() {
    let mut session = established(SessionType::Client);
    session
        .accept_message(&infer_begin(1, 1, 0, 0, MAX_PROMPT_BYTES))
        .unwrap();

    let mut sent = 0u32;
    while sent < MAX_PROMPT_BYTES {
        let remaining = (MAX_PROMPT_BYTES - sent) as usize;
        let this_chunk = remaining.min(MAX_PROMPT_CHUNK);
        let chunk = vec![0x41u8; this_chunk];
        session.accept_message(&prompt_chunk(1, &chunk)).unwrap();
        sent += this_chunk as u32;
    }
    assert_eq!(
        session.request_phase(),
        RequestPhase::Collecting {
            request_id: 1,
            declared_length: MAX_PROMPT_BYTES,
            accumulated_length: MAX_PROMPT_BYTES,
        }
    );

    session.accept_message(&infer_commit(1)).unwrap();
    assert_eq!(
        session.request_phase(),
        RequestPhase::Streaming { request_id: 1 }
    );
}

#[test]
fn an_admin_session_accepts_every_verb_and_stays_established() {
    let mut session = established(SessionType::Admin);
    for verb in all_six_verbs() {
        match session.accept_message(&verb).unwrap() {
            InboundMessage::Admin(_) => {}
            other => panic!("expected an admin verb, got {other:?}"),
        }
        assert_eq!(session.state(), SessionState::Established);
    }
}

// ----------------------------------------------- accessors found by coverage
//
// `request_id()` is how a server correlates a response with the request that
// caused it. Coverage showed only the `Reboot` and `InferCommit` arms were ever
// executed, so five admin verbs and three client requests had an untested
// correlation path — the failure mode being a response attributed to the wrong
// request, which on a multiplexed session means one client's answer reaching
// another.

#[test]
fn every_admin_verb_reports_its_own_request_id() {
    let id = 0xA1B2_C3D4_u32;
    let verbs: [(&str, Vec<u8>); 6] = [
        (
            "enroll-key",
            enroll_key(id, CredentialRole::Client.to_wire(), nonce(0x21)),
        ),
        ("revoke-key", revoke_key(id, sixteen(0x22))),
        ("load-weights", load_weights(id, nonce(0x23))),
        ("read-audit-log", read_audit_log(id, 7, 3)),
        (
            "restart-server",
            restart_server(id, RestartTarget::Servd.to_wire()),
        ),
        ("reboot", reboot(id)),
    ];
    for (name, bytes) in verbs {
        assert_eq!(
            AdminVerb::decode(&bytes).unwrap().request_id(),
            id,
            "{name} lost its request_id in decode"
        );
    }
}

#[test]
fn every_client_request_reports_its_own_request_id() {
    let id = 0x0102_0304_u32;

    assert_eq!(
        ClientRequest::decode(&infer_begin(id, 16, 700, 900, 5))
            .unwrap()
            .request_id(),
        Some(id)
    );
    assert_eq!(
        ClientRequest::decode(&prompt_chunk(id, b"hello"))
            .unwrap()
            .request_id(),
        Some(id)
    );
    assert_eq!(
        ClientRequest::decode(&cancel(id)).unwrap().request_id(),
        Some(id)
    );
    assert_eq!(
        ClientRequest::decode(&close()).unwrap().request_id(),
        None,
        "Close correlates with no request; reporting an id would invent one"
    );
}

#[test]
fn finish_reason_round_trips_through_its_wire_value() {
    let all = [
        FinishReason::Ok,
        FinishReason::Length,
        FinishReason::Cancelled,
        FinishReason::ModelError,
    ];
    for reason in all {
        assert_eq!(
            FinishReason::from_wire(reason.to_wire()),
            Ok(reason),
            "{reason:?} did not survive the wire round trip"
        );
    }

    // The assignment is normative (§10.3): a client on the other end of a
    // different implementation decodes these numbers, so they are not free to
    // drift with the enum's declaration order.
    assert_eq!(FinishReason::Ok.to_wire(), 0);
    assert_eq!(FinishReason::Length.to_wire(), 1);
    assert_eq!(FinishReason::Cancelled.to_wire(), 2);
    assert_eq!(FinishReason::ModelError.to_wire(), 3);

    for unknown in [4u8, 5, 127, 128, 255] {
        assert_eq!(
            FinishReason::from_wire(unknown),
            Err(brainix_bsp::BspError::UnknownMessageType),
            "{unknown} is not an assigned finish reason and must not be guessed"
        );
    }
}

#[test]
fn a_default_session_is_a_new_session() {
    assert_eq!(Session::default().state(), Session::new().state());
}

/// What actually keeps a response inside one record is the PER-VARIANT cap,
/// not the record bound.
///
/// Written while chasing the uncovered `ResponseExceedsRecordPlaintext` arm,
/// which turned out to be unreachable: `MAX_TOKEN_CHUNK` is 512 and
/// `MAX_AUDIT_CHUNK` is 1024, both far under the 4096-byte record plaintext, so
/// the variant's own cap always denies first. The record bound is defence in
/// depth behind them. Pinning that ordering here means a future widening of
/// either cap has to confront this test rather than silently rely on the outer
/// check.
#[test]
fn the_per_variant_cap_denies_before_the_record_bound_is_reached() {
    let mut out = vec![0u8; brainix_bsp::BSP_MAX_RECORD_PLAINTEXT * 2];

    let oversized_tokens = vec![0x41u8; brainix_bsp::MAX_TOKEN_CHUNK + 1];
    assert_eq!(
        ClientResponse::TokenChunk {
            request_id: 7,
            tokens: &oversized_tokens,
        }
        .encode(&mut out),
        Err(brainix_bsp::BspError::TokenChunkExceedsMaximum)
    );

    let oversized_records = vec![0x42u8; brainix_bsp::MAX_AUDIT_CHUNK + 1];
    assert_eq!(
        AdminResponse::AuditChunk {
            request_id: 9,
            next_cursor: 0,
            records: &oversized_records,
        }
        .encode(&mut out),
        Err(brainix_bsp::BspError::AuditChunkExceedsMaximum)
    );

    assert!(
        brainix_bsp::MAX_TOKEN_CHUNK < brainix_bsp::BSP_MAX_RECORD_PLAINTEXT
            && brainix_bsp::MAX_AUDIT_CHUNK < brainix_bsp::BSP_MAX_RECORD_PLAINTEXT,
        "if either cap ever reaches the record plaintext, the record bound stops \
         being unreachable and its exemption in response.rs must be removed"
    );
}
