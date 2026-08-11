//! Adversarial fixtures.
//!
//! Every input here is what a hostile remote client sends. Each test states the
//! attack it encodes and asserts the **exact** reason the decoder denies it —
//! `is_err()` would pass for a decoder that returned the wrong reason for every
//! input, which is a decoder whose audit log is fiction.
//!
//! Nothing here may panic, hang, allocate, or return a partially decoded
//! message.

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
    MIN_PACKET_LENGTH,
};
use brainix_bsp::{
    AdminResponse, AdminVerb, BspError, ClientAuth, ClientHello, ClientRequest, ClientResponse,
    Disposition, ErrorCode, FinishReason, PacketLength, SequenceCounter, ServerHello,
    LEN_CLIENT_AUTH, LEN_CLIENT_HELLO, LEN_SERVER_HELLO, MAX_AUDIT_CHUNK, MAX_AUDIT_RECORDS,
    MAX_PROMPT_BYTES, MAX_PROMPT_CHUNK, MAX_RECORD_SEQ, MAX_TOKENS_REQUESTED, MAX_TOKEN_CHUNK,
};
use common::{
    all_six_verbs, cancel, client_hello, close, data_record, enroll_key, infer_begin, infer_commit,
    load_weights, nonce, prompt_chunk, prompt_chunk_with_declared_length, read_audit_log,
    restart_server, revoke_key, server_hello, sixteen, tagged_request_id, valid_client_auth,
    valid_client_hello,
};

// ---------------------------------------------------------------------------
// Degenerate inputs
// ---------------------------------------------------------------------------

#[test]
fn a_zero_length_input_denies_at_every_entry_point() {
    assert_eq!(
        ClientHello::decode(&[]).unwrap_err(),
        BspError::ClientHelloLengthMismatch
    );
    assert_eq!(
        ServerHello::decode(&[]).unwrap_err(),
        BspError::ServerHelloLengthMismatch
    );
    assert_eq!(
        ClientAuth::decode(&[]).unwrap_err(),
        BspError::ClientAuthLengthMismatch
    );
    assert_eq!(
        ClientRequest::decode(&[]).unwrap_err(),
        BspError::EmptyMessage
    );
    assert_eq!(AdminVerb::decode(&[]).unwrap_err(), BspError::EmptyMessage);
}

// ---------------------------------------------------------------------------
// Rows H1 and H4 — a handshake message of any other length
// ---------------------------------------------------------------------------

#[test]
fn a_client_hello_of_any_other_length_denies() {
    let full = valid_client_hello();
    // Every truncation, and every extension by one byte through twice the
    // message. 64 is the only accepted count.
    for length in 0..LEN_CLIENT_HELLO {
        assert_eq!(
            ClientHello::decode(&full[..length]).unwrap_err(),
            BspError::ClientHelloLengthMismatch,
            "truncated to {length}"
        );
    }
    for extra in 1..=LEN_CLIENT_HELLO {
        let mut oversized = full.clone();
        oversized.extend(core::iter::repeat_n(0u8, extra));
        assert_eq!(
            ClientHello::decode(&oversized).unwrap_err(),
            BspError::ClientHelloLengthMismatch,
            "extended by {extra}"
        );
    }
    assert!(ClientHello::decode(&full).is_ok());
}

#[test]
fn a_client_auth_of_any_other_length_denies() {
    let full = valid_client_auth();
    for length in 0..LEN_CLIENT_AUTH {
        assert_eq!(
            ClientAuth::decode(&full[..length]).unwrap_err(),
            BspError::ClientAuthLengthMismatch,
            "truncated to {length}"
        );
    }
    let mut oversized = full.clone();
    oversized.push(0);
    assert_eq!(
        ClientAuth::decode(&oversized).unwrap_err(),
        BspError::ClientAuthLengthMismatch
    );
}

#[test]
fn a_server_hello_of_any_other_length_denies() {
    let full = server_hello(nonce(1), nonce(2));
    for length in 0..LEN_SERVER_HELLO {
        assert_eq!(
            ServerHello::decode(&full[..length]).unwrap_err(),
            BspError::ServerHelloLengthMismatch,
            "truncated to {length}"
        );
    }
}

#[test]
fn a_client_auth_length_message_delivered_as_a_client_hello_denies() {
    // The two messages differ only in length once the preamble is stripped, so
    // the length check must be what separates them — not a field comparison
    // that happens to fail.
    assert_eq!(
        ClientHello::decode(&valid_client_auth()).unwrap_err(),
        BspError::ClientHelloLengthMismatch
    );
    assert_eq!(
        ClientAuth::decode(&valid_client_hello()).unwrap_err(),
        BspError::ClientAuthLengthMismatch
    );
}

// ---------------------------------------------------------------------------
// Row H2 — the four exact-match preamble fields
// ---------------------------------------------------------------------------

#[test]
fn a_wrong_magic_denies_with_its_own_reason() {
    for index in 0..4 {
        let mut bytes = valid_client_hello();
        bytes[index] ^= 0xff;
        assert_eq!(
            ClientHello::decode(&bytes).unwrap_err(),
            BspError::BadMagic,
            "magic byte {index}"
        );
    }
}

#[test]
fn every_other_version_major_denies() {
    for major in 0u8..=255 {
        if major == 2 {
            continue;
        }
        let mut bytes = valid_client_hello();
        bytes[4] = major;
        assert_eq!(
            ClientHello::decode(&bytes).unwrap_err(),
            BspError::UnsupportedVersionMajor,
            "version_major {major}"
        );
    }
}

#[test]
fn every_other_version_minor_denies_rather_than_being_a_negotiation() {
    // §5.5: version_minor is an exact-match field, not an extension point. A
    // "newer minor" is not forward compatible; it is refused.
    for minor in 1u8..=255 {
        let mut bytes = valid_client_hello();
        bytes[5] = minor;
        assert_eq!(
            ClientHello::decode(&bytes).unwrap_err(),
            BspError::UnsupportedVersionMinor,
            "version_minor {minor}"
        );
    }
}

#[test]
fn any_nonzero_reserved_value_denies() {
    for reserved in [1u16, 0x0100, 0x8000, u16::MAX] {
        let mut bytes = valid_client_hello();
        bytes[6..8].copy_from_slice(&reserved.to_be_bytes());
        assert_eq!(
            ClientHello::decode(&bytes).unwrap_err(),
            BspError::ReservedFieldNonZero,
            "reserved {reserved:#06x}"
        );
    }
}

#[test]
fn the_preamble_is_checked_before_any_opaque_field_is_read() {
    // A hello that is wrong in the magic *and* carries a wild counter must
    // report the magic: the checked fields gate the opaque ones.
    let mut bytes = client_hello(u64::MAX, nonce(9), sixteen(9));
    bytes[0] = b'X';
    assert_eq!(ClientHello::decode(&bytes).unwrap_err(), BspError::BadMagic);
}

// ---------------------------------------------------------------------------
// Row R1 — the pre-touch packet length check
// ---------------------------------------------------------------------------

#[test]
fn a_packet_length_of_zero_and_of_the_maximum() {
    assert_eq!(
        PacketLength::decode(0u32.to_be_bytes()).unwrap_err(),
        BspError::PacketLengthBelowMinimum
    );
    assert_eq!(
        PacketLength::decode(1u32.to_be_bytes()).unwrap_err(),
        BspError::PacketLengthBelowMinimum
    );
    assert!(PacketLength::decode(MIN_PACKET_LENGTH.to_be_bytes()).is_ok());
    assert!(PacketLength::decode(MAX_PACKET_LENGTH.to_be_bytes()).is_ok());
    assert_eq!(
        PacketLength::decode((MAX_PACKET_LENGTH + 1).to_be_bytes()).unwrap_err(),
        BspError::PacketLengthAboveMaximum
    );
    assert_eq!(
        PacketLength::decode(u32::MAX.to_be_bytes()).unwrap_err(),
        BspError::PacketLengthAboveMaximum
    );
}

#[test]
fn a_length_prefix_larger_than_the_buffer_denies() {
    // The prefix is in range; it simply names more bytes than arrived. Nothing
    // is read short, nothing is zero-filled, and no buffer is sized to fit.
    let length = PacketLength::decode(4096u32.to_be_bytes()).unwrap();
    let full = data_record(4096);
    for truncated in [0usize, 1, 4, 100, full.len() - 1] {
        assert_eq!(
            split_data_record(&full[..truncated], length).unwrap_err(),
            BspError::RecordExceedsAvailableBytes,
            "stream of {truncated} bytes"
        );
    }
    assert!(split_data_record(&full, length).is_ok());
}

#[test]
fn a_record_at_the_maximum_packet_length_still_frames_exactly() {
    let length = PacketLength::decode(MAX_PACKET_LENGTH.to_be_bytes()).unwrap();
    let stream = data_record(MAX_PACKET_LENGTH);
    let record = split_data_record(&stream, length).unwrap();
    assert_eq!(record.total_length, stream.len());
    assert_eq!(record.ciphertext.len(), MAX_PACKET_LENGTH as usize);
}

// ---------------------------------------------------------------------------
// §4.2 — the record plaintext padding rules
// ---------------------------------------------------------------------------

#[test]
fn a_plaintext_whose_length_disagrees_with_the_packet_length_denies() {
    let mut framed = [0u8; 64];
    let written = encode_record_plaintext(b"payload", &mut framed).unwrap();
    let honest = PacketLength::decode((written as u32).to_be_bytes()).unwrap();
    assert!(decode_record_plaintext(&framed[..written], honest).is_ok());

    // The prefix says one thing and the plaintext is another.
    let lying = PacketLength::decode(((written + 8) as u32).to_be_bytes()).unwrap();
    assert_eq!(
        decode_record_plaintext(&framed[..written], lying).unwrap_err(),
        BspError::RecordPlaintextLengthMismatch
    );
}

#[test]
fn a_padding_length_that_would_underflow_the_payload_denies() {
    // padding_length + 1 > packet_length is the open_packet containment rule.
    // Without it the payload length subtraction underflows.
    let mut plaintext = vec![0u8; 16];
    for padding in [16u8, 17, 200, 255] {
        plaintext[0] = padding;
        let length = PacketLength::decode(16u32.to_be_bytes()).unwrap();
        assert_eq!(
            decode_record_plaintext(&plaintext, length).unwrap_err(),
            BspError::PaddingLengthExceedsPacket,
            "padding_length {padding}"
        );
    }
}

#[test]
fn fewer_than_four_padding_bytes_denies() {
    let mut plaintext = vec![0u8; 16];
    let length = PacketLength::decode(16u32.to_be_bytes()).unwrap();
    for padding in 0u8..4 {
        plaintext[0] = padding;
        assert_eq!(
            decode_record_plaintext(&plaintext, length).unwrap_err(),
            BspError::PaddingBelowMinimum,
            "padding_length {padding}"
        );
    }
    plaintext[0] = 4;
    assert!(decode_record_plaintext(&plaintext, length).is_ok());
}

#[test]
fn a_plaintext_that_is_not_a_whole_number_of_blocks_denies() {
    for length_value in [2u32, 7, 9, 15, 4095] {
        let plaintext = vec![4u8; length_value as usize];
        let length = PacketLength::decode(length_value.to_be_bytes()).unwrap();
        assert_eq!(
            decode_record_plaintext(&plaintext, length).unwrap_err(),
            BspError::RecordPlaintextNotBlockAligned,
            "packet_length {length_value}"
        );
    }
}

#[test]
fn a_payload_over_the_record_ceiling_denies() {
    // packet_length may legally reach 35000, well above BSP_MAX_RECORD_PLAINTEXT.
    // Row R4 is what stops the surplus reaching the message decoder.
    let length_value = 8192u32;
    let mut plaintext = vec![0u8; length_value as usize];
    plaintext[0] = 4;
    let length = PacketLength::decode(length_value.to_be_bytes()).unwrap();
    assert_eq!(
        decode_record_plaintext(&plaintext, length).unwrap_err(),
        BspError::PayloadExceedsRecordPlaintext
    );
}

#[test]
fn encoding_a_payload_over_the_record_ceiling_denies() {
    let payload = vec![0u8; brainix_bsp::BSP_MAX_RECORD_PLAINTEXT + 1];
    let mut out = [0u8; 8192];
    assert_eq!(
        encode_record_plaintext(&payload, &mut out).unwrap_err(),
        BspError::PayloadExceedsRecordPlaintext
    );
}

#[test]
fn encoding_into_a_buffer_that_is_one_byte_short_denies() {
    let mut out = [0u8; 15];
    // "payload" is 7 bytes, so the frame is 1 + 7 + 8 = 16.
    assert_eq!(
        encode_record_plaintext(b"payload", &mut out).unwrap_err(),
        BspError::OutputBufferTooSmall
    );
}

// ---------------------------------------------------------------------------
// Row R5 — the sequence never wraps
// ---------------------------------------------------------------------------

#[test]
fn a_sequence_counter_never_wraps() {
    // The record *at* MAX_RECORD_SEQ is legal; the advance past it is the
    // denial. Wrapping to zero would reuse a nonce, which for a stream cipher
    // is catastrophic rather than merely a protocol fault.
    let mut counter = SequenceCounter::at(MAX_RECORD_SEQ - 1);
    assert!(!counter.is_exhausted());
    counter.advance().unwrap();

    assert_eq!(counter.value(), MAX_RECORD_SEQ);
    assert!(counter.is_exhausted());
    assert_eq!(counter.nonce(), [0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);

    assert_eq!(counter.advance().unwrap_err(), BspError::SequenceExhausted);
    assert_eq!(counter.value(), MAX_RECORD_SEQ, "must not wrap to zero");

    // Denial is stable: a peer that keeps sending does not eventually get
    // through by exhausting the guard.
    for _ in 0..8 {
        assert_eq!(counter.advance().unwrap_err(), BspError::SequenceExhausted);
        assert_eq!(counter.value(), MAX_RECORD_SEQ);
    }
}

#[test]
fn a_sequence_nonce_never_sets_its_high_thirty_two_bits() {
    // §4.2: a 64-bit big-endian nonce whose low 32 bits are the sequence. The
    // high half is what distinguishes it from a 64-bit counter, and the guard
    // above is what keeps it zero.
    for value in [0u32, 1, 0x7fff_ffff, 0x8000_0000, MAX_RECORD_SEQ] {
        let counter = SequenceCounter::at(value);
        assert_eq!(&counter.nonce()[..4], &[0, 0, 0, 0], "sequence {value}");
        assert_eq!(
            &counter.nonce()[4..],
            &value.to_be_bytes(),
            "sequence {value}"
        );
    }
}

// ---------------------------------------------------------------------------
// Rows M1, M2 — the tag partition
// ---------------------------------------------------------------------------

#[test]
fn an_admin_tag_on_a_client_session_denies() {
    for tag in 0x10u8..=0x1f {
        let payload = tagged_request_id(tag, 1);
        assert_eq!(
            ClientRequest::decode(&payload).unwrap_err(),
            BspError::WrongSessionTypeRange,
            "tag {tag:#04x}"
        );
    }
}

#[test]
fn a_client_tag_on_an_admin_session_denies() {
    for tag in 0x00u8..=0x0f {
        let payload = tagged_request_id(tag, 1);
        assert_eq!(
            AdminVerb::decode(&payload).unwrap_err(),
            BspError::WrongSessionTypeRange,
            "tag {tag:#04x}"
        );
    }
}

#[test]
fn a_server_to_client_tag_arriving_from_the_peer_denies() {
    for tag in [0x80u8, 0x81, 0x82, 0x83, 0x8e, 0x8f, 0x90, 0x92, 0x9f] {
        let payload = tagged_request_id(tag, 1);
        assert_eq!(
            ClientRequest::decode(&payload).unwrap_err(),
            BspError::WrongDirectionTag,
            "tag {tag:#04x}"
        );
        assert_eq!(
            AdminVerb::decode(&payload).unwrap_err(),
            BspError::WrongDirectionTag,
            "tag {tag:#04x}"
        );
    }
}

#[test]
fn a_tag_outside_the_partition_denies() {
    for tag in [0x20u8, 0x30, 0x4f, 0x55, 0x60, 0x7f, 0xa0, 0xf0, 0xff] {
        let payload = tagged_request_id(tag, 1);
        assert_eq!(
            ClientRequest::decode(&payload).unwrap_err(),
            BspError::UnknownMessageType,
            "tag {tag:#04x}"
        );
    }
}

#[test]
fn an_unrecognized_client_tag_inside_the_client_range_denies() {
    // 0x00 and 0x06..0x0F are in the right range and name no message.
    for tag in [0x00u8, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0e, 0x0f] {
        let payload = tagged_request_id(tag, 1);
        assert_eq!(
            ClientRequest::decode(&payload).unwrap_err(),
            BspError::UnknownMessageType,
            "tag {tag:#04x}"
        );
    }
}

#[test]
fn an_unrecognized_admin_verb_tag_denies() {
    // The set is six. 0x10 and 0x17..0x1F are in the admin range and name no
    // verb — in particular there is no seventh verb at 0x17, which is where a
    // `rotate` would have gone (§7.3).
    for tag in [0x10u8, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f] {
        let payload = tagged_request_id(tag, 1);
        assert_eq!(
            AdminVerb::decode(&payload).unwrap_err(),
            BspError::UnknownMessageType,
            "tag {tag:#04x}"
        );
    }
}

#[test]
fn exactly_six_admin_tags_are_recognized() {
    let mut recognized = Vec::new();
    for tag in 0x10u8..=0x1f {
        // A body long enough that no verb can be refused for truncation alone.
        let mut payload = vec![tag];
        payload.extend(core::iter::repeat_n(0x01u8, 64));
        if AdminVerb::decode(&payload).unwrap_err() != BspError::UnknownMessageType {
            recognized.push(tag);
        }
    }
    assert_eq!(recognized, vec![0x11, 0x12, 0x13, 0x14, 0x15, 0x16]);
}

// ---------------------------------------------------------------------------
// Row M3 — truncation at every structural boundary of every message
// ---------------------------------------------------------------------------

#[test]
fn every_client_message_truncated_at_every_boundary_denies() {
    let messages = vec![
        infer_begin(1, 10, 0, 0, 0),
        prompt_chunk(1, b"0123456789"),
        infer_commit(1),
        cancel(1),
    ];
    for message in messages {
        for length in 1..message.len() {
            let result = ClientRequest::decode(&message[..length]);
            assert!(
                result.is_err(),
                "tag {:#04x} truncated to {length} must deny",
                message[0]
            );
            assert!(
                matches!(
                    result.unwrap_err(),
                    BspError::TruncatedMessageBody
                        | BspError::TruncatedVarBytesLength
                        | BspError::TruncatedVarBytesValue
                ),
                "tag {:#04x} truncated to {length} must be a truncation",
                message[0]
            );
        }
        assert!(ClientRequest::decode(&message).is_ok());
    }
}

#[test]
fn every_admin_verb_truncated_at_every_boundary_denies() {
    for verb in all_six_verbs() {
        for length in 1..verb.len() {
            let result = AdminVerb::decode(&verb[..length]);
            assert_eq!(
                result.unwrap_err(),
                BspError::TruncatedMessageBody,
                "verb {:#04x} truncated to {length}",
                verb[0]
            );
        }
        assert!(AdminVerb::decode(&verb).is_ok());
    }
}

#[test]
fn a_message_with_bytes_past_its_last_field_denies() {
    let mut cases: Vec<Vec<u8>> = vec![
        infer_begin(1, 10, 0, 0, 0),
        infer_commit(1),
        cancel(1),
        close(),
        prompt_chunk(1, b"abc"),
    ];
    cases.extend(all_six_verbs());
    for message in cases {
        let mut extended = message.clone();
        extended.push(0x00);
        let result = if message[0] < 0x10 {
            ClientRequest::decode(&extended).map(|_| ())
        } else {
            AdminVerb::decode(&extended).map(|_| ())
        };
        assert_eq!(
            result.unwrap_err(),
            BspError::TrailingBytesAfterBody,
            "tag {:#04x}",
            message[0]
        );
    }
}

// ---------------------------------------------------------------------------
// Row M4 — the bounded var-bytes reader
// ---------------------------------------------------------------------------

#[test]
fn a_prompt_chunk_declaring_more_than_the_maximum_denies() {
    // The declared length is checked against the compile-time MAX before the
    // remaining-bytes test, so an absurd claim is refused by the bound rather
    // than by whether the attacker also supplied the bytes.
    let chunk = vec![0u8; MAX_PROMPT_CHUNK + 1];
    let payload = prompt_chunk(1, &chunk);
    assert_eq!(
        ClientRequest::decode(&payload).unwrap_err(),
        BspError::VarBytesLengthExceedsMaximum
    );

    let bare = prompt_chunk_with_declared_length(1, b"", u16::MAX);
    assert_eq!(
        ClientRequest::decode(&bare).unwrap_err(),
        BspError::VarBytesLengthExceedsMaximum
    );
}

#[test]
fn a_prompt_chunk_declaring_more_bytes_than_it_carries_denies() {
    let payload = prompt_chunk_with_declared_length(1, b"abc", 100);
    assert_eq!(
        ClientRequest::decode(&payload).unwrap_err(),
        BspError::TruncatedVarBytesValue
    );
}

#[test]
fn a_prompt_chunk_missing_its_length_prefix_denies() {
    let mut payload = tagged_request_id(0x02, 1);
    payload.push(0x00); // one byte of a two-byte prefix
    assert_eq!(
        ClientRequest::decode(&payload).unwrap_err(),
        BspError::TruncatedVarBytesLength
    );
}

// ---------------------------------------------------------------------------
// Row M5 — the InferBegin ceilings
// ---------------------------------------------------------------------------

#[test]
fn an_infer_begin_over_the_token_ceiling_denies_and_keeps_the_channel() {
    let over = infer_begin(1, MAX_TOKENS_REQUESTED + 1, 0, 0, 0);
    let reason = ClientRequest::decode(&over).unwrap_err();
    assert_eq!(reason, BspError::MaxTokensExceedsLimit);
    assert_eq!(reason.disposition(), Disposition::ErrorKeep);
    assert_eq!(reason.error_code(), Some(ErrorCode::Limit));

    assert!(ClientRequest::decode(&infer_begin(1, MAX_TOKENS_REQUESTED, 0, 0, 0)).is_ok());
    assert_eq!(
        ClientRequest::decode(&infer_begin(1, u32::MAX, 0, 0, 0)).unwrap_err(),
        BspError::MaxTokensExceedsLimit
    );
}

#[test]
fn an_infer_begin_over_the_prompt_ceiling_denies() {
    assert!(ClientRequest::decode(&infer_begin(1, 1, 0, 0, MAX_PROMPT_BYTES)).is_ok());
    for declared in [MAX_PROMPT_BYTES + 1, u32::MAX] {
        assert_eq!(
            ClientRequest::decode(&infer_begin(1, 1, 0, 0, declared)).unwrap_err(),
            BspError::PromptLengthExceedsLimit,
            "prompt_total_len {declared}"
        );
    }
}

// ---------------------------------------------------------------------------
// Rows A1, A6, A7 — the admin verb field checks
// ---------------------------------------------------------------------------

#[test]
fn an_enroll_key_with_an_out_of_range_role_drops() {
    for role in 0u8..=255 {
        if role == 0x01 || role == 0x02 {
            continue;
        }
        let reason = AdminVerb::decode(&enroll_key(1, role, nonce(0))).unwrap_err();
        assert_eq!(reason, BspError::InvalidEnrollRole, "role {role:#04x}");
        // Row A1 is Drop, not Error+keep: an out-of-range authority byte is not
        // a benign mistake.
        assert_eq!(reason.disposition(), Disposition::Drop);
        assert_eq!(reason.error_code(), None);
    }
}

#[test]
fn a_restart_server_with_an_unknown_target_answers_rather_than_drops() {
    for target in [0u8, 5, 6, 0x7f, 0xff] {
        let reason = AdminVerb::decode(&restart_server(1, target)).unwrap_err();
        assert_eq!(reason, BspError::UnknownRestartTarget, "target {target}");
        assert_eq!(reason.disposition(), Disposition::ErrorKeep);
        assert_eq!(reason.error_code(), Some(ErrorCode::BadTarget));
    }
}

#[test]
fn a_read_audit_log_over_the_record_ceiling_denies() {
    assert!(AdminVerb::decode(&read_audit_log(1, 0, MAX_AUDIT_RECORDS)).is_ok());
    for count in [MAX_AUDIT_RECORDS + 1, 1000, u16::MAX] {
        let reason = AdminVerb::decode(&read_audit_log(1, 0, count)).unwrap_err();
        assert_eq!(
            reason,
            BspError::AuditRecordCountExceedsLimit,
            "max_records {count}"
        );
        assert_eq!(reason.error_code(), Some(ErrorCode::Limit));
    }
}

#[test]
fn a_revoke_key_and_a_load_weights_never_carry_a_path() {
    // Both fields are exactly-N fixed arrays; a shorter or longer one denies,
    // so there is no way to smuggle a variable-length name through either.
    let mut short = revoke_key(1, sixteen(0));
    short.pop();
    assert_eq!(
        AdminVerb::decode(&short).unwrap_err(),
        BspError::TruncatedMessageBody
    );

    let mut long = load_weights(1, nonce(0));
    long.push(b'/');
    assert_eq!(
        AdminVerb::decode(&long).unwrap_err(),
        BspError::TrailingBytesAfterBody
    );
}

// ---------------------------------------------------------------------------
// Response encoding bounds
// ---------------------------------------------------------------------------

#[test]
fn a_token_chunk_over_its_maximum_denies() {
    let tokens = vec![0u8; MAX_TOKEN_CHUNK + 1];
    let mut out = [0u8; 2048];
    assert_eq!(
        ClientResponse::TokenChunk {
            request_id: 1,
            tokens: &tokens,
        }
        .encode(&mut out)
        .unwrap_err(),
        BspError::TokenChunkExceedsMaximum
    );
}

#[test]
fn an_audit_chunk_over_its_maximum_denies() {
    let records = vec![0u8; MAX_AUDIT_CHUNK + 1];
    let mut out = [0u8; 4096];
    assert_eq!(
        AdminResponse::AuditChunk {
            request_id: 1,
            next_cursor: 0,
            records: &records,
        }
        .encode(&mut out)
        .unwrap_err(),
        BspError::AuditChunkExceedsMaximum
    );
}

#[test]
fn every_response_denies_rather_than_overrunning_a_short_buffer() {
    let tokens = [0u8; 16];
    let responses: Vec<(ClientResponse<'_>, usize)> = vec![
        (ClientResponse::Accepted { request_id: 1 }, 5),
        (
            ClientResponse::TokenChunk {
                request_id: 1,
                tokens: &tokens,
            },
            23,
        ),
        (
            ClientResponse::StreamEnd {
                request_id: 1,
                finish_reason: FinishReason::Ok,
            },
            6,
        ),
        (
            ClientResponse::Error {
                request_id: 1,
                error_code: 1,
            },
            7,
        ),
        (ClientResponse::Bye, 1),
    ];
    for (response, exact) in responses {
        for short in 0..exact {
            let mut out = vec![0u8; short];
            assert_eq!(
                response.encode(&mut out).unwrap_err(),
                BspError::OutputBufferTooSmall,
                "{response:?} into {short} bytes"
            );
        }
        let mut out = vec![0u8; exact];
        assert_eq!(response.encode(&mut out).unwrap(), exact);
    }
}

#[test]
fn an_unrecognized_finish_reason_denies() {
    for value in 4u8..=255 {
        assert_eq!(
            FinishReason::from_wire(value).unwrap_err(),
            BspError::UnknownMessageType,
            "finish_reason {value}"
        );
    }
}

// ---------------------------------------------------------------------------
// The §12 disposition table itself
// ---------------------------------------------------------------------------

#[test]
fn every_error_keep_variant_is_a_named_row() {
    // §12's design rule: only limit / busy / incomplete / unknown-handle style
    // faults keep the channel. Everything else drops. This pins the whole list
    // so that adding a variant on the lenient side is a deliberate edit.
    let keeps = [
        BspError::MaxTokensExceedsLimit,
        BspError::PromptLengthExceedsLimit,
        BspError::AuditRecordCountExceedsLimit,
        BspError::RequestAlreadyInFlight,
        BspError::RequestIdMismatch,
        BspError::PromptIncomplete,
        BspError::MessageInvalidInState,
        BspError::UnknownRestartTarget,
    ];
    for reason in keeps {
        assert_eq!(reason.disposition(), Disposition::ErrorKeep, "{reason:?}");
        assert!(reason.error_code().is_some(), "{reason:?}");
    }

    let drops = [
        BspError::OffsetOverflow,
        BspError::TruncatedMessageBody,
        BspError::TrailingBytesAfterBody,
        BspError::TruncatedVarBytesLength,
        BspError::VarBytesLengthExceedsMaximum,
        BspError::TruncatedVarBytesValue,
        BspError::ClientHelloLengthMismatch,
        BspError::ServerHelloLengthMismatch,
        BspError::ClientAuthLengthMismatch,
        BspError::BadMagic,
        BspError::UnsupportedVersionMajor,
        BspError::UnsupportedVersionMinor,
        BspError::ReservedFieldNonZero,
        BspError::HandshakeMessageInWrongState,
        BspError::EstablishBeforeAuthentication,
        BspError::PacketLengthBelowMinimum,
        BspError::PacketLengthAboveMaximum,
        BspError::RecordExceedsAvailableBytes,
        BspError::RecordPlaintextLengthMismatch,
        BspError::PaddingLengthExceedsPacket,
        BspError::PaddingBelowMinimum,
        BspError::RecordPlaintextNotBlockAligned,
        BspError::PayloadExceedsRecordPlaintext,
        BspError::SequenceExhausted,
        BspError::EmptyMessage,
        BspError::UnknownMessageType,
        BspError::WrongSessionTypeRange,
        BspError::WrongDirectionTag,
        BspError::PromptChunkExceedsDeclaredLength,
        BspError::PromptChunkExceedsPromptBuffer,
        BspError::DataMessageBeforeEstablished,
        BspError::SessionClosed,
        BspError::InvalidEnrollRole,
        BspError::OutputBufferTooSmall,
        BspError::TokenChunkExceedsMaximum,
        BspError::AuditChunkExceedsMaximum,
        BspError::ResponseExceedsRecordPlaintext,
    ];
    for reason in drops {
        assert_eq!(reason.disposition(), Disposition::Drop, "{reason:?}");
        assert_eq!(reason.error_code(), None, "{reason:?}");
    }
    assert_eq!(keeps.len() + drops.len(), 45, "every variant is classified");
}

#[test]
fn a_denial_names_the_verb_it_denied_where_the_row_attributes_one() {
    assert_eq!(BspError::MaxTokensExceedsLimit.attributed_tag(), Some(0x01));
    assert_eq!(
        BspError::PromptChunkExceedsDeclaredLength.attributed_tag(),
        Some(0x02)
    );
    assert_eq!(BspError::InvalidEnrollRole.attributed_tag(), Some(0x11));
    assert_eq!(BspError::UnknownRestartTarget.attributed_tag(), Some(0x15));
    assert_eq!(
        BspError::AuditRecordCountExceedsLimit.attributed_tag(),
        Some(0x14)
    );
    assert_eq!(BspError::BadMagic.attributed_tag(), None);
}

#[test]
fn every_error_code_has_a_distinct_wire_value() {
    let codes = [
        ErrorCode::BadType,
        ErrorCode::Limit,
        ErrorCode::Busy,
        ErrorCode::NoRequest,
        ErrorCode::Incomplete,
        ErrorCode::State,
        ErrorCode::NoCapacity,
        ErrorCode::NoSuchKey,
        ErrorCode::Forbidden,
        ErrorCode::NoSuchWeights,
        ErrorCode::BadTarget,
        ErrorCode::Duplicate,
    ];
    let mut seen = Vec::new();
    for code in codes {
        assert!(!seen.contains(&code.to_wire()), "{code:?} collides");
        seen.push(code.to_wire());
    }
    assert_eq!(seen.len(), 12);
}
