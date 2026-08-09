#![no_main]

//! Fuzz target: the BSP v2 wire decoder with adversarial client traffic.
//!
//! `brainix-bsp` is the first code in BraiNIX that touches a byte from a hostile
//! remote client and is the outermost attack surface the project controls
//! (`docs/THREAT_MODEL.md`, `docs/security/SECURITY_INVARIANTS.md` §16,
//! `INV-PARSE-001`). This target feeds arbitrary bytes to every decoder the
//! crate exposes and asserts the outcome is always either a decoded value or a
//! [`BspError`] — never a panic, an out-of-bounds read, an allocation, or a
//! hang (`INV-PARSE-001`, `-002`).
//!
//! Decoding is only half of it. A message that decodes but panics while it is
//! *used* is exactly the bug class a decode-only harness misses, so every
//! successful decode is followed by a full read of every field, and the §5.5
//! session state machine is driven through transitions chosen by the fuzzer.
//! Random bytes almost never form a `ClientHello` — the `"BSP2"` magic alone is
//! a 2^-32 event — so the driver also *builds* well-formed messages out of fuzz
//! bytes, which is what lets the fuzzer reach `ESTABLISHED` and attack the
//! request phase behind it rather than bouncing off row H2 forever.
//!
//! The assertions this target makes, beyond "no panic":
//!
//! - every borrowed slice the API hands back lies wholly inside the input;
//! - every decoded value respects the §8 bound its own decoder claims to apply;
//! - a data record's parts add up to exactly the extent it reports;
//! - a framed record plaintext round-trips back to the payload it framed;
//! - the sequence counter advances by exactly one and never wraps;
//! - the session's granted capability exists **iff** it is `ESTABLISHED`;
//! - a session that is not `ESTABLISHED` has no request phase left over;
//! - a collecting request never accumulates past what it declared, and never
//!   declares past `MAX_PROMPT_BYTES` (row M8);
//! - a decoded message whose §12 disposition is `Drop` leaves the session
//!   `Closed`, and one whose disposition is `ErrorKeep` leaves it untouched.

use brainix_bsp::record::{
    decode_record_plaintext, encode_record_plaintext, split_data_record, MAX_PACKET_LENGTH,
    MIN_PACKET_LENGTH, MIN_RECORD_PADDING, RECORD_LENGTH_PREFIX_BYTES, RECORD_PLAINTEXT_BLOCK,
    RECORD_TAG_BYTES,
};
use brainix_bsp::{
    AdminResponse, AdminVerb, BspError, ClientAuth, ClientHello, ClientRequest, ClientResponse,
    CredentialRole, Disposition, FinishReason, InboundMessage, PacketLength, RequestPhase,
    RestartTarget, SequenceCounter, ServerHello, Session, SessionState, SessionType, TagRange,
    BSP_MAGIC, BSP_MAX_RECORD_PLAINTEXT, BSP_VERSION_MAJOR, BSP_VERSION_MINOR, LEN_CLIENT_AUTH,
    LEN_CLIENT_HELLO, LEN_SERVER_HELLO, MAX_AUDIT_CHUNK, MAX_AUDIT_RECORDS, MAX_PROMPT_BYTES,
    MAX_PROMPT_CHUNK, MAX_TOKENS_REQUESTED, MAX_TOKEN_CHUNK,
};
use libfuzzer_sys::fuzz_target;

/// Bytes in the largest framed record plaintext: the §8 payload ceiling, the
/// `padding_length` field, and the most padding the block rule can add.
const FRAMED_PLAINTEXT_CAPACITY: usize = BSP_MAX_RECORD_PLAINTEXT + 1 + RECORD_PLAINTEXT_BLOCK;

/// Bytes in the response encoders' output buffer. Larger than row R4's ceiling
/// on purpose: an encoder that overran it would be caught here rather than
/// masked by a buffer that could not hold the overrun.
const RESPONSE_BUFFER_BYTES: usize = BSP_MAX_RECORD_PLAINTEXT + 64;

/// Session transitions the driver may take per step.
const SESSION_STEP_BUDGET: usize = 64;

/// Whether `part` is a sub-slice of `whole`.
///
/// The decoder never copies a variable-length field: every chunk, ciphertext,
/// tag, and payload it returns must point into the caller's buffer. Comparing
/// the addresses is how that is checked without trusting the decoder's own
/// arithmetic.
fn is_inside(whole: &[u8], part: &[u8]) -> bool {
    let base = whole.as_ptr() as usize;
    let start = part.as_ptr() as usize;
    if start < base {
        return false;
    }
    match start
        .checked_sub(base)
        .and_then(|at| at.checked_add(part.len()))
    {
        Some(end) => end <= whole.len(),
        None => false,
    }
}

/// A forward-only cursor that turns the fuzzer's bytes into decisions.
///
/// Reads past the end wrap to the front rather than stopping, so a short input
/// still drives a long transition sequence and the fuzzer is not forced to
/// spend length on the opcode stream before it can spend any on the payloads.
struct Driver<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Driver<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    /// The next decision byte, or `0` when the input is empty.
    fn byte(&mut self) -> u8 {
        if self.data.is_empty() {
            return 0;
        }
        let index = self.at % self.data.len();
        self.at = self.at.wrapping_add(1);
        self.data.get(index).copied().unwrap_or(0)
    }

    /// The next `count` decision bytes.
    fn bytes(&mut self, count: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(count.min(1024));
        let mut taken = 0usize;
        while taken < count {
            out.push(self.byte());
            taken = taken.saturating_add(1);
        }
        out
    }

    /// The next big-endian `u32` of decision bytes.
    fn u32(&mut self) -> u32 {
        u32::from_be_bytes([self.byte(), self.byte(), self.byte(), self.byte()])
    }

    /// The next big-endian `u16` of decision bytes.
    fn u16(&mut self) -> u16 {
        u16::from_be_bytes([self.byte(), self.byte()])
    }

    /// The next big-endian `u64` of decision bytes.
    fn u64(&mut self) -> u64 {
        let mut value = 0u64;
        let mut taken = 0usize;
        while taken < 8 {
            value = value.wrapping_shl(8) | u64::from(self.byte());
            taken = taken.saturating_add(1);
        }
        value
    }
}

// ---------------------------------------------------------------------------
// Stateless decoders, driven with the raw input
// ---------------------------------------------------------------------------

/// Feeds the raw fuzz input to every decoder that takes a byte slice.
///
/// The whole input is offered to each, and so is the exact-length prefix each
/// handshake message requires, because rows H1 and H4 are length checks and a
/// harness that only ever offered the wrong length would never reach the field
/// checks behind them.
fn decode_everything(data: &[u8]) {
    exercise_client_hello(data);
    exercise_server_hello(data);
    exercise_client_auth(data);
    exercise_client_request(data);
    exercise_admin_verb(data);

    if let Some(prefix) = data.get(..LEN_CLIENT_HELLO) {
        exercise_client_hello(prefix);
    }
    if let Some(prefix) = data.get(..LEN_SERVER_HELLO) {
        exercise_server_hello(prefix);
    }
    if let Some(prefix) = data.get(..LEN_CLIENT_AUTH) {
        exercise_client_auth(prefix);
    }
    if let Some(body) = data.get(1..) {
        exercise_client_request(body);
        exercise_admin_verb(body);
    }
}

/// Decodes a `ClientHello` and reads every field of a successful decode.
fn exercise_client_hello(bytes: &[u8]) {
    let hello = match ClientHello::decode(bytes) {
        Ok(hello) => hello,
        Err(error) => return classify(error),
    };
    assert!(
        bytes.len() == LEN_CLIENT_HELLO,
        "a ClientHello decoded from a length row H1 forbids"
    );
    assert!(
        bytes.get(..4) == Some(&BSP_MAGIC[..]),
        "a ClientHello decoded without the BSP2 magic"
    );
    assert!(
        bytes.get(4) == Some(&BSP_VERSION_MAJOR) && bytes.get(5) == Some(&BSP_VERSION_MINOR),
        "a ClientHello decoded with a version row H2 forbids"
    );
    assert!(
        bytes.get(6..8) == Some(&[0u8, 0u8][..]),
        "a ClientHello decoded with a nonzero reserved field"
    );
    let _ = hello.chain_counter;
    let _ = hello.client_nonce;
    let _ = hello.key_selector;
}

/// Decodes a `ServerHello`, reads it, and re-encodes it.
///
/// The re-encode is the point: a decoder and an encoder that disagree about the
/// field order would produce a round trip that is not the identity, and no
/// decode-only harness could see it.
fn exercise_server_hello(bytes: &[u8]) {
    let hello = match ServerHello::decode(bytes) {
        Ok(hello) => hello,
        Err(error) => return classify(error),
    };
    assert!(
        bytes.len() == LEN_SERVER_HELLO,
        "a ServerHello decoded from a length the format forbids"
    );
    let mut out = [0u8; LEN_SERVER_HELLO];
    match hello.encode(&mut out) {
        Ok(written) => {
            assert!(
                written == LEN_SERVER_HELLO,
                "a ServerHello encoded to a length other than the constant"
            );
            assert!(
                out.as_slice() == bytes,
                "a ServerHello did not re-encode to the bytes it decoded from"
            );
        }
        Err(error) => classify(error),
    }
    // A buffer one byte short must deny rather than write a partial message.
    let mut cramped = [0u8; LEN_SERVER_HELLO - 1];
    assert!(
        hello.encode(&mut cramped).is_err(),
        "a ServerHello encoded into a buffer too small to hold it"
    );
}

/// Decodes a `ClientAuth`.
fn exercise_client_auth(bytes: &[u8]) {
    match ClientAuth::decode(bytes) {
        Ok(auth) => {
            assert!(
                bytes.len() == LEN_CLIENT_AUTH,
                "a ClientAuth decoded from a length row H4 forbids"
            );
            assert!(
                auth.client_confirm.as_slice() == bytes,
                "a ClientAuth's confirmation is not the bytes it decoded from"
            );
        }
        Err(error) => classify(error),
    }
}

/// Decodes a §10.2 client message and reads every field of a successful decode.
fn exercise_client_request(payload: &[u8]) {
    let request = match ClientRequest::decode(payload) {
        Ok(request) => request,
        Err(error) => return classify(error),
    };
    let tag = payload.first().copied().unwrap_or(0);
    assert!(
        TagRange::of(tag) == TagRange::ClientInbound,
        "a client request decoded from a tag outside the 0x0X range"
    );
    let _ = request.request_id();
    match request {
        ClientRequest::InferBegin(begin) => {
            assert!(
                begin.max_tokens <= MAX_TOKENS_REQUESTED,
                "an InferBegin decoded past the row M5 max_tokens ceiling"
            );
            assert!(
                begin.prompt_total_length <= MAX_PROMPT_BYTES,
                "an InferBegin decoded past the row M5 prompt-length ceiling"
            );
            let _ = begin.temperature;
            let _ = begin.top_p;
            let _ = begin.request_id;
        }
        ClientRequest::PromptChunk { request_id, chunk } => {
            assert!(
                chunk.len() <= MAX_PROMPT_CHUNK,
                "a PromptChunk decoded past the row M4 chunk ceiling"
            );
            assert!(
                is_inside(payload, chunk),
                "a PromptChunk's bytes escaped the record payload"
            );
            let _ = request_id;
        }
        ClientRequest::InferCommit { request_id } | ClientRequest::Cancel { request_id } => {
            let _ = request_id;
        }
        ClientRequest::Close => {
            assert!(
                payload.len() == 1,
                "a Close decoded from a body that is not empty"
            );
        }
    }
}

/// Decodes a §10.4 admin verb and reads every field of a successful decode.
fn exercise_admin_verb(payload: &[u8]) {
    let verb = match AdminVerb::decode(payload) {
        Ok(verb) => verb,
        Err(error) => return classify(error),
    };
    let tag = payload.first().copied().unwrap_or(0);
    assert!(
        TagRange::of(tag) == TagRange::AdminInbound,
        "an admin verb decoded from a tag outside the 0x1X range"
    );
    let _ = verb.request_id();
    match verb {
        AdminVerb::EnrollKey { role, .. } => {
            // Past this boundary the role is a Rust enum, so an unrecognized
            // one is unrepresentable rather than merely refused (row A1).
            assert!(
                matches!(role, CredentialRole::Client | CredentialRole::Admin),
                "an EnrollKey decoded a role outside the enumeration"
            );
            assert!(
                CredentialRole::from_wire(role.to_wire()) == Ok(role),
                "a decoded role does not round-trip through its wire byte"
            );
        }
        AdminVerb::RevokeKey { handle, .. } => {
            let _ = handle;
        }
        AdminVerb::LoadWeights { weights_digest, .. } => {
            let _ = weights_digest;
        }
        AdminVerb::ReadAuditLog {
            cursor,
            max_records,
            ..
        } => {
            assert!(
                max_records <= MAX_AUDIT_RECORDS,
                "a ReadAuditLog decoded past the row A7 record ceiling"
            );
            let _ = cursor;
        }
        AdminVerb::RestartServer { target, .. } => {
            assert!(
                RestartTarget::from_wire(target.to_wire()) == Ok(target),
                "a decoded restart target does not round-trip through its wire byte"
            );
        }
        AdminVerb::Reboot { .. } => {}
    }
}

/// Reads the §12 attributes of a denial. Every error must answer all three.
fn classify(error: BspError) {
    let disposition = error.disposition();
    assert!(
        matches!(disposition, Disposition::Drop | Disposition::ErrorKeep),
        "a denial carries no §12 disposition"
    );
    if let Some(code) = error.error_code() {
        let _ = code.to_wire();
    }
    let _ = error.attributed_tag();
}

// ---------------------------------------------------------------------------
// The §4.2 record layer
// ---------------------------------------------------------------------------

/// Drives the framing, padding, and sequence rules of §4.2.
fn exercise_record_layer(data: &[u8], driver: &mut Driver<'_>) {
    exercise_packet_length(driver.u32());
    if let Some(field) = data.get(..RECORD_LENGTH_PREFIX_BYTES) {
        let mut prefix = [0u8; RECORD_LENGTH_PREFIX_BYTES];
        prefix.copy_from_slice(field);
        exercise_packet_length(u32::from_be_bytes(prefix));
        if let Ok(length) = PacketLength::decode(prefix) {
            exercise_split(data, length);
        }
    }
    exercise_plaintext_round_trip(data);
    exercise_plaintext_decode(data, driver);
    exercise_sequence(driver.u32());
}

/// Row R1, and the extent arithmetic behind it.
fn exercise_packet_length(value: u32) {
    let length = match PacketLength::decode(value.to_be_bytes()) {
        Ok(length) => length,
        Err(_) => {
            assert!(
                !(MIN_PACKET_LENGTH..=MAX_PACKET_LENGTH).contains(&value),
                "an in-range packet length was refused by row R1"
            );
            return;
        }
    };
    assert!(
        length.value() >= MIN_PACKET_LENGTH && length.value() <= MAX_PACKET_LENGTH,
        "an out-of-range packet length passed row R1"
    );
    assert!(length.value() == value, "a packet length changed value");
    match length.record_length() {
        Ok(total) => {
            let expected = (value as usize)
                .checked_add(RECORD_LENGTH_PREFIX_BYTES)
                .and_then(|at| at.checked_add(RECORD_TAG_BYTES));
            assert!(
                expected == Some(total),
                "a record extent is not prefix + ciphertext + tag"
            );
        }
        Err(_) => panic!("a validated packet length has no record extent"),
    }
}

/// Splits a data record and checks the parts add up to the extent claimed.
fn exercise_split(stream: &[u8], length: PacketLength) {
    let record = match split_data_record(stream, length) {
        Ok(record) => record,
        Err(_) => return,
    };
    assert!(
        is_inside(stream, record.ciphertext),
        "a record ciphertext escaped the stream"
    );
    assert!(
        is_inside(stream, record.tag),
        "a record tag escaped the stream"
    );
    assert!(
        record.ciphertext.len() == length.value() as usize,
        "a record ciphertext is not the declared packet length"
    );
    assert!(
        record.tag.len() == RECORD_TAG_BYTES,
        "a record tag is not the Poly1305 width"
    );
    assert!(
        record.total_length <= stream.len(),
        "a record consumed more bytes than arrived"
    );
    assert!(
        Ok(record.total_length) == length.record_length(),
        "a record's consumed length disagrees with its extent"
    );
}

/// Frames the input as a record plaintext and recovers it.
///
/// The encoder and the decoder are the sender and receiver halves of the same
/// §4.2 rule, so a round trip that is not the identity is a disagreement
/// between the two ends of a live connection.
fn exercise_plaintext_round_trip(payload: &[u8]) {
    let mut framed = vec![0u8; FRAMED_PLAINTEXT_CAPACITY];
    let written = match encode_record_plaintext(payload, &mut framed) {
        Ok(written) => written,
        Err(_) => {
            assert!(
                payload.len() > BSP_MAX_RECORD_PLAINTEXT,
                "a payload within the ceiling failed to frame"
            );
            return;
        }
    };
    assert!(
        written.is_multiple_of(RECORD_PLAINTEXT_BLOCK),
        "a framed plaintext is not block-aligned"
    );
    let padding = usize::from(framed.first().copied().unwrap_or(0));
    assert!(
        padding >= MIN_RECORD_PADDING,
        "a framed plaintext carries less than the minimum padding"
    );
    assert!(
        written == payload.len().saturating_add(1).saturating_add(padding),
        "a framed plaintext's length is not field + payload + padding"
    );

    let declared = match u32::try_from(written) {
        Ok(declared) => declared,
        Err(_) => return,
    };
    let length = match PacketLength::decode(declared.to_be_bytes()) {
        Ok(length) => length,
        Err(_) => return,
    };
    let plaintext = match framed.get(..written) {
        Some(plaintext) => plaintext,
        None => return,
    };
    match decode_record_plaintext(plaintext, length) {
        Ok(recovered) => assert!(
            recovered == payload,
            "a framed record plaintext did not recover the payload it framed"
        ),
        Err(_) => panic!("a plaintext this crate framed was refused by its own decoder"),
    }
}

/// Decodes the raw input as a record plaintext, at its own length and at a
/// length the fuzzer chose.
///
/// Offering a length the plaintext does not have is deliberate: check 1 of
/// `decode_record_plaintext` is that the two framings agree, and a harness that
/// only ever offered the agreeing length would never reach it.
fn exercise_plaintext_decode(data: &[u8], driver: &mut Driver<'_>) {
    for declared in [data.len() as u64, u64::from(driver.u32())] {
        let Ok(narrowed) = u32::try_from(declared) else {
            continue;
        };
        let Ok(length) = PacketLength::decode(narrowed.to_be_bytes()) else {
            continue;
        };
        match decode_record_plaintext(data, length) {
            Ok(payload) => {
                assert!(
                    is_inside(data, payload),
                    "a recovered payload escaped the plaintext"
                );
                assert!(
                    payload.len() <= BSP_MAX_RECORD_PLAINTEXT,
                    "a recovered payload exceeded the row R4 ceiling"
                );
                assert!(
                    data.len() == narrowed as usize,
                    "a plaintext decoded at a length it does not have"
                );
                assert!(
                    data.len().is_multiple_of(RECORD_PLAINTEXT_BLOCK),
                    "an unaligned plaintext decoded"
                );
            }
            Err(error) => classify(error),
        }
    }
}

/// Row R5 — the sequence advances by exactly one and never wraps.
fn exercise_sequence(start: u32) {
    let mut counter = SequenceCounter::at(start);
    assert!(
        counter.value() == start,
        "a counter did not start where placed"
    );
    let exhausted = counter.is_exhausted();
    let nonce = counter.nonce();
    assert!(
        u64::from_be_bytes(nonce) == u64::from(start),
        "a nonce is not the sequence in the low 32 bits"
    );
    match counter.advance() {
        Ok(()) => {
            assert!(!exhausted, "an exhausted counter advanced");
            assert!(
                counter.value() == start.wrapping_add(1) && counter.value() > start,
                "a counter did not advance by exactly one"
            );
        }
        Err(_) => {
            assert!(exhausted, "a counter that could advance refused to");
            assert!(
                counter.value() == start,
                "a refused advance moved the counter"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The §5.5 session state machine
// ---------------------------------------------------------------------------

/// The invariants that must hold of a session in **every** reachable state.
///
/// This is the "cannot be driven into an illegal state" property, checked after
/// every transition rather than at the end, so the first step that breaks it is
/// the step the reproducer names.
fn check_session_invariants(session: &Session) {
    let established = session.state() == SessionState::Established;
    assert!(
        session.session_type().is_some() == established,
        "a capability exists in a state other than ESTABLISHED"
    );
    if !established {
        assert!(
            session.request_phase() == RequestPhase::Idle,
            "a request phase survived outside ESTABLISHED"
        );
    }
    if let RequestPhase::Collecting {
        declared_length,
        accumulated_length,
        ..
    } = session.request_phase()
    {
        assert!(
            accumulated_length <= declared_length,
            "a prompt accumulated past what row M8 admitted"
        );
        assert!(
            declared_length <= MAX_PROMPT_BYTES,
            "a prompt declared past the row M5 ceiling"
        );
    }
}

/// Drives one session through a fuzzer-chosen transition sequence.
fn drive_session(driver: &mut Driver<'_>) {
    let mut session = Session::new();
    check_session_invariants(&session);
    let steps = usize::from(driver.byte()) % SESSION_STEP_BUDGET;
    let mut taken = 0usize;
    while taken < steps {
        taken = taken.saturating_add(1);
        let before = session.state();
        step(&mut session, driver);
        check_session_invariants(&session);
        assert!(
            before != SessionState::Closed || session.state() == SessionState::Closed,
            "a closed session left the closed state"
        );
    }
}

/// Applies one fuzzer-chosen transition.
fn step(session: &mut Session, driver: &mut Driver<'_>) {
    match driver.byte() % 8 {
        0 => {
            let count = usize::from(driver.byte()) % 96;
            let bytes = driver.bytes(count);
            offer_client_hello(session, &bytes);
        }
        1 => {
            let bytes = build_client_hello(driver);
            offer_client_hello(session, &bytes);
        }
        2 => {
            let count = usize::from(driver.byte()) % 48;
            let bytes = driver.bytes(count);
            offer_client_auth(session, &bytes);
        }
        3 => {
            let bytes = driver.bytes(LEN_CLIENT_AUTH);
            offer_client_auth(session, &bytes);
        }
        4 => offer_establish(session, driver),
        5 => {
            session.close();
            assert!(
                session.state() == SessionState::Closed,
                "close left the session open"
            );
        }
        6 => {
            let count = usize::from(driver.byte()) % 64;
            let bytes = driver.bytes(count);
            deliver(session, &bytes);
        }
        _ => {
            let bytes = build_message(driver);
            deliver(session, &bytes);
        }
    }
}

/// Offers a `ClientHello` and checks the transition it caused.
fn offer_client_hello(session: &mut Session, bytes: &[u8]) {
    let before = session.state();
    match session.accept_client_hello(bytes) {
        Ok(hello) => {
            assert!(
                before == SessionState::WaitHello,
                "a ClientHello was accepted outside WaitHello"
            );
            assert!(
                session.state() == SessionState::WaitClientAuth,
                "an accepted ClientHello did not advance to WaitClientAuth"
            );
            assert!(
                session.session_type().is_none(),
                "a ClientHello granted a capability"
            );
            let _ = hello.chain_counter;
        }
        Err(error) => check_denial(session, before, error),
    }
}

/// Offers a `ClientAuth` and checks the transition it caused.
fn offer_client_auth(session: &mut Session, bytes: &[u8]) {
    let before = session.state();
    match session.accept_client_auth(bytes) {
        Ok(auth) => {
            assert!(
                before == SessionState::WaitClientAuth,
                "a ClientAuth was accepted outside WaitClientAuth"
            );
            assert!(
                session.state() == SessionState::AuthPending,
                "an accepted ClientAuth did not advance to AuthPending"
            );
            assert!(
                session.session_type().is_none(),
                "a ClientAuth granted a capability before row H5 ran"
            );
            let _ = auth.client_confirm;
        }
        Err(error) => check_denial(session, before, error),
    }
}

/// Attempts the §7.2 capability grant.
fn offer_establish(session: &mut Session, driver: &mut Driver<'_>) {
    let granted = if driver.byte().is_multiple_of(2) {
        SessionType::Client
    } else {
        SessionType::Admin
    };
    let before = session.state();
    match session.establish(granted) {
        Ok(()) => {
            assert!(
                before == SessionState::AuthPending,
                "a session established from a state other than AuthPending"
            );
            assert!(
                session.state() == SessionState::Established,
                "an accepted establish did not reach ESTABLISHED"
            );
            assert!(
                session.session_type() == Some(granted),
                "an established session was granted a different capability"
            );
        }
        Err(error) => check_denial(session, before, error),
    }
}

/// §12's action column, checked as a property of the session rather than of the
/// caller's memory of a table.
///
/// A `Drop` denial must leave the session `Closed`; an `ErrorKeep` denial must
/// leave the state exactly as it was. That is what "never advances session state
/// on bad input" means, and it is checkable here rather than asserted in prose.
fn check_denial(session: &Session, before: SessionState, error: BspError) {
    classify(error);
    match error.disposition() {
        Disposition::Drop => assert!(
            session.state() == SessionState::Closed,
            "a Drop denial left the session open"
        ),
        Disposition::ErrorKeep => assert!(
            session.state() == before,
            "an ErrorKeep denial moved the session"
        ),
    }
}

/// Delivers a data-phase message and checks what it did to the session.
fn deliver(session: &mut Session, payload: &[u8]) {
    let before = session.state();
    let phase_before = session.request_phase();
    match session.accept_message(payload) {
        Ok(InboundMessage::Client(request)) => {
            assert!(
                before == SessionState::Established,
                "a data message was accepted before ESTABLISHED"
            );
            // `Close` ends the session, so the grant is gone by the time this
            // runs; every other message leaves it in place.
            assert!(
                session.session_type() == Some(SessionType::Client)
                    || session.state() == SessionState::Closed,
                "a client request was accepted on a session that is not a client session"
            );
            if let ClientRequest::PromptChunk { chunk, .. } = request {
                assert!(
                    is_inside(payload, chunk),
                    "an accepted PromptChunk's bytes escaped the record payload"
                );
            }
        }
        Ok(InboundMessage::Admin(verb)) => {
            assert!(
                before == SessionState::Established,
                "an admin verb was accepted before ESTABLISHED"
            );
            assert!(
                session.session_type() == Some(SessionType::Admin),
                "an admin verb was accepted on a session that is not an admin session"
            );
            let _ = verb.request_id();
        }
        Err(error) => {
            check_denial(session, before, error);
            if error.disposition() == Disposition::ErrorKeep {
                assert!(
                    session.request_phase() == phase_before,
                    "an ErrorKeep denial advanced the request phase"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Well-formed message builders
//
// Random bytes reach row H2 and stop: the "BSP2" magic alone is a 2^-32 event.
// These builders spend fuzz bytes on the fields that matter and constants on
// the fields whose only legal value is a constant, which is what lets the
// fuzzer get past the handshake and attack the request phase behind it.
// ---------------------------------------------------------------------------

/// A `ClientHello` whose checked fields are correct and whose opaque fields are
/// the fuzzer's.
fn build_client_hello(driver: &mut Driver<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(LEN_CLIENT_HELLO);
    out.extend_from_slice(&BSP_MAGIC);
    out.push(BSP_VERSION_MAJOR);
    out.push(BSP_VERSION_MINOR);
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&driver.u64().to_be_bytes());
    out.extend_from_slice(&driver.bytes(32));
    out.extend_from_slice(&driver.bytes(16));
    out
}

/// One §10.2 or §10.4 message, shaped by the fuzzer.
fn build_message(driver: &mut Driver<'_>) -> Vec<u8> {
    let selector = driver.byte();
    match selector % 12 {
        0 => build_infer_begin(driver),
        1 => build_prompt_chunk(driver),
        2 => tagged(0x03, driver.u32()),
        3 => tagged(0x04, driver.u32()),
        4 => vec![0x05],
        5 => build_enroll_key(driver),
        6 => {
            let mut out = tagged(0x12, driver.u32());
            out.extend_from_slice(&driver.bytes(16));
            out
        }
        7 => {
            let mut out = tagged(0x13, driver.u32());
            out.extend_from_slice(&driver.bytes(32));
            out
        }
        8 => build_read_audit_log(driver),
        9 => {
            let mut out = tagged(0x15, driver.u32());
            out.push(driver.byte());
            out
        }
        10 => tagged(0x16, driver.u32()),
        // An unassigned tag with a fuzzer-chosen body: row M1, reached on
        // purpose rather than by luck.
        _ => {
            let mut out = vec![driver.byte()];
            let count = usize::from(driver.byte()) % 40;
            out.extend_from_slice(&driver.bytes(count));
            out
        }
    }
}

/// `0x01` — with `max_tokens` and `prompt_total_len` straddling their ceilings.
fn build_infer_begin(driver: &mut Driver<'_>) -> Vec<u8> {
    let mut out = tagged(0x01, driver.u32());
    out.extend_from_slice(&near_ceiling(driver, MAX_TOKENS_REQUESTED).to_be_bytes());
    out.extend_from_slice(&driver.u16().to_be_bytes());
    out.extend_from_slice(&driver.u16().to_be_bytes());
    out.extend_from_slice(&near_ceiling(driver, MAX_PROMPT_BYTES).to_be_bytes());
    out
}

/// `0x02` — with a declared length that may disagree with the bytes that follow.
fn build_prompt_chunk(driver: &mut Driver<'_>) -> Vec<u8> {
    let mut out = tagged(0x02, driver.u32());
    let present = usize::from(driver.u16()) % 512;
    let declared = match driver.byte() % 4 {
        0 => present as u16,
        1 => (present as u16).wrapping_add(1),
        2 => MAX_PROMPT_CHUNK as u16,
        _ => driver.u16(),
    };
    out.extend_from_slice(&declared.to_be_bytes());
    out.extend_from_slice(&driver.bytes(present));
    out
}

/// `0x11` — with a `role` byte that is usually, but not always, in range.
fn build_enroll_key(driver: &mut Driver<'_>) -> Vec<u8> {
    let mut out = tagged(0x11, driver.u32());
    out.push(match driver.byte() % 4 {
        0 => CredentialRole::WIRE_CLIENT,
        1 => CredentialRole::WIRE_ADMIN,
        _ => driver.byte(),
    });
    out.extend_from_slice(&driver.bytes(32));
    out
}

/// `0x14` — with `max_records` straddling row A7.
fn build_read_audit_log(driver: &mut Driver<'_>) -> Vec<u8> {
    let mut out = tagged(0x14, driver.u32());
    out.extend_from_slice(&driver.u64().to_be_bytes());
    let records = match driver.byte() % 4 {
        0 => MAX_AUDIT_RECORDS,
        1 => MAX_AUDIT_RECORDS.wrapping_add(1),
        _ => driver.u16(),
    };
    out.extend_from_slice(&records.to_be_bytes());
    out
}

/// `tag[1] || request_id[4]`.
fn tagged(tag: u8, request_id: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    out.push(tag);
    out.extend_from_slice(&request_id.to_be_bytes());
    out
}

/// A value at, just below, just above, or well away from `ceiling`.
///
/// Off-by-one on a bound is the defect a uniformly random `u32` finds with
/// probability 2^-32, so the boundary is offered explicitly.
fn near_ceiling(driver: &mut Driver<'_>, ceiling: u32) -> u32 {
    match driver.byte() % 4 {
        0 => ceiling,
        1 => ceiling.wrapping_add(1),
        2 => ceiling.wrapping_sub(1),
        _ => driver.u32(),
    }
}

// ---------------------------------------------------------------------------
// Response encoders
// ---------------------------------------------------------------------------

/// Encodes every §10.3 and §10.5 response shape into a fixed buffer.
///
/// The ceiling is checked on the way out as well as on the way in (§10.3), so
/// an encoder that could emit an unframeable record would be a way to violate
/// row R4 from the inside — which is what these assertions look for.
fn exercise_encoders(data: &[u8], driver: &mut Driver<'_>) {
    let mut out = vec![0u8; RESPONSE_BUFFER_BYTES];
    let request_id = driver.u32();
    let opaque = data
        .get(..data.len().min(MAX_AUDIT_CHUNK.max(MAX_TOKEN_CHUNK)))
        .unwrap_or(&[]);

    let client = [
        ClientResponse::Accepted { request_id },
        ClientResponse::TokenChunk {
            request_id,
            tokens: opaque,
        },
        ClientResponse::StreamEnd {
            request_id,
            finish_reason: FinishReason::from_wire(driver.byte() % 5)
                .unwrap_or(FinishReason::ModelError),
        },
        ClientResponse::Error {
            request_id,
            error_code: driver.u16(),
        },
        ClientResponse::Bye,
    ];
    for response in client {
        check_encoded(response.encode(&mut out));
    }

    let mut handle = [0u8; 16];
    handle.copy_from_slice(&driver.bytes(16));
    let admin = [
        AdminResponse::Ok {
            request_id,
            status: driver.u16(),
        },
        AdminResponse::KeyEnrolled { request_id, handle },
        AdminResponse::AuditChunk {
            request_id,
            next_cursor: driver.u64(),
            records: opaque,
        },
        AdminResponse::Error {
            request_id,
            error_code: driver.u16(),
        },
        AdminResponse::Bye,
    ];
    for response in admin {
        check_encoded(response.encode(&mut out));
    }

    // A one-byte buffer cannot hold any response but `Bye`, and must deny
    // rather than write what fits.
    let mut cramped = [0u8; 1];
    let _ = ClientResponse::Accepted { request_id }.encode(&mut cramped);
    let _ = AdminResponse::Bye.encode(&mut cramped);
}

/// Every encode either denies or reports a length within row R4.
fn check_encoded(outcome: Result<usize, BspError>) {
    match outcome {
        Ok(written) => assert!(
            written <= BSP_MAX_RECORD_PLAINTEXT,
            "a response encoded past the row R4 ceiling"
        ),
        Err(error) => classify(error),
    }
}

// ---------------------------------------------------------------------------

fuzz_target!(|data: &[u8]| {
    // Every byte of the input classified through the §10 tag partition. The
    // partition must be total: `TagRange::of` has no failure mode and every
    // byte lands in exactly one quadrant.
    for byte in data.iter().copied() {
        let range = TagRange::of(byte);
        let quadrants = [
            range == TagRange::ClientInbound,
            range == TagRange::AdminInbound,
            range == TagRange::ClientOutbound,
            range == TagRange::AdminOutbound,
            range == TagRange::Unassigned,
        ];
        assert!(
            quadrants.iter().filter(|held| **held).count() == 1,
            "a tag byte fell in other than exactly one quadrant"
        );
        let _ = CredentialRole::from_wire(byte);
        let _ = RestartTarget::from_wire(byte);
        let _ = FinishReason::from_wire(byte);
    }

    decode_everything(data);

    let mut driver = Driver::new(data);
    exercise_record_layer(data, &mut driver);
    exercise_encoders(data, &mut driver);
    drive_session(&mut driver);
});
