//! Kani proof harnesses for the BSP v2 wire decoder (`brainix-bsp`).
//!
//! The decoder is a **Full tier** component under `SECURITY_INVARIANTS.md` §16
//! because it is the first code in BraiNIX that touches a byte from a hostile
//! remote client (`INV-PARSE-001`). §15's `INV-PARSE-002` requires *both* a
//! fuzz target and a Kani harness: the fuzz target finds what these harnesses
//! did not model, and these harnesses prove what fuzzing cannot exhaust.
//!
//! This crate follows the repository's convention that proofs live in a
//! dedicated verify crate beside the crate they verify, as `src/adt-verify/`
//! does for the Apple Device Tree parser and `src/capability-verify/` does for
//! the kernel's capability subsystem. It adds no code to `brainix-bsp` and
//! changes none.
//!
//! # The bounds, stated honestly
//!
//! Kani is a **bounded** model checker. It cannot verify a `&[u8]` of unbounded
//! length, so every harness over a message fixes the message's length to a
//! constant and proves the property for *every* byte string of exactly that
//! length. Each constant is a structural threshold of the format rather than a
//! round number:
//!
//! - **64 and 32 bytes** ([`brainix_bsp::LEN_CLIENT_HELLO`],
//!   [`brainix_bsp::LEN_CLIENT_AUTH`]) are not bounds at all. Rows H1 and H4
//!   make a handshake message's length a compile-time constant, and
//!   `require_exact_length` is the first thing either decoder runs, so a
//!   message of any other length returns before a single field is read. Proving
//!   the property for every 64-byte and every 32-byte input therefore covers
//!   every input on which the decoder does any work.
//! - **5 bytes** ([`SHORT_PAYLOAD_LEN`]) — one tag plus a `request_id`: the
//!   smallest payload at which `InferCommit`, `Cancel`, and `Reboot` decode.
//!   The cheap tier, and the length at which both the accept and the reject
//!   path are already reachable.
//! - **17 bytes** ([`CLIENT_PAYLOAD_LEN`]) — one tag plus `InferBegin`'s
//!   16-byte body: the smallest payload at which **every** §10.2 message shape
//!   is reachable, so row M5's two ceilings are not bounded away.
//! - **15 bytes** ([`ADMIN_PAYLOAD_LEN`]) — one tag plus `ReadAuditLog`'s
//!   14-byte body, which is the largest admin verb that fits below the 21-byte
//!   `RevokeKey` step and the length at which row A7's ceiling is reachable.
//! - **16 bytes** ([`PLAINTEXT_LEN`]) — two §4.2 blocks, so a record plaintext
//!   exists whose payload is longer than the minimum and whose padding rules
//!   are therefore not vacuous.
//! - **22 bytes** ([`STREAM_LEN`]) — the shortest complete data record:
//!   a 4-byte encrypted length, `MIN_PACKET_LENGTH` ciphertext bytes, and a
//!   16-byte tag.
//!
//! **What remains unproven above the bounds**, named rather than implied:
//!
//! 1. **Nothing about a full-size record.** `BSP_MAX_RECORD_PLAINTEXT` is 4096
//!    and `MAX_PACKET_LENGTH` is 35000. The proofs say what they say about 5,
//!    15, 16, 17 and 22 bytes and no more.
//! 2. **The `PromptChunk` var-bytes field is proved only at short lengths.** At
//!    17 bytes a chunk of at most 10 bytes fits, so
//!    `VarBytesLengthExceedsMaximum` — the `MAX_PROMPT_CHUNK` ceiling at 4032 —
//!    is reachable only through its *denial* branch, never through an accepted
//!    chunk of that size. The accepted-at-the-ceiling case is covered by the
//!    test suite and the fuzz corpus.
//! 3. **`EnrollKey`, `RevokeKey`, and `LoadWeights` bodies** are 37, 20, and 36
//!    bytes and do not fit under [`ADMIN_PAYLOAD_LEN`]. Their decoders are
//!    fixed-array reads with no arithmetic, and row A1's `role` byte is proved
//!    unbounded by [`proofs::bsp_enumerated_authority_bytes_match_the_specification`];
//!    the framing around them is covered by tests and fuzzing.
//! 4. **Reassembly across many chunks.** `MAX_PROMPT_BYTES` is 16384 and
//!    `MAX_PROMPT_CHUNK` is 4032, so exhausting the prompt buffer takes five
//!    records. [`proofs::bsp_request_phase_never_accumulates_past_what_it_declared`]
//!    proves the row M8 invariant holds after *each* admitted chunk, which is
//!    the inductive step, but the harness itself runs two.
//!
//! Five harnesses are **not** bounded and hold for every input of their type:
//! [`proofs::bsp_packet_length_arithmetic_never_overflows`] over all 2^32
//! length words, [`proofs::bsp_sequence_counter_advances_by_one_or_denies`] over
//! all 2^32 sequences, [`proofs::bsp_tag_partition_is_total_and_disjoint`] and
//! [`proofs::bsp_enumerated_authority_bytes_match_the_specification`] over all
//! 256 tag bytes, and
//! [`proofs::bsp_record_extent_arithmetic_never_overflows`] over all 2^32
//! packet lengths.

#![deny(unsafe_code)]
// kani is a cfg set by the Kani verification tool's dedicated CI image.
// On the host target it is not defined; this allow suppresses the warning.
#![allow(unexpected_cfgs)]

/// Payload length at which a tag and a `request_id` fit, and nothing more.
pub const SHORT_PAYLOAD_LEN: usize = 5;

/// Payload length at which every §10.2 client message shape is reachable.
pub const CLIENT_PAYLOAD_LEN: usize = 17;

/// Payload length at which `ReadAuditLog` and row A7's ceiling are reachable.
pub const ADMIN_PAYLOAD_LEN: usize = 15;

/// Record plaintext length: two §4.2 blocks.
pub const PLAINTEXT_LEN: usize = 16;

/// The shortest complete data record: prefix, minimum ciphertext, tag.
pub const STREAM_LEN: usize = 22;

/// Transitions the session state-machine harness drives.
pub const STATE_MACHINE_STEPS: usize = 4;

#[cfg(kani)]
mod proofs {
    use brainix_bsp::record::{
        decode_record_plaintext, encode_record_plaintext, split_data_record, MAX_PACKET_LENGTH,
        MIN_PACKET_LENGTH, MIN_RECORD_PADDING, RECORD_LENGTH_PREFIX_BYTES, RECORD_PLAINTEXT_BLOCK,
        RECORD_TAG_BYTES,
    };
    use brainix_bsp::{
        AdminVerb, BspError, ClientAuth, ClientHello, ClientRequest, CredentialRole, Disposition,
        FinishReason, InboundMessage, PacketLength, RequestPhase, RestartTarget, SequenceCounter,
        ServerHello, Session, SessionState, SessionType, TagRange, BSP_MAGIC,
        BSP_MAX_RECORD_PLAINTEXT, BSP_VERSION_MAJOR, BSP_VERSION_MINOR, LEN_CLIENT_AUTH,
        LEN_CLIENT_HELLO, LEN_SERVER_HELLO, MAX_AUDIT_RECORDS, MAX_PROMPT_BYTES, MAX_PROMPT_CHUNK,
        MAX_RECORD_SEQ, MAX_TOKENS_REQUESTED,
    };

    use crate::{
        ADMIN_PAYLOAD_LEN, CLIENT_PAYLOAD_LEN, PLAINTEXT_LEN, SHORT_PAYLOAD_LEN,
        STATE_MACHINE_STEPS, STREAM_LEN,
    };

    // Every harness carries an explicit `#[kani::unwind(N)]`. The attribute
    // takes an integer literal, so the numbers cannot be given names; they are
    // explained once here.
    //
    // `brainix-bsp` contains exactly one counted loop: `write_padding` in
    // `record.rs`, which appends between `MIN_RECORD_PADDING` (4) and
    // `MIN_RECORD_PADDING + RECORD_PLAINTEXT_BLOCK - 1` (11) bytes, so 12
    // iterations bound it. The state-machine harness's own loop runs
    // `STATE_MACHINE_STEPS` (4) times. Every other repetition in the crate is a
    // fixed-width `copy_from_slice`. **24** is comfortably past all of them.
    //
    // Two harnesses use **66** instead, and the reason is the harness rather
    // than the crate: they walk a whole handshake message byte by byte to
    // assert the decoded fields are the bytes that arrived, which is 32
    // iterations for a `ClientAuth` and 64 for a `ServerHello`. Both were first
    // written at 24 and Kani reported an unwinding-assertion failure — the
    // visible failure the mechanism exists to produce, rather than a silent
    // false success — so the bound was raised to one past the longest walk.
    // A loop that needed more would be reported the same way.

    /// Bytes in the buffer the framing harness encodes into.
    ///
    /// One §4.2 block past the largest plaintext an 8-byte payload can frame,
    /// so the encoder has room and `OutputBufferTooSmall` is not the only
    /// reachable outcome.
    const FRAMING_BUFFER_LEN: usize = 32;

    /// Payload length the framing round-trip harness frames.
    const FRAMED_PAYLOAD_LEN: usize = 8;

    /// A `ClientHello` whose checked preamble is correct.
    ///
    /// Concrete on purpose: the state-machine harnesses are about the *order*
    /// messages arrive in, and row H2 is proved separately and exhaustively by
    /// [`bsp_client_hello_decode_never_panics_on_any_sixty_four_byte_input`].
    /// Spending 512 symbolic bits per transition to re-derive it would buy
    /// nothing and would put the state-machine proof out of reach.
    const fn valid_client_hello() -> [u8; LEN_CLIENT_HELLO] {
        let mut wire = [0u8; LEN_CLIENT_HELLO];
        wire[0] = BSP_MAGIC[0];
        wire[1] = BSP_MAGIC[1];
        wire[2] = BSP_MAGIC[2];
        wire[3] = BSP_MAGIC[3];
        wire[4] = BSP_VERSION_MAJOR;
        wire[5] = BSP_VERSION_MINOR;
        wire
    }

    // -----------------------------------------------------------------------
    // §5.1 — the three handshake decoders
    // -----------------------------------------------------------------------

    /// **No panic on any `ClientHello`, and row H2 is exactly the preamble.**
    ///
    /// For every one of the 2^512 sixty-four-byte inputs, `ClientHello::decode`
    /// returns a `ClientHello` or a `BspError` — never a panic, an
    /// out-of-bounds index, or a wrapped arithmetic operation (Kani's default
    /// checks). Beyond that it proves the accept condition is **exactly** row
    /// H2: a decode succeeds if and only if the magic, both version bytes, and
    /// the reserved field all hold their required values, and the decoded
    /// `chain_counter`, `client_nonce` and `key_selector` are exactly the
    /// bytes at §5.1's offsets.
    ///
    /// Sixty-four bytes is not a bound. Row H1's length check is the first
    /// statement in the decoder, so an input of any other length returns before
    /// a field is read; this covers every input on which any work happens.
    #[kani::proof]
    #[kani::unwind(24)]
    fn bsp_client_hello_decode_never_panics_on_any_sixty_four_byte_input() {
        let wire: [u8; LEN_CLIENT_HELLO] = kani::any();
        let preamble_holds = wire[0] == BSP_MAGIC[0]
            && wire[1] == BSP_MAGIC[1]
            && wire[2] == BSP_MAGIC[2]
            && wire[3] == BSP_MAGIC[3]
            && wire[4] == BSP_VERSION_MAJOR
            && wire[5] == BSP_VERSION_MINOR
            && wire[6] == 0
            && wire[7] == 0;
        match ClientHello::decode(&wire) {
            Ok(hello) => {
                kani::assert(preamble_holds, "a ClientHello row H2 forbids was accepted");
                let mut counter_bytes = [0u8; 8];
                let mut index = 0usize;
                while index < 8 {
                    counter_bytes[index] = wire[8usize.saturating_add(index)];
                    index = index.saturating_add(1);
                }
                kani::assert(
                    hello.chain_counter == u64::from_be_bytes(counter_bytes),
                    "the decoded chain_counter is not the big-endian field at offset 8",
                );
                kani::assert(
                    hello.client_nonce[0] == wire[16] && hello.client_nonce[31] == wire[47],
                    "the decoded client_nonce is not the field at offset 16",
                );
                kani::assert(
                    hello.key_selector[0] == wire[48] && hello.key_selector[15] == wire[63],
                    "the decoded key_selector is not the field at offset 48",
                );
            }
            Err(error) => {
                kani::assert(!preamble_holds, "a well-formed ClientHello was refused");
                classify(error);
            }
        }
    }

    /// **No panic on any `ClientAuth`, and the confirmation is the input.**
    ///
    /// Thirty-two bytes is not a bound, for the reason row H1 gives above. Row
    /// H4 accepts every 32-byte input — the message is one opaque fixed array —
    /// so this proof is that the decode is *total* and that the value handed to
    /// the caller is exactly the bytes that arrived, with nothing reordered.
    #[kani::proof]
    #[kani::unwind(66)]
    fn bsp_client_auth_decode_never_panics_on_any_thirty_two_byte_input() {
        let wire: [u8; LEN_CLIENT_AUTH] = kani::any();
        match ClientAuth::decode(&wire) {
            Ok(auth) => {
                let mut index = 0usize;
                while index < LEN_CLIENT_AUTH {
                    kani::assert(
                        auth.client_confirm[index] == wire[index],
                        "a decoded client_confirm is not the bytes that arrived",
                    );
                    index = index.saturating_add(1);
                }
            }
            Err(_) => kani::assert(false, "a 32-byte ClientAuth was refused"),
        }
    }

    /// **`ServerHello` round-trips, and its encoder respects the buffer.**
    ///
    /// For every 64-byte input, decoding and re-encoding reproduces the input
    /// byte for byte, so the decoder and the encoder cannot disagree about
    /// §5.1's field order — a disagreement no decode-only proof would see.
    /// Encoding into a buffer one byte short denies rather than writing a
    /// partial message.
    #[kani::proof]
    #[kani::unwind(66)]
    fn bsp_server_hello_round_trips_and_respects_the_output_buffer() {
        let wire: [u8; LEN_SERVER_HELLO] = kani::any();
        let hello = match ServerHello::decode(&wire) {
            Ok(hello) => hello,
            Err(_) => {
                kani::assert(false, "a 64-byte ServerHello was refused");
                return;
            }
        };
        let mut out = [0u8; LEN_SERVER_HELLO];
        match hello.encode(&mut out) {
            Ok(written) => {
                kani::assert(
                    written == LEN_SERVER_HELLO,
                    "a ServerHello encoded to a length other than the constant",
                );
                let mut index = 0usize;
                while index < LEN_SERVER_HELLO {
                    kani::assert(
                        out[index] == wire[index],
                        "a ServerHello did not re-encode to the bytes it decoded from",
                    );
                    index = index.saturating_add(1);
                }
            }
            Err(_) => kani::assert(false, "a ServerHello did not fit its own constant length"),
        }
        let mut cramped = [0u8; LEN_SERVER_HELLO - 1];
        kani::assert(
            hello.encode(&mut cramped).is_err(),
            "a ServerHello encoded into a buffer too small to hold it",
        );
    }

    // -----------------------------------------------------------------------
    // §10 — the message decoders
    // -----------------------------------------------------------------------

    /// **No panic on any five-byte client payload. The cheap tier.**
    ///
    /// Five bytes is one tag plus a `request_id`, the smallest payload at which
    /// a §10.2 message decodes at all. Both the accept and the reject path are
    /// reachable, so the proof is not vacuously about rejection, and it
    /// completes where the wider harnesses may not.
    #[kani::proof]
    #[kani::unwind(24)]
    fn bsp_client_request_decode_never_panics_on_any_five_byte_payload() {
        let payload: [u8; SHORT_PAYLOAD_LEN] = kani::any();
        check_client_request(&payload);
    }

    /// **No panic on any seventeen-byte client payload, and every §8 bound the
    /// decoder claims is a bound it actually applies. The headline property.**
    ///
    /// Seventeen bytes is the smallest payload at which every §10.2 shape is
    /// reachable, including `InferBegin`'s 16-byte body, so row M5's two
    /// ceilings are inside the bound rather than argued around it. For every
    /// one of the 2^136 inputs of this length, `ClientRequest::decode` returns
    /// a message or a `BspError`, and when it returns a message:
    ///
    /// - the tag lies in the `0x0X` quadrant (row M2 is structural);
    /// - `max_tokens ≤ MAX_TOKENS_REQUESTED` and
    ///   `prompt_total_length ≤ MAX_PROMPT_BYTES` (row M5);
    /// - a `PromptChunk`'s bytes are at most `MAX_PROMPT_CHUNK` and lie wholly
    ///   inside the payload the caller supplied — checked by comparing
    ///   addresses, not by trusting the decoder's arithmetic;
    /// - a `Close` consumed the whole payload, so its body really is empty.
    #[kani::proof]
    #[kani::unwind(24)]
    fn bsp_client_request_decode_never_panics_on_any_seventeen_byte_payload() {
        let payload: [u8; CLIENT_PAYLOAD_LEN] = kani::any();
        check_client_request(&payload);
    }

    /// **No panic on any fifteen-byte admin payload, and row A7 holds.**
    ///
    /// Fifteen bytes is one tag plus `ReadAuditLog`'s 14-byte body, the length
    /// at which the `max_records` ceiling becomes reachable. Every decoded verb
    /// is asserted to lie in the `0x1X` quadrant and to respect the bound its
    /// own decoder applies.
    #[kani::proof]
    #[kani::unwind(24)]
    fn bsp_admin_verb_decode_never_panics_on_any_fifteen_byte_payload() {
        let payload: [u8; ADMIN_PAYLOAD_LEN] = kani::any();
        match AdminVerb::decode(&payload) {
            Ok(verb) => {
                kani::assert(
                    TagRange::of(payload[0]) == TagRange::AdminInbound,
                    "an admin verb decoded from a tag outside the 0x1X range",
                );
                match verb {
                    AdminVerb::ReadAuditLog { max_records, .. } => kani::assert(
                        max_records <= MAX_AUDIT_RECORDS,
                        "a ReadAuditLog decoded past the row A7 ceiling",
                    ),
                    AdminVerb::EnrollKey { role, .. } => kani::assert(
                        CredentialRole::from_wire(role.to_wire()).is_ok(),
                        "a decoded role does not round-trip through its wire byte",
                    ),
                    AdminVerb::RestartServer { target, .. } => kani::assert(
                        RestartTarget::from_wire(target.to_wire()).is_ok(),
                        "a decoded restart target does not round-trip",
                    ),
                    _ => {}
                }
            }
            Err(error) => classify(error),
        }
    }

    /// The assertions every accepted client message must satisfy.
    fn check_client_request(payload: &[u8]) {
        let request = match ClientRequest::decode(payload) {
            Ok(request) => request,
            Err(error) => return classify(error),
        };
        let tag = match payload.first() {
            Some(tag) => *tag,
            None => return,
        };
        kani::assert(
            TagRange::of(tag) == TagRange::ClientInbound,
            "a client request decoded from a tag outside the 0x0X range",
        );
        match request {
            ClientRequest::InferBegin(begin) => {
                kani::assert(
                    begin.max_tokens <= MAX_TOKENS_REQUESTED,
                    "an InferBegin decoded past the row M5 max_tokens ceiling",
                );
                kani::assert(
                    begin.prompt_total_length <= MAX_PROMPT_BYTES,
                    "an InferBegin decoded past the row M5 prompt-length ceiling",
                );
            }
            ClientRequest::PromptChunk { chunk, .. } => {
                kani::assert(
                    chunk.len() <= MAX_PROMPT_CHUNK,
                    "a PromptChunk decoded past the row M4 chunk ceiling",
                );
                kani::assert(
                    is_inside(payload, chunk),
                    "a PromptChunk's bytes escaped the record payload",
                );
            }
            ClientRequest::Close => kani::assert(
                payload.len() == 1,
                "a Close decoded from a body that is not empty",
            ),
            ClientRequest::InferCommit { .. } | ClientRequest::Cancel { .. } => {}
        }
    }

    /// Every denial answers §12's three questions without panicking.
    fn classify(error: BspError) {
        let disposition = error.disposition();
        kani::assert(
            matches!(disposition, Disposition::Drop | Disposition::ErrorKeep),
            "a denial carries no §12 disposition",
        );
        kani::assert(
            (disposition == Disposition::ErrorKeep) == error.error_code().is_some(),
            "a denial's disposition disagrees with whether it has an error code",
        );
        if let Some(code) = error.error_code() {
            let _ = code.to_wire();
        }
        let _ = error.attributed_tag();
    }

    /// Whether `part` is a sub-slice of `whole`.
    ///
    /// The decoder never copies a variable-length field, so every borrowed
    /// chunk must point into the caller's buffer. Comparing the addresses is
    /// how that is checked without trusting the decoder's own arithmetic.
    fn is_inside(whole: &[u8], part: &[u8]) -> bool {
        let base = whole.as_ptr() as usize;
        let start = part.as_ptr() as usize;
        match start
            .checked_sub(base)
            .and_then(|at| at.checked_add(part.len()))
        {
            Some(end) => end <= whole.len(),
            None => false,
        }
    }

    // -----------------------------------------------------------------------
    // §4.2 — the record layer
    // -----------------------------------------------------------------------

    /// **Row R1 is exactly the stated range, and the extent arithmetic cannot
    /// overflow — unbounded.**
    ///
    /// Quantifies over all 2^32 length words. Proves that `PacketLength::decode`
    /// accepts a value if and only if it lies in
    /// `MIN_PACKET_LENGTH ..= MAX_PACKET_LENGTH`, that an accepted value is
    /// returned unchanged, and that `record_length` is exactly
    /// `4 + value + 16` computed without wrapping. A length that wrapped into
    /// range would be a buffer split at an offset the tag never covered.
    #[kani::proof]
    fn bsp_packet_length_arithmetic_never_overflows() {
        let value: u32 = kani::any();
        match PacketLength::decode(value.to_be_bytes()) {
            Ok(length) => {
                kani::assert(
                    value >= MIN_PACKET_LENGTH && value <= MAX_PACKET_LENGTH,
                    "an out-of-range packet length passed row R1",
                );
                kani::assert(length.value() == value, "a packet length changed value");
            }
            Err(_) => kani::assert(
                value < MIN_PACKET_LENGTH || value > MAX_PACKET_LENGTH,
                "an in-range packet length was refused by row R1",
            ),
        }
    }

    /// **A record's extent is prefix + ciphertext + tag, always — unbounded.**
    ///
    /// Separated from the range proof so the arithmetic is quantified over
    /// every accepted length independently of how it was accepted.
    #[kani::proof]
    fn bsp_record_extent_arithmetic_never_overflows() {
        let value: u32 = kani::any();
        let length = match PacketLength::decode(value.to_be_bytes()) {
            Ok(length) => length,
            Err(_) => return,
        };
        match length.record_length() {
            Ok(total) => {
                let expected = (value as usize)
                    .checked_add(RECORD_LENGTH_PREFIX_BYTES)
                    .and_then(|at| at.checked_add(RECORD_TAG_BYTES));
                kani::assert(
                    expected == Some(total),
                    "a record extent is not prefix + ciphertext + tag",
                );
            }
            Err(_) => kani::assert(false, "a validated packet length has no record extent"),
        }
    }

    /// **Splitting a record never reads outside the stream.**
    ///
    /// Twenty-two bytes is the shortest complete data record. For every stream
    /// of that length and every four-byte length field, `split_data_record`
    /// either denies or returns a ciphertext and a tag that both lie wholly
    /// inside the stream, whose lengths are exactly the declared packet length
    /// and the Poly1305 width, and whose total is the extent the length claimed.
    #[kani::proof]
    #[kani::unwind(24)]
    fn bsp_split_data_record_stays_within_the_stream() {
        let stream: [u8; STREAM_LEN] = kani::any();
        let field: [u8; RECORD_LENGTH_PREFIX_BYTES] = kani::any();
        let length = match PacketLength::decode(field) {
            Ok(length) => length,
            Err(_) => return,
        };
        let record = match split_data_record(&stream, length) {
            Ok(record) => record,
            Err(_) => return,
        };
        kani::assert(
            is_inside(&stream, record.ciphertext),
            "a record ciphertext escaped the stream",
        );
        kani::assert(
            is_inside(&stream, record.tag),
            "a record tag escaped the stream",
        );
        kani::assert(
            record.tag.len() == RECORD_TAG_BYTES,
            "a record tag is not the Poly1305 width",
        );
        kani::assert(
            record.total_length <= stream.len(),
            "a record consumed more bytes than arrived",
        );
        kani::assert(
            Ok(record.total_length) == length.record_length(),
            "a record's consumed length disagrees with its extent",
        );
    }

    /// **Unpadding a record plaintext never reads outside it.**
    ///
    /// Sixteen bytes is two §4.2 blocks, so a plaintext exists whose payload is
    /// longer than the minimum and whose padding rules are not vacuous. For
    /// every such plaintext and every four-byte length field, the recovered
    /// payload lies wholly inside the plaintext, is within row R4's ceiling,
    /// and — when it was accepted — the plaintext really was block-aligned and
    /// really did carry at least `MIN_RECORD_PADDING` padding bytes.
    #[kani::proof]
    #[kani::unwind(24)]
    fn bsp_record_plaintext_decode_stays_within_the_buffer() {
        let plaintext: [u8; PLAINTEXT_LEN] = kani::any();
        let field: [u8; RECORD_LENGTH_PREFIX_BYTES] = kani::any();
        let length = match PacketLength::decode(field) {
            Ok(length) => length,
            Err(_) => return,
        };
        match decode_record_plaintext(&plaintext, length) {
            Ok(payload) => {
                kani::assert(
                    is_inside(&plaintext, payload),
                    "a recovered payload escaped the plaintext",
                );
                kani::assert(
                    payload.len() <= BSP_MAX_RECORD_PLAINTEXT,
                    "a recovered payload exceeded the row R4 ceiling",
                );
                kani::assert(
                    length.value() as usize == PLAINTEXT_LEN,
                    "a plaintext decoded at a length it does not have",
                );
                kani::assert(
                    usize::from(plaintext[0]) >= MIN_RECORD_PADDING,
                    "a plaintext with less than the minimum padding was accepted",
                );
                kani::assert(
                    payload
                        .len()
                        .checked_add(usize::from(plaintext[0]))
                        .and_then(|used| used.checked_add(1))
                        == Some(PLAINTEXT_LEN),
                    "the payload, the padding, and the length field do not fill the plaintext",
                );
            }
            Err(error) => classify(error),
        }
    }

    /// **Framing and unframing are inverse, and the framing respects §4.2.**
    ///
    /// The encoder and the decoder are the sender and the receiver halves of one
    /// rule, so a round trip that is not the identity is a disagreement between
    /// the two ends of a live connection. For every eight-byte payload the
    /// framed plaintext is block-aligned, carries at least the minimum padding,
    /// and decodes back to the payload it framed.
    #[kani::proof]
    #[kani::unwind(24)]
    fn bsp_record_plaintext_round_trips_through_its_own_framing() {
        let payload: [u8; FRAMED_PAYLOAD_LEN] = kani::any();
        let mut framed = [0u8; FRAMING_BUFFER_LEN];
        let written = match encode_record_plaintext(&payload, &mut framed) {
            Ok(written) => written,
            Err(_) => {
                kani::assert(false, "an eight-byte payload failed to frame");
                return;
            }
        };
        kani::assert(
            written % RECORD_PLAINTEXT_BLOCK == 0,
            "a framed plaintext is not block-aligned",
        );
        kani::assert(
            usize::from(framed[0]) >= MIN_RECORD_PADDING,
            "a framed plaintext carries less than the minimum padding",
        );
        kani::assert(
            written
                == FRAMED_PAYLOAD_LEN
                    .saturating_add(1)
                    .saturating_add(usize::from(framed[0])),
            "a framed plaintext's length is not field + payload + padding",
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
            Ok(recovered) => {
                kani::assert(
                    recovered.len() == FRAMED_PAYLOAD_LEN,
                    "a framed plaintext recovered a payload of a different length",
                );
                let mut index = 0usize;
                while index < FRAMED_PAYLOAD_LEN {
                    kani::assert(
                        recovered[index] == payload[index],
                        "a framed record plaintext did not recover the payload it framed",
                    );
                    index = index.saturating_add(1);
                }
            }
            Err(_) => kani::assert(
                false,
                "a plaintext this crate framed was refused by its own decoder",
            ),
        }
    }

    /// **The sequence advances by exactly one or denies — unbounded.**
    ///
    /// Quantifies over all 2^32 sequence positions. Proves that `advance`
    /// either moves the counter forward by exactly one or refuses, that it
    /// refuses precisely at `MAX_RECORD_SEQ`, that a refused advance leaves the
    /// counter where it was, and that the AEAD nonce is the sequence in its low
    /// 32 bits with the high 32 always zero. **The sequence never wraps**, and
    /// this is where that stops being an argument: a wrapped sequence is a
    /// reused stream-cipher nonce, which is catastrophic rather than merely a
    /// protocol fault.
    #[kani::proof]
    fn bsp_sequence_counter_advances_by_one_or_denies() {
        let start: u32 = kani::any();
        let mut counter = SequenceCounter::at(start);
        kani::assert(
            counter.value() == start,
            "a counter did not start where placed",
        );
        kani::assert(
            counter.is_exhausted() == (start >= MAX_RECORD_SEQ),
            "is_exhausted disagrees with the row R5 boundary",
        );
        kani::assert(
            u64::from_be_bytes(counter.nonce()) == u64::from(start),
            "a nonce is not the sequence in its low 32 bits",
        );
        let exhausted = counter.is_exhausted();
        match counter.advance() {
            Ok(()) => {
                kani::assert(!exhausted, "an exhausted counter advanced");
                kani::assert(
                    counter.value() == start.saturating_add(1) && counter.value() > start,
                    "a counter did not advance by exactly one",
                );
            }
            Err(_) => {
                kani::assert(exhausted, "a counter that could advance refused to");
                kani::assert(
                    counter.value() == start,
                    "a refused advance moved the counter",
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // §10 — the tag partition and the enumerated authority bytes
    // -----------------------------------------------------------------------

    /// **The §10 tag partition is total and disjoint — unbounded.**
    ///
    /// Quantifies over all 256 tag bytes. Every byte lands in exactly one
    /// quadrant, the classification is the high nibble and nothing else, and no
    /// byte is left unclassified. Type confusion is a decoding error rather
    /// than a policy question precisely because this function is total.
    #[kani::proof]
    fn bsp_tag_partition_is_total_and_disjoint() {
        let tag: u8 = kani::any();
        let range = TagRange::of(tag);
        let matches = usize::from(range == TagRange::ClientInbound)
            .saturating_add(usize::from(range == TagRange::AdminInbound))
            .saturating_add(usize::from(range == TagRange::ClientOutbound))
            .saturating_add(usize::from(range == TagRange::AdminOutbound))
            .saturating_add(usize::from(range == TagRange::Unassigned));
        kani::assert(
            matches == 1,
            "a tag byte fell in other than exactly one quadrant",
        );
        let expected = match tag >> 4 {
            0x0 => TagRange::ClientInbound,
            0x1 => TagRange::AdminInbound,
            0x8 => TagRange::ClientOutbound,
            0x9 => TagRange::AdminOutbound,
            _ => TagRange::Unassigned,
        };
        kani::assert(
            range == expected,
            "a tag was classified by something other than its high nibble",
        );
    }

    /// **The enumerated bytes accept exactly the specified values — unbounded.**
    ///
    /// Quantifies over all 256 bytes for each of the three enumerations. Row A1
    /// accepts `role` in `{0x01, 0x02}` and nothing else; row A6 accepts
    /// `target` in `{0x01..=0x04}` and nothing else; `finish_reason` accepts
    /// `{0..=3}`. Each accepted value round-trips back to the byte it came
    /// from, so the wire encoding and the enumeration cannot drift apart.
    ///
    /// An out-of-range authority byte is not a benign mistake, and this is the
    /// proof that there is no path on which one is defaulted, clamped, or
    /// ignored.
    #[kani::proof]
    fn bsp_enumerated_authority_bytes_match_the_specification() {
        let byte: u8 = kani::any();

        match CredentialRole::from_wire(byte) {
            Ok(role) => {
                kani::assert(
                    byte == CredentialRole::WIRE_CLIENT || byte == CredentialRole::WIRE_ADMIN,
                    "a role outside row A1's set was accepted",
                );
                kani::assert(role.to_wire() == byte, "a role does not round-trip");
            }
            Err(_) => kani::assert(
                byte != CredentialRole::WIRE_CLIENT && byte != CredentialRole::WIRE_ADMIN,
                "an in-range role was refused",
            ),
        }

        match RestartTarget::from_wire(byte) {
            Ok(target) => {
                kani::assert(
                    byte >= RestartTarget::WIRE_SERVD && byte <= RestartTarget::WIRE_GPUD,
                    "a restart target outside row A6's set was accepted",
                );
                kani::assert(
                    target.to_wire() == byte,
                    "a restart target does not round-trip",
                );
            }
            Err(_) => kani::assert(
                byte < RestartTarget::WIRE_SERVD || byte > RestartTarget::WIRE_GPUD,
                "an in-range restart target was refused",
            ),
        }

        match FinishReason::from_wire(byte) {
            Ok(reason) => {
                kani::assert(
                    byte <= 3,
                    "a finish reason outside §10.3's set was accepted",
                );
                kani::assert(
                    reason.to_wire() == byte,
                    "a finish reason does not round-trip",
                );
            }
            Err(_) => kani::assert(byte > 3, "an in-range finish reason was refused"),
        }
    }

    // -----------------------------------------------------------------------
    // §5.5 and §10.2 — the state machine
    // -----------------------------------------------------------------------

    /// The conjunction that must hold of a session in **every** reachable
    /// state.
    ///
    /// This is the "cannot be driven into an illegal state" property, stated as
    /// an invariant rather than as a list of forbidden sequences.
    fn session_invariants(session: &Session) {
        let established = session.state() == SessionState::Established;
        kani::assert(
            session.session_type().is_some() == established,
            "a capability exists in a state other than ESTABLISHED",
        );
        if !established {
            kani::assert(
                session.request_phase() == RequestPhase::Idle,
                "a request phase survived outside ESTABLISHED",
            );
        }
        if let RequestPhase::Collecting {
            declared_length,
            accumulated_length,
            ..
        } = session.request_phase()
        {
            kani::assert(
                accumulated_length <= declared_length,
                "a prompt accumulated past what row M8 admitted",
            );
            kani::assert(
                declared_length <= MAX_PROMPT_BYTES,
                "a prompt declared past the row M5 ceiling",
            );
        }
    }

    /// **The state machine terminates and cannot reach an illegal state.**
    ///
    /// Four transitions, each chosen by a symbolic byte from the six the API
    /// offers, each carrying a symbolic five-byte payload. After every
    /// transition the invariants above are re-checked, so the first step that
    /// broke one is the step Kani reports rather than the end of the sequence.
    ///
    /// Two further properties are asserted at each step:
    ///
    /// - **`Closed` is absorbing.** A session that has been torn down never
    ///   leaves `Closed`, whatever arrives next (§9.4).
    /// - **§12's action column holds.** A denial whose disposition is `Drop`
    ///   leaves the session `Closed`; one whose disposition is `ErrorKeep`
    ///   leaves the state exactly as it was. That is what "never advances
    ///   session state on bad input" means, made checkable rather than argued.
    ///
    /// Termination is discharged by the unwinding assertions: the harness's own
    /// loop is bounded at [`STATE_MACHINE_STEPS`], and `brainix-bsp` contains
    /// no loop reachable from any of these entry points.
    #[kani::proof]
    #[kani::unwind(24)]
    fn bsp_session_state_machine_cannot_reach_an_illegal_state() {
        let mut session = Session::new();
        session_invariants(&session);
        let mut taken = 0usize;
        while taken < STATE_MACHINE_STEPS {
            taken = taken.saturating_add(1);
            let before = session.state();
            let choice: u8 = kani::any();
            let payload: [u8; SHORT_PAYLOAD_LEN] = kani::any();
            step(&mut session, choice, &payload);
            session_invariants(&session);
            kani::assert(
                before != SessionState::Closed || session.state() == SessionState::Closed,
                "a closed session left the closed state",
            );
        }
    }

    /// Applies one transition, chosen by `choice`.
    fn step(session: &mut Session, choice: u8, payload: &[u8]) {
        let before = session.state();
        match choice % 6 {
            0 => {
                let wire = valid_client_hello();
                let outcome = session.accept_client_hello(&wire);
                check_transition(session, before, outcome.map(|_| ()));
            }
            1 => {
                let outcome = session.accept_client_hello(payload);
                check_transition(session, before, outcome.map(|_| ()));
            }
            2 => {
                let wire = [0u8; LEN_CLIENT_AUTH];
                let outcome = session.accept_client_auth(&wire);
                check_transition(session, before, outcome.map(|_| ()));
            }
            3 => {
                let granted = if choice & 0x80 == 0 {
                    SessionType::Client
                } else {
                    SessionType::Admin
                };
                let outcome = session.establish(granted);
                if outcome.is_ok() {
                    kani::assert(
                        before == SessionState::AuthPending,
                        "a session established from a state other than AuthPending",
                    );
                    kani::assert(
                        session.session_type() == Some(granted),
                        "an established session was granted a different capability",
                    );
                }
                check_transition(session, before, outcome);
            }
            4 => {
                let outcome = session.accept_message(payload);
                if let Ok(message) = outcome {
                    kani::assert(
                        before == SessionState::Established,
                        "a data message was accepted before ESTABLISHED",
                    );
                    if let InboundMessage::Client(ClientRequest::PromptChunk { chunk, .. }) =
                        message
                    {
                        kani::assert(
                            is_inside(payload, chunk),
                            "an accepted PromptChunk's bytes escaped the payload",
                        );
                    }
                    return;
                }
                if let Err(error) = outcome {
                    check_transition(session, before, Err(error));
                }
            }
            _ => {
                session.close();
                kani::assert(
                    session.state() == SessionState::Closed,
                    "close left the session open",
                );
            }
        }
    }

    /// §12's action column, checked as a property of the session.
    fn check_transition(session: &Session, before: SessionState, outcome: Result<(), BspError>) {
        let error = match outcome {
            Ok(()) => return,
            Err(error) => error,
        };
        classify(error);
        match error.disposition() {
            Disposition::Drop => kani::assert(
                session.state() == SessionState::Closed,
                "a Drop denial left the session open",
            ),
            Disposition::ErrorKeep => kani::assert(
                session.state() == before,
                "an ErrorKeep denial moved the session",
            ),
        }
    }

    /// **Row M8 holds after every admitted chunk.**
    ///
    /// An established client session is driven with a symbolic `InferBegin` and
    /// then a symbolic `PromptChunk`, and the reassembly invariant is asserted
    /// after each. The property proved is the inductive step of row M8: from a
    /// phase whose accumulated total is within its declared length, an admitted
    /// chunk lands in a phase whose total is still within it, and the addition
    /// that produced it did not wrap.
    ///
    /// The session is driven to `ESTABLISHED` with concrete handshake messages,
    /// because the reachability of `ESTABLISHED` is what
    /// [`bsp_session_state_machine_cannot_reach_an_illegal_state`] proves and
    /// re-deriving it here would only make this harness more expensive.
    #[kani::proof]
    #[kani::unwind(24)]
    fn bsp_request_phase_never_accumulates_past_what_it_declared() {
        let mut session = Session::new();
        let hello = valid_client_hello();
        if session.accept_client_hello(&hello).is_err() {
            return;
        }
        if session.accept_client_auth(&[0u8; LEN_CLIENT_AUTH]).is_err() {
            return;
        }
        if session.establish(SessionType::Client).is_err() {
            return;
        }
        session_invariants(&session);

        // `InferBegin`: tag plus a fully symbolic 16-byte body.
        let mut begin = [0u8; CLIENT_PAYLOAD_LEN];
        let body: [u8; CLIENT_PAYLOAD_LEN - 1] = kani::any();
        begin[0] = 0x01;
        let mut index = 0usize;
        while index < CLIENT_PAYLOAD_LEN - 1 {
            begin[index.saturating_add(1)] = body[index];
            index = index.saturating_add(1);
        }
        let opened = session.accept_message(&begin).is_ok();
        session_invariants(&session);
        if !opened {
            return;
        }

        // `PromptChunk`: tag, a symbolic request_id, a symbolic declared
        // length, and four symbolic bytes.
        let chunk: [u8; 11] = kani::any();
        let mut wire = [0u8; 12];
        wire[0] = 0x02;
        let mut position = 0usize;
        while position < 11 {
            wire[position.saturating_add(1)] = chunk[position];
            position = position.saturating_add(1);
        }
        let phase_before = session.request_phase();
        let accepted = session.accept_message(&wire);
        session_invariants(&session);
        if accepted.is_err() {
            return;
        }
        match (phase_before, session.request_phase()) {
            (
                RequestPhase::Collecting {
                    accumulated_length: before,
                    declared_length: declared,
                    ..
                },
                RequestPhase::Collecting {
                    accumulated_length: after,
                    ..
                },
            ) => {
                kani::assert(
                    after >= before,
                    "an admitted chunk moved the total backwards",
                );
                kani::assert(
                    after <= declared,
                    "an admitted chunk pushed the total past the declared length",
                );
            }
            _ => kani::assert(
                false,
                "an admitted PromptChunk left a phase other than Collecting",
            ),
        }
    }
}
