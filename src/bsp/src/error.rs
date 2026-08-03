//! The single failure enum for the BSP v2 decoder, and the §12 disposition it
//! carries.
//!
//! One variant per failure mode, so that a rejected message can be audited for
//! *why* it was rejected rather than merely *that* it was. Deliberately not
//! `#[non_exhaustive]`: callers inside BraiNIX are meant to match exhaustively
//! so that a newly added failure mode is a compile error, not a silent wildcard
//! arm.
//!
//! Each variant names the §12 row it implements. The row also fixes the
//! fail-closed *action*, which is why [`BspError::disposition`] exists: the
//! choice between dropping the connection and answering `Error` while staying
//! `ESTABLISHED` is normative, and encoding it in the type is what stops it
//! being re-decided per call site.

use crate::admin::{TAG_ENROLL_KEY, TAG_READ_AUDIT_LOG, TAG_RESTART_SERVER};
use crate::message::{TAG_INFER_BEGIN, TAG_PROMPT_CHUNK};

/// The §12 fail-closed action a failure requires.
///
/// §12's design rule: anything that could only arise from a non-conforming or
/// hostile peer after authentication, and that indicates framing, type, or
/// state corruption, is [`Disposition::Drop`]. Faults a benign peer could
/// plausibly hit — over-limit, busy, incomplete, unknown handle — are
/// [`Disposition::ErrorKeep`]. Both branches are fail-closed: neither ever
/// allocates, grows a pool, advances a chain, or advances session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Terminate the connection, release the slot, zeroize its key material and
    /// any scratch chain material, and commit no chain advance (§9.4, §6.2).
    ///
    /// Every handshake fault is a `Drop`: there is no authenticated session to
    /// keep and no partial-trust state.
    Drop,

    /// Emit `Error{code}`, consume the offending record, and remain
    /// `ESTABLISHED`.
    ErrorKeep,
}

/// A §12 `Error` message code.
///
/// **The specification names these codes and assigns no numeric values.** The
/// wire values below are therefore this crate's, chosen in §12 row order, and
/// are flagged as provisional rather than presented as the format's: any
/// authority that later assigns them overrides this enum, and
/// [`ErrorCode::to_wire`] is the one place that changes. Naming them is not
/// optional — §12 is unimplementable without a code — but inventing them
/// silently would be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// Row M1 — unknown message `type` tag.
    ///
    /// Reachable only under the *lenient* reading of §15 question 1. This crate
    /// takes the strict reading, so it never emits this code; it is named
    /// because §12 names it.
    BadType,
    /// Rows M5 and A7 — a request exceeded a `const` ceiling.
    Limit,
    /// Row M6 — a second `InferBegin` while a request is in flight.
    Busy,
    /// Row M7 — `request_id` does not match the open request in this slot.
    NoRequest,
    /// Row M9 — `InferCommit` with accumulated bytes ≠ declared.
    Incomplete,
    /// Row M10 — a message of a type invalid in the current state.
    State,
    /// Row A2 — the credential table is full.
    NoCapacity,
    /// Row A3 — `RevokeKey` on an unknown handle.
    NoSuchKey,
    /// Row A4 — `EnrollKey` or `RevokeKey` targeting the break-glass handle.
    ///
    /// Emitted by the credential store, not by this crate: the break-glass
    /// handle is not knowable from the wire bytes alone.
    Forbidden,
    /// Row A5 — `LoadWeights` names a digest that matches no verifying blob.
    NoSuchWeights,
    /// Row A6 — `RestartServer` with an unknown `target`.
    BadTarget,
    /// §10.4 — `EnrollKey` whose derived handle is already enrolled.
    Duplicate,
}

impl ErrorCode {
    /// The provisional 16-bit wire value. See this type's caveat.
    #[must_use]
    pub const fn to_wire(self) -> u16 {
        match self {
            Self::BadType => 0x0001,
            Self::Limit => 0x0002,
            Self::Busy => 0x0003,
            Self::NoRequest => 0x0004,
            Self::Incomplete => 0x0005,
            Self::State => 0x0006,
            Self::NoCapacity => 0x0007,
            Self::NoSuchKey => 0x0008,
            Self::Forbidden => 0x0009,
            Self::NoSuchWeights => 0x000a,
            Self::BadTarget => 0x000b,
            Self::Duplicate => 0x000c,
        }
    }
}

/// Every way a BSP v2 message can be refused.
///
/// There is no "warning" and no partial success. Any value of this type means
/// the operation denied and nothing was produced, decoded, or advanced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BspError {
    // -- Readers and arithmetic ---------------------------------------------
    /// A checked addition on an offset would have overflowed. Overflow denies;
    /// it never wraps and never saturates.
    OffsetOverflow,

    /// A message body ended before one of its fixed fields (row M3).
    TruncatedMessageBody,

    /// A message body carried bytes past its last declared field.
    ///
    /// The specification does not state this case, and the safest fail-closed
    /// reading is refusal: a payload longer than its type requires is a
    /// disagreement between the record length and the message grammar, and a
    /// decoder that ignores the excess is a decoder an attacker can use to
    /// smuggle bytes past a length check downstream.
    TrailingBytesAfterBody,

    /// Fewer than 2 bytes remained for a bounded var-bytes length prefix —
    /// §3 form 3 check (a).
    TruncatedVarBytesLength,

    /// A bounded var-bytes `len` exceeds that field's compile-time `MAX` —
    /// §3 form 3 check (b), row M4.
    ///
    /// The `MAX` is **always** the `const`, never the value just read.
    VarBytesLengthExceedsMaximum,

    /// Fewer than `len` bytes remained after a bounded var-bytes length —
    /// §3 form 3 check (c).
    TruncatedVarBytesValue,

    // -- Handshake, §5.1 and §12 rows H1..H4 --------------------------------
    /// Row H1 — a `ClientHello` whose length is not exactly
    /// [`LEN_CLIENT_HELLO`](crate::LEN_CLIENT_HELLO).
    ClientHelloLengthMismatch,

    /// A `ServerHello` whose length is not exactly
    /// [`LEN_SERVER_HELLO`](crate::LEN_SERVER_HELLO). The client-side mirror of
    /// row H1.
    ServerHelloLengthMismatch,

    /// Row H4 — a `ClientAuth` whose length is not exactly
    /// [`LEN_CLIENT_AUTH`](crate::LEN_CLIENT_AUTH).
    ClientAuthLengthMismatch,

    /// Row H2 — `magic` is not ASCII `"BSP2"`.
    BadMagic,

    /// Row H2 — `version_major` is not 2. Exact match, not a negotiation.
    UnsupportedVersionMajor,

    /// Row H2 — `version_minor` is not 0. Exact match, not a negotiation.
    UnsupportedVersionMinor,

    /// Row H2 — `reserved` is not `0x0000`.
    ///
    /// A distinct reason from the version bytes because it is a distinct claim:
    /// a peer setting it has invented an extension point that §5.1 refuses to
    /// provide.
    ReservedFieldNonZero,

    /// A handshake message arrived in a state that does not expect it — a
    /// `ClientHello` mid-session, or a `ClientAuth` before a `ClientHello`
    /// (§5.5).
    HandshakeMessageInWrongState,

    /// [`Session::establish`](crate::Session::establish) was called from a
    /// state other than the one that follows a decoded `ClientAuth`.
    ///
    /// The capability grant is frozen at exactly one transition (§7.2); this is
    /// the guard that makes every other path to it unreachable.
    EstablishBeforeAuthentication,

    // -- Record layer, §4.2 and §12 rows R1..R5 -----------------------------
    /// Row R1 — the decrypted `packet_length` is below 2.
    ///
    /// Checked **before any buffer is touched**, which is the placement §4.2
    /// makes normative.
    PacketLengthBelowMinimum,

    /// Row R1 — the decrypted `packet_length` is above 35000.
    ///
    /// An absolute, client-independent bound, checked before any buffer is
    /// touched.
    PacketLengthAboveMaximum,

    /// The record's total wire extent — prefix, ciphertext, and tag — does not
    /// fit in the bytes available.
    ///
    /// This is the "length prefix larger than the buffer" case: the length is
    /// in range yet names more bytes than arrived. It never sizes a read.
    RecordExceedsAvailableBytes,

    /// The recovered plaintext length disagrees with the `packet_length` the
    /// length field declared.
    RecordPlaintextLengthMismatch,

    /// `padding_length + 1 > packet_length` — the §4.2 `open_packet` rule.
    PaddingLengthExceedsPacket,

    /// Fewer than the 4 padding bytes §4.2 requires.
    ///
    /// §4.2 states the padding rule as a property of what the sender produces
    /// and `open_packet`'s enumerated checks stop at the containment test. The
    /// safest fail-closed reading is to enforce the stated rule on receipt as
    /// well: a receiver that accepts what the format forbids is a second,
    /// looser grammar.
    PaddingBelowMinimum,

    /// The record plaintext is not a multiple of 8 bytes. Same reading as
    /// [`BspError::PaddingBelowMinimum`].
    RecordPlaintextNotBlockAligned,

    /// Row R4 — the recovered payload exceeds
    /// [`BSP_MAX_RECORD_PLAINTEXT`](crate::BSP_MAX_RECORD_PLAINTEXT).
    PayloadExceedsRecordPlaintext,

    /// Row R5 — the per-direction sequence would exceed
    /// [`MAX_RECORD_SEQ`](crate::MAX_RECORD_SEQ).
    ///
    /// The sequence never wraps; the session is torn down instead (§9.4).
    SequenceExhausted,

    // -- Message layer, §10 and §12 rows M1..M10 ----------------------------
    /// A record payload carried no `type` byte at all.
    ///
    /// Distinct from [`BspError::TruncatedMessageBody`] so that "empty" and
    /// "short" are separable in an audit record.
    EmptyMessage,

    /// Row M1 — an unrecognized `type` tag.
    ///
    /// §15 question 1 leaves the Drop-vs-`Error` policy open. This crate takes
    /// the **strict** reading — Drop — because §12's own design rule puts every
    /// type-corruption row on the Drop side and because a lenient reading lets
    /// an authenticated peer probe the tag space indefinitely.
    UnknownMessageType,

    /// Row M2 — a `0x1X` tag on a client session, or a `0x0X` tag on an admin
    /// session. Type confusion inside an authenticated channel is treated as an
    /// attack.
    WrongSessionTypeRange,

    /// A `0x8X` or `0x9X` tag — a server→client tag — arrived from the peer.
    ///
    /// §10's table partitions the tag space by direction as well as by session
    /// type but §12 names only the session-type half. The safest fail-closed
    /// reading is that a direction violation is the same class of type
    /// confusion as row M2, and therefore also a Drop.
    WrongDirectionTag,

    /// Row M5 — `InferBegin` with `max_tokens` above
    /// [`MAX_TOKENS_REQUESTED`](crate::MAX_TOKENS_REQUESTED).
    MaxTokensExceedsLimit,

    /// Row M5 — `InferBegin` with `prompt_total_len` above
    /// [`MAX_PROMPT_BYTES`](crate::MAX_PROMPT_BYTES).
    PromptLengthExceedsLimit,

    /// Row M6 — a second `InferBegin` while a request is in flight.
    RequestAlreadyInFlight,

    /// Row M7 — `request_id` is not the open request's.
    ///
    /// The comparison is only ever made **within this slot**: `request_id` is
    /// an inert correlation token and never selects a session, buffer, or
    /// credential (§10.1).
    RequestIdMismatch,

    /// Row M8 — a `PromptChunk` whose running total exceeds the declared
    /// `prompt_total_len`. A declared-length lie is treated as an attack.
    PromptChunkExceedsDeclaredLength,

    /// Row M8 — a `PromptChunk` whose running total exceeds
    /// [`MAX_PROMPT_BYTES`](crate::MAX_PROMPT_BYTES).
    ///
    /// Implied by the declared-length guard, since the declared length is
    /// itself bounded at `InferBegin`. Kept as its own check and its own reason
    /// because the buffer bound is the one that must hold even if the declared
    /// bound is ever weakened: the cap is the buffer size, never `len`.
    PromptChunkExceedsPromptBuffer,

    /// Row M9 — `InferCommit` with accumulated bytes ≠ `prompt_total_len`.
    PromptIncomplete,

    /// Row M10 — a message of a type invalid in the current request phase.
    MessageInvalidInState,

    /// A data-phase message arrived before the session reached `ESTABLISHED`.
    ///
    /// Pre-key bytes reaching the message decoder would mean the record layer
    /// admitted an unauthenticated record; the guard is here as well because
    /// §11 rests on the message decoder being unreachable to an
    /// unauthenticated attacker.
    DataMessageBeforeEstablished,

    /// A message arrived on a session that has been torn down.
    SessionClosed,

    // -- Admin verbs, §10.4 and §12 rows A1..A7 -----------------------------
    /// Row A1 — `EnrollKey` with `role` outside `{0x01, 0x02}`.
    ///
    /// Drop, because an out-of-range authority byte is not a benign mistake.
    InvalidEnrollRole,

    /// Row A6 — `RestartServer` with a `target` outside the enumeration.
    UnknownRestartTarget,

    /// Row A7 — `ReadAuditLog` with `max_records` above
    /// [`MAX_AUDIT_RECORDS`](crate::MAX_AUDIT_RECORDS).
    AuditRecordCountExceedsLimit,

    // -- Encoding -----------------------------------------------------------
    /// The caller-supplied output buffer is too small for the response.
    ///
    /// The buffer is never grown and never partially committed: an encode that
    /// returns this wrote nothing a caller may transmit.
    OutputBufferTooSmall,

    /// A `TokenChunk` payload exceeds
    /// [`MAX_TOKEN_CHUNK`](crate::MAX_TOKEN_CHUNK).
    TokenChunkExceedsMaximum,

    /// An `AuditChunk` payload exceeds
    /// [`MAX_AUDIT_CHUNK`](crate::MAX_AUDIT_CHUNK).
    AuditChunkExceedsMaximum,

    /// An encoded response exceeds
    /// [`BSP_MAX_RECORD_PLAINTEXT`](crate::BSP_MAX_RECORD_PLAINTEXT) and could
    /// not be carried in one data record.
    ResponseExceedsRecordPlaintext,
}

impl BspError {
    /// The §12 fail-closed action this failure requires.
    ///
    /// Enforces the §12 table's action column. Every variant not listed as
    /// [`Disposition::ErrorKeep`] is a `Drop`, which is the fail-closed default
    /// and the reason the match is written this way round: a newly added
    /// failure mode drops the connection until someone argues otherwise.
    ///
    /// Verified by: `tests::adversarial::every_error_keep_variant_is_a_named_row`
    #[must_use]
    pub const fn disposition(self) -> Disposition {
        match self.error_code() {
            Some(_) => Disposition::ErrorKeep,
            None => Disposition::Drop,
        }
    }

    /// The `Error{error_code}` this failure is answered with, or `None` when
    /// §12 requires the connection to drop instead.
    ///
    /// A `Some` here and a [`Disposition::ErrorKeep`] are the same statement:
    /// an `Error` message exists exactly when there is still a session to send
    /// it on.
    #[must_use]
    pub const fn error_code(self) -> Option<ErrorCode> {
        match self {
            Self::MaxTokensExceedsLimit | Self::PromptLengthExceedsLimit => Some(ErrorCode::Limit),
            Self::AuditRecordCountExceedsLimit => Some(ErrorCode::Limit),
            Self::RequestAlreadyInFlight => Some(ErrorCode::Busy),
            Self::RequestIdMismatch => Some(ErrorCode::NoRequest),
            Self::PromptIncomplete => Some(ErrorCode::Incomplete),
            Self::MessageInvalidInState => Some(ErrorCode::State),
            Self::UnknownRestartTarget => Some(ErrorCode::BadTarget),
            _ => None,
        }
    }

    /// The `type` tag whose decoder raised this failure, where §12 attributes
    /// the row to one message.
    ///
    /// Used for audit attribution (`INV-SERVE-005`) so a denial names the verb
    /// it denied rather than only the reason.
    #[must_use]
    pub const fn attributed_tag(self) -> Option<u8> {
        match self {
            Self::MaxTokensExceedsLimit | Self::PromptLengthExceedsLimit => Some(TAG_INFER_BEGIN),
            Self::PromptChunkExceedsDeclaredLength | Self::PromptChunkExceedsPromptBuffer => {
                Some(TAG_PROMPT_CHUNK)
            }
            Self::InvalidEnrollRole => Some(TAG_ENROLL_KEY),
            Self::UnknownRestartTarget => Some(TAG_RESTART_SERVER),
            Self::AuditRecordCountExceedsLimit => Some(TAG_READ_AUDIT_LOG),
            _ => None,
        }
    }
}
