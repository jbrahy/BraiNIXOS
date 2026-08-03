//! BSP v2 wire-protocol decoder — P2-T3.
//!
//! The first code in BraiNIX that touches a byte from a hostile remote client.
//! It is the outermost attack surface the project controls
//! (`docs/THREAT_MODEL.md` §"Hostile remote clients and the inbound protocol"),
//! and it is a **Full**-tier hostile-input parser
//! (`docs/security/SECURITY_INVARIANTS.md` §16, `INV-PARSE-001`).
//!
//! The format is specified by
//! [`docs/architecture/BSP-v2-serving-protocol.md`](../../../docs/architecture/BSP-v2-serving-protocol.md).
//! Every rule identifier in this crate's documentation — `H1`, `R4`, `M8`,
//! `A6` — is that document's §12 table, so a denial can be traced to a line of
//! the specification without reading the decoder.
//!
//! # Scope: structure, never cryptography
//!
//! This crate decodes and encodes **byte layouts**. It holds no key, computes
//! no hash, verifies no confirmation value, and compares nothing in constant
//! time. The PSK key schedule of §5.2–§5.4, the selector scan of §5.3, the
//! chain ratchet of §6, and the ChaCha20-Poly1305 record protection of §4.2 are
//! P2-T2's. What this crate owns is the part that runs *before* and *after*
//! those: the exact field offsets they operate on, and every length, tag,
//! range, and state check around them.
//!
//! The seam is deliberate and is visible in the API. [`ClientHello::decode`]
//! hands back a `key_selector` it cannot match; [`handshake::ClientAuth`]
//! hands back a `client_confirm` it cannot verify;
//! [`record::PacketLength::decode`] takes the *already decrypted* four length
//! bytes because decrypting them needs `K_1`. A decoder that held key material
//! would be a decoder whose bugs are key-material bugs.
//!
//! # What this crate guarantees
//!
//! - `#![no_std]`, the crate-level `forbid(unsafe_code)` below, and **no
//!   allocation of any kind** — no heap, no arena, no growable buffer, no
//!   owned copy of a prompt. Every working set is a fixed-size array, a
//!   borrowed slice, or a caller-supplied output buffer (`INV-MEM`,
//!   `INV-SERVE-002`). No pool is ever sized, grown, or indexed from a
//!   client-supplied length, offset, or tag.
//! - **Total decoding.** Every malformed input returns a [`BspError`]. There is
//!   no panicking index, no unchecked `Option` access, and no arithmetic that
//!   can wrap: every operation on a wire-supplied value is checked, and a value
//!   that does not fit **denies** — it never saturates and never wraps.
//! - **Fail closed.** A violation ends the operation. Nothing is skipped,
//!   nothing is clamped, no length is truncated to what fits, and no field is
//!   defaulted. Absence of an explicit accept path is denial.
//! - **Every bound is a `const`.** The values below are §8's table verbatim. A
//!   client length is only ever *compared against* one of them.
//! - **The verb set is exactly six** ([`AdminVerb`], §10.4). There is no
//!   `rotate`, no `set-config`, no `read-file`, and no `exec`. An unrecognized
//!   verb tag denies; it is never ignored.
//! - **Disposition is part of the type.** Every [`BspError`] carries the §12
//!   fail-closed action — [`Disposition::Drop`] or [`Disposition::ErrorKeep`] —
//!   so "which faults kill the connection" is answered by the error, not by the
//!   caller's memory of a table.
//!
//! # What this crate deliberately does not do
//!
//! - No socket, no timer. `HS_TIMEOUT` and `IDLE_TIMEOUT` are exported as
//!   constants and enforced by `servd`, which owns the clock.
//! - No session pool. [`MAX_SESSIONS`] and friends are exported; admission
//!   (§9.1, rows S1–S2) is `servd`'s because it owns the pool.
//! - No `prompt_buf`. [`Session`] tracks the reassembly *accounting* — declared
//!   length, running total, and the §12 M8 guard — and hands out each chunk as
//!   a borrowed slice. The fixed `MAX_PROMPT_BYTES` buffer belongs to the
//!   session slot, which is `servd`'s (§9.1).
//! - No zeroization. [`AdminVerb::EnrollKey`] carries 32 bytes of secret key
//!   material by value; destroying it after §5.2 runs is the caller's
//!   obligation, because this crate never learns when the expansion is done.
//!
//! # Example
//!
//! ```
//! use brainix_bsp::{BspError, InboundMessage, Session, SessionType};
//!
//! fn drive(hello: &[u8], auth: &[u8], first_record: &[u8]) -> Result<(), BspError> {
//!     let mut session = Session::new();
//!     let _client_hello = session.accept_client_hello(hello)?;
//!     // ... P2-T2 runs the selector scan and sends ServerHello ...
//!     let _client_auth = session.accept_client_auth(auth)?;
//!     // ... P2-T2 verifies client_confirm in constant time ...
//!     session.establish(SessionType::Client)?;
//!     match session.accept_message(first_record)? {
//!         InboundMessage::Client(_request) => Ok(()),
//!         InboundMessage::Admin(_verb) => Ok(()),
//!     }
//! }
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod admin;
mod error;
pub mod handshake;
mod message;
mod raw;
pub mod record;
mod response;
mod session;

pub use crate::admin::{AdminVerb, CredentialRole, RestartTarget};
pub use crate::error::{BspError, Disposition, ErrorCode};
pub use crate::handshake::{ClientAuth, ClientHello, ServerHello};
pub use crate::message::{ClientRequest, InferBegin, TagRange};
pub use crate::record::{DataRecord, PacketLength, SequenceCounter};
pub use crate::response::{AdminResponse, ClientResponse, FinishReason};
pub use crate::session::{InboundMessage, RequestPhase, Session, SessionState, SessionType};

// ---------------------------------------------------------------------------
// §8 — explicit maximum sizes (build-time pool sizing)
//
// The whole table is transcribed, including the values this crate does not
// itself consume, because §8 is one table and splitting it across two crates
// is how the two copies drift. A value used only by P2-T2 or by `servd` is
// marked as such in its doc comment.
// ---------------------------------------------------------------------------

/// The 4-byte protocol tag, ASCII `"BSP2"` (§5.1, §8).
pub const BSP_MAGIC: [u8; 4] = *b"BSP2";

/// Accepted `version_major`. Exact match, not a negotiation (§5.5g).
pub const BSP_VERSION_MAJOR: u8 = 2;

/// Accepted `version_minor`. Exact match.
pub const BSP_VERSION_MINOR: u8 = 0;

/// Accepted value of `ClientHello`'s `reserved` field.
///
/// **Not an extension point.** §5.1 makes a nonzero value a REJECT precisely so
/// that no future version can smuggle a negotiated parameter through it.
pub const BSP_RESERVED: u16 = 0;

/// Bytes in a `ClientHello` (§5.1). Exact; H1 rejects any other length.
pub const LEN_CLIENT_HELLO: usize = 64;

/// Bytes in a `ServerHello` (§5.1). Exact.
pub const LEN_SERVER_HELLO: usize = 64;

/// Bytes in a `ClientAuth` (§5.1). Exact; H4 rejects any other length.
pub const LEN_CLIENT_AUTH: usize = 32;

/// Bytes of enrolled key material, destroyed after the §5.2 expansion.
///
/// The wire width of `EnrollKey`'s `key_material` field (§10.4).
pub const LEN_PSK: usize = 32;

/// Bytes in `K_id`, the stable identification secret (§2.2).
///
/// P2-T2's; never on the wire. Present so §8 lives in one place.
pub const LEN_KEY_ID: usize = 32;

/// Bytes in a chain key `CK_n` (§2.2).
///
/// P2-T2's; never on the wire.
pub const LEN_CHAIN_KEY: usize = 32;

/// Bytes in a credential `handle` (§2.2).
///
/// The wire width of `RevokeKey`'s `handle` and `KeyEnrolled`'s reply field.
/// Never appears pre-key.
pub const LEN_HANDLE: usize = 16;

/// Bytes in the per-connection blinded `key_selector` (§5.3).
pub const LEN_SELECTOR: usize = 16;

/// Bytes in each side's handshake nonce (§5.1).
pub const LEN_NONCE: usize = 32;

/// Bytes in each confirmation value (§5.4).
pub const LEN_CONFIRM: usize = 32;

/// Bytes in one direction's key set: payload key `K_2` ‖ length key `K_1`.
///
/// P2-T2's; never on the wire.
pub const LEN_DIR_KEYS: usize = 64;

/// Bytes in every HKDF label, NUL-padded (§5.4).
///
/// P2-T2's; never on the wire.
pub const LEN_LABEL: usize = 16;

/// Bytes in a SHA-256 digest, the width of `LoadWeights`'s `weights_digest`.
pub const LEN_WEIGHTS_DIGEST: usize = 32;

/// Slots in the fixed credential table, and the constant-work factor of the
/// §5.3 selector scan.
///
/// P2-T2's and the credential store's.
pub const MAX_ENROLLED_KEYS: usize = 32;

/// Bound on forward chain resolution per handshake (§6.3).
///
/// P2-T2's. `chain_counter` is decoded here and bounded there, because the
/// bound is relative to persisted state this crate cannot see.
pub const MAX_CHAIN_CATCHUP: u64 = 64;

/// Maximum BSP message bytes carried in one data record (§4.2, §8).
///
/// `≤` the AEAD internal plaintext buffer. §4.2 requires that raising this
/// above 4096 make that internal buffer a shared named `const` in the same
/// change.
pub const BSP_MAX_RECORD_PLAINTEXT: usize = 4096;

/// Total prompt bytes per request, reassembled across `PromptChunk` records
/// into a fixed **per-session** buffer (§8, §10.2).
pub const MAX_PROMPT_BYTES: u32 = 16384;

/// Bytes in one `PromptChunk` payload (§8). `≤ BSP_MAX_RECORD_PLAINTEXT`
/// minus the 7-byte tag/`request_id`/length header.
pub const MAX_PROMPT_CHUNK: usize = 4032;

/// Bytes in one outbound `TokenChunk` payload (§8).
pub const MAX_TOKEN_CHUNK: usize = 512;

/// Ceiling on the `max_tokens` a request may ask for (§8, §10.2).
pub const MAX_TOKENS_REQUESTED: u32 = 4096;

/// Bytes in one outbound `AuditChunk` payload (§8).
pub const MAX_AUDIT_CHUNK: usize = 1024;

/// Ceiling on records returned per `ReadAuditLog` (§8, §10.4).
pub const MAX_AUDIT_RECORDS: u16 = 64;

/// Session slots for the whole server (§8).
///
/// `servd`'s pool bound; exported so §8 is not transcribed twice.
pub const MAX_SESSIONS: usize = 8;

/// Admin sessions concurrently live, within [`MAX_SESSIONS`] (§8).
pub const MAX_ADMIN_SESSIONS: usize = 1;

/// Per-credential admission, **counting half-open handshakes**
/// (`INV-SERVE-003`, §9.1).
pub const MAX_SESSIONS_PER_CREDENTIAL: usize = 2;

/// At most one active inference per session (§8).
///
/// Enforced here by [`RequestPhase`]: a second `InferBegin` while a request is
/// in flight is row M6.
pub const MAX_INFLIGHT_PER_SESSION: usize = 1;

/// Wall-clock bound on each pre-`ESTABLISHED` state, in seconds (§8, row H3).
///
/// `servd`'s; this crate owns no clock.
pub const HS_TIMEOUT_SECONDS: u32 = 5;

/// Maximum idle time in `ESTABLISHED` before server teardown, in seconds
/// (§8, row T1).
///
/// `servd`'s; this crate owns no clock.
pub const IDLE_TIMEOUT_SECONDS: u32 = 120;

/// Per-direction record sequence ceiling (§4.2, §8).
///
/// Reaching it forces teardown (§9.4, row R5). The sequence MUST NOT wrap, and
/// [`SequenceCounter::advance`] is what makes that structural rather than
/// argued.
pub const MAX_RECORD_SEQ: u32 = u32::MAX;
