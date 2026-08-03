//! Client-session client→server messages (§10.2) and the §10 tag partition.
//!
//! The inner payload of a data record is `type[1] || body`. The tag space is
//! partitioned so that type confusion is a **decoding error rather than a
//! policy question**:
//!
//! | Range | Direction | Session type |
//! |---|---|---|
//! | `0x0X` | client → server | client session |
//! | `0x1X` | client → server | admin session |
//! | `0x8X` | server → client | client session |
//! | `0x9X` | server → client | admin session |
//!
//! **No message carries a session, KV, or weights selector** (`INV-SERVE-001`,
//! `INV-MODEL`). The only correlation field is `request_id`, and §10.1 fixes
//! what it is not: not an index, handle, offset, or key into any server-side
//! structure. It is validated only as "equals the `request_id` of the in-flight
//! request in *this* slot", which is why a duplicate or garbage value cannot
//! reach another session — there is no path along which it could travel.

use crate::error::BspError;
use crate::raw::FieldReader;
use crate::{MAX_PROMPT_BYTES, MAX_PROMPT_CHUNK, MAX_TOKENS_REQUESTED};

/// `InferBegin` (§10.2).
pub(crate) const TAG_INFER_BEGIN: u8 = 0x01;

/// `PromptChunk` (§10.2).
pub(crate) const TAG_PROMPT_CHUNK: u8 = 0x02;

/// `InferCommit` (§10.2).
pub(crate) const TAG_INFER_COMMIT: u8 = 0x03;

/// `Cancel` (§10.2).
pub(crate) const TAG_CANCEL: u8 = 0x04;

/// `Close` (§10.2).
pub(crate) const TAG_CLOSE: u8 = 0x05;

/// Bits a tag's range occupies.
const TAG_RANGE_SHIFT: u32 = 4;

/// `0x0X` — client→server on a client session.
const RANGE_CLIENT_INBOUND: u8 = 0x0;

/// `0x1X` — client→server on an admin session.
const RANGE_ADMIN_INBOUND: u8 = 0x1;

/// `0x8X` — server→client on a client session.
const RANGE_CLIENT_OUTBOUND: u8 = 0x8;

/// `0x9X` — server→client on an admin session.
const RANGE_ADMIN_OUTBOUND: u8 = 0x9;

/// Which quadrant of §10's tag partition a `type` byte falls in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagRange {
    /// `0x0X` — client→server on a client session.
    ClientInbound,
    /// `0x1X` — client→server on an admin session.
    AdminInbound,
    /// `0x8X` — server→client on a client session.
    ClientOutbound,
    /// `0x9X` — server→client on an admin session.
    AdminOutbound,
    /// Outside the partition entirely.
    Unassigned,
}

impl TagRange {
    /// Classifies a `type` byte by its high nibble.
    #[must_use]
    pub const fn of(tag: u8) -> Self {
        match tag >> TAG_RANGE_SHIFT {
            RANGE_CLIENT_INBOUND => Self::ClientInbound,
            RANGE_ADMIN_INBOUND => Self::AdminInbound,
            RANGE_CLIENT_OUTBOUND => Self::ClientOutbound,
            RANGE_ADMIN_OUTBOUND => Self::AdminOutbound,
            _ => Self::Unassigned,
        }
    }
}

/// Denies any tag that is not inbound in the range `expected`.
///
/// Rows M1 and M2, plus the direction half of §10's partition that §12 leaves
/// unnamed. A `0x1X` tag on a client session and a `0x0X` tag on an admin
/// session are both Drop — inside an authenticated channel, type confusion is
/// treated as an attack, not as a recoverable hiccup.
pub(crate) fn require_tag_range(tag: u8, expected: TagRange) -> Result<(), BspError> {
    let actual = TagRange::of(tag);
    if actual == expected {
        return Ok(());
    }
    Err(range_violation(actual))
}

/// The reason a tag outside the expected range denies.
fn range_violation(actual: TagRange) -> BspError {
    match actual {
        TagRange::ClientInbound | TagRange::AdminInbound => BspError::WrongSessionTypeRange,
        TagRange::ClientOutbound | TagRange::AdminOutbound => BspError::WrongDirectionTag,
        TagRange::Unassigned => BspError::UnknownMessageType,
    }
}

/// Splits a record payload into its `type` byte and its body.
///
/// An empty payload is its own reason: "no message at all" and "a message whose
/// body is short" are different faults and an audit record must be able to tell
/// them apart.
pub(crate) fn split_tag(payload: &[u8]) -> Result<(u8, &[u8]), BspError> {
    let tag = *payload.first().ok_or(BspError::EmptyMessage)?;
    let body = payload.get(1..).ok_or(BspError::EmptyMessage)?;
    Ok((tag, body))
}

/// The body of an `InferBegin` (§10.2), 16 bytes of fixed scalars.
///
/// | Off | Len | Field |
/// |--:|--:|---|
/// | 0 | 4 | `request_id` |
/// | 4 | 4 | `max_tokens` |
/// | 8 | 2 | `temperature` — u16 fixed-point, /1000 |
/// | 10 | 2 | `top_p` — u16 fixed-point, /1000 |
/// | 12 | 4 | `prompt_total_len` |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InferBegin {
    /// The peer's inert correlation token (§10.1).
    ///
    /// Every 32-bit value is legal, `0` and `u32::MAX` included: §10.1 defines
    /// it as opaque and peer-chosen, and reserving a value would make it a
    /// namespace.
    pub request_id: u32,

    /// Tokens requested. Bounded by
    /// [`MAX_TOKENS_REQUESTED`](crate::MAX_TOKENS_REQUESTED) — row M5.
    pub max_tokens: u32,

    /// Sampling temperature as u16 fixed-point, divided by 1000.
    ///
    /// Uninterpreted here. Fixed-point is what keeps the decoder free of float
    /// bit-pattern classification on the hostile-input path.
    pub temperature: u16,

    /// Nucleus sampling threshold as u16 fixed-point, divided by 1000.
    pub top_p: u16,

    /// The total prompt length the client declares it will send. Bounded by
    /// [`MAX_PROMPT_BYTES`](crate::MAX_PROMPT_BYTES) — row M5.
    ///
    /// It **declares**; it never sizes. The destination is a fixed
    /// per-session buffer and this value only bounds a copy into it
    /// (`INV-SERVE-002`).
    pub prompt_total_length: u32,
}

impl InferBegin {
    /// Decodes and applies the two row-M5 ceilings.
    ///
    /// The limits are checked here rather than in the session because they are
    /// properties of the message alone, and both are `Error`-then-continue: a
    /// benign client can plausibly ask for too much.
    fn decode(body: &[u8]) -> Result<Self, BspError> {
        let mut reader = FieldReader::new(body);
        let decoded = Self::read_fields(&mut reader)?;
        reader.finish()?;
        decoded.check_limits()?;
        Ok(decoded)
    }

    /// Reads the five fixed fields.
    fn read_fields(reader: &mut FieldReader<'_>) -> Result<Self, BspError> {
        Ok(Self {
            request_id: reader.take_u32()?,
            max_tokens: reader.take_u32()?,
            temperature: reader.take_u16()?,
            top_p: reader.take_u16()?,
            prompt_total_length: reader.take_u32()?,
        })
    }

    /// Row M5 — both ceilings, each with its own reason.
    fn check_limits(&self) -> Result<(), BspError> {
        if self.max_tokens > MAX_TOKENS_REQUESTED {
            return Err(BspError::MaxTokensExceedsLimit);
        }
        if self.prompt_total_length > MAX_PROMPT_BYTES {
            return Err(BspError::PromptLengthExceedsLimit);
        }
        Ok(())
    }
}

/// A decoded client→server message on a client session (§10.2).
///
/// There is deliberately no variant that selects a model, loads weights, names
/// another session, or requests a kernel action: §10.6's absence list is
/// enforced by this enum having no such case to construct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientRequest<'a> {
    /// `0x01` — opens a request. The slot must be idle (row M6).
    InferBegin(InferBegin),

    /// `0x02` — one chunk of prompt bytes, borrowed from the record payload.
    PromptChunk {
        /// Must match the open request (row M7).
        request_id: u32,
        /// At most [`MAX_PROMPT_CHUNK`](crate::MAX_PROMPT_CHUNK) bytes
        /// (row M4). Opaque; never interpreted as control.
        chunk: &'a [u8],
    },

    /// `0x03` — hands `prompt_buf[..total]` to the confined model.
    InferCommit {
        /// Must match the open request.
        request_id: u32,
    },

    /// `0x04` — cancels the in-flight request.
    Cancel {
        /// Must match the open request.
        request_id: u32,
    },

    /// `0x05` — graceful teardown (§9.4). Empty body.
    Close,
}

impl<'a> ClientRequest<'a> {
    /// Decodes one client-session inbound message from a record payload.
    ///
    /// Order: the tag's range is checked before its value, because a `0x1X` tag
    /// here is row M2 — an attack — while an unrecognized `0x0X` tag is row M1,
    /// and conflating them would lose that distinction in the audit record.
    ///
    /// Verified by: `tests::adversarial::an_admin_tag_on_a_client_session_denies`
    pub fn decode(payload: &'a [u8]) -> Result<Self, BspError> {
        let (tag, body) = split_tag(payload)?;
        require_tag_range(tag, TagRange::ClientInbound)?;
        Self::dispatch(tag, body)
    }

    /// Dispatches on the tag. An unrecognized value denies (row M1); it is
    /// never ignored and never falls through to a default shape.
    fn dispatch(tag: u8, body: &'a [u8]) -> Result<Self, BspError> {
        match tag {
            TAG_INFER_BEGIN => Ok(Self::InferBegin(InferBegin::decode(body)?)),
            TAG_PROMPT_CHUNK => Self::decode_prompt_chunk(body),
            TAG_INFER_COMMIT => Ok(Self::InferCommit {
                request_id: decode_request_id_only(body)?,
            }),
            TAG_CANCEL => Ok(Self::Cancel {
                request_id: decode_request_id_only(body)?,
            }),
            TAG_CLOSE => Self::decode_close(body),
            _ => Err(BspError::UnknownMessageType),
        }
    }

    /// `request_id[4]`, then a bounded var-bytes chunk (§3 form 3).
    fn decode_prompt_chunk(body: &'a [u8]) -> Result<Self, BspError> {
        let mut reader = FieldReader::new(body);
        let request_id = reader.take_u32()?;
        let chunk = reader.take_bounded_var_bytes(MAX_PROMPT_CHUNK)?;
        reader.finish()?;
        Ok(Self::PromptChunk { request_id, chunk })
    }

    /// An empty body, exactly.
    fn decode_close(body: &[u8]) -> Result<Self, BspError> {
        FieldReader::new(body).finish()?;
        Ok(Self::Close)
    }

    /// The `request_id` this message correlates with, if it carries one.
    #[must_use]
    pub const fn request_id(&self) -> Option<u32> {
        match self {
            Self::InferBegin(begin) => Some(begin.request_id),
            Self::PromptChunk { request_id, .. }
            | Self::InferCommit { request_id }
            | Self::Cancel { request_id } => Some(*request_id),
            Self::Close => None,
        }
    }
}

/// Decodes a body that is exactly `request_id[4]` and nothing else.
pub(crate) fn decode_request_id_only(body: &[u8]) -> Result<u32, BspError> {
    let mut reader = FieldReader::new(body);
    let request_id = reader.take_u32()?;
    reader.finish()?;
    Ok(request_id)
}
