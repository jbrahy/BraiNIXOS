//! Server→client responses: §10.3 on a client session, §10.5 on an admin one.
//!
//! Every encoder writes into a **caller-supplied buffer** and returns the byte
//! count. Nothing is allocated, nothing is grown, and no response is ever
//! larger than [`BSP_MAX_RECORD_PLAINTEXT`](crate::BSP_MAX_RECORD_PLAINTEXT) —
//! the ceiling is checked on the way out as well as on the way in, because an
//! encoder that could emit an unframeable record would be a way to violate row
//! R4 from the inside.
//!
//! `tokens` and `records` are **opaque bytes** — model output and audit bytes
//! respectively — rendered by the client and never interpreted as control by
//! BSP (`INV-MODEL-003`). This module copies them and reads nothing in them.

use crate::error::BspError;
use crate::raw::ResponseWriter;
use crate::{BSP_MAX_RECORD_PLAINTEXT, LEN_HANDLE, MAX_AUDIT_CHUNK, MAX_TOKEN_CHUNK};

/// `Accepted` (§10.3).
pub(crate) const TAG_ACCEPTED: u8 = 0x81;

/// `TokenChunk` (§10.3).
pub(crate) const TAG_TOKEN_CHUNK: u8 = 0x82;

/// `StreamEnd` (§10.3).
pub(crate) const TAG_STREAM_END: u8 = 0x83;

/// Client-session `Error` (§10.3).
pub(crate) const TAG_CLIENT_ERROR: u8 = 0x8e;

/// Client-session `Bye` (§10.3).
pub(crate) const TAG_CLIENT_BYE: u8 = 0x8f;

/// `AdminOk` (§10.5).
pub(crate) const TAG_ADMIN_OK: u8 = 0x90;

/// `KeyEnrolled` (§10.5).
pub(crate) const TAG_KEY_ENROLLED: u8 = 0x91;

/// `AuditChunk` (§10.5).
pub(crate) const TAG_AUDIT_CHUNK: u8 = 0x92;

/// Admin-session `Error` (§10.5).
pub(crate) const TAG_ADMIN_ERROR: u8 = 0x9e;

/// Admin-session `Bye` (§10.5).
pub(crate) const TAG_ADMIN_BYE: u8 = 0x9f;

/// Why a stream ended (§10.3, `StreamEnd.finish_reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinishReason {
    /// `0` — the model stopped on its own.
    Ok,
    /// `1` — `max_tokens` was reached.
    Length,
    /// `2` — the client sent `Cancel`.
    Cancelled,
    /// `3` — the confined model failed.
    ModelError,
}

impl FinishReason {
    /// The wire value, as §10.3 assigns it.
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Length => 1,
            Self::Cancelled => 2,
            Self::ModelError => 3,
        }
    }

    /// Decodes a `finish_reason` byte — the client-side mirror.
    pub const fn from_wire(value: u8) -> Result<Self, BspError> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Length),
            2 => Ok(Self::Cancelled),
            3 => Ok(Self::ModelError),
            _ => Err(BspError::UnknownMessageType),
        }
    }
}

/// A server→client message on a client session (§10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientResponse<'a> {
    /// `0x81` — acks a valid `InferCommit`; streaming begins.
    Accepted {
        /// Echoed from the request being answered.
        request_id: u32,
    },

    /// `0x82` — one chunk of opaque model output.
    TokenChunk {
        /// Echoed from the request being answered.
        request_id: u32,
        /// At most [`MAX_TOKEN_CHUNK`](crate::MAX_TOKEN_CHUNK) bytes.
        tokens: &'a [u8],
    },

    /// `0x83` — streaming ended; the slot returns to idle.
    StreamEnd {
        /// Echoed from the request being answered.
        request_id: u32,
        /// Why it ended.
        finish_reason: FinishReason,
    },

    /// `0x8E` — a non-fatal protocol error at message level.
    Error {
        /// The offending request's id, or `0` when there is none (§10.3).
        request_id: u32,
        /// The §12 code. [`BspError::error_code`](crate::BspError::error_code)
        /// is what maps a denial to one.
        error_code: u16,
    },

    /// `0x8F` — teardown ack; the connection closes after.
    Bye,
}

impl ClientResponse<'_> {
    /// Encodes into `out` and returns the bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, BspError> {
        let mut writer = ResponseWriter::new(out);
        self.write_into(&mut writer)?;
        let written = writer.finish();
        check_response_bound(written)?;
        Ok(written)
    }

    /// Writes `type[1] || body`.
    fn write_into(&self, writer: &mut ResponseWriter<'_>) -> Result<(), BspError> {
        match self {
            Self::Accepted { request_id } => {
                write_tagged_request_id(writer, TAG_ACCEPTED, *request_id)
            }
            Self::TokenChunk { request_id, tokens } => {
                write_token_chunk(writer, *request_id, tokens)
            }
            Self::StreamEnd {
                request_id,
                finish_reason,
            } => write_stream_end(writer, *request_id, *finish_reason),
            Self::Error {
                request_id,
                error_code,
            } => write_error(writer, TAG_CLIENT_ERROR, *request_id, *error_code),
            Self::Bye => writer.push_u8(TAG_CLIENT_BYE),
        }
    }
}

/// `0x82` — `request_id[4]`, `tokens[u16 len ≤ MAX_TOKEN_CHUNK]`.
fn write_token_chunk(
    writer: &mut ResponseWriter<'_>,
    request_id: u32,
    tokens: &[u8],
) -> Result<(), BspError> {
    writer.push_u8(TAG_TOKEN_CHUNK)?;
    writer.push_u32(request_id)?;
    writer.push_bounded_var_bytes(tokens, MAX_TOKEN_CHUNK, BspError::TokenChunkExceedsMaximum)
}

/// `0x83` — `request_id[4]`, `finish_reason[1]`.
fn write_stream_end(
    writer: &mut ResponseWriter<'_>,
    request_id: u32,
    finish_reason: FinishReason,
) -> Result<(), BspError> {
    writer.push_u8(TAG_STREAM_END)?;
    writer.push_u32(request_id)?;
    writer.push_u8(finish_reason.to_wire())
}

/// A server→client message on an admin session (§10.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminResponse<'a> {
    /// `0x90` — `AdminOk`: the verb completed.
    Ok {
        /// Echoed from the verb being answered.
        request_id: u32,
        /// An enumerated result code.
        status: u16,
    },

    /// `0x91` — reply to `EnrollKey`; the handle `RevokeKey` will later use.
    KeyEnrolled {
        /// Echoed from the verb being answered.
        request_id: u32,
        /// The non-secret administrative handle.
        handle: [u8; LEN_HANDLE],
    },

    /// `0x92` — zero or more opaque audit records, plus a resume cursor.
    AuditChunk {
        /// Echoed from the verb being answered.
        request_id: u32,
        /// Where the next `ReadAuditLog` should resume.
        next_cursor: u64,
        /// At most [`MAX_AUDIT_CHUNK`](crate::MAX_AUDIT_CHUNK) opaque bytes.
        records: &'a [u8],
    },

    /// `0x9E` — an admin-side non-fatal error.
    Error {
        /// The offending verb's id, or `0` when there is none.
        request_id: u32,
        /// The §12 code.
        error_code: u16,
    },

    /// `0x9F` — teardown ack; the connection closes after.
    Bye,
}

impl AdminResponse<'_> {
    /// Encodes into `out` and returns the bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, BspError> {
        let mut writer = ResponseWriter::new(out);
        self.write_into(&mut writer)?;
        let written = writer.finish();
        check_response_bound(written)?;
        Ok(written)
    }

    /// Writes `type[1] || body`.
    fn write_into(&self, writer: &mut ResponseWriter<'_>) -> Result<(), BspError> {
        match self {
            Self::Ok { request_id, status } => write_admin_ok(writer, *request_id, *status),
            Self::KeyEnrolled { request_id, handle } => {
                write_key_enrolled(writer, *request_id, handle)
            }
            Self::AuditChunk {
                request_id,
                next_cursor,
                records,
            } => write_audit_chunk(writer, *request_id, *next_cursor, records),
            Self::Error {
                request_id,
                error_code,
            } => write_error(writer, TAG_ADMIN_ERROR, *request_id, *error_code),
            Self::Bye => writer.push_u8(TAG_ADMIN_BYE),
        }
    }
}

/// `0x90` — `request_id[4]`, `status[2]`.
fn write_admin_ok(
    writer: &mut ResponseWriter<'_>,
    request_id: u32,
    status: u16,
) -> Result<(), BspError> {
    writer.push_u8(TAG_ADMIN_OK)?;
    writer.push_u32(request_id)?;
    writer.push_u16(status)
}

/// `0x91` — `request_id[4]`, `handle[16]`.
fn write_key_enrolled(
    writer: &mut ResponseWriter<'_>,
    request_id: u32,
    handle: &[u8; LEN_HANDLE],
) -> Result<(), BspError> {
    writer.push_u8(TAG_KEY_ENROLLED)?;
    writer.push_u32(request_id)?;
    writer.push_bytes(handle)
}

/// `0x92` — `request_id[4]`, `next_cursor[8]`,
/// `records[u16 len ≤ MAX_AUDIT_CHUNK]`.
fn write_audit_chunk(
    writer: &mut ResponseWriter<'_>,
    request_id: u32,
    next_cursor: u64,
    records: &[u8],
) -> Result<(), BspError> {
    writer.push_u8(TAG_AUDIT_CHUNK)?;
    writer.push_u32(request_id)?;
    writer.push_u64(next_cursor)?;
    writer.push_bounded_var_bytes(records, MAX_AUDIT_CHUNK, BspError::AuditChunkExceedsMaximum)
}

/// Any `tag[1] || request_id[4]` message.
fn write_tagged_request_id(
    writer: &mut ResponseWriter<'_>,
    tag: u8,
    request_id: u32,
) -> Result<(), BspError> {
    writer.push_u8(tag)?;
    writer.push_u32(request_id)
}

/// Either `Error` shape — `request_id[4]`, `error_code[2]`.
fn write_error(
    writer: &mut ResponseWriter<'_>,
    tag: u8,
    request_id: u32,
    error_code: u16,
) -> Result<(), BspError> {
    write_tagged_request_id(writer, tag, request_id)?;
    writer.push_u16(error_code)
}

/// Row R4, applied on the way out.
fn check_response_bound(written: usize) -> Result<(), BspError> {
    if written > BSP_MAX_RECORD_PLAINTEXT {
        // COVERAGE-EXEMPT: every response variant carries a tighter cap of
        // its own -- MAX_TOKEN_CHUNK 512, MAX_AUDIT_CHUNK 1024, both far under
        // this 4096 -- so a per-variant check always denies first. Pinned
        // twice: at run time by
        // `the_per_variant_cap_denies_before_the_record_bound_is_reached`, and
        // at BUILD time by the `const _: () = assert!(..)` beside it in
        // tests/valid.rs, which fails compilation if either cap ever reaches
        // the record plaintext.
        return Err(BspError::ResponseExceedsRecordPlaintext);
    }
    Ok(())
}
