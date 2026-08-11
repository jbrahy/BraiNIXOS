//! Bounds-checked big-endian readers and the response writer.
//!
//! §3 admits exactly three encoding forms and this module implements one reader
//! each, and nothing else:
//!
//! 1. **Fixed scalar** — [`FieldReader::take_u8`], [`FieldReader::take_u16`],
//!    [`FieldReader::take_u32`], [`FieldReader::take_u64`]. All big-endian. A
//!    short buffer denies.
//! 2. **Fixed array** — [`FieldReader::take_array`]. Requires ≥ N remaining
//!    bytes. No length prefix.
//! 3. **Bounded var-bytes** — [`FieldReader::take_bounded_var_bytes`], whose
//!    three checks run in the order §3 fixes and whose `MAX` is always the
//!    compile-time `const`, never the value just read.
//!
//! There is no self-describing/TLV recursion, no length that governs a
//! following length, and no in-band control byte. Structure is decided by the
//! tagged type, never interpreted from the byte stream.
//!
//! Nothing here reads through a typed pointer, so no field has an alignment
//! requirement and no offset needs one.

use crate::error::BspError;

/// Bytes in a bounded var-bytes length prefix (§3 form 3).
pub(crate) const VAR_BYTES_LENGTH_PREFIX: usize = 2;

/// Bytes in a big-endian `u16`.
const U16_LEN: usize = 2;

/// Bytes in a big-endian `u32`.
const U32_LEN: usize = 4;

/// Bytes in a big-endian `u64`.
const U64_LEN: usize = 8;

/// Denies unless a message is exactly the length its type requires.
///
/// This is the whole of rows H1 and H4: a handshake message's length is a
/// compile-time constant, so any deviation is one comparison and one REJECT.
pub(crate) fn require_exact_length(
    actual: usize,
    expected: usize,
    reason: BspError,
) -> Result<(), BspError> {
    if actual == expected {
        return Ok(());
    }
    Err(reason)
}

/// A forward-only cursor over a message body.
///
/// Every read is bounds-checked immediately before it happens, not once after
/// forming an offset, and the cursor advances only on a read that succeeded.
pub(crate) struct FieldReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> FieldReader<'a> {
    /// Starts a cursor at the front of `bytes`.
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    /// Borrows the next `count` bytes, or denies.
    fn take(&mut self, count: usize) -> Result<&'a [u8], BspError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(BspError::OffsetOverflow)?;
        let field = self
            .bytes
            .get(self.offset..end)
            .ok_or(BspError::TruncatedMessageBody)?;
        self.offset = end;
        Ok(field)
    }

    /// Reads a `u8`.
    pub(crate) fn take_u8(&mut self) -> Result<u8, BspError> {
        let field = self.take(1)?;
        let byte = field.first().ok_or(BspError::TruncatedMessageBody)?;
        Ok(*byte)
    }

    /// Reads a big-endian `u16`.
    pub(crate) fn take_u16(&mut self) -> Result<u16, BspError> {
        let field: [u8; U16_LEN] = self.take_fixed()?;
        Ok(u16::from_be_bytes(field))
    }

    /// Reads a big-endian `u32`.
    pub(crate) fn take_u32(&mut self) -> Result<u32, BspError> {
        let field: [u8; U32_LEN] = self.take_fixed()?;
        Ok(u32::from_be_bytes(field))
    }

    /// Reads a big-endian `u64`.
    pub(crate) fn take_u64(&mut self) -> Result<u64, BspError> {
        let field: [u8; U64_LEN] = self.take_fixed()?;
        Ok(u64::from_be_bytes(field))
    }

    /// Reads an exactly-`N`-byte fixed array field (§3 form 2).
    pub(crate) fn take_array<const N: usize>(&mut self) -> Result<[u8; N], BspError> {
        self.take_fixed()
    }

    /// The one place a borrowed fixed field becomes an owned array.
    fn take_fixed<const N: usize>(&mut self) -> Result<[u8; N], BspError> {
        let field = self.take(N)?;
        let array = <[u8; N]>::try_from(field).map_err(|_| BspError::TruncatedMessageBody)?;
        Ok(array)
    }

    /// Reads a bounded var-bytes field (§3 form 3).
    ///
    /// The three checks run in the specification's order — length prefix
    /// present, decoded length within the compile-time `MAX`, then declared
    /// bytes present — and each has its own reason so an audit record can tell
    /// a truncation from an over-length claim. `maximum` is always a `const`;
    /// the destination buffer is pre-sized to it and the decoded length only
    /// ever bounds a copy into it (`INV-SERVE-002`).
    pub(crate) fn take_bounded_var_bytes(&mut self, maximum: usize) -> Result<&'a [u8], BspError> {
        self.require_remaining(VAR_BYTES_LENGTH_PREFIX, BspError::TruncatedVarBytesLength)?;
        let declared = usize::from(self.take_u16()?);
        if declared > maximum {
            return Err(BspError::VarBytesLengthExceedsMaximum);
        }
        self.require_remaining(declared, BspError::TruncatedVarBytesValue)?;
        self.take(declared)
    }

    /// Denies unless at least `count` bytes remain.
    fn require_remaining(&self, count: usize, reason: BspError) -> Result<(), BspError> {
        let remaining = self
            .bytes
            .len()
            .checked_sub(self.offset)
            .ok_or(BspError::OffsetOverflow)?;
        if remaining < count {
            return Err(reason);
        }
        Ok(())
    }

    /// Denies unless the body ended exactly where its last field did.
    ///
    /// A body longer than its type requires is a disagreement between the
    /// record length and the message grammar; see
    /// [`BspError::TrailingBytesAfterBody`].
    pub(crate) fn finish(self) -> Result<(), BspError> {
        if self.offset == self.bytes.len() {
            return Ok(());
        }
        Err(BspError::TrailingBytesAfterBody)
    }
}

/// A forward-only cursor over a caller-supplied output buffer.
///
/// The buffer is never grown, never reallocated, and never partially committed:
/// an encode that denies has written nothing the caller may transmit, because
/// the caller learns the byte count only from [`ResponseWriter::finish`].
pub(crate) struct ResponseWriter<'a> {
    buffer: &'a mut [u8],
    written: usize,
}

impl<'a> ResponseWriter<'a> {
    /// Starts a cursor at the front of `buffer`.
    pub(crate) fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, written: 0 }
    }

    /// Reserves the next `count` bytes, or denies.
    fn reserve(&mut self, count: usize) -> Result<&mut [u8], BspError> {
        let start = self.written;
        let end = start.checked_add(count).ok_or(BspError::OffsetOverflow)?;
        if end > self.buffer.len() {
            return Err(BspError::OutputBufferTooSmall);
        }
        self.written = end;
        self.buffer
            .get_mut(start..end)
            .ok_or(BspError::OutputBufferTooSmall)
    }

    /// Appends a fixed array or borrowed field.
    pub(crate) fn push_bytes(&mut self, value: &[u8]) -> Result<(), BspError> {
        let region = self.reserve(value.len())?;
        region.copy_from_slice(value);
        Ok(())
    }

    /// Appends a `u8`.
    pub(crate) fn push_u8(&mut self, value: u8) -> Result<(), BspError> {
        self.push_bytes(&[value])
    }

    /// Appends a big-endian `u16`.
    pub(crate) fn push_u16(&mut self, value: u16) -> Result<(), BspError> {
        self.push_bytes(&value.to_be_bytes())
    }

    /// Appends a big-endian `u32`.
    pub(crate) fn push_u32(&mut self, value: u32) -> Result<(), BspError> {
        self.push_bytes(&value.to_be_bytes())
    }

    /// Appends a big-endian `u64`.
    pub(crate) fn push_u64(&mut self, value: u64) -> Result<(), BspError> {
        self.push_bytes(&value.to_be_bytes())
    }

    /// Appends a bounded var-bytes field: `u16 len` then `len` bytes (§3).
    pub(crate) fn push_bounded_var_bytes(
        &mut self,
        value: &[u8],
        maximum: usize,
        reason: BspError,
    ) -> Result<(), BspError> {
        if value.len() > maximum {
            return Err(reason);
        }
        let declared = u16::try_from(value.len()).map_err(|_| reason)?;
        self.push_u16(declared)?;
        self.push_bytes(value)
    }

    /// The number of bytes written, once the whole message is committed.
    pub(crate) fn finish(self) -> usize {
        self.written
    }
}
