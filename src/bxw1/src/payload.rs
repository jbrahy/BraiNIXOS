//! Stage S7: one pass over the payload.
//!
//! Computes the whole-blob SHA-256 and every per-tensor SHA-256, validates
//! every `Q8_0` scale and every `F32` element bit pattern, and verifies that
//! every pad byte is zero -- the pads between extents and after the last, and
//! every `Q8_0` inter-plane pad (rules C2, C3, C4, D19, D21).
//!
//! **Every byte of the blob is read exactly once.** The extents are already
//! known to be ascending and disjoint (rules D15-D18), so the walk below
//! consumes the blob strictly left to right -- header and table, then
//! alternating pad and extent, then the trailing pad -- and feeds each byte to
//! the whole-blob hasher on the way past. The per-tensor hash of an extent is
//! computed from the same borrowed slice, so no byte is fetched twice and
//! nothing is copied.
//!
//! The quant plane of a `Q8_0` tensor is **deliberately unvalidated**: all 256
//! bit patterns are valid `i8` and the dequantization of §4.2 is well-defined
//! for every one of them, including `-128`. It is the only field in the format
//! that is unvalidated by construction rather than by omission, and it is
//! called out here so its absence from the checks below is not read as a gap.

use sha2::{Digest, Sha256};

use crate::error::Bxw1Error;
use crate::header::Header;
use crate::raw::{
    digests_equal, is_finite_element, is_positive_finite, require_zero, slice_at, DIGEST_LEN,
};
use crate::table::{q8_planes, Record};
use crate::Dtype;

/// Bytes in a little-endian binary32.
const F32_BYTES: usize = 4;

/// Runs the payload pass and returns the whole-blob digest.
///
/// The whole-blob digest is **returned, not compared**: the value it is
/// compared against arrives in the `LoadWeights` verb (rule C5) and the
/// detached Ed25519 signature over it (rule C9) is stage S8's, which needs a
/// key this crate does not have and must not hold.
pub(crate) fn verify(
    blob: &[u8],
    table: &[u8],
    header: &Header,
) -> Result<[u8; DIGEST_LEN], Bxw1Error> {
    let mut whole = Sha256::new();

    // Header, table, and the pad between the table and the first extent. The
    // pad's *length* is already bounded by rule H10; rule D19 is what makes
    // its contents accounted for.
    let table_end = header.table_end()?;
    let gap = header
        .tensor_data_off
        .checked_sub(table_end)
        .ok_or(Bxw1Error::TensorDataOffsetBeforeTable)?;
    require_zero(slice_at(blob, table_end, gap).ok_or(Bxw1Error::ExtentPastBlob)?)?;
    whole.update(slice_at(blob, 0, header.tensor_data_off).ok_or(Bxw1Error::ExtentPastBlob)?);

    let mut cursor = header.tensor_data_off;
    for index in 0..header.tensor_count {
        let record = Record::decode(table, index)?;
        let pad = record
            .data_off
            .checked_sub(cursor)
            .ok_or(Bxw1Error::OverlappingExtents)?;
        let pad_bytes = slice_at(blob, cursor, pad).ok_or(Bxw1Error::ExtentPastBlob)?;
        require_zero(pad_bytes)?;
        whole.update(pad_bytes);

        let payload =
            slice_at(blob, record.data_off, record.data_len).ok_or(Bxw1Error::ExtentPastBlob)?;
        whole.update(payload);
        verify_tensor_digest(payload, record.digest)?;
        verify_content(&record, payload)?;

        cursor = record.extent_end()?;
    }

    // The trailing pad. Rule D18 has already fixed its length at less than
    // `BXW1_ALIGN`; this is what makes its contents accounted for.
    let tail = header
        .total_size
        .checked_sub(cursor)
        .ok_or(Bxw1Error::ExtentPastBlob)?;
    let tail_bytes = slice_at(blob, cursor, tail).ok_or(Bxw1Error::ExtentPastBlob)?;
    require_zero(tail_bytes)?;
    whole.update(tail_bytes);

    Ok(finish(whole))
}

/// Rule C1: the table's SHA-256 must equal `tensor_table_digest`.
///
/// Runs **before** any record's contents are used for anything beyond bounds
/// checking (stage S4), so a corrupt table cannot silently relabel correct
/// data.
pub(crate) fn verify_table_digest(table: &[u8], header: &Header) -> Result<(), Bxw1Error> {
    let mut hasher = Sha256::new();
    hasher.update(table);
    if !digests_equal(&finish(hasher), &header.tensor_table_digest) {
        return Err(Bxw1Error::TensorTableDigestMismatch);
    }
    Ok(())
}

/// Rule C2: a tensor's SHA-256 must equal its record's `digest`.
///
/// A mismatch denies the **whole blob**, not the tensor: there is no partial
/// activation.
fn verify_tensor_digest(payload: &[u8], declared: &[u8]) -> Result<(), Bxw1Error> {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    if !digests_equal(&finish(hasher), declared) {
        return Err(Bxw1Error::TensorDigestMismatch);
    }
    Ok(())
}

/// Rules C3, C4 and the `Q8_0` inter-plane pad (rule D21).
fn verify_content(record: &Record<'_>, payload: &[u8]) -> Result<(), Bxw1Error> {
    match record.dtype {
        Dtype::F32 => {
            for element in payload.chunks_exact(F32_BYTES) {
                if !is_finite_element(le_bits(element).ok_or(Bxw1Error::ExtentPastBlob)?) {
                    return Err(Bxw1Error::NonFiniteF32Element);
                }
            }
            Ok(())
        }
        Dtype::Q8 => {
            let (scale_len, quant_off) = q8_planes(record.elements)?;
            let scales = slice_at(payload, 0, scale_len).ok_or(Bxw1Error::ExtentPastBlob)?;
            for scale in scales.chunks_exact(F32_BYTES) {
                if !is_positive_finite(le_bits(scale).ok_or(Bxw1Error::ExtentPastBlob)?) {
                    return Err(Bxw1Error::InvalidQ8Scale);
                }
            }
            let pad_len = quant_off
                .checked_sub(scale_len)
                .ok_or(Bxw1Error::DerivedLengthOverflow)?;
            require_zero(slice_at(payload, scale_len, pad_len).ok_or(Bxw1Error::ExtentPastBlob)?)
            // The quant plane is not validated: see the module documentation.
        }
    }
}

/// Reads a little-endian `u32` bit pattern from exactly four bytes.
fn le_bits(bytes: &[u8]) -> Option<u32> {
    match bytes {
        [b0, b1, b2, b3] => Some(u32::from_le_bytes([*b0, *b1, *b2, *b3])),
        _ => None,
    }
}

/// Finalizes a hasher into an owned 32-byte array without indexing and
/// without depending on a `GenericArray` conversion.
fn finish(hasher: Sha256) -> [u8; DIGEST_LEN] {
    let computed = hasher.finalize();
    let mut digest = [0_u8; DIGEST_LEN];
    for (slot, byte) in digest.iter_mut().zip(computed.iter()) {
        *slot = *byte;
    }
    digest
}
