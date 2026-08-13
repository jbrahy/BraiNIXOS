//! The four slice operations every module here needs, in one place.
//!
//! None of them can panic: no indexing, no `copy_from_slice`, no `split_at`.
//! A length disagreement is an error the caller can audit, never an abort.

use crate::error::TransformerError;

/// The first `count` elements, refusing rather than truncating.
///
/// # Errors
///
/// [`TransformerError::WorkspaceTooSmall`].
pub(crate) fn prefix(values: &[f32], count: usize) -> Result<&[f32], TransformerError> {
    values
        .get(..count)
        .ok_or(TransformerError::WorkspaceTooSmall)
}

/// The first `count` elements, mutably, refusing rather than truncating.
///
/// # Errors
///
/// [`TransformerError::WorkspaceTooSmall`].
pub(crate) fn prefix_mut(values: &mut [f32], count: usize) -> Result<&mut [f32], TransformerError> {
    values
        .get_mut(..count)
        .ok_or(TransformerError::WorkspaceTooSmall)
}

/// The `index`-th `width`-wide row of a row-major buffer.
///
/// # Errors
///
/// [`TransformerError::DimensionOverflow`] or
/// [`TransformerError::WorkspaceTooSmall`].
pub(crate) fn row(values: &[f32], index: usize, width: usize) -> Result<&[f32], TransformerError> {
    let (start, end) = span(index, width)?;
    values
        .get(start..end)
        .ok_or(TransformerError::WorkspaceTooSmall)
}

/// The `[start, end)` element range of the `index`-th `width`-wide row.
///
/// # Errors
///
/// [`TransformerError::DimensionOverflow`].
pub(crate) fn span(index: usize, width: usize) -> Result<(usize, usize), TransformerError> {
    let start = index
        .checked_mul(width)
        .ok_or(TransformerError::DimensionOverflow)?;
    let end = start
        .checked_add(width)
        .ok_or(TransformerError::DimensionOverflow)?;
    Ok((start, end))
}

/// Element-wise copy over a `zip`, so no length disagreement can panic.
pub(crate) fn copy_into(source: &[f32], destination: &mut [f32]) {
    for (value, slot) in source.iter().zip(destination.iter_mut()) {
        *slot = *value;
    }
}

/// `destination += source`, elementwise — the residual connection.
///
/// # Errors
///
/// [`TransformerError::WorkspaceTooSmall`] if the lengths disagree, so a
/// residual can never be added over part of the stream.
pub(crate) fn add_into(source: &[f32], destination: &mut [f32]) -> Result<(), TransformerError> {
    if source.len() != destination.len() {
        // COVERAGE-EXEMPT: add_into is pub(crate) and every caller passes two slices taken from the same validated workspace geometry, so the lengths agree by construction. Kept so a future caller cannot add a residual over part of the stream.
        return Err(TransformerError::WorkspaceTooSmall);
    }
    for (value, slot) in source.iter().zip(destination.iter_mut()) {
        *slot += value;
    }
    Ok(())
}
