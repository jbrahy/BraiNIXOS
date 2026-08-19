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
        return Err(TransformerError::WorkspaceTooSmall);
    }
    for (value, slot) in source.iter().zip(destination.iter_mut()) {
        *slot += value;
    }
    Ok(())
}

/// `add_into` at the disagreement its callers cannot produce.
#[cfg(test)]
mod tests {
    use super::add_into;
    use crate::error::TransformerError;

    #[test]
    fn adding_over_a_shorter_destination_is_refused_not_truncated() {
        // The residual connection. `zip` would silently add over the prefix and
        // leave the tail untouched, which is a model that runs and is wrong --
        // the worst failure mode available here, because nothing downstream can
        // tell a half-added residual from a badly trained one.
        let source = [1.0_f32, 2.0, 3.0];
        let mut short = [0.0_f32; 2];
        assert_eq!(
            add_into(&source, &mut short),
            Err(TransformerError::WorkspaceTooSmall)
        );
        assert_eq!(short, [0.0, 0.0], "nothing is written on refusal");

        // And in the other direction, which `zip` would also accept.
        let mut long = [0.0_f32; 4];
        assert_eq!(
            add_into(&source, &mut long),
            Err(TransformerError::WorkspaceTooSmall)
        );
        assert_eq!(long, [0.0; 4]);
    }

    #[test]
    fn equal_lengths_accumulate_in_place() {
        let source = [1.0_f32, 2.0, 3.0];
        let mut destination = [10.0_f32, 20.0, 30.0];
        assert_eq!(add_into(&source, &mut destination), Ok(()));
        assert_eq!(destination, [11.0, 22.0, 33.0]);

        // Empty and empty agree, so a zero-width stream is a no-op rather than
        // an error -- the boundary a `!=` check gets right and a `<` gets wrong.
        assert_eq!(add_into(&[], &mut []), Ok(()));
    }
}
