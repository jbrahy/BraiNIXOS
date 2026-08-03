//! The single failure enum for the tensor kernels.
//!
//! One variant per failure mode, so a refused call can be audited for *why* it
//! was refused rather than merely *that* it was. Deliberately not
//! `#[non_exhaustive]`: callers inside BraiNIX are meant to match exhaustively
//! so that a newly added failure mode is a compile error, not a silent wildcard
//! arm. This mirrors [`brainix_adt::AdtError`](../../adt/src/error.rs).

/// Every way a tensor kernel can refuse a call.
///
/// There is no partial computation. Any value of this type means **no output
/// slice was written** — every kernel validates its whole shape agreement
/// before it touches a single output element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TensorError {
    /// A declared extent — `n_tokens`, `n_in`, `n_out`, a head width, a row
    /// width — is zero.
    ///
    /// Refused rather than treated as a no-op, for the reason BXW1 §7.4 rule D4
    /// gives: a zero extent makes the element product zero, which passes a
    /// naive length check and then computes nothing while reporting success.
    ZeroDimension,

    /// A checked multiplication or addition over the declared shape would have
    /// overflowed `usize`. Overflow refuses; it never wraps and never
    /// saturates.
    DimensionOverflow,

    /// A supplied slice's length is not the length the declared shape requires,
    /// in either direction.
    ///
    /// A short slice would truncate; a long one means the caller and the kernel
    /// disagree about the shape, and BXW1 §7.5 (`INV-PARSE-004`) is explicit
    /// that disagreeing sources fail closed with no precedence rule. Never
    /// silently truncated to the shorter of the two.
    ShapeMismatch,

    /// A `Q8_0` tensor's fastest-varying dimension is not a multiple of
    /// [`Q8_0_BLOCK`](crate::Q8_0_BLOCK) (BXW1 §4.2, rule D8).
    ///
    /// This is the constraint that lets a row decompose into whole blocks with
    /// no partial-block branch in the inner loop.
    NotBlockAligned,

    /// A `Q8_0` payload's byte length is not the length BXW1 §4.3 derives from
    /// its shape — scale plane, pad to [`BXW1_ALIGN`](crate::BXW1_ALIGN), quant
    /// plane.
    PayloadLengthMismatch,

    /// A `Q8_0` payload slice could not be split into its two planes at the
    /// derived offsets.
    ///
    /// Unreachable once [`TensorError::PayloadLengthMismatch`] has passed;
    /// retained because "unreachable" is an argument about the program and a
    /// checked split is a property of it.
    MalformedPayload,

    /// An input a kernel's algorithm depends on being finite is NaN or ±Inf.
    ///
    /// Raised only where the value is *load bearing*: softmax's row maximum and
    /// RMSNorm's mean square. See the crate documentation on which kernels
    /// validate and which propagate.
    NonFiniteInput,

    /// The RMSNorm epsilon is not a positive, finite, normal `f32`.
    ///
    /// Classified from its bit pattern by integer comparison, following BXW1
    /// §4.7: comparing an unvalidated float is itself the bug, since `NaN < x`
    /// and `NaN > x` are both false and a float-comparison range check accepts
    /// NaN silently.
    InvalidEpsilon,

    /// The RoPE base θ is not a positive, finite, normal `f32`, or is not
    /// greater than one.
    ///
    /// Classified by the same bit-pattern rule as
    /// [`TensorError::InvalidEpsilon`]. θ ≤ 1 is refused because
    /// `θ^(−2i/rope_dim)` would then be non-decreasing in `i`, which is not a
    /// rotary embedding.
    InvalidTheta,

    /// `rope_dim` is zero, odd, or greater than `d_head` (BXW1 §7.2 rule H17).
    InvalidRopeDim,

    /// A BXW1 `rope_pairing` value is not one of the two the format enumerates
    /// (BXW1 §5.5, §7.2 rule H17a).
    ///
    /// **`0` is refused like any other unrecognized value.** It is not a
    /// default and not "unspecified": it is what a converter that never heard
    /// of the field writes, which is precisely the case the field exists to
    /// catch. Defaulting here would mean the one case worth disambiguating is
    /// the one case that is not disambiguated.
    InvalidRopePairing,

    /// The RoPE position exceeds [`MAX_ROPE_POSITION`](crate::MAX_ROPE_POSITION).
    ///
    /// A stated accuracy bound, not a capacity one: beyond it the argument
    /// reduction inside the sine/cosine kernel loses the exactness its
    /// two-term Cody-Waite split depends on, and the rotation would be quietly
    /// wrong rather than absent.
    PositionTooLarge,
}
