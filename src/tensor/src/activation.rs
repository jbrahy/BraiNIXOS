//! SiLU and the SwiGLU product.
//!
//! ```text
//! silu(v)          = v · σ(v) = v / (1 + e^−v)
//! swiglu(g, u)[i]  = silu(g[i]) · u[i]
//! ```
//!
//! In BXW1 §6.2's naming, `w1` is the gate projection, `w3` the up projection
//! and `w2` the down projection, composing as `w2( SiLU(w1 x) ⊙ (w3 x) )`.
//! [`swiglu`] is the middle term: it takes `w1 x` as `gate` and `w3 x` as `up`
//! and produces the vector `w2` is applied to. Which matmul feeds which
//! argument is the caller's to get right, and the parameter names are the only
//! thing standing between a correct FFN and a plausible-looking wrong one.
//!
//! # These two do not validate their inputs, and that is deliberate
//!
//! Softmax and RMSNorm refuse non-finite input because their algorithms depend
//! on it: a row maximum and a reciprocal-square-root domain respectively.
//! SiLU and SwiGLU have no such dependence — they are elementwise and total,
//! and a non-finite input propagates to exactly the elements it entered
//! through, which is what any elementwise operator does. Adding a scan here
//! would cost a pass over `d_ffn` per token to convert one flavour of garbage
//! into another. Validation lives where it is load bearing, and nowhere else.

use crate::error::TensorError;
use crate::math::exp;

/// `σ(v) = 1/(1 + e^−v)`, without an intermediate that can overflow.
///
/// The naive form overflows for `v` around `−88` in `f32` and `−709` in `f64`:
/// `e^−v` becomes `+Inf` and the quotient collapses to `0`, which happens to be
/// the right limit but only by accident, and produces an `Inf` on the way. The
/// branch below keeps the exponential's argument non-positive on both sides, so
/// no intermediate ever leaves the representable range.
fn sigmoid(v: f64) -> f64 {
    if v >= 0.0 {
        1.0 / (1.0 + exp(-v))
    } else {
        let e = exp(v);
        e / (1.0 + e)
    }
}

/// SiLU (also called swish-1) elementwise.
///
/// Exact at zero: `exp(0) == 1` gives `σ(0) == 0.5` and `silu(0) == 0.0`.
///
/// # Errors
///
/// - [`TensorError::ZeroDimension`] if `x` is empty.
/// - [`TensorError::ShapeMismatch`] if `out.len() != x.len()`.
///
/// Nothing is written on either.
pub fn silu(x: &[f32], out: &mut [f32]) -> Result<(), TensorError> {
    if x.is_empty() {
        return Err(TensorError::ZeroDimension);
    }
    if out.len() != x.len() {
        return Err(TensorError::ShapeMismatch);
    }
    for (value, slot) in x.iter().zip(out.iter_mut()) {
        let v = f64::from(*value);
        *slot = (v * sigmoid(v)) as f32;
    }
    Ok(())
}

/// `out[i] = silu(gate[i]) × up[i]` — the SwiGLU product.
///
/// Fused rather than composed from [`silu`] plus a multiply, because composing
/// would need a `d_ffn`-sized temporary. This crate allocates nothing and owns
/// no buffer (`INV-MEM`), so the temporary would have to be a fourth
/// caller-supplied slice — a worse interface bought with an extra
/// `d_ffn × 4`-byte write and read per token, on the machine whose ceiling is
/// bytes moved.
///
/// `out` may alias neither input, since Rust's borrow checker forbids it; it is
/// therefore safe to write each element as it is computed.
///
/// # Errors
///
/// - [`TensorError::ZeroDimension`] if `gate` is empty.
/// - [`TensorError::ShapeMismatch`] if `up` and `out` are not the same length
///   as `gate`.
///
/// Nothing is written on either.
pub fn swiglu(gate: &[f32], up: &[f32], out: &mut [f32]) -> Result<(), TensorError> {
    if gate.is_empty() {
        return Err(TensorError::ZeroDimension);
    }
    if up.len() != gate.len() || out.len() != gate.len() {
        return Err(TensorError::ShapeMismatch);
    }
    for ((g, u), slot) in gate.iter().zip(up.iter()).zip(out.iter_mut()) {
        let v = f64::from(*g);
        *slot = ((v * sigmoid(v)) as f32) * u;
    }
    Ok(())
}
