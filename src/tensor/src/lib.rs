//! Tensor kernels for BXW1 weights — P3-T4.
//!
//! The first code in BraiNIX that computes anything a language model needs.
//! Everything here is architecture-neutral and host-testable: no hardware, no
//! capability, no syscall, no device. It is the substrate the transformer
//! forward pass (P3-T6) is built from, and it is written against the
//! dequantization formula, storage convention and hyperparameter meanings that
//! `docs/architecture/BXW1-weight-format.md` pins.
//!
//! # What this crate guarantees
//!
//! - `#![no_std]`, `#![forbid(unsafe_code)]`, and **zero allocation**. No heap,
//!   no arena, no growable buffer, no owned buffer of any kind. Every working
//!   set is a caller-supplied slice or a fixed-size array (`INV-MEM`). A kernel
//!   never allocates and never owns a buffer, which is why every one of them
//!   takes an explicit output slice.
//! - **Shape agreement is validated before anything is computed.** A slice
//!   whose length disagrees with the declared shape returns
//!   [`TensorError::ShapeMismatch`] in *either* direction. Nothing is truncated
//!   to the shorter of the two, and no output element is written on any error
//!   path.
//! - **No panicking construct.** No `unwrap`, no `expect`, no `panic!`, no
//!   slice index that can be out of range, and no unchecked integer arithmetic
//!   — the crate builds clean under the workspace's `unwrap_used`, `panic`,
//!   `expect_used` and `arithmetic_side_effects` denials.
//! - **Soft float, scalar, no intrinsics.** There is no SIMD here yet, on
//!   purpose: the userspace FP/SIMD enablement (P3-T0) has not landed and the
//!   context-switch save/restore does not preserve vector state, so a NEON
//!   kernel today would be a correctness bug wearing a performance costume. The
//!   loop shapes below are chosen so a later vector pass has somewhere to land
//!   — see *SIMD seams*.
//!
//! # Bytes moved is the metric
//!
//! Inference on the reference machine — a 32 GB unified-memory Mac mini M2 Pro
//! — is **memory-bandwidth-bound, not compute-bound**. Single-stream decode
//! reads essentially the whole weight set per token, so the ceiling is
//! (model bytes ÷ memory bandwidth), and reducing instructions does not move
//! it. Reducing bytes does. Every design decision in this crate was made
//! against that arithmetic:
//!
//! - [`matmul_q8_0`] dequantizes **in the inner loop, against activations
//!   already in registers**. It never materializes an `f32` weight matrix.
//!   Materializing would move 1.125 bytes to read the weights, then 4 to write
//!   and 4 to read back the dequantized copy — 8× the traffic of the `f32` path
//!   it was meant to beat, which would defeat the entire point of storing
//!   `Q8_0`.
//! - Both matmuls run weights-outer, tokens-inner, so **every weight byte is
//!   touched exactly once per call** regardless of how many tokens are in
//!   flight. See [`matmul`]'s module documentation for the arithmetic and for
//!   where blocking would go.
//! - The transcendental functions live in a private module and are called
//!   `O(d_model)` or `O(seq_len)` times per layer, never `O(d_model × d_ffn)`.
//!   They are computed in `f64` because accuracy there is free — none of them
//!   is on the bandwidth-bound path.
//!
//! # Two helpers are published alongside the kernels
//!
//! [`rsqrt`] and [`is_positive_normal`] are not kernels and are exported anyway,
//! because a `#![no_std]` consumer has no `sqrt` in `core` and no way to write
//! BXW1 §4.7's bit-pattern classification without writing it again. While both
//! were private, `brainix_transformer` carried its own copy of each. Two
//! implementations of a rule whose entire value is that every float in the
//! system is classified identically is a defect in waiting, so the rule has one
//! home and it is here.
//!
//! # SIMD seams
//!
//! Named here so the later NEON pass is an edit rather than a rewrite:
//!
//! 1. **The `Q8_0` block dot** in [`matmul_q8_0`] — 32 `i8`×`f32` products and
//!    a reduction, over a 32-byte quant slice that is 128-byte-aligned in the
//!    weights region. Two `vld1q_s8` loads, widen, convert, four `vfmaq_f32`
//!    against activations already held, one horizontal add per block. The
//!    scale is applied once per block, outside the 32, which is exactly where a
//!    vector implementation wants it.
//! 2. **The scale plane** — four consecutive scales are one `vld1q_f32`. This
//!    is the property the split-plane layout buys and interleaving forbids
//!    (BXW1 §4.6), and reading it four at a time is a change to the
//!    `chunks_exact(4)` walk in [`Q8Weights`] and nothing else.
//! 3. **The `f32` dot** in [`matmul_f32`] — a plain `zip` over two contiguous
//!    slices, the shape LLVM already auto-vectorizes and a hand-written
//!    four-accumulator `vfmaq_f32` loop replaces cleanly.
//! 4. **The elementwise kernels** — [`silu`], [`swiglu`], and softmax's
//!    normalization pass are single `zip`s with no cross-element dependence.
//!    Only [`softmax`]'s exponential and [`rmsnorm`]'s reciprocal square root
//!    need vector transcendentals, and both are off the bandwidth-bound path,
//!    so they are the *last* things worth vectorizing rather than the first.
//! 5. **Nothing indexes.** Every hot loop is `chunks_exact`/`zip`, so no bounds
//!    check survives into it and no induction variable has to be proven
//!    in-range before a vector pass can widen it.
//!
//! # Where validation lives
//!
//! Kernels validate shapes always, and values only where a value is *load
//! bearing* for the algorithm:
//!
//! | Kernel | Validates values? | Why |
//! |---|---|---|
//! | [`softmax`] | yes — NaN, ±Inf | stability rests on the row maximum, and NaN is unordered |
//! | [`rmsnorm`] | yes — ε, and the mean square | the reciprocal square root has a domain |
//! | [`rope`] | yes — θ, `rope_dim`, position, pairing | θ is a base for a logarithm; position bounds an argument reduction; an unrecognized [`RopePairing`] is refused at the `u32` boundary and unrepresentable past it |
//! | [`matmul_f32`], [`matmul_q8_0`] | no | a non-finite weight propagates to its row and nowhere else; scanning would be a second full pass over the weights |
//! | [`silu`], [`swiglu`] | no | elementwise and total for every input |
//!
//! Float classification is done **by integer comparison on the bit pattern**,
//! following BXW1 §4.7, and never by a float comparison — `NaN < x` and
//! `NaN > x` are both false, so a float-comparison range check accepts NaN
//! silently.
//!
//! # Preconditions this crate does not re-check
//!
//! `Q8_0` payloads reaching [`Q8Weights`] are assumed to have passed the
//! Full-tier BXW1 loader (P3-T3): per-tensor digest, every scale a positive
//! finite normal (rule C3), every pad byte zero (rule D19). Repeating those
//! here would mean a second full pass over the weights per matmul on a
//! bandwidth-bound machine. **The loader does not exist yet** (BXW1 §11), so
//! today that precondition is discharged by nothing; it is stated rather than
//! assumed silently, and it is a shape assumption, never a safety one — a bad
//! scale produces bad numbers, not unsafety.
//!
//! # Example
//!
//! ```
//! use brainix_tensor::{matmul_q8_0, MatMulShape, Q8Weights, TensorError};
//!
//! fn project(payload: &[u8], x: &[f32], y: &mut [f32]) -> Result<(), TensorError> {
//!     let weights = Q8Weights::new(payload, y.len(), x.len())?;
//!     let shape = MatMulShape { n_tokens: 1, n_in: x.len(), n_out: y.len() };
//!     matmul_q8_0(shape, &weights, x, y)
//! }
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(test)]
extern crate std;

mod activation;
mod error;
mod math;
pub mod matmul;
mod norm;
pub mod q4;
mod q8;
mod rope;
mod softmax;

pub use crate::activation::{silu, swiglu};
pub use crate::error::TensorError;
pub use crate::math::rsqrt;
pub use crate::matmul::{
    matmul_f32, matmul_q4_0_q8a, matmul_q8_0, matmul_q8_0_q8a, matmul_q8_0_q8a_rows,
    quantize_activations, MatMulShape,
};
pub use crate::norm::{is_positive_normal, rmsnorm};
pub use crate::q4::{quantize_q4_0, Q4Weights, Q4_0_BLOCK};
pub use crate::q8::{Q8Weights, BXW1_ALIGN, Q8_0_BLOCK};
pub use crate::rope::{rope, RopePairing, RopeParams, MAX_ROPE_POSITION};
pub use crate::softmax::softmax;
