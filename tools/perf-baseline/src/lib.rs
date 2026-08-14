#![no_std]
#![deny(unsafe_code)]

//! The arithmetic serving performance is judged against (P3-T10).
//!
//! The north star makes performance a craft standard and says how to think
//! about it: **"inference on this machine is memory-bandwidth-bound, not
//! compute-bound. Single-stream decode reads essentially the whole weight set
//! per token, so the ceiling is (model bytes) ÷ (memory bandwidth), and every
//! design decision should be judged against that arithmetic first."**
//!
//! It also says slowness must be justified by a **named invariant** rather than
//! by vague caution. That is not checkable without a number, and until this
//! module there was no number: no task in the roadmap produced one, which is
//! why P3-T10 was added.
//!
//! # Why the ceiling is a *ceiling*
//!
//! It assumes the arithmetic is free and the memory system is perfect: every
//! weight byte is read exactly once per token, at the full advertised
//! bandwidth, with no cache misses that re-read, no latency the prefetcher
//! fails to hide, and no time spent anywhere else. Nothing achieves it. Its use
//! is as a **denominator**: a decoder at 60% of ceiling has a bandwidth
//! problem worth 40%, and one at 6% has a different problem entirely, and
//! without the ratio both are just "some tokens per second".
//!
//! # The sharp consequence
//!
//! Because the ceiling is bytes over bandwidth, **quantization divides it
//! directly**, while micro-optimizing arithmetic moves nothing. The north star
//! draws that conclusion; this module is where it becomes arithmetic anyone can
//! check — and checking it corrects the obvious version of the claim.
//!
//! Q8_0 against f16 is **1.78×, not 2×**. One byte per weight is half of f16's
//! two, but the format stores a four-byte scale per 32-element block, which is
//! another 0.125 bytes per weight: 1.125 against 2.0. A twelve per cent
//! overhead is small enough to be dropped from a summary and large enough to
//! matter when it is the denominator of a performance target, which is exactly
//! the kind of figure a written-down model catches and an intuition does not.
//! This module's first test asserted 2× and failed.

/// Bytes per element, by weight encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// 32-bit float: four bytes per weight.
    F32,
    /// 16-bit float: two bytes per weight.
    F16,
    /// The BXW1 Q8_0 block: one byte per weight plus a scale per 32-element
    /// block, so 32 weights occupy 32 + 4 = 36 bytes.
    Q8_0,
}

impl Encoding {
    /// Bytes occupied by `weights` weights in this encoding.
    ///
    /// # Errors
    ///
    /// `None` on overflow — a weight count that cannot be sized is a model that
    /// cannot be served, and returning a wrapped figure would put a plausible
    /// ceiling on an impossible model.
    #[must_use]
    pub const fn bytes_for(self, weights: u64) -> Option<u64> {
        match self {
            Self::F32 => weights.checked_mul(4),
            Self::F16 => weights.checked_mul(2),
            Self::Q8_0 => {
                // One byte each, plus a four-byte scale per 32-element block,
                // rounding the final partial block up: a block is stored whole.
                let blocks = weights.div_ceil(32);
                match blocks.checked_mul(4) {
                    Some(scales) => weights.checked_add(scales),
                    None => None,
                }
            }
        }
    }
}

/// A model's size, as the ceiling cares about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelSize {
    /// Total weights across every tensor read during a decode step.
    pub weights: u64,
    /// How those weights are stored.
    pub encoding: Encoding,
}

impl ModelSize {
    /// The bytes a single-stream decode step must read.
    ///
    /// # Errors
    ///
    /// `None` if the size does not compute.
    #[must_use]
    pub const fn bytes_per_token(&self) -> Option<u64> {
        self.encoding.bytes_for(self.weights)
    }
}

/// The ceiling, in tokens per second, and what it was computed from.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Ceiling {
    /// Bytes read per token.
    pub bytes_per_token: u64,
    /// The memory bandwidth assumed, in bytes per second.
    pub bandwidth_bytes_per_second: u64,
    /// Tokens per second, if the memory system were perfect and arithmetic free.
    pub tokens_per_second: f64,
}

/// The single-stream decode ceiling for a model on a machine.
///
/// # Errors
///
/// `None` for a zero bandwidth, a zero-byte model, or a size that does not
/// compute. Each would produce an infinite or meaningless ceiling, and a
/// denominator that silently becomes infinity is how a performance claim stops
/// being falsifiable.
#[must_use]
pub fn decode_ceiling(model: &ModelSize, bandwidth_bytes_per_second: u64) -> Option<Ceiling> {
    let bytes_per_token = model.bytes_per_token()?;
    if bytes_per_token == 0 || bandwidth_bytes_per_second == 0 {
        return None;
    }
    Some(Ceiling {
        bytes_per_token,
        bandwidth_bytes_per_second,
        tokens_per_second: bandwidth_bytes_per_second as f64 / bytes_per_token as f64,
    })
}

/// How close a measurement came to the ceiling, as a fraction.
///
/// The number that matters. A decoder at 0.6 has a bandwidth problem worth
/// forty per cent; one at 0.06 has a different problem, and the ratio is what
/// distinguishes them.
///
/// # Errors
///
/// `None` if the ceiling is not positive.
#[must_use]
pub fn fraction_of_ceiling(measured_tokens_per_second: f64, ceiling: &Ceiling) -> Option<f64> {
    if ceiling.tokens_per_second <= 0.0 {
        return None;
    }
    Some(measured_tokens_per_second / ceiling.tokens_per_second)
}

/// The Mac mini M2 Pro's advertised unified-memory bandwidth, in bytes/second.
///
/// 200 GB/s, using the decimal GB Apple advertises in. It is the *advertised*
/// figure and therefore optimistic — the achievable figure is lower and is a
/// measurement, not a specification — which is the right direction for a
/// denominator: it makes the ratio conservative rather than flattering.
pub const M2_PRO_BANDWIDTH_BYTES_PER_SECOND: u64 = 200_000_000_000;
