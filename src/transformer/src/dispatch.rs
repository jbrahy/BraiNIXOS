//! How the forward pass gets its work onto more than one core.
//!
//! # Why this is a trait and not a thread pool
//!
//! This crate is `#![no_std]` and allocates nothing. It cannot own threads, and
//! on the target it will eventually be driven by a kernel scheduler that has
//! nothing to do with `std::thread`. So parallelism is **injected**: the caller
//! supplies something that can run a closure over disjoint chunks of the output,
//! and the forward pass stays ignorant of how.
//!
//! The parameter is generic rather than `dyn`, so every call monomorphizes and
//! the serial case compiles to exactly the loop it replaced -- no vtable, no
//! indirect call on the hot path, and nothing to allocate.
//!
//! # What is worth splitting, measured
//!
//! Row-splitting one matmul across four workers is worth **2.4-2.6x** on this
//! machine, and a fifth and sixth worker buy nothing: the memory bus saturates
//! around 110 GB/s. A caller sizing its pool from the core count rather than
//! from that measurement pays for contention it cannot use.

use crate::error::TransformerError;

/// Runs a body over disjoint chunks of an output slice.
///
/// # Contract
///
/// `for_each_chunk` must call `body(chunk_index, chunk)` exactly once for every
/// chunk `out.chunks_mut(chunk_len)` would yield, in any order and on any
/// thread, and must not return until all of them have completed. The chunks are
/// disjoint by construction, which is what makes a parallel implementation safe
/// without the implementor reasoning about aliasing.
pub trait Dispatch {
    /// How many chunks this dispatcher wants the work split into.
    ///
    /// A hint, not a promise: the caller may split into fewer if the work does
    /// not divide, and one is always valid.
    fn chunks(&self) -> usize;

    /// Runs `body` over `out.chunks_mut(chunk_len)`.
    fn for_each_chunk<F>(&self, out: &mut [f32], chunk_len: usize, body: F)
    where
        F: Fn(usize, &mut [f32]) + Sync;
}

/// The single-threaded dispatcher.
///
/// What the kernel uses until it has a scheduler, and what every existing test
/// gets by default. Compiles to the loop the forward pass had before this trait
/// existed.
#[derive(Debug, Clone, Copy, Default)]
pub struct Serial;

impl Dispatch for Serial {
    fn chunks(&self) -> usize {
        1
    }

    fn for_each_chunk<F>(&self, out: &mut [f32], chunk_len: usize, body: F)
    where
        F: Fn(usize, &mut [f32]) + Sync,
    {
        for (index, chunk) in out.chunks_mut(chunk_len.max(1)).enumerate() {
            body(index, chunk);
        }
    }
}

/// Chunk length that divides `n_out` into at most `chunks` pieces.
///
/// Rounded **up**, so the last chunk is the short one and no chunk is empty. A
/// rounded-down length would produce a trailing remainder chunk and one more
/// worker than asked for.
pub(crate) fn chunk_len(n_out: usize, chunks: usize) -> Result<usize, TransformerError> {
    if n_out == 0 {
        return Err(TransformerError::ZeroDimension);
    }
    Ok(n_out.div_ceil(chunks.max(1)))
}
