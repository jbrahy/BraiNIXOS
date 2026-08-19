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

    /// Smallest amount of work, in weight bytes, worth splitting.
    ///
    /// # Why a threshold exists at all
    ///
    /// Splitting costs a synchronization -- a barrier pair here, an IPI and a
    /// completion signal on the target -- and that cost is per *call*, not per
    /// byte. A projection smaller than the synchronization is slower split than
    /// left alone, and a decode makes 168 of them per token, so the loss is paid
    /// 168 times.
    ///
    /// The sizes are not close to each other. In the reference model a layer's
    /// `k` and `v` projections are ~0.15 MB apiece while `gate`, `up` and `down`
    /// are ~4.7 MB -- a factor of thirty. A single threshold cleanly separates
    /// them, which is why this is one number rather than a policy.
    ///
    /// Returning 0 splits everything, which is the old behaviour.
    fn minimum_split_bytes(&self) -> usize {
        0
    }

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

#[cfg(test)]
mod tests {
    use super::{chunk_len, Dispatch, Serial};
    use crate::error::TransformerError;

    /// `Serial` is what every existing test gets by default, and that is
    /// exactly why nothing exercised it: it is reached through `Model::forward`
    /// and never asked anything directly. The coverage gate found the whole
    /// impl uncovered.
    #[test]
    fn the_serial_dispatcher_reports_one_chunk_and_no_threshold() {
        let serial = Serial;
        assert_eq!(serial.chunks(), 1, "serial work is one chunk by definition");
        assert_eq!(
            serial.minimum_split_bytes(),
            0,
            "a dispatcher that cannot split has no size below which splitting is a loss"
        );
    }

    #[test]
    fn the_serial_dispatcher_visits_every_chunk_exactly_once_in_order() {
        let mut out = [0.0_f32; 7];
        let serial = Serial;
        // Deliberately not a divisor of the length: the last chunk is short,
        // which is the case a `chunks_mut` loop gets wrong if it assumes even
        // division.
        serial.for_each_chunk(&mut out, 3, |index, chunk| {
            for slot in chunk.iter_mut() {
                *slot = index as f32;
            }
        });
        assert_eq!(out, [0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 2.0]);
    }

    #[test]
    fn a_zero_chunk_length_does_not_hang() {
        // `chunks_mut(0)` panics, so the impl clamps to one. Without that this
        // is not a wrong answer, it is a process that never returns -- the
        // worst failure mode available to a kernel.
        // The closure is `Fn`, not `FnMut` -- it has to be, because a parallel
        // implementation shares it across threads -- so the counter is atomic
        // rather than captured by mutable reference.
        let mut out = [0.0_f32; 3];
        let visits = core::sync::atomic::AtomicUsize::new(0);
        Serial.for_each_chunk(&mut out, 0, |_, chunk| {
            assert_eq!(chunk.len(), 1);
            visits.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        });
        assert_eq!(
            visits.load(core::sync::atomic::Ordering::Relaxed),
            3,
            "a zero length must degrade to one element each"
        );
    }

    #[test]
    fn chunk_len_rounds_up_so_no_chunk_is_empty() {
        // Rounded DOWN, 10 outputs over 4 workers gives width 2 and a fifth
        // trailing chunk -- one more worker than asked for. Rounded up it is 3,
        // and the last chunk is the short one.
        assert_eq!(chunk_len(10, 4).expect("width"), 3);
        assert_eq!(chunk_len(8, 4).expect("width"), 2);
        assert_eq!(chunk_len(1, 4).expect("width"), 1);
    }

    #[test]
    fn chunk_len_treats_zero_chunks_as_one_rather_than_dividing_by_it() {
        assert_eq!(chunk_len(10, 0).expect("width"), 10);
    }

    #[test]
    fn chunk_len_denies_a_zero_output_width() {
        assert_eq!(
            chunk_len(0, 4).unwrap_err(),
            TransformerError::ZeroDimension,
            "no split of nothing is meaningful, and a zero here would become a \
             zero chunk length downstream"
        );
    }
}
