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
    /// # How to choose it, rather than guess it
    ///
    /// Splitting `bytes` across `w` workers saves `(bytes / rate) x (1 - 1/w)`
    /// and costs one synchronization round trip, so the crossover is
    ///
    /// ```text
    /// minimum_split_bytes ~= round_trip_cost x rate / (1 - 1/w)
    /// ```
    ///
    /// where `rate` is the single-core weight-byte throughput, about 47 GB/s
    /// for the `Q8_0` kernel on this class of machine.
    ///
    /// **The rule is measured, not derived and hoped for.**
    /// `benches/matmul.rs` sweeps the real crossover and compares:
    ///
    /// | workers | round trip | crossover measured | rule predicts |
    /// | --- | --- | --- | --- |
    /// | 2 | 6.8 us | 576 KB | 519 KB |
    /// | 4 | 18.0 us | between 1152 and 2304 KB | 1238 KB |
    ///
    /// The sweep doubles, so the 4-worker row brackets rather than pins it, and
    /// the prediction lands inside the bracket.
    ///
    /// # Confirmed against a whole model, 2026-08-19
    ///
    /// The table above is a per-kernel sweep. `examples/perplexity` runs the
    /// same thresholds through a complete forward pass, which is the thing that
    /// actually has to get faster.
    ///
    /// The host was busy -- load average 6.7, twelve cores -- so single runs
    /// were useless: one baseline fell from 225 to 136 tok/s between rounds.
    /// **Best-of-N fixes that**, because contention can only ever make a run
    /// slower, so the maximum over enough runs converges on the uncontended
    /// figure. Nine runs on the small model, five on the large one.
    ///
    /// Two synthetic models, because the first one gave the wrong answer:
    ///
    /// | threshold | 180 MB model | 900 MB model |
    /// | --- | --- | --- |
    /// | one core | 1.00x | 1.00x |
    /// | pool, never splits (control) | 1.01x | 0.96x |
    /// | split everything | 0.96x | 1.28x |
    /// | >= 512 KB | 0.96x | 1.28x |
    /// | >= 2 MB | **1.07x** | **1.37x** |
    /// | >= 4 MB | 1.01x | **1.38x** |
    ///
    /// `d_model` 1024 with `d_ffn` 2816 puts only the three FFN projections over
    /// the crossover; the four attention projections are 1 MB or less and stay
    /// serial whatever the threshold says. So the 180 MB column measures
    /// Amdahl's law, not the dispatcher. `d_model` 2048 with `d_ffn` 5632 puts
    /// every projection over it, and the win appears: **1.37x end to end on four
    /// workers.**
    ///
    /// Both columns agree on the thing the threshold is for. Splitting below the
    /// crossover is not merely neutral, it costs: 1.28x against 1.37x on the
    /// large model, a 7% loss for setting the number too low. A dispatcher that
    /// splits everything gives back a fifth of what splitting is worth.
    ///
    /// # What four workers do not do
    ///
    /// 1.37x, not 4x, and not the 1.68x to 1.90x that `measure_pool` gets on a
    /// single large matmul. The gap is everything that stays serial: `softmax`,
    /// `swiglu`, `rmsnorm` and every projection under the threshold. At the
    /// reference shape `benches/matmul.rs` puts the elementwise total at
    /// 11.95 ms/token, of which `softmax` alone is 9.44 ms.
    ///
    /// The next multiple is therefore not in this dispatcher. It is in making
    /// the serial remainder smaller or splitting it too.
    ///
    /// # Why this replaces a constant
    ///
    /// The perplexity harness carries 4 MB, swept once against a
    /// `std::sync::Barrier`. A dispatcher with a different round trip needs a
    /// different number, and the kernel's own is about **2 us** -- measured on
    /// the target, against roughly 30 us for a host barrier. Putting 2 us
    /// through the rule at four workers gives about **125 KB**, some thirty
    /// times smaller than the constant. A dispatcher that inherited 4 MB would
    /// leave nearly every projection in a decode unsplit.
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
