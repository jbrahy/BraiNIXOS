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

/// Single-core `Q8_0` weight-byte throughput, in bytes per microsecond.
///
/// 47 GB/s, measured by `benches/matmul.rs` on an M2 Pro performance core and
/// stable across the shapes a decode uses. It appears here as bytes per
/// microsecond so [`split_threshold_bytes`] needs no floating point: 47 GB/s is
/// 47000 bytes/us.
pub const SINGLE_CORE_BYTES_PER_MICROSECOND: usize = 47_000;

/// The smallest work worth splitting, from a dispatcher's own round trip.
///
/// # Why this is a function and not a constant
///
/// [`Dispatch::minimum_split_bytes`] documents the rule
/// `round_trip x rate / (1 - 1/w)` and then every implementation has to apply
/// it by hand, which means every implementation carries a number fitted to
/// whatever machine its author measured. The numbers in this crate's history
/// were fitted to a laptop whose pooled round trip is about 26 us; the
/// kernel's own is about 2 us, an order of magnitude apart, and a dispatcher
/// that inherits the wrong one either splits work too small to pay or leaves
/// nearly every projection unsplit.
///
/// A dispatcher knows its own round trip -- it can time its barrier pair once
/// at construction. Given that, this computes the threshold, and the constant
/// stops being a property of the machine the code was written on.
///
/// # The arithmetic
///
/// Splitting `bytes` across `w` workers saves `(bytes / rate) x (1 - 1/w)` and
/// costs one round trip, so the crossover is where those are equal:
///
/// ```text
/// bytes = round_trip x rate x w / (w - 1)
/// ```
///
/// `w / (w - 1)` rather than `1 / (1 - 1/w)` because they are the same number
/// and the first one divides integers exactly once.
///
/// # Measured against the sweep it replaces
///
/// `benches/matmul.rs` sweeps the real crossover by doubling. On this host:
///
/// | workers | round trip | measured crossover | this function |
/// | --- | --- | --- | --- |
/// | 2 | 8.45 us | 1152 KB | 734 KB |
/// | 4 | 25.83 us | 2304 KB | 1530 KB |
///
/// Both **under-predict by about 1.5x**, consistently. The model counts only
/// the weight bytes and ignores the activation read and the output write, so
/// it thinks a split saves more than it does.
///
/// Erring low is the right direction and the measurements say by how much.
/// Splitting slightly-too-small work costs a few percent -- the `>= 512 KB`
/// row against `>= 2 MB` in `attention`'s note. Leaving whole projections
/// serial costs 1.37x. A caller that wants the measured crossover rather than
/// the conservative one can multiply by 3/2; the default here is the one whose
/// failure mode is cheap.
///
/// # Examples
///
/// ```
/// # use brainix_transformer::dispatch::split_threshold_bytes;
/// // A pooled dispatcher that timed its barrier pair at 26 us, four workers.
/// assert_eq!(split_threshold_bytes(26, 4), 1_629_333);
/// // The kernel's own IPI round trip is far cheaper, so it splits far more.
/// assert_eq!(split_threshold_bytes(2, 4), 125_333);
/// // One worker never splits, whatever the round trip.
/// assert_eq!(split_threshold_bytes(26, 1), usize::MAX);
/// ```
#[must_use]
pub const fn split_threshold_bytes(round_trip_microseconds: usize, workers: usize) -> usize {
    if workers <= 1 {
        // Nothing to split onto, so nothing is ever worth splitting. `MAX`
        // rather than 0: this is a threshold work must EXCEED, and 0 would
        // mean "split everything" -- the opposite.
        return usize::MAX;
    }
    let saved_fraction_denominator = match workers.checked_sub(1) {
        Some(value) => value,
        // COVERAGE-EXEMPT: `workers > 1` is guaranteed by the branch above, so
        // the subtraction cannot underflow. `checked_sub` because this is a
        // `const fn` on the crate's surface and a bare `-` here would be a
        // panic waiting for someone to relax the guard.
        None => return usize::MAX,
    };
    let cost = match round_trip_microseconds.checked_mul(SINGLE_CORE_BYTES_PER_MICROSECOND) {
        Some(value) => value,
        None => return usize::MAX,
    };
    let scaled = match cost.checked_mul(workers) {
        Some(value) => value,
        None => return usize::MAX,
    };
    match scaled.checked_div(saved_fraction_denominator) {
        Some(value) => value,
        // COVERAGE-EXEMPT: `workers > 1` above makes the divisor at least 1,
        // so this cannot divide by zero. `checked_div` rather than `/` because
        // the workspace denies bare arithmetic and a `const fn` on the crate's
        // surface should not carry a panic path for a future caller to find.
        None => usize::MAX,
    }
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
#[allow(clippy::expect_used, clippy::unwrap_used)]
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

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod threshold_tests {
    use super::{split_threshold_bytes, SINGLE_CORE_BYTES_PER_MICROSECOND};

    #[test]
    fn one_worker_never_splits_whatever_the_round_trip() {
        // `MAX` and not 0. This is a threshold work must EXCEED, so 0 would
        // mean "split everything" -- precisely backwards for a dispatcher with
        // nowhere to split onto.
        assert_eq!(split_threshold_bytes(0, 1), usize::MAX);
        assert_eq!(split_threshold_bytes(26, 1), usize::MAX);
        assert_eq!(split_threshold_bytes(usize::MAX, 0), usize::MAX);
    }

    #[test]
    fn the_threshold_is_the_round_trip_priced_in_weight_bytes() {
        // Two workers: half the work is moved, so the saving is bytes/2 and
        // the crossover is twice what one round trip costs.
        let round_trip = 8;
        assert_eq!(
            split_threshold_bytes(round_trip, 2),
            round_trip * SINGLE_CORE_BYTES_PER_MICROSECOND * 2
        );

        // Four workers save three quarters, so the crossover is 4/3 of the
        // cost -- lower than at two, which is the direction that matters: more
        // workers make more work worth splitting, not less.
        assert!(split_threshold_bytes(8, 4) < split_threshold_bytes(8, 2));
        assert!(split_threshold_bytes(8, 8) < split_threshold_bytes(8, 4));
    }

    #[test]
    fn a_cheaper_round_trip_splits_more_work() {
        // The whole reason this is a function. The host's pooled barrier is
        // ~26 us and the kernel's own IPI is ~2 us, so the same code splits
        // work an order of magnitude smaller on the target -- and a dispatcher
        // that inherited the host's constant would leave nearly every
        // projection in a decode unsplit.
        let host = split_threshold_bytes(26, 4);
        let target = split_threshold_bytes(2, 4);
        assert!(
            target * 10 < host,
            "26 us gives {host} and 2 us gives {target}; the ratio should track \
             the round trips"
        );
        assert_eq!(host, 1_629_333);
        assert_eq!(target, 125_333);
    }

    #[test]
    fn a_free_round_trip_makes_everything_worth_splitting() {
        // Not a real dispatcher, but the boundary the arithmetic has to hold
        // at: zero cost means no work is too small.
        assert_eq!(split_threshold_bytes(0, 4), 0);
        assert_eq!(split_threshold_bytes(0, 2), 0);
    }

    #[test]
    fn an_absurd_round_trip_saturates_instead_of_wrapping() {
        // Caller-supplied, so the overflow guards are reachable from outside
        // and must refuse rather than wrap into a small threshold -- which
        // would silently turn "never split" into "split everything".
        assert_eq!(split_threshold_bytes(usize::MAX, 4), usize::MAX);
        assert_eq!(split_threshold_bytes(usize::MAX / 2, 4), usize::MAX);

        // Both multiplications, separately. The two above overflow on the
        // first one (round trip x rate); this one survives that and overflows
        // on the second (x workers), which is a different guard and was
        // unreached until the coverage gate said so.
        let survives_the_first = usize::MAX / SINGLE_CORE_BYTES_PER_MICROSECOND;
        assert!(survives_the_first
            .checked_mul(SINGLE_CORE_BYTES_PER_MICROSECOND)
            .is_some());
        assert_eq!(split_threshold_bytes(survives_the_first, 4), usize::MAX);
    }
}
