//! The row-split path, which no test had ever taken.
//!
//! # Why it was uncovered
//!
//! Every existing test builds its `Workspace` with `&mut []` for the quantized
//! activation scratch. An empty scratch selects the `f32`-activation kernel by
//! design, so the whole `Q8_0` branch in `weights.rs` -- quantize, view, decide
//! whether the work is worth splitting, split it -- was never entered.
//!
//! That is the branch a decode actually runs, and the one the multi-core work
//! is built on. It was the largest uncovered region left in the crate.
//!
//! # What is asserted
//!
//! That splitting changes nothing. Worker `k` writes its own slice of the
//! output and reads all of the activations, so the decomposition is supposed to
//! be exact -- not approximate, not tolerant. The comparison against the serial
//! `Q8_0` run is therefore for EQUALITY, and a chunking bug that dropped or
//! duplicated a row shows up immediately.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::arithmetic_side_effects
)]

mod common;

use brainix_tensor::RopePairing;
use brainix_transformer::{
    quantized_activation_bytes, session_cache_floats, workspace_floats, CacheGeometry, Dispatch,
    KeyValueArena, Model, Serial, Workspace,
};
use common::Fixture;

const MAXIMUM_BATCH: usize = 4;

/// A dispatcher that really splits, and runs the chunks in this thread.
///
/// Sequential execution is deliberate. The question here is whether the
/// DECOMPOSITION is right -- the chunk boundaries, the row offsets, the
/// threshold -- and threads would add a scheduling variable to a test about
/// arithmetic. `perplexity.rs` already exercises a threaded implementation.
struct Chunked {
    chunks: usize,
    minimum_bytes: usize,
}

impl Dispatch for Chunked {
    fn chunks(&self) -> usize {
        self.chunks
    }

    fn minimum_split_bytes(&self) -> usize {
        self.minimum_bytes
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

/// Decode `tokens` under `dispatch`, with a real quantized-activation scratch.
fn logits_under<D: Dispatch>(dispatch: &D, tokens: &[u32]) -> Vec<f32> {
    let fixture = Fixture::new(common::fixture_config(RopePairing::HalfSplit), 0xD15EA5E);
    let config = fixture.config;
    let layers = fixture.layer_views();
    let weights = fixture.weights(&layers);
    let model = Model::new(config, weights).unwrap();

    let mut workspace_storage = vec![0.0_f32; workspace_floats(&config, MAXIMUM_BATCH).unwrap()];
    // The whole point: a scratch that is NOT empty, which selects the Q8_0
    // activation kernel and makes the split branch reachable.
    let mut scratch = vec![0_u8; quantized_activation_bytes(&config, MAXIMUM_BATCH).unwrap()];
    let mut workspace =
        Workspace::new(&mut workspace_storage, &mut scratch, &config, MAXIMUM_BATCH).unwrap();

    let mut cache_storage = vec![0.0_f32; session_cache_floats(&config, 1).unwrap()];
    let mut arena = KeyValueArena::new(
        &mut cache_storage,
        CacheGeometry::for_config(&config).unwrap(),
    )
    .unwrap();
    let mut session = arena.issue_session().unwrap();

    let mut logits = vec![0.0_f32; config.vocabulary_size];
    model
        .forward(dispatch, &mut workspace, &mut session, tokens, &mut logits)
        .unwrap();
    logits
}

#[test]
fn splitting_the_work_does_not_change_the_answer() {
    let tokens = [1_u32];
    let serial = logits_under(&Serial, &tokens);

    for chunks in [2_usize, 3, 4, 8] {
        let split = logits_under(
            &Chunked {
                chunks,
                // Zero threshold: split everything, so even this small fixture
                // takes the branch. The threshold's own behaviour is the next
                // test.
                minimum_bytes: 0,
            },
            &tokens,
        );
        assert_eq!(
            split, serial,
            "{chunks} chunks disagreed with one, and a row split is supposed \
             to be exact rather than approximate"
        );
    }
}

#[test]
fn work_below_the_threshold_stays_on_the_calling_core() {
    let tokens = [2_u32];
    let serial = logits_under(&Serial, &tokens);

    // A threshold nothing in this fixture can exceed, so `worth_splitting` is
    // false and the split branch is skipped even though `chunks() > 1`. The
    // answer must be identical to the serial one, which is what makes the
    // threshold safe to tune: it is a performance knob and never a
    // correctness one.
    let unsplit = logits_under(
        &Chunked {
            chunks: 4,
            minimum_bytes: usize::MAX,
        },
        &tokens,
    );
    assert_eq!(unsplit, serial);
}

#[test]
fn a_single_chunk_dispatcher_matches_serial() {
    // `chunks() == 1` fails the `> 1` guard, so this is the serial path reached
    // through a non-Serial dispatcher -- the case a caller hits when its pool
    // has one worker.
    let tokens = [3_u32];
    let serial = logits_under(&Serial, &tokens);
    let one = logits_under(
        &Chunked {
            chunks: 1,
            minimum_bytes: 0,
        },
        &tokens,
    );
    assert_eq!(one, serial);
}

#[test]
fn a_multi_token_batch_is_token_split_and_the_answer_does_not_move() {
    // This test was named `prefill_stays_serial_even_when_the_dispatcher_would_split`
    // and its reasoning was that row-splitting is unsound for `n_tokens > 1` --
    // the output is `[n_tokens, n_out]` row-major, so a contiguous range of
    // output ROWS is not a contiguous range of the destination. That is still
    // true, and it was never a reason for prefill to stay serial. It is a
    // reason for prefill to split on the other axis.
    //
    // Token `t` owns `[t * n_out, ..)`, which IS contiguous, so a range of
    // tokens is a range of the destination. Since 2026-08-20 a multi-token
    // batch takes `matmul_q8_0_q8a_tokens` across the dispatcher's chunks.
    //
    // The assertion is unchanged and is the one that matters either way: the
    // split must reproduce the serial answer bit for bit, not approximately.
    // What changed is that it is now checking a decomposition that runs rather
    // than one that is declined.
    for chunks in [2_usize, 3, 4, 8] {
        let tokens = [1_u32, 2, 3];
        let serial = logits_under(&Serial, &tokens);
        let split = logits_under(
            &Chunked {
                chunks,
                minimum_bytes: 0,
            },
            &tokens,
        );
        assert_eq!(
            split, serial,
            "{chunks} chunks disagreed with one over a 3-token batch"
        );
    }
}

#[test]
fn a_prefill_below_the_threshold_stays_on_the_calling_core() {
    // The prefill threshold prices the arithmetic, which scales with the batch,
    // rather than the weight bytes, which do not. A ceiling nothing can reach
    // means the branch is declined and the serial kernel runs -- and the answer
    // is the same either way, which is the only thing observable from here.
    let tokens = [1_u32, 2, 3];
    let serial = logits_under(&Serial, &tokens);
    let unsplit = logits_under(
        &Chunked {
            chunks: 4,
            minimum_bytes: usize::MAX,
        },
        &tokens,
    );
    assert_eq!(
        unsplit, serial,
        "a prefill under the threshold must match the serial answer"
    );
}
