//! The arithmetic, at the sizes the project actually cares about.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
#![allow(clippy::cognitive_complexity, clippy::float_cmp)]

use brainix_perf_baseline::{
    decode_ceiling, fraction_of_ceiling, Encoding, ModelSize, M2_PRO_BANDWIDTH_BYTES_PER_SECOND,
};

/// A seven-billion-weight model, the size the reference machine is sized for.
fn seven_billion(encoding: Encoding) -> ModelSize {
    ModelSize {
        weights: 7_000_000_000,
        encoding,
    }
}

#[test]
fn quantization_divides_the_ceiling_which_is_the_whole_argument_for_it() {
    let f16 = decode_ceiling(
        &seven_billion(Encoding::F16),
        M2_PRO_BANDWIDTH_BYTES_PER_SECOND,
    )
    .expect("a real model on a real machine");
    let q8 = decode_ceiling(
        &seven_billion(Encoding::Q8_0),
        M2_PRO_BANDWIDTH_BYTES_PER_SECOND,
    )
    .expect("a real model on a real machine");

    // 1.78x, not 2x. One byte per weight is half of f16's two, but a four-byte
    // scale per 32-element block adds 0.125 bytes per weight: 1.125 against
    // 2.0. This assertion said 2x when it was written, and failed, which is the
    // whole reason the model is written down rather than reasoned about.
    let ratio = q8.tokens_per_second / f16.tokens_per_second;
    assert!(ratio > 1.77, "Q8 buys {ratio:.3}x, expected about 1.78x");
    assert!(ratio < 1.79, "Q8 buys {ratio:.3}x, expected about 1.78x");
}

#[test]
fn the_ceiling_for_the_reference_machine_is_the_number_design_is_judged_against() {
    let ceiling = decode_ceiling(
        &seven_billion(Encoding::Q8_0),
        M2_PRO_BANDWIDTH_BYTES_PER_SECOND,
    )
    .expect("computable");

    // 7e9 weights + 7e9/32 four-byte scales = 7.875e9 bytes per token, so
    // 200 GB/s buys about 25 tokens per second and no more, whatever the
    // arithmetic does.
    assert_eq!(ceiling.bytes_per_token, 7_875_000_000);
    assert!(ceiling.tokens_per_second > 25.0);
    assert!(ceiling.tokens_per_second < 26.0);
}

#[test]
fn every_encoding_sizes_the_way_its_format_says() {
    assert_eq!(Encoding::F32.bytes_for(1_000), Some(4_000));
    assert_eq!(Encoding::F16.bytes_for(1_000), Some(2_000));
    // 1000 weights is 32 blocks after rounding the partial block up: 1000
    // bytes of weights plus 32 * 4 bytes of scales.
    assert_eq!(Encoding::Q8_0.bytes_for(1_000), Some(1_000 + 32 * 4));
    // A whole number of blocks needs no rounding.
    assert_eq!(Encoding::Q8_0.bytes_for(64), Some(64 + 2 * 4));
}

#[test]
fn a_size_that_cannot_be_computed_denies_rather_than_wrapping() {
    // A wrapped figure would put a plausible ceiling on an impossible model,
    // which is worse than no figure.
    assert_eq!(Encoding::F32.bytes_for(u64::MAX), None);
    assert_eq!(Encoding::F16.bytes_for(u64::MAX), None);
    assert_eq!(Encoding::Q8_0.bytes_for(u64::MAX), None);

    let impossible = ModelSize {
        weights: u64::MAX,
        encoding: Encoding::F32,
    };
    assert_eq!(impossible.bytes_per_token(), None);
    assert_eq!(
        decode_ceiling(&impossible, M2_PRO_BANDWIDTH_BYTES_PER_SECOND),
        None
    );
}

#[test]
fn a_zero_denominator_denies_rather_than_becoming_infinity() {
    // A denominator that silently becomes infinity is how a performance claim
    // stops being falsifiable.
    let model = seven_billion(Encoding::Q8_0);
    assert_eq!(decode_ceiling(&model, 0), None);

    let empty = ModelSize {
        weights: 0,
        encoding: Encoding::F32,
    };
    assert_eq!(
        decode_ceiling(&empty, M2_PRO_BANDWIDTH_BYTES_PER_SECOND),
        None
    );
}

#[test]
fn the_fraction_of_ceiling_is_what_distinguishes_two_kinds_of_slow() {
    let ceiling = decode_ceiling(
        &seven_billion(Encoding::Q8_0),
        M2_PRO_BANDWIDTH_BYTES_PER_SECOND,
    )
    .expect("computable");

    let bandwidth_bound =
        fraction_of_ceiling(ceiling.tokens_per_second * 0.6, &ceiling).expect("a positive ceiling");
    let something_else = fraction_of_ceiling(ceiling.tokens_per_second * 0.06, &ceiling)
        .expect("a positive ceiling");

    assert!((bandwidth_bound - 0.6).abs() < 1e-9);
    assert!((something_else - 0.06).abs() < 1e-9);
    // Ten times apart: one has a bandwidth problem worth 40%, the other has a
    // different problem, and without the ratio both are "some tokens/second".
    assert!(bandwidth_bound > something_else * 9.0);
}

#[test]
fn a_ceiling_that_is_not_positive_has_no_fraction() {
    let degenerate = brainix_perf_baseline::Ceiling {
        bytes_per_token: 1,
        bandwidth_bytes_per_second: 1,
        tokens_per_second: 0.0,
    };
    assert_eq!(fraction_of_ceiling(1.0, &degenerate), None);
}
