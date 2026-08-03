//! Sampling: determinism where it is promised, bounds where they are declared,
//! and no entropy from anywhere but the caller.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cognitive_complexity
)]

use brainix_transformer::{
    sample, sampler_scratch_floats, Sampler, TransformerError, MAXIMUM_TOP_K,
};

/// A small logit vector with a clear ordering and one deliberate tie.
fn logits() -> Vec<f32> {
    vec![0.5, 2.0, -1.0, 2.0, 0.0, -3.0, 1.25, 0.75]
}

fn scratch(vocabulary_size: usize) -> Vec<f32> {
    vec![0.0_f32; sampler_scratch_floats(vocabulary_size).unwrap()]
}

// ------------------------------------------------------------------- greedy

#[test]
fn greedy_is_deterministic_and_ignores_the_deviate() {
    let values = logits();
    let mut buffer = scratch(values.len());
    let first = sample(&values, &mut buffer, Sampler::Greedy, 0.0).unwrap();
    for deviate in [0.0_f32, 0.25, 0.5, 0.999_999] {
        let token = sample(&values, &mut buffer, Sampler::Greedy, deviate).unwrap();
        assert_eq!(token, first);
    }
}

#[test]
fn greedy_breaks_ties_toward_the_lower_identifier() {
    // Indices 1 and 3 both hold 2.0, the maximum.
    let values = logits();
    let mut buffer = scratch(values.len());
    assert_eq!(
        sample(&values, &mut buffer, Sampler::Greedy, 0.5).unwrap(),
        1
    );
}

#[test]
fn greedy_refuses_a_non_finite_logit() {
    let mut values = logits();
    values[4] = f32::NAN;
    let mut buffer = scratch(values.len());
    assert_eq!(
        sample(&values, &mut buffer, Sampler::Greedy, 0.5),
        Err(TransformerError::NonFiniteLogits)
    );
}

// -------------------------------------------------------------- temperature

#[test]
fn a_deviate_of_zero_selects_the_first_token_with_positive_mass() {
    // Inverse-transform sampling at u = 0 lands in bucket 0, whatever the
    // temperature, because the first bucket's mass is strictly positive.
    let values = logits();
    let mut buffer = scratch(values.len());
    let sampler = Sampler::Temperature { temperature: 1.0 };
    assert_eq!(sample(&values, &mut buffer, sampler, 0.0).unwrap(), 0);
}

#[test]
fn a_deviate_near_one_selects_the_last_token() {
    let values = logits();
    let mut buffer = scratch(values.len());
    let sampler = Sampler::Temperature { temperature: 1.0 };
    let token = sample(&values, &mut buffer, sampler, 0.999_999).unwrap();
    assert_eq!(token as usize, values.len() - 1);
}

#[test]
fn a_very_low_temperature_collapses_onto_the_argmax() {
    let values = logits();
    let mut buffer = scratch(values.len());
    let sampler = Sampler::Temperature {
        temperature: 1.0e-3,
    };
    // With the distribution collapsed onto the two tied maxima at 1 and 3,
    // every deviate below one half must land on the lower of them.
    for deviate in [0.0_f32, 0.1, 0.4] {
        assert_eq!(sample(&values, &mut buffer, sampler, deviate).unwrap(), 1);
    }
}

#[test]
fn the_same_deviate_always_produces_the_same_token() {
    let values = logits();
    let mut buffer = scratch(values.len());
    let sampler = Sampler::Temperature { temperature: 0.8 };
    let first = sample(&values, &mut buffer, sampler, 0.37).unwrap();
    let second = sample(&values, &mut buffer, sampler, 0.37).unwrap();
    assert_eq!(first, second);
}

#[test]
fn temperature_must_be_a_positive_normal() {
    let values = logits();
    let mut buffer = scratch(values.len());
    for temperature in [0.0_f32, -1.0, f32::NAN, f32::INFINITY, -0.0] {
        let sampler = Sampler::Temperature { temperature };
        assert_eq!(
            sample(&values, &mut buffer, sampler, 0.5),
            Err(TransformerError::InvalidTemperature),
            "temperature {temperature} was accepted"
        );
    }
}

// -------------------------------------------------------------------- top-k

#[test]
fn top_one_is_greedy() {
    let values = logits();
    let mut buffer = scratch(values.len());
    let sampler = Sampler::TopK {
        temperature: 1.0,
        top_k: 1,
    };
    for deviate in [0.0_f32, 0.5, 0.999] {
        let token = sample(&values, &mut buffer, sampler, deviate).unwrap();
        assert_eq!(
            token,
            sample(&values, &mut buffer, Sampler::Greedy, 0.0).unwrap()
        );
    }
}

#[test]
fn top_k_never_selects_a_token_outside_the_k_most_probable() {
    let values = logits();
    let mut buffer = scratch(values.len());
    let sampler = Sampler::TopK {
        temperature: 1.0,
        top_k: 3,
    };
    // The three highest logits are at indices 1, 3 (both 2.0) and 6 (1.25).
    let permitted = [1_u32, 3, 6];
    for step in 0..1000 {
        let deviate = (step as f32) / 1000.0;
        let token = sample(&values, &mut buffer, sampler, deviate).unwrap();
        assert!(
            permitted.contains(&token),
            "deviate {deviate} produced token {token}, outside the top three"
        );
    }
}

#[test]
fn top_k_covers_every_selected_token_as_the_deviate_sweeps() {
    let values = logits();
    let mut buffer = scratch(values.len());
    let sampler = Sampler::TopK {
        temperature: 1.0,
        top_k: 3,
    };
    let mut seen = [false; 8];
    for step in 0..1000 {
        let token = sample(&values, &mut buffer, sampler, (step as f32) / 1000.0).unwrap();
        seen[token as usize] = true;
    }
    assert!(
        seen[1] && seen[3] && seen[6],
        "some selected token was unreachable"
    );
}

#[test]
fn top_k_must_be_within_its_declared_bounds() {
    let values = logits();
    let mut buffer = scratch(values.len());
    for top_k in [0_usize, values.len() + 1, MAXIMUM_TOP_K + 1] {
        let sampler = Sampler::TopK {
            temperature: 1.0,
            top_k,
        };
        assert_eq!(
            sample(&values, &mut buffer, sampler, 0.5),
            Err(TransformerError::InvalidTopK),
            "top_k {top_k} was accepted"
        );
    }
}

/// Top-`k` at `k = vocab_size` keeps the whole distribution's support.
///
/// It does **not** map deviates to the same tokens as
/// [`Sampler::Temperature`], and that is by construction rather than by
/// accident: top-`k` walks its cumulative distribution in descending
/// probability order and plain temperature walks it in token order. The two
/// therefore agree on *which tokens are reachable and with what mass*, not on
/// which deviate lands where. Asserting the support is the honest form of the
/// property; asserting token-for-token equality would be asserting an
/// implementation detail that is deliberately different.
#[test]
fn top_k_equal_to_the_vocabulary_keeps_the_whole_support() {
    let values = logits();
    let mut buffer = scratch(values.len());
    let full = Sampler::TopK {
        temperature: 0.9,
        top_k: values.len(),
    };
    let plain = Sampler::Temperature { temperature: 0.9 };
    let mut by_top_k = [false; 8];
    let mut by_temperature = [false; 8];
    for step in 0..2000 {
        let deviate = (step as f32) / 2000.0;
        by_top_k[sample(&values, &mut buffer, full, deviate).unwrap() as usize] = true;
        by_temperature[sample(&values, &mut buffer, plain, deviate).unwrap() as usize] = true;
    }
    assert_eq!(by_top_k, by_temperature);
    assert!(by_top_k.iter().all(|reached| *reached));
}

/// Top-`k` walks its cumulative distribution most-probable-first, so a deviate
/// of zero is the argmax — the same token greedy sampling returns.
#[test]
fn a_deviate_of_zero_under_top_k_is_the_argmax() {
    let values = logits();
    let mut buffer = scratch(values.len());
    let sampler = Sampler::TopK {
        temperature: 1.0,
        top_k: 4,
    };
    assert_eq!(
        sample(&values, &mut buffer, sampler, 0.0).unwrap(),
        sample(&values, &mut buffer, Sampler::Greedy, 0.0).unwrap()
    );
}

// ------------------------------------------------------------------- bounds

#[test]
fn the_deviate_must_lie_in_the_unit_interval() {
    let values = logits();
    let mut buffer = scratch(values.len());
    for deviate in [-0.001_f32, 1.0, 1.5, f32::NAN, f32::INFINITY] {
        assert_eq!(
            sample(&values, &mut buffer, Sampler::Greedy, deviate),
            Err(TransformerError::InvalidUniformDeviate),
            "deviate {deviate} was accepted"
        );
    }
}

#[test]
fn the_scratch_length_is_exact_in_both_directions() {
    let values = logits();
    for length in [
        0_usize,
        values.len(),
        values.len() * 2 - 1,
        values.len() * 2 + 1,
    ] {
        let mut buffer = vec![0.0_f32; length];
        assert_eq!(
            sample(&values, &mut buffer, Sampler::Greedy, 0.5),
            Err(TransformerError::SamplerScratchLengthMismatch),
            "scratch length {length} was accepted"
        );
    }
}

#[test]
fn an_empty_logit_vector_is_refused() {
    let mut buffer: Vec<f32> = Vec::new();
    assert_eq!(
        sample(&[], &mut buffer, Sampler::Greedy, 0.5),
        Err(TransformerError::LogitsLengthMismatch)
    );
}

#[test]
fn a_non_finite_logit_is_refused_on_the_temperature_path_too() {
    let mut values = logits();
    values[2] = f32::INFINITY;
    let mut buffer = scratch(values.len());
    let sampler = Sampler::Temperature { temperature: 1.0 };
    assert_eq!(
        sample(&values, &mut buffer, sampler, 0.5),
        Err(TransformerError::NonFiniteLogits)
    );
}

#[test]
fn the_scratch_size_is_two_rows_of_the_vocabulary() {
    assert_eq!(sampler_scratch_floats(32_000).unwrap(), 64_000);
    assert_eq!(
        sampler_scratch_floats(usize::MAX),
        Err(TransformerError::DimensionOverflow)
    );
}
