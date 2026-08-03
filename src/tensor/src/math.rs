//! Soft-float elementary functions, because `core` does not have them.
//!
//! `core` exposes `f32::abs`, `is_finite`, `to_bits` and `from_bits`, but **not**
//! `sqrt`, `exp`, `ln`, `sin` or `cos` — those live in `std`, which a `#![no_std]`
//! crate does not have. BXW1 §0 forbids adding an external crate for a primitive
//! this small, so the five functions the kernels need are implemented here.
//!
//! Everything is computed in `f64` and rounded to `f32` at the boundary. That is
//! a deliberate accuracy-for-throughput trade and it is affordable because none
//! of these functions is on the bandwidth-bound path: RMSNorm calls [`rsqrt`]
//! once per row, RoPE calls [`powf`] and [`sin_cos`] once per dimension pair,
//! softmax and SiLU call [`exp`] once per element of a vector whose length is
//! `seq_len` or `d_ffn`. The matmuls, which move essentially the whole weight
//! set, call none of them.
//!
//! **Preconditions are the caller's.** These functions are total for every
//! input — no panic, no unbounded loop — but [`ln`] and [`rsqrt`] are only
//! *accurate* for positive normals, and [`sin_cos`] only for arguments bounded
//! by [`MAX_SIN_COS_ARG`]. Each kernel classifies its inputs by bit pattern
//! before calling, following BXW1 §4.7.

/// Largest argument for which [`sin_cos`]'s two-term argument reduction is
/// exact.
///
/// `PIO2_HI` carries 33 significant bits, so `n × PIO2_HI` is exact only while
/// `n` fits in 20 bits. `n` is `x × 2/π`, so the bound on `x` is `2^20`.
/// [`crate::rope`] refuses a position that could exceed it rather than
/// returning a quietly wrong rotation, and re-exports this value as
/// [`crate::MAX_ROPE_POSITION`].
pub(crate) const MAX_SIN_COS_ARG: u32 = 1 << 20;

/// High part of `ln 2` — the leading 33 bits, so `k × LN2_HI` is exact.
const LN2_HI: f64 = 6.931_471_803_691_238e-1;

/// Low part of `ln 2`, carrying the bits `LN2_HI` dropped.
const LN2_LO: f64 = 1.908_214_929_270_587_7e-10;

/// Above this, `e^x` overflows `f64`.
const EXP_OVERFLOW: f64 = 709.0;

/// Below this, `e^x` is nearer zero than any normal `f64`. Returning `0.0`
/// rather than a subnormal costs nothing observable: every consumer rounds to
/// `f32`, whose smallest subnormal is `1.4e-45`.
const EXP_UNDERFLOW: f64 = -708.0;

/// Leading 33 bits of `π/2`. Chosen so `n × PIO2_HI` is exact for `|n| < 2^20`.
const PIO2_HI: f64 = 1.570_796_326_734_125_6;

/// `π/2 − PIO2_HI`, to full `f64` precision.
const PIO2_LO: f64 = 6.077_100_506_506_192e-11;

/// Mantissa field of an IEEE-754 binary64.
const F64_MANTISSA_MASK: u64 = 0x000f_ffff_ffff_ffff;

/// Exponent field of `1.0f64`, used to force a mantissa into `[1, 2)`.
const F64_ONE_EXPONENT: u64 = 0x3ff0_0000_0000_0000;

/// Exponent bias of an IEEE-754 binary64.
const F64_EXPONENT_BIAS: i64 = 1023;

/// [`F64_EXPONENT_BIAS`] less one, for the halved-mantissa branch of [`ln`].
/// Written as its own constant rather than as `BIAS - 1` because the workspace
/// denies `clippy::arithmetic_side_effects` and a checked subtraction here
/// would be noise.
const F64_EXPONENT_BIAS_MINUS_ONE: i64 = 1022;

/// Seed constant for the reciprocal-square-root Newton iteration — the `f64`
/// analogue of the well-known `0x5f37_59df`.
const RSQRT_SEED: u64 = 0x5fe6_eb50_c7b5_37a9;

/// Rounds to the nearest integer, halfway cases away from zero.
///
/// `core` has no `round`, and the `as` cast truncates toward zero, so the
/// half is added with the sign of the operand. The intermediate goes through
/// `i64` rather than staying in `f64` so the result is exactly an integer;
/// `as` saturates at the `i64` bounds rather than wrapping, and every caller
/// has already bounded its argument far below them.
fn round_to_nearest(value: f64) -> f64 {
    let biased = if value >= 0.0 {
        value + 0.5
    } else {
        value - 0.5
    };
    (biased as i64) as f64
}

/// `2^k`, built directly from the exponent field.
///
/// Returns `0.0` below the normal range and `+Inf` above it rather than
/// producing a nonsense exponent, so the function is total for every `i64`.
fn two_pow(k: i64) -> f64 {
    let biased = k.wrapping_add(F64_EXPONENT_BIAS);
    if biased <= 0 {
        return 0.0;
    }
    if biased >= 0x7ff {
        return f64::INFINITY;
    }
    f64::from_bits((biased as u64) << 52)
}

/// `e^r` for `|r| <= ln(2)/2`, by a degree-12 Taylor polynomial in Horner form.
///
/// The truncation error is `r^13/13!`, which at the interval's edge is
/// `5.6e-7 / 6.2e9 ≈ 9e-17` — below `f64`'s unit roundoff, so the polynomial is
/// not the limiting term in [`exp`]'s accuracy.
fn exp_poly(r: f64) -> f64 {
    const C2: f64 = 5.0e-1;
    const C3: f64 = 1.666_666_666_666_666_6e-1;
    const C4: f64 = 4.166_666_666_666_666_4e-2;
    const C5: f64 = 8.333_333_333_333_333e-3;
    const C6: f64 = 1.388_888_888_888_889e-3;
    const C7: f64 = 1.984_126_984_126_984e-4;
    const C8: f64 = 2.480_158_730_158_73e-5;
    const C9: f64 = 2.755_731_922_398_589_3e-6;
    const C10: f64 = 2.755_731_922_398_589e-7;
    const C11: f64 = 2.505_210_838_544_172e-8;
    const C12: f64 = 2.087_675_698_786_81e-9;
    const C13: f64 = 1.605_904_383_682_161_3e-10;

    let mut p = C13;
    p = p * r + C12;
    p = p * r + C11;
    p = p * r + C10;
    p = p * r + C9;
    p = p * r + C8;
    p = p * r + C7;
    p = p * r + C6;
    p = p * r + C5;
    p = p * r + C4;
    p = p * r + C3;
    p = p * r + C2;
    p = p * r + 1.0;
    p * r + 1.0
}

/// `e^x`.
///
/// Total for every input: NaN propagates, arguments outside the representable
/// range saturate to `+Inf` or `0.0`. Exact at zero — `exp(0.0) == 1.0` — which
/// [`crate::silu`] relies on for `silu(0) == 0`.
pub(crate) fn exp(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }
    if x >= EXP_OVERFLOW {
        return f64::INFINITY;
    }
    if x <= EXP_UNDERFLOW {
        return 0.0;
    }
    // Split x = k·ln2 + r with |r| <= ln2/2. The two-part ln2 keeps `k·ln2`
    // accurate to well beyond f64: `k · LN2_HI` is exact because LN2_HI has
    // 33 significant bits and |k| < 2^11.
    let kf = round_to_nearest(x * core::f64::consts::LOG2_E);
    let r = (x - kf * LN2_HI) - kf * LN2_LO;
    exp_poly(r) * two_pow(kf as i64)
}

/// `ln(x)` for `x` a positive normal.
///
/// Total for every input, but only *accurate* on its stated domain: zero,
/// negative, subnormal, and non-finite arguments produce an unspecified finite
/// or non-finite value rather than a panic. [`crate::rope`] classifies θ by bit
/// pattern before calling.
pub(crate) fn ln(x: f64) -> f64 {
    // Reciprocal odd integers, the atanh series `2(s + s³/3 + s⁵/5 + …)`.
    const A3: f64 = 3.333_333_333_333_333e-1;
    const A5: f64 = 2.0e-1;
    const A7: f64 = 1.428_571_428_571_428_5e-1;
    const A9: f64 = 1.111_111_111_111_111e-1;
    const A11: f64 = 9.090_909_090_909_091e-2;
    const A13: f64 = 7.692_307_692_307_693e-2;
    const A15: f64 = 6.666_666_666_666_667e-2;
    const A17: f64 = 5.882_352_941_176_471e-2;
    const A19: f64 = 5.263_157_894_736_842e-2;
    const A21: f64 = 4.761_904_761_904_762e-2;

    let bits = x.to_bits();
    let raw_exponent = ((bits >> 52) & 0x7ff) as i64;
    let mantissa = f64::from_bits((bits & F64_MANTISSA_MASK) | F64_ONE_EXPONENT);

    // Fold the mantissa into [1/√2, √2) so the series argument stays small.
    let (m, exponent) = if mantissa > core::f64::consts::SQRT_2 {
        (
            mantissa * 0.5,
            raw_exponent.wrapping_sub(F64_EXPONENT_BIAS_MINUS_ONE),
        )
    } else {
        (mantissa, raw_exponent.wrapping_sub(F64_EXPONENT_BIAS))
    };

    // |s| <= 0.1716 on that interval, so s^21/21 is below 1e-16.
    let s = (m - 1.0) / (m + 1.0);
    let s2 = s * s;
    let mut p = A21;
    p = p * s2 + A19;
    p = p * s2 + A17;
    p = p * s2 + A15;
    p = p * s2 + A13;
    p = p * s2 + A11;
    p = p * s2 + A9;
    p = p * s2 + A7;
    p = p * s2 + A5;
    p = p * s2 + A3;
    p = p * s2 + 1.0;
    let ln_mantissa = 2.0 * s * p;

    let e = exponent as f64;
    ln_mantissa + (e * LN2_HI + e * LN2_LO)
}

/// `base^exponent` for `base` a positive normal.
///
/// Only the positive-base case exists because it is the only case BraiNIX has:
/// RoPE's `θ^(−2i/rope_dim)` with θ validated positive. There is no negative
/// base, no integer-exponent fast path, and no special-case table, because
/// nothing needs one.
pub(crate) fn powf(base: f64, exponent: f64) -> f64 {
    if exponent == 0.0 {
        return 1.0;
    }
    exp(exponent * ln(base))
}

/// `1/sqrt(x)` for `x` a positive normal, by Newton–Raphson from a bit-pattern
/// seed.
///
/// The seed's relative error is about `3.4e-2` and each iteration squares it
/// (`e ← 1.5 e²`), so four iterations reach `f64` precision and the fifth is
/// margin. Returning the reciprocal square root directly, rather than
/// `1.0/sqrt(x)`, avoids a division on RMSNorm's per-row path.
pub(crate) fn rsqrt(x: f64) -> f64 {
    let mut y = f64::from_bits(RSQRT_SEED.wrapping_sub(x.to_bits() >> 1));
    let half = x * 0.5;
    y *= 1.5 - half * y * y;
    y *= 1.5 - half * y * y;
    y *= 1.5 - half * y * y;
    y *= 1.5 - half * y * y;
    y *= 1.5 - half * y * y;
    y
}

/// `sin(r)` for `|r| <= π/4`, degree-15 odd Taylor polynomial.
fn sin_poly(r: f64) -> f64 {
    const S3: f64 = -1.666_666_666_666_666_6e-1;
    const S5: f64 = 8.333_333_333_333_333e-3;
    const S7: f64 = -1.984_126_984_126_984e-4;
    const S9: f64 = 2.755_731_922_398_589_3e-6;
    const S11: f64 = -2.505_210_838_544_172e-8;
    const S13: f64 = 1.605_904_383_682_161_3e-10;
    const S15: f64 = -7.647_163_731_819_816e-13;

    let r2 = r * r;
    let mut p = S15;
    p = p * r2 + S13;
    p = p * r2 + S11;
    p = p * r2 + S9;
    p = p * r2 + S7;
    p = p * r2 + S5;
    p = p * r2 + S3;
    r + r * r2 * p
}

/// `cos(r)` for `|r| <= π/4`, degree-16 even Taylor polynomial.
fn cos_poly(r: f64) -> f64 {
    const C2: f64 = -5.0e-1;
    const C4: f64 = 4.166_666_666_666_666_4e-2;
    const C6: f64 = -1.388_888_888_888_889e-3;
    const C8: f64 = 2.480_158_730_158_73e-5;
    const C10: f64 = -2.755_731_922_398_589e-7;
    const C12: f64 = 2.087_675_698_786_81e-9;
    const C14: f64 = -1.147_074_559_772_972_3e-11;
    const C16: f64 = 4.779_477_332_387_385e-14;

    let r2 = r * r;
    let mut p = C16;
    p = p * r2 + C14;
    p = p * r2 + C12;
    p = p * r2 + C10;
    p = p * r2 + C8;
    p = p * r2 + C6;
    p = p * r2 + C4;
    p = p * r2 + C2;
    1.0 + r2 * p
}

/// `(sin(x), cos(x))`, accurate for `|x| <= `[`MAX_SIN_COS_ARG`].
///
/// Both are produced together because RoPE always needs both, and the argument
/// reduction — the expensive part — is shared.
///
/// **Exact at zero:** `x == 0.0` gives `n == 0`, `r == 0.0`, and the
/// polynomials evaluate to exactly `(0.0, 1.0)`. That is what makes position 0
/// an exact identity rotation rather than an approximate one.
pub(crate) fn sin_cos(x: f64) -> (f64, f64) {
    let n = round_to_nearest(x * core::f64::consts::FRAC_2_PI);
    // Cody–Waite: `n · PIO2_HI` is exact, and `n · PIO2_LO` carries the rest.
    let r = (x - n * PIO2_HI) - n * PIO2_LO;
    let s = sin_poly(r);
    let c = cos_poly(r);
    // Two's complement makes this the correct quadrant for negative n too.
    match (n as i64) & 3 {
        0 => (s, c),
        1 => (c, -s),
        2 => (-s, -c),
        _ => (-c, s),
    }
}

#[cfg(test)]
mod tests {
    use super::{exp, ln, powf, rsqrt, sin_cos, MAX_SIN_COS_ARG};

    /// Deterministic xorshift64\* — the tests must not depend on a host RNG.
    struct Rng(u64);

    impl Rng {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        /// Uniform in `[low, high)`.
        fn next_range(&mut self, low: f64, high: f64) -> f64 {
            let unit = (self.next_u64() >> 11) as f64 * (1.0 / 9_007_199_254_740_992.0);
            low + unit * (high - low)
        }
    }

    fn relative_error(actual: f64, reference: f64) -> f64 {
        if reference == 0.0 {
            return actual.abs();
        }
        ((actual - reference) / reference).abs()
    }

    #[test]
    fn exp_matches_std_over_the_useful_range() {
        let mut rng = Rng(0x1234_5678_9abc_def0);
        let mut worst = 0.0_f64;
        for _ in 0..20_000 {
            let x = rng.next_range(-100.0, 100.0);
            worst = worst.max(relative_error(exp(x), x.exp()));
        }
        assert!(worst < 1e-14, "worst relative error {worst}");
    }

    #[test]
    fn exp_is_exact_at_zero_and_saturates_at_the_extremes() {
        assert_eq!(exp(0.0), 1.0);
        assert_eq!(exp(-1e9), 0.0);
        assert_eq!(exp(1e9), f64::INFINITY);
        assert!(exp(f64::NAN).is_nan());
    }

    #[test]
    fn ln_matches_std_across_many_binades() {
        let mut rng = Rng(0x0fed_cba9_8765_4321);
        let mut worst = 0.0_f64;
        for _ in 0..20_000 {
            let x = exp(rng.next_range(-200.0, 200.0));
            if x == 0.0 || !x.is_finite() {
                continue;
            }
            let error = (ln(x) - x.ln()).abs();
            worst = worst.max(error);
        }
        // Absolute, not relative: ln has a zero at x = 1 where relative error
        // is unbounded for any implementation.
        assert!(worst < 1e-13, "worst absolute error {worst}");
    }

    #[test]
    fn ln_is_exact_at_one() {
        assert_eq!(ln(1.0), 0.0);
    }

    #[test]
    fn powf_matches_std_on_the_rope_domain() {
        let mut rng = Rng(0xabcd_ef01_2345_6789);
        let mut worst = 0.0_f64;
        for _ in 0..20_000 {
            let base = rng.next_range(100.0, 1e8);
            let exponent = rng.next_range(-1.0, 0.0);
            worst = worst.max(relative_error(powf(base, exponent), base.powf(exponent)));
        }
        assert!(worst < 1e-13, "worst relative error {worst}");
        assert_eq!(powf(10_000.0, 0.0), 1.0);
    }

    #[test]
    fn rsqrt_matches_std_across_many_binades() {
        let mut rng = Rng(0x5555_aaaa_5555_aaaa);
        let mut worst = 0.0_f64;
        for _ in 0..20_000 {
            let x = exp(rng.next_range(-200.0, 200.0));
            if x == 0.0 || !x.is_finite() {
                continue;
            }
            worst = worst.max(relative_error(rsqrt(x), 1.0 / x.sqrt()));
        }
        assert!(worst < 1e-15, "worst relative error {worst}");
    }

    #[test]
    fn sin_cos_matches_std_up_to_the_stated_bound() {
        let mut rng = Rng(0x0123_4567_89ab_cdef);
        let mut worst = 0.0_f64;
        for _ in 0..40_000 {
            let bound = f64::from(MAX_SIN_COS_ARG);
            let x = rng.next_range(-bound, bound);
            let (s, c) = sin_cos(x);
            worst = worst.max((s - x.sin()).abs()).max((c - x.cos()).abs());
        }
        assert!(worst < 1e-12, "worst absolute error {worst}");
    }

    #[test]
    fn sin_cos_is_exact_at_zero() {
        assert_eq!(sin_cos(0.0), (0.0, 1.0));
    }

    #[test]
    fn sin_cos_is_norm_preserving() {
        let mut rng = Rng(0xfeed_face_dead_beef);
        for _ in 0..20_000 {
            let bound = f64::from(MAX_SIN_COS_ARG);
            let x = rng.next_range(-bound, bound);
            let (s, c) = sin_cos(x);
            assert!((s * s + c * c - 1.0).abs() < 1e-12);
        }
    }
}
