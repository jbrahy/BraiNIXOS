//! HKDF-SHA256 (RFC 5869) — `Extract` and `Expand`, and nothing else.
//!
//! §5.2: "`HKDF` is RFC 5869 over SHA-256: `Extract(salt, ikm) =
//! HMAC-SHA256(salt, ikm)`, and `Expand(prk, info, L)` is the standard counter
//! mode. Every `L` below is a `const` and every `info` is a fixed-length byte
//! string, so no HKDF call in this protocol has an input whose length depends
//! on the wire."
//!
//! That property is enforced by the *types* here, not by discipline:
//! [`expand`] is generic over its output length, so `L` is a compile-time
//! constant at every call site by construction, and every `info` in
//! [`crate::schedule`] and [`crate::credential`] is a fixed-size array.
//!
//! In-tree for the reason [`crate::hmac`] gives: there is no vendored `hkdf`
//! and this task adds no dependency. Checked against RFC 5869's test cases in
//! `tests/known_answer.rs`.

use crate::hmac::{HmacSha256, HMAC_OUTPUT_BYTES};
use crate::secret::Secret;

/// `HKDF-Extract(salt, ikm) = HMAC-SHA256(salt, ikm)`.
///
/// The PRK is 32 bytes and is always a [`Secret`]: `PRK_enroll`, `PRK_id`,
/// `PRK_session`, and `PRK_step` are each material a compromise would care
/// about, and §5.2 and §6.1 name two of them in an explicit `zeroize`.
#[must_use]
pub fn extract(salt: &[u8], input_key_material: &[u8]) -> Secret<HMAC_OUTPUT_BYTES> {
    let mut state = HmacSha256::new(salt);
    state.update(input_key_material);
    Secret::from_bytes(state.finalize())
}

/// `HKDF-Expand(prk, info, N)` in RFC 5869's counter mode.
///
/// `N` is a const generic, which is how §5.2's "every `L` is a `const`" is
/// made structural. Every use in BSP v2 is `N ∈ {16, 32, 64}`, so the loop runs
/// at most twice and the one-byte counter is nowhere near RFC 5869's
/// `255 × HashLen` ceiling.
#[must_use]
pub fn expand<const N: usize>(
    pseudorandom_key: &Secret<HMAC_OUTPUT_BYTES>,
    info: &[u8],
) -> Secret<N> {
    let mut output = Secret::<N>::zero();
    let mut previous = Secret::<HMAC_OUTPUT_BYTES>::zero();
    let mut written = 0usize;
    let mut counter = 1u8;
    while written < N {
        previous = expand_block(pseudorandom_key, info, &previous, counter, written == 0);
        written = copy_block(output.expose_mut(), written, previous.expose());
        counter = counter.wrapping_add(1);
    }
    output
}

/// `T(i) = HMAC(PRK, T(i-1) || info || i)`, with `T(0)` the empty string.
///
/// `previous` is dropped — and therefore zeroized — by the caller's
/// reassignment on the next iteration.
fn expand_block(
    pseudorandom_key: &Secret<HMAC_OUTPUT_BYTES>,
    info: &[u8],
    previous: &Secret<HMAC_OUTPUT_BYTES>,
    counter: u8,
    is_first: bool,
) -> Secret<HMAC_OUTPUT_BYTES> {
    let mut state = HmacSha256::new(pseudorandom_key.expose());
    if !is_first {
        state.update(previous.expose());
    }
    state.update(info);
    state.update(&[counter]);
    Secret::from_bytes(state.finalize())
}

/// Copies as much of `block` as still fits, and returns the new write offset.
///
/// Every index is produced by `saturating_sub`/`saturating_add` and every slice
/// is taken through `get`/`get_mut`, so the function is total: it cannot panic
/// and it cannot write past `output`.
fn copy_block(output: &mut [u8], written: usize, block: &[u8; HMAC_OUTPUT_BYTES]) -> usize {
    let remaining = output.len().saturating_sub(written);
    let take = remaining.min(HMAC_OUTPUT_BYTES);
    let end = written.saturating_add(take);
    match (output.get_mut(written..end), block.get(..take)) {
        (Some(destination), Some(source)) => destination.copy_from_slice(source),
        // COVERAGE-EXEMPT: `take` is computed as min(remaining, HMAC_OUTPUT_BYTES) and `end` as written + take, so both slices are in range by construction. The arm keeps copy_block total rather than indexing.
        _ => return output.len(),
    }
    end
}
