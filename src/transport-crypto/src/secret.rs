//! [`Secret`] — a fixed-size byte array that is zeroized on drop, compared in
//! constant time, and selected in constant time.
//!
//! Every value in this crate that a compromise would care about lives in one of
//! these: the enrolled key material, `PRK_enroll`, `K_id`, `PRK_id`, every chain
//! key `CK_n`, `PRK_step`, `PRK_session`, both confirmation values, and both
//! directional key sets.
//!
//! # Why this type exists rather than the `zeroize` crate
//!
//! `zeroize` is not vendored and this task adds no dependency
//! (`docs/NORTH_STAR.md`). The guarantee is reconstructed from three stable,
//! **safe** constructs, because the crate is `#![forbid(unsafe_code)]` and
//! `core::ptr::write_volatile` is not available to it:
//!
//! 1. the bytes are overwritten with zero;
//! 2. [`core::sync::atomic::compiler_fence`] with
//!    [`Ordering::SeqCst`](core::sync::atomic::Ordering::SeqCst) forbids the
//!    compiler from sinking that store past the fence;
//! 3. [`core::hint::black_box`] makes the buffer observably read *after* the
//!    store, so the store is not dead.
//!
//! This is the strongest guarantee available without `unsafe`, and the
//! substitution is recorded rather than glossed: it is an optimizer barrier,
//! not an architectural one. It does not evict a copy the compiler already
//! spilled to a register or a stack slot this type never named. `INV-MEM-006`
//! is satisfied for the storage this type owns.

use core::hint::black_box;
use core::sync::atomic::{compiler_fence, Ordering};

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// `N` bytes of key material, zeroized on drop.
///
/// Deliberately **not** `Copy`: a `Copy` secret is a secret with an unbounded
/// number of un-zeroized duplicates. [`Clone`] is provided because the key
/// schedule genuinely needs a second owned copy (a chain key resolved into
/// scratch, for instance), and every clone carries the same `Drop`.
///
/// Deliberately **not** [`core::fmt::Debug`], [`PartialEq`], or
/// [`core::fmt::Display`]: the first prints key material into an audit log, and
/// the second is a variable-time comparison with an inviting name. Use
/// [`Secret::ct_eq`].
#[derive(Clone)]
pub struct Secret<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> Secret<N> {
    /// An all-zero secret — the identity used before material is derived into
    /// it, and the state every [`Secret`] ends in.
    #[must_use]
    pub const fn zero() -> Self {
        Self { bytes: [0u8; N] }
    }

    /// Takes ownership of `bytes`.
    ///
    /// The caller's copy is moved, not borrowed; if the caller held it in a
    /// named array, zeroizing that array remains the caller's obligation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Borrows the material.
    ///
    /// Every use in this crate is an input to a hash, a cipher, or a
    /// constant-time comparison. Nothing copies it out into an unmanaged
    /// buffer.
    #[must_use]
    pub const fn expose(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Borrows the material mutably, so a derivation can write in place rather
    /// than build a second copy that would then need zeroizing too.
    pub const fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.bytes
    }

    /// Constant-time equality — the only comparison this type offers.
    ///
    /// Delegates to [`subtle::ConstantTimeEq`] for `[u8]`, which is the
    /// vendored implementation the rest of the tree already depends on
    /// (`curve25519-dalek`). The `bool` is produced by
    /// [`subtle::Choice::unwrap_u8`], so the branch the caller writes is on a
    /// value that took the same time to compute either way.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).unwrap_u8() == 1
    }

    /// Constant-time equality against a plain array — for comparing a derived
    /// confirmation value against one that arrived on the wire.
    #[must_use]
    pub fn ct_eq_bytes(&self, other: &[u8; N]) -> bool {
        self.bytes.ct_eq(other).unwrap_u8() == 1
    }

    /// Overwrites `self` with `source` when `choice` is set, and leaves it
    /// unchanged otherwise — **without branching on `choice`**.
    ///
    /// This is the accumulator of the §5.3 selector scan: the matching
    /// credential's material is selected into place without the loop ever
    /// taking a different path for the slot that matched.
    pub fn conditional_assign(&mut self, source: &Self, choice: Choice) {
        for (destination, candidate) in self.bytes.iter_mut().zip(source.bytes.iter()) {
            destination.conditional_assign(candidate, choice);
        }
    }

    /// Overwrites the material with zero and forbids the compiler from
    /// eliding the stores.
    ///
    /// Called by [`Drop`], and called **explicitly** at every point the
    /// specification names a zeroization — §5.2's destruction of the enrolled
    /// key material, §6.1's `zeroize(CK_n, PRK_step)`, and §9.4's teardown.
    pub fn zeroize(&mut self) {
        self.bytes.fill(0);
        compiler_fence(Ordering::SeqCst);
        let _ = black_box(&self.bytes);
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Constant-time equality for two byte arrays of the same length.
///
/// Used for the Poly1305 tag comparison, where neither side is a [`Secret`]:
/// the received tag is attacker-supplied and the computed tag is a public
/// function of key material rather than key material itself.
#[must_use]
pub fn constant_time_eq<const N: usize>(left: &[u8; N], right: &[u8; N]) -> bool {
    left.ct_eq(right).unwrap_u8() == 1
}
