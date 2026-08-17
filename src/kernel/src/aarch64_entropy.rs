//! Where entropy comes from on a part that has no `RNDR`.
//!
//! # The problem this exists to solve
//!
//! `ID_AA64ISAR0_EL1 = 0x0221100110212120` on the M2 Pro: the `RNDR` field is
//! **zero**. There is no hardware random number generator to enable, so
//! everything that needs unpredictable bytes -- pointer authentication keys
//! first -- has nowhere to get them. Pointer authentication was enabled and
//! proven on this machine while still running on *firmware's* key, and that is
//! the gap this closes.
//!
//! # `/chosen/random-seed`
//!
//! iBoot leaves 64 bytes in the device tree at `/chosen/random-seed`. That it
//! exists proves nothing; what matters is whether it is fresh, and that was
//! measured rather than assumed. Four independent reads:
//!
//! | when | first eight bytes |
//! | --- | --- |
//! | captured fixture | `7558166c851e9572` |
//! | boot 1 | `3a182c6dcf382651` |
//! | boot 2 | `fdee395561310b24` |
//! | boot 3 | `4825d9b55323425a` |
//!
//! All different, all full-entropy-looking, 63 or 64 of 64 bytes non-zero. This
//! is a genuine per-boot seed.
//!
//! `/chosen/cl4-entropy` is the other candidate and is **192 bytes of zeros** on
//! this machine. It is named here so the next reader does not spend the same
//! hour on it.
//!
//! # Why the seed is hashed rather than used directly
//!
//! [`derive`] runs the seed through SHA-256 with a domain separator instead of
//! slicing bytes out of it. Two reasons, and neither is ceremony:
//!
//! - **Firmware bytes should not end up in a register as themselves.** The seed
//!   is supplied by code this kernel does not control and cannot audit. Hashing
//!   means a partial disclosure of a derived key says nothing about the seed,
//!   and a partially predictable seed still has to be inverted through SHA-256
//!   before it says anything about a key.
//! - **One seed, many consumers.** Pointer authentication needs five key pairs;
//!   stack canaries, ASLR and anything else will want more. Handing each of them
//!   a different slice of the same 64 bytes correlates them: recovering one
//!   reveals the seed material next to it. A domain separator gives each
//!   consumer a value that is independent of the others even though they share
//!   an origin.
//!
//! # Pure over bytes, on purpose
//!
//! Same split as `aarch64_devices`, `aarch64_walk` and `aarch64_tables`: the
//! parsing and the derivation are functions over a slice, so both are tested on
//! the host against the real tree read off the target. Reading that slice out of
//! live memory, and erasing it afterwards, is the hardware half and lives in
//! `arch::aarch64::entropy`.

use brainix_adt::DeviceTree;
use sha2::{Digest, Sha256};

/// Bytes iBoot leaves at `/chosen/random-seed`.
pub const BOOT_SEED_BYTES: usize = 64;

/// The boot seed, as a slice into `adt_blob`.
///
/// Returns `None` when the property is absent. It is deliberately **not**
/// rejected for being short or zero -- that is a judgement for
/// [`SeedQuality`], and a lookup that silently returns `None` for a seed that
/// is present but bad would report "no entropy source" for a condition that
/// needs a much louder answer.
pub fn boot_seed(adt_blob: &[u8]) -> Option<&[u8]> {
    let tree = DeviceTree::parse(adt_blob).ok()?;
    let chosen = tree.resolve(b"/chosen").ok()?;
    let property = chosen.node().find_property(b"random-seed").ok()??;
    Some(property.value())
}

/// Byte offset of the boot seed within `adt_blob`, and its length.
///
/// The address is what lets the caller **erase** the seed after using it. A
/// kernel that seeds itself and leaves the original in memory has published a
/// key-equivalent to everything that can map that page, for the rest of the
/// boot.
pub fn boot_seed_span(adt_blob: &[u8]) -> Option<(usize, usize)> {
    let seed = boot_seed(adt_blob)?;
    // Both slices come from the same allocation, so the difference of their
    // start addresses is the offset. Computed rather than tracked through the
    // parser, which would mean threading an offset through every accessor for
    // this one caller.
    let base = adt_blob.as_ptr() as usize;
    let start = seed.as_ptr() as usize;
    Some((start.checked_sub(base)?, seed.len()))
}

/// What the seed looks like, so a caller can refuse a bad one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeedQuality {
    /// Length of the property as found.
    pub len: usize,
    /// How many of its bytes are non-zero.
    pub nonzero: usize,
    /// How many distinct byte values it contains.
    ///
    /// A cheap smoke test, not a randomness test. It exists to catch the
    /// failure that actually happens -- a buffer that was never filled, or was
    /// filled with a repeating pattern -- rather than to make any claim about
    /// distribution. `cl4-entropy` on this machine is 192 bytes with exactly one
    /// distinct value, and that is the shape of the thing worth catching.
    pub distinct: usize,
}

impl SeedQuality {
    /// Measure `seed`.
    pub fn of(seed: &[u8]) -> Self {
        let mut seen = [false; 256];
        let mut nonzero = 0usize;
        let mut distinct = 0usize;
        for &byte in seed {
            if byte != 0 {
                nonzero = nonzero.saturating_add(1);
            }
            let slot = usize::from(byte);
            if let Some(flag) = seen.get_mut(slot) {
                if !*flag {
                    *flag = true;
                    distinct = distinct.saturating_add(1);
                }
            }
        }
        Self {
            len: seed.len(),
            nonzero,
            distinct,
        }
    }

    /// Whether this seed is fit to derive keys from.
    ///
    /// Deliberately a low bar, and deliberately not a randomness test: no test
    /// this cheap can distinguish a good seed from a bad one, and pretending
    /// otherwise would be worse than not checking. What it rules out is the
    /// failure that occurs in practice -- an absent, truncated or never-written
    /// buffer. `cl4-entropy` fails it; every observed `random-seed` passes.
    pub fn usable(&self) -> bool {
        self.len >= 32 && self.nonzero >= self.len / 2 && self.distinct >= 16
    }
}

/// Derive 32 bytes for `domain` from `seed`.
///
/// `domain` separates consumers: the same seed yields unrelated values for
/// `b"pac.apia"` and `b"pac.apib"`, so recovering one key says nothing about
/// the next. The length is mixed in as well, so a domain that is a prefix of
/// another cannot collide with it.
pub fn derive(seed: &[u8], domain: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BraiNIX/entropy/v1");
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    hasher.update((seed.len() as u64).to_le_bytes());
    hasher.update(seed);
    hasher.finalize().into()
}

/// Derive a pair of `u64`s for `domain`, for a register pair like an APIA key.
pub fn derive_pair(seed: &[u8], domain: &[u8]) -> (u64, u64) {
    let bytes = derive(seed, domain);
    let mut low = [0u8; 8];
    let mut high = [0u8; 8];
    low.copy_from_slice(bytes.get(0..8).unwrap_or(&[0; 8]));
    high.copy_from_slice(bytes.get(8..16).unwrap_or(&[0; 8]));
    (u64::from_le_bytes(low), u64::from_le_bytes(high))
}
