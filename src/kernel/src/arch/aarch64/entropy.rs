//! Reading the boot seed out of live memory, and erasing it.
//!
//! The parsing and the key derivation are in [`crate::aarch64_entropy`], where
//! they are pure functions over a slice and tested on the host against the real
//! tree. What is here is the part that cannot be: locating the device tree from
//! the firmware pointer, and **overwriting the seed once it has been used**.
//!
//! # Why erasing is not optional
//!
//! The seed is 64 bytes in ordinary DRAM, sitting inside a structure whose
//! address firmware advertises. Deriving keys from it and leaving it there
//! means the key material remains recoverable, in the clear, by anything that
//! can map that page, for the rest of the boot -- which on a machine whose whole
//! point is confining an assistant and an auditor is the wrong default. Erasing
//! makes the window the length of the boot path rather than the length of the
//! uptime.
//!
//! It is also what makes the seed **single-use**, which is the property that
//! stops two subsystems from independently deriving the same "unpredictable"
//! value because they both read the same place.

#![allow(unsafe_code)]

use crate::aarch64_entropy::{boot_seed, boot_seed_span, derive_pair, SeedQuality};
use brainix_adt::adt_window;

/// Bytes of `boot_args` needed to locate the device tree.
const BOOT_ARGS_PREFIX_LEN: usize = 256;

/// What was found where the boot seed should be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeedReport {
    /// Whether the property was found at all.
    pub present: bool,
    /// Its length, or zero.
    pub len: usize,
    /// Non-zero bytes in it.
    pub nonzero: usize,
    /// Distinct byte values in it.
    pub distinct: usize,
    /// Whether it passes [`SeedQuality::usable`].
    pub usable: bool,
    /// Its first eight bytes, so a reader can see it change between boots.
    ///
    /// Eight and not sixty-four, and this is a deliberate limit rather than a
    /// convenience: the report crosses a serial link and is printed. Enough to
    /// prove the value differs per boot, not enough to reconstruct the seed
    /// from a transcript.
    pub first_eight: u64,
    /// Whether the seed was erased after being read.
    pub erased: bool,
}

/// The device tree, as a slice, from the firmware `boot_args` pointer.
///
/// # Safety
///
/// `boot_args` must be the firmware pointer or null. The returned slice aliases
/// live firmware memory, so nothing else may be writing it.
unsafe fn device_tree<'a>(boot_args: *const u8) -> Option<&'a [u8]> {
    if boot_args.is_null() {
        return None;
    }
    // SAFETY: firmware guarantees the structure; every field access inside it
    // is bounds-checked by `brainix_adt`.
    let header = unsafe { core::slice::from_raw_parts(boot_args, BOOT_ARGS_PREFIX_LEN) };
    let window = adt_window(header).ok()?;
    // SAFETY: `adt_window` validated that this range lies entirely inside the
    // DRAM window firmware reported, is aligned, and does not overflow.
    Some(unsafe {
        core::slice::from_raw_parts(window.phys_addr as usize as *const u8, window.len as usize)
    })
}

/// Look at the boot seed without consuming it.
///
/// For measurement. The probe runs many times per boot and an erasing read
/// would make every run after the first report "no entropy" -- a measurement
/// that destroys what it measures is not one that can be repeated.
///
/// # Safety
///
/// As [`device_tree`].
pub unsafe fn peek(boot_args: *const u8) -> SeedReport {
    // SAFETY: the caller guarantees the `boot_args` contract.
    let Some(blob) = (unsafe { device_tree(boot_args) }) else {
        return SeedReport {
            present: false,
            len: 0,
            nonzero: 0,
            distinct: 0,
            usable: false,
            first_eight: 0,
            erased: false,
        };
    };
    let Some(seed) = boot_seed(blob) else {
        return SeedReport {
            present: false,
            len: 0,
            nonzero: 0,
            distinct: 0,
            usable: false,
            first_eight: 0,
            erased: false,
        };
    };
    let quality = SeedQuality::of(seed);
    let mut first = [0u8; 8];
    for (slot, byte) in first.iter_mut().zip(seed.iter()) {
        *slot = *byte;
    }
    SeedReport {
        present: true,
        len: quality.len,
        nonzero: quality.nonzero,
        distinct: quality.distinct,
        usable: quality.usable(),
        first_eight: u64::from_be_bytes(first),
        erased: false,
    }
}

/// Derive a key pair for `domain`, then **erase the seed**.
///
/// Returns `None` when there is no seed or it does not pass
/// [`SeedQuality::usable`]. That is the whole reason the check exists: a caller
/// that cannot tell a real seed from an unwritten buffer installs an all-zero
/// key and reports success, which is worse than installing no key at all,
/// because it looks like a mitigation.
///
/// # Erasing before returning
///
/// The seed is overwritten before this function returns, not by the caller
/// afterwards. A caller that forgets leaves key material in memory, and "the
/// caller must remember to" is how that ends up happening.
///
/// # Safety
///
/// As [`device_tree`], and this **writes** to firmware memory. The device tree
/// must not be in use by anything else, which holds during early boot.
pub unsafe fn consume(boot_args: *const u8, domain: &[u8]) -> Option<((u64, u64), SeedReport)> {
    // SAFETY: the caller guarantees the `boot_args` contract.
    let mut report = unsafe { peek(boot_args) };
    if !report.present || !report.usable {
        return None;
    }

    // SAFETY: as above.
    let blob = unsafe { device_tree(boot_args) }?;
    let seed = boot_seed(blob)?;
    let pair = derive_pair(seed, domain);
    let (offset, seed_bytes) = boot_seed_span(blob)?;

    // Erase. `write_volatile` because an ordinary write to memory that is never
    // read again is exactly what an optimiser is entitled to delete, and a
    // deleted erase is indistinguishable from a successful one until someone
    // dumps the page.
    let base = blob.as_ptr() as usize;
    for index in 0..seed_bytes {
        let Some(address) = base.checked_add(offset).and_then(|a| a.checked_add(index)) else {
            break;
        };
        // SAFETY: `boot_seed_span` derived this offset from a slice of `blob`,
        // so every address in the range lies inside the mapped device tree.
        unsafe { core::ptr::write_volatile(address as *mut u8, 0) };
    }
    report.erased = true;
    Some((pair, report))
}
