//! Zeroing `.bss`.
//!
//! Raw pointer writes over a linker-defined region.
//! # Why this is not automatic
//!
//! A hosted program gets zeroed `.bss` from its loader. A raw boot object has
//! no loader: `objcopy -O binary` emits only sections with contents, so `.bss`
//! is *not in the image at all*, and whoever places the image in memory copies
//! only the bytes that exist. On the target this was measured as
//!
//! ```text
//! flat image ends   0x13F91
//! __bss_start       0x13FA0     past the end of the copied bytes
//! __bss_end         0x13FD8
//! ```
//!
//! so every `static` with a zero initialiser began life as whatever was already
//! in that memory. That is not a hypothetical: it produced exception-syndrome
//! readings that were unreproducible and unexplainable, and cost an evening.
//!
//! # Why it is separate from the entry point
//!
//! Because there are two entry points and both need it. `_start` is the boot
//! object's, and `kernel_probe` is called directly through m1n1's proxy without
//! ever passing through `_start`. A `zero_bss` hidden inside `_start` would
//! leave every proxy-verified measurement running on uninitialised statics --
//! which is precisely the configuration that misled us.

#![allow(unsafe_code)]

extern "C" {
    /// First byte of `.bss`, from the linker script.
    static mut __bss_start: u8;
    /// One past the last byte of `.bss`.
    static mut __bss_end: u8;
}

/// Zero `.bss`.
///
/// Idempotent, and cheap enough to call from every entry point rather than
/// reasoning about which one ran first.
///
/// # Safety
///
/// Must run before anything reads a `static`, and while nothing else is using
/// that memory. Both hold at an entry point, which is the only place this is
/// called from.
pub unsafe fn zero() {
    // SAFETY: both symbols are defined by the linker script and bracket a
    // region belonging solely to this image. `sub_ptr` is not used because the
    // symbols are `u8` statics rather than a slice, and their difference is the
    // region length by construction.
    unsafe {
        let start = core::ptr::addr_of_mut!(__bss_start);
        let end = core::ptr::addr_of_mut!(__bss_end);
        let length = (end as usize).saturating_sub(start as usize);
        core::ptr::write_bytes(start, 0, length);
    }
}

/// The `.bss` region, for reporting.
///
/// Exposed so a probe can show that the region it zeroed is the region the
/// linker actually placed, rather than trusting that the symbols resolved to
/// something sensible.
pub fn region() -> (u64, u64) {
    // SAFETY: taking addresses of linker-defined symbols; never dereferenced.
    unsafe {
        (
            core::ptr::addr_of!(__bss_start) as u64,
            core::ptr::addr_of!(__bss_end) as u64,
        )
    }
}
