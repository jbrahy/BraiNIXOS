//! The kernel's console on Apple Silicon.
//!
//! # Why this is thin
//!
//! Every hard question here was already answered, on the machine, on
//! 2026-08-16, and the answers live in `src/boot-stub-apple/`:
//!
//! - the console is **DockChannel**, not the s5l UART, and a flawless s5l
//!   driver emits nothing a host can see (OQ-5, resolved);
//! - its `reg` must be translated through `/arm-io`'s `ranges`, and the
//!   translated value matches the address m1n1 printed live;
//! - `boot_args`' `devtree - virt_base` is **modular** arithmetic, because
//!   firmware hands a sign-extended kernel `virt_base` far above `devtree`.
//!
//! Re-deriving any of that here would be re-deriving it wrong. This module is
//! the seam that hands the kernel what the boot stub already proved, so the
//! difference between an aarch64 backend that has been *written* and one that
//! has been *run* is preserved.
//!
//! # What it does not do
//!
//! No allocation, no formatting machinery, no locking. A kernel console that
//! panics or blocks during early boot is worse than no console: it converts a
//! diagnosable fault into silence, which is the failure this whole platform
//! effort has been paying for.

//! Volatile MMIO and raw firmware pointers cannot be expressed safely; this
//! follows the same per-module allowlist the x86-64 siblings use (see
//! `arch/hardware_registers.rs`) rather than relaxing the crate-wide deny.
//! Every block below carries its precondition.
#![allow(unsafe_code)]

use brainix_adt::adt_window;
use brainix_boot_stub_apple::dockchannel::DockChannel;
use brainix_boot_stub_apple::registers::DOCKCHANNEL_BASE_OBSERVED;
use brainix_boot_stub_apple::uart::Mmio;
use brainix_boot_stub_apple::{console_from_adt, ConsoleChoice};

/// Largest `boot_args` prefix read. Only the fixed header is consumed.
const BOOT_ARGS_PREFIX_LEN: usize = 0x100;

/// A real MMIO window: volatile 32-bit accesses at a fixed physical base.
struct PhysicalMmio {
    base: *mut u32,
}

impl Mmio for PhysicalMmio {
    fn read_u32(&self, offset: usize) -> u32 {
        // SAFETY: `base` is a translated `reg` from the ADT (or the observed
        // constant), and `offset` is one of the DockChannel register offsets,
        // all inside the block the tree reports as 0x10004 bytes long.
        unsafe { core::ptr::read_volatile(self.base.byte_add(offset)) }
    }

    fn write_u32(&mut self, offset: usize, value: u32) {
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile(self.base.byte_add(offset), value) }
    }
}

/// The kernel's early console.
pub struct Console {
    inner: DockChannel<PhysicalMmio>,
    /// Where the base came from. Reported, never assumed.
    resolved_from_adt: bool,
}

impl Console {
    /// Bring up the console from the firmware's `boot_args` pointer.
    ///
    /// Falls back to [`DOCKCHANNEL_BASE_OBSERVED`] when the ADT cannot be
    /// reached, purely so that the failure itself is reportable. The fallback
    /// is a measurement from this exact machine rather than a guess, and
    /// [`Self::resolved_from_adt`] says which was used so nothing downstream
    /// can mistake one for the other.
    ///
    /// # Safety
    ///
    /// `boot_args` must be the pointer firmware placed in `x0` at entry, or
    /// null. The MMU must still be off, so physical addresses are usable
    /// directly.
    pub unsafe fn from_boot_args(boot_args: *const u8) -> Self {
        let base = unsafe { Self::resolve_base(boot_args) };
        Self {
            inner: DockChannel::new(PhysicalMmio {
                base: base.0 as usize as *mut u32,
            }),
            resolved_from_adt: base.1,
        }
    }

    /// Returns `(base, came_from_adt)`.
    ///
    /// # Safety
    ///
    /// As [`Self::from_boot_args`].
    unsafe fn resolve_base(boot_args: *const u8) -> (u64, bool) {
        if boot_args.is_null() {
            return (DOCKCHANNEL_BASE_OBSERVED, false);
        }
        // SAFETY: firmware guarantees the structure; the read is bounded and
        // every field access inside it is bounds-checked by `brainix_adt`.
        let header = unsafe { core::slice::from_raw_parts(boot_args, BOOT_ARGS_PREFIX_LEN) };

        let Ok(window) = adt_window(header) else {
            return (DOCKCHANNEL_BASE_OBSERVED, false);
        };
        // SAFETY: `adt_window` validated that this range lies entirely inside
        // the DRAM window firmware reported, is aligned, and does not overflow.
        let blob = unsafe {
            core::slice::from_raw_parts(window.phys_addr as usize as *const u8, window.len as usize)
        };

        match console_from_adt(blob) {
            // The s5l branch is deliberately *not* taken as a console here.
            // On this SoC it emits nothing, so selecting it would produce
            // silence that reads as "the kernel never started" -- the exact
            // ambiguity that cost this project two days. Better to drive the
            // peripheral that works and report that discovery disagreed.
            Ok(ConsoleChoice::DockChannel { base }) => (base, true),
            Ok(ConsoleChoice::S5lUart { .. }) | Err(_) => (DOCKCHANNEL_BASE_OBSERVED, false),
        }
    }

    /// Whether the base came from the ADT rather than the fallback constant.
    pub fn resolved_from_adt(&self) -> bool {
        self.resolved_from_adt
    }

    /// Write a line, translating `\n` to `\r\n`.
    pub fn write_line(&mut self, text: &str) {
        let _ = self.inner.write_line(text);
    }

    /// Write bytes with no terminator.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        let _ = self.inner.write_bytes(bytes);
    }

    /// Write `value` as 16 uppercase hex digits.
    pub fn write_hex64(&mut self, value: u64) {
        let _ = self.inner.write_hex64(value);
    }
}
