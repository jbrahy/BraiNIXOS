//! The bare-metal payload.
//!
//! This is the only file in the crate that cannot run on a host, and it is
//! deliberately the thinnest part: entry assembly, two volatile accessors, a
//! physical-memory slice, and a panic handler. Every decision lives in the
//! library, where it is tested.
//!
//! Built with:
//!
//! ```text
//! cargo build --target aarch64-unknown-none-softfloat --features bare-metal --release
//! ```

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::arch::global_asm;
use core::panic::PanicInfo;
use core::ptr;

use brainix_adt::{adt_window, framebuffer, Framebuffer};
use brainix_boot_stub_apple::dockchannel::DockChannel;
use brainix_boot_stub_apple::registers::DOCKCHANNEL_BASE_OBSERVED;
use brainix_boot_stub_apple::uart::Mmio;
use brainix_boot_stub_apple::{bring_up_console, progress, ConsoleOutcome, MmioFactory, Surface};

global_asm!(include_str!("start.S"));

/// A real MMIO window: volatile 32-bit accesses at a fixed physical base.
///
/// The MMU is off at entry (fact table §4), so a physical address is directly
/// usable as a pointer with no mapping step.
struct PhysicalMmio {
    base: *mut u32,
}

impl Mmio for PhysicalMmio {
    fn read_u32(&self, offset: usize) -> u32 {
        // SAFETY: `base` comes from either the ADT's translated `reg` or the
        // documented fallback constant, and `offset` is one of the two register
        // offsets in `registers`, both inside the UART's 0x4000-byte block.
        // The MMU is off, so the address is the physical register.
        unsafe { ptr::read_volatile(self.base.byte_add(offset)) }
    }

    fn write_u32(&mut self, offset: usize, value: u32) {
        // SAFETY: as above.
        unsafe { ptr::write_volatile(self.base.byte_add(offset), value) }
    }
}

/// Hands out [`PhysicalMmio`] windows.
struct PhysicalMmioFactory;

impl MmioFactory for PhysicalMmioFactory {
    type Window = PhysicalMmio;

    fn window_at(&mut self, base: u64) -> Self::Window {
        PhysicalMmio {
            base: base as usize as *mut u32,
        }
    }
}

/// The panel iBoot handed us, written directly.
///
/// The MMU is off at entry, so the framebuffer's physical address is usable
/// as a pointer with no mapping step -- the same property the UART path
/// relies on.
struct PhysicalSurface {
    base: *mut u8,
}

impl Surface for PhysicalSurface {
    fn put_u32(&mut self, byte_offset: u64, value: u32) {
        // SAFETY: every offset reaching here came from
        // `Framebuffer::pixel_offset`, which returns `None` outside the
        // visible area, and the framebuffer's span was checked for overflow
        // by `brainix_adt::framebuffer` before this surface was constructed.
        unsafe {
            ptr::write_volatile(
                self.base.byte_add(byte_offset as usize).cast::<u32>(),
                value,
            )
        }
    }
}

/// Paints `reached` stage stripes if firmware gave us a panel.
///
/// Silently does nothing when there is no framebuffer. That is the correct
/// behaviour rather than a fallback worth reporting: the UART path is
/// unaffected, and a headless machine has nothing to show.
fn show(panel: Option<Framebuffer>, reached: u64, denied: bool) {
    if let Some(fb) = panel {
        let mut surface = PhysicalSurface {
            base: fb.phys_addr as usize as *mut u8,
        };
        progress(&mut surface, &fb, reached, denied);
    }
}

/// Largest `boot_args` prefix read. Only the fixed header through
/// `devtree_size` is consumed; `cmdline` and beyond are never touched.
const BOOT_ARGS_PREFIX_LEN: usize = 0x100;

/// Rust entry, called from `start.S` with the `boot_args` pointer in `x0`.
///
/// # Safety
///
/// `boot_args` must be the pointer the firmware placed in `x0` at entry.
#[no_mangle]
pub unsafe extern "C" fn boot_stub_main(boot_args: *const u8) -> ! {
    let mut factory = PhysicalMmioFactory;

    if boot_args.is_null() {
        // Nothing to paint with: the panel's address lives in the structure
        // we do not have. Serial is the only channel left.
        let mut emergency = DockChannel::new(factory.window_at(DOCKCHANNEL_BASE_OBSERVED));
        emergency.write_line("[!!] BraiNIX: boot_args pointer is null");
        hang();
    }

    // SAFETY: the firmware guarantees a `boot_args` structure at this address,
    // and the prefix read is bounded by BOOT_ARGS_PREFIX_LEN. `adt_window`
    // bounds-checks every field access within the slice it is given.
    let boot_args_bytes = unsafe { core::slice::from_raw_parts(boot_args, BOOT_ARGS_PREFIX_LEN) };

    // Stage 1 -- we are executing, and firmware described a panel. This is the
    // stripe that answers the question the serial console could not: whether
    // any of our code runs at all (OQ-5).
    let panel = framebuffer(boot_args_bytes).ok();
    show(panel, 1, false);

    let window = match adt_window(boot_args_bytes) {
        Ok(window) => window,
        Err(_) => {
            show(panel, 2, true);
            let mut emergency = DockChannel::new(factory.window_at(DOCKCHANNEL_BASE_OBSERVED));
            emergency.write_line("[!!] BraiNIX: boot_args did not yield an adt window");
            hang();
        }
    };

    // Stage 2 -- the ADT window derived and passed every check.
    show(panel, 2, false);

    // SAFETY: `adt_window` has validated that this range lies entirely inside
    // the DRAM window the firmware reported, is 4-byte aligned, and does not
    // overflow. The MMU is off, so the physical address is directly readable.
    let adt_blob = unsafe {
        core::slice::from_raw_parts(window.phys_addr as usize as *const u8, window.len as usize)
    };

    let outcome = bring_up_console(&mut factory, adt_blob);

    // Stage 3 -- the ADT parsed and UART discovery ran. Red here means
    // discovery denied, and the serial console carries the reason if it is
    // reaching anyone.
    let denied = matches!(outcome, ConsoleOutcome::Denied(_));
    show(panel, 3, denied);

    hang()
}

/// Park the core. Never returns.
fn hang() -> ! {
    loop {
        // SAFETY: `wfe` is unprivileged and has no memory effects.
        unsafe { core::arch::asm!("wfe", options(nomem, nostack)) }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // The panic path cannot rely on the ADT having resolved, so it reports on
    // the fallback console. A fixed marker, no formatting: `core::fmt` in a
    // panic handler is how a panic becomes a double fault.
    let mut factory = PhysicalMmioFactory;
    let mut emergency = DockChannel::new(factory.window_at(DOCKCHANNEL_BASE_OBSERVED));
    emergency.write_line("[!!] BraiNIX: panic in boot stub");
    hang()
}
