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

use brainix_adt::adt_window;
use brainix_boot_stub_apple::registers::UART_BASE_FALLBACK;
use brainix_boot_stub_apple::uart::{Mmio, Uart};
use brainix_boot_stub_apple::{bring_up, MmioFactory};

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
        let mut fallback = Uart::new(factory.window_at(UART_BASE_FALLBACK));
        fallback.write_str("\r\n[!!] BraiNIX: boot_args pointer is null\r\n");
        hang();
    }

    // SAFETY: the firmware guarantees a `boot_args` structure at this address,
    // and the prefix read is bounded by BOOT_ARGS_PREFIX_LEN. `adt_window`
    // bounds-checks every field access within the slice it is given.
    let boot_args_bytes = unsafe { core::slice::from_raw_parts(boot_args, BOOT_ARGS_PREFIX_LEN) };

    let window = match adt_window(boot_args_bytes) {
        Ok(window) => window,
        Err(_) => {
            let mut fallback = Uart::new(factory.window_at(UART_BASE_FALLBACK));
            fallback.write_str("\r\n[!!] BraiNIX: boot_args did not yield an adt window\r\n");
            hang();
        }
    };

    // SAFETY: `adt_window` has validated that this range lies entirely inside
    // the DRAM window the firmware reported, is 4-byte aligned, and does not
    // overflow. The MMU is off, so the physical address is directly readable.
    let adt_blob = unsafe {
        core::slice::from_raw_parts(window.phys_addr as usize as *const u8, window.len as usize)
    };

    let _outcome = bring_up(&mut factory, adt_blob);

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
    let mut fallback = Uart::new(factory.window_at(UART_BASE_FALLBACK));
    fallback.write_str("\r\n[!!] BraiNIX: panic in boot stub\r\n");
    hang()
}
