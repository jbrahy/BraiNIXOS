//! Kernel binary entry point.
//!
//! Allowlist: `src/kernel/src/main.rs` — `_start` entry ABI and `hlt` in halt loops.
#![no_std]
#![no_main]
#![allow(unsafe_code)]

use brainix_kernel::arch::interrupts::halt::disable_interrupts_and_halt;
use brainix_kernel::boot::logger::BootStepLogger;
use brainix_kernel::boot::phases::execute_boot_sequence;
use brainix_kernel::boot::serial::SerialOutputPort;
use core::fmt::Write;

/// Kernel entry point. Called by the bootloader after handoff to 64-bit mode.
///
/// Enforces invariant INV-BOOT-001: serial console is initialized before any
/// output is attempted.
///
/// # Safety
/// Called directly by the bootloader. The stack pointer must be valid.
// SAFETY: _start is the raw kernel entry point. The bootloader guarantees a
// valid stack. We initialize serial immediately before any Rust code that
// could panic.
// - Precondition: bootloader has placed the CPU in 64-bit long mode.
// - Invariant: INV-BOOT-001 (serial initialized before all other output).
// - Evidence: QEMU integration test observes serial output.
// Allowlist: src/kernel/src/main.rs — _start entry ABI.
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    let serial_output_port = SerialOutputPort::initialize();
    let mut boot_step_logger = BootStepLogger::new(serial_output_port);
    execute_boot_sequence(&mut boot_step_logger);
    // SAFETY: hlt suspends the processor until the next interrupt. The loop
    // ensures we never return to the bootloader if execute_boot_sequence exits.
    // Allowlist: src/kernel/src/main.rs — hlt in boot completion loop.
    loop {
        core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
    }
}

/// Kernel panic handler. Re-initializes serial and writes the panic location
/// before halting. Designed to work even if the boot sequence never completed.
#[panic_handler]
fn handle_kernel_panic(panic_information: &core::panic::PanicInfo) -> ! {
    let mut emergency_serial_port = SerialOutputPort::initialize();
    write_panic_banner(&mut emergency_serial_port);
    write_panic_details(&mut emergency_serial_port, panic_information);
    // Enforces INV-BOOT-003 (panic handler disables interrupts before halt) and
    // INV-FAULT-003 (fault paths halt with interrupts disabled). The shared helper
    // in arch::interrupts::halt issues cli then hlt in a loop.
    // Verified by: test_panic_handler_disables_interrupts_before_halt.
    disable_interrupts_and_halt()
}

fn write_panic_banner(serial_output_port: &mut SerialOutputPort) {
    let _ = writeln!(serial_output_port);
    let _ = writeln!(
        serial_output_port,
        "[PANIC] ========================================"
    );
    let _ = writeln!(serial_output_port, "[PANIC] KERNEL PANIC -- system halted");
    let _ = writeln!(
        serial_output_port,
        "[PANIC] ========================================"
    );
}

fn write_panic_details(
    serial_output_port: &mut SerialOutputPort,
    panic_information: &core::panic::PanicInfo,
) {
    let _ = writeln!(serial_output_port, "[PANIC] {}", panic_information);
    let _ = writeln!(
        serial_output_port,
        "[PANIC] Inspect serial output above for context"
    );
}
