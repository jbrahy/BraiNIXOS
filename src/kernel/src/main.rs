//! Kernel binary entry point.
//!
//! Allowlist: `src/kernel/src/main.rs` — `_start` entry ABI and `hlt` in halt loops.
#![no_std]
#![no_main]
#![allow(unsafe_code)]

#[cfg(target_arch = "x86_64")]
use brainix_kernel::arch::interrupts::halt::disable_interrupts_and_halt;
#[cfg(target_arch = "x86_64")]
use brainix_kernel::boot::logger::BootStepLogger;
#[cfg(target_arch = "x86_64")]
use brainix_kernel::boot::phases::execute_boot_sequence;
#[cfg(target_arch = "x86_64")]
use brainix_kernel::boot::serial::SerialOutputPort;
#[cfg(target_arch = "x86_64")]
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
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    // SAFETY: eax contains the multiboot2 magic value (0x36D76289) and rbx
    // contains the multiboot2 info structure pointer, both placed by GRUB per
    // the multiboot2 specification (D-02, D-03). Must be captured before any
    // Rust prologue or function call that might clobber these registers.
    // - Precondition: GRUB has placed magic in eax, info pointer in rbx.
    // - Invariant: INV-BOOT-001 (boot parameters captured before use).
    // - Evidence: QEMU integration test observes multiboot2 validation log.
    // Allowlist: src/kernel/src/main.rs — inline assembly for register capture.
    let multiboot2_magic_value: u32;
    let multiboot2_info_address: u64;
    core::arch::asm!(
        "mov {:e}, eax",
        "mov {}, rbx",
        out(reg) multiboot2_magic_value,
        out(reg) multiboot2_info_address,
        options(nomem, nostack, preserves_flags),
    );
    let serial_output_port = SerialOutputPort::initialize();
    let mut boot_step_logger = BootStepLogger::new(serial_output_port);
    execute_boot_sequence(
        multiboot2_magic_value,
        multiboot2_info_address,
        &mut boot_step_logger,
    );
    // SAFETY: hlt suspends the processor until the next interrupt. The loop
    // ensures we never return to the bootloader if execute_boot_sequence exits.
    // Allowlist: src/kernel/src/main.rs — hlt in boot completion loop.
    loop {
        core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
    }
}

/// Kernel panic handler. Re-initializes serial and writes the panic location
/// before halting. Designed to work even if the boot sequence never completed.
#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "x86_64")]
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

// ===========================================================================
// aarch64 / Apple Silicon — AS-1c.
// ===========================================================================

/// Kernel entry on Apple Silicon.
///
/// # The ABI is different, and that is the point
///
/// The x86-64 entry above recovers multiboot2's magic from `eax` and its info
/// pointer from `rbx`, because GRUB put them there. Nothing of that exists
/// here: iBoot (or m1n1, chainloading) enters with a single argument in `x0`,
/// the pointer to `boot_args`. Sharing one `_start` between the two was never
/// possible, and pretending otherwise is how `asm!("cli")` ended up in an
/// aarch64 build.
///
/// # Why the console comes first
///
/// Before anything that can fail. On this hardware a kernel that dies before
/// its console is up is indistinguishable from one that never ran: the
/// framebuffer firmware hands a custom boot object is a dummy that is never
/// scanned out, so there is no second channel to fall back on. See
/// `docs/operations/FIRST_LIGHT_RUNBOOK.md` §9.
///
/// # Safety
///
/// `boot_args` must be the pointer firmware placed in `x0`. The MMU is off at
/// entry, so physical addresses are directly usable.
#[cfg(target_arch = "aarch64")]
#[no_mangle]
// Placed in `.text.boot`, which linker-aarch64.ld KEEPs first.
//
// Without this the linker is free to lay `_start` anywhere in `.text`, and it
// chose 0x58. A raw boot object is entered at **offset 0** of the flat image,
// so an image whose first instruction is not `_start` executes whatever
// function happened to be laid down first -- which on this platform fails with
// no output at all, and is indistinguishable from never running.
#[link_section = ".text.boot"]
pub unsafe extern "C" fn _start(boot_args: *const u8) -> ! {
    // SAFETY: the caller is firmware, which guarantees the `boot_args`
    // contract; a null pointer is handled inside.
    let mut console = unsafe { brainix_kernel::arch::aarch64::Console::from_boot_args(boot_args) };

    console.write_line("");
    console.write_line("[OK] BraiNIX kernel: aarch64 entry");

    console.write_bytes(b"     boot_args     0x");
    console.write_hex64(boot_args as usize as u64);
    console.write_line("");

    console.write_bytes(b"     exception lvl EL");
    console.write_hex64(u64::from(
        brainix_kernel::arch::aarch64::current_exception_level(),
    ));
    console.write_line("");

    // Said out loud rather than assumed. A console on the fallback constant
    // still prints, and a reader who cannot tell the two apart will trust an
    // address that was never confirmed against this machine's own tree.
    console.write_line(if console.resolved_from_adt() {
        "     console      dockchannel, resolved from the adt"
    } else {
        "     console      dockchannel, FALLBACK CONSTANT (adt discovery denied)"
    });

    brainix_kernel::arch::aarch64::park()
}

/// Panic handler on Apple Silicon.
///
/// Deliberately does **not** re-derive the console from `boot_args`: the
/// pointer is not available here, and a panic path that parses a device tree is
/// a panic path that can panic. The observed base is a measurement from this
/// machine, and a fixed marker with no formatting keeps a panic from becoming a
/// double fault.
#[cfg(target_arch = "aarch64")]
#[panic_handler]
fn handle_kernel_panic_aarch64(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: a null `boot_args` selects the observed fallback base and parses
    // nothing.
    let mut console = unsafe { brainix_kernel::arch::aarch64::Console::from_boot_args(core::ptr::null()) };
    console.write_line("");
    console.write_line("[PANIC] BraiNIX kernel panic -- system halted");
    brainix_kernel::arch::aarch64::park()
}
