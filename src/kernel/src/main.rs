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
/// `boot_args` must be the pointer firmware placed in `x0`, and the addresses
/// it yields must be directly dereferenceable. Entered from iBoot the MMU is
/// off; entered under m1n1 it is on with an identity mapping over the device
/// memory this touches (`SCTLR_EL1 = 0x30901185`, measured). See
/// `arch::aarch64::Console::from_boot_args`.
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
    // SAFETY: first thing at the entry point, before any `static` is read.
    unsafe { brainix_kernel::arch::aarch64::bss::zero() };

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

/// Magic returned by [`kernel_probe`].
#[cfg(target_arch = "aarch64")]
pub const KERNEL_PROBE_MAGIC: u64 = 0x4B72_6E6C_4E49_5802; // "Krnl NIX\x02"

/// Run the kernel's early decisions against real firmware and report them in
/// memory, touching no MMIO, then **return**.
///
/// # Why the kernel needs its own probe
///
/// `_start` above parks forever, which is right for a kernel and useless for
/// verification: chainloading it destroys m1n1, and on this rig the SBU serial
/// path delivers nothing, so a chainloaded kernel produces exactly the one bit
/// -- "it went quiet" -- that this project has repeatedly mistaken for a fault
/// in its own code.
///
/// `src/boot-stub-apple`'s `boot_stub_probe` proved this works and found a real
/// bug on its first run. This is the same technique applied one layer up, so
/// AS-1c closes on evidence rather than on a successful link.
///
/// # Report layout
///
/// | index | meaning |
/// | --- | --- |
/// | 0 | [`KERNEL_PROBE_MAGIC`] |
/// | 1 | current exception level |
/// | 2 | resolved console base |
/// | 3 | 1 if the base came from the ADT, 0 if it is the fallback constant |
///
/// # Safety
///
/// `boot_args` must be the firmware pointer, or null. `out` must have room for
/// four `u64`s.
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn kernel_probe(boot_args: *const u8, out: *mut u64) -> u64 {
    // Before anything reads a `static`. This entry point never passes through
    // `_start`, so without it every measurement here runs on whatever was in
    // that memory -- which is what made the first exception readings
    // unreproducible.
    //
    // SAFETY: at an entry point, nothing else is using this image's `.bss`.
    unsafe { brainix_kernel::arch::aarch64::bss::zero() };

    // SAFETY: the caller guarantees `out` has room for four `u64`s.
    let put = |index: usize, value: u64| unsafe { core::ptr::write_volatile(out.add(index), value) };

    put(0, KERNEL_PROBE_MAGIC);
    put(
        1,
        u64::from(brainix_kernel::arch::aarch64::current_exception_level()),
    );

    // SAFETY: the caller guarantees the `boot_args` contract; null is handled
    // inside, and `probe` resolves without constructing a driver or touching
    // MMIO, which matters because m1n1 is resident and hosting this call.
    let (base, from_adt) = unsafe { brainix_kernel::arch::aarch64::Console::probe(boot_args) };
    put(2, base);
    put(3, u64::from(from_adt));

    // AS-1b groundwork, all reads. `TCR_EL1` and `TTBR*_EL1` cannot be written
    // correctly without these, and a wrong translation configuration takes the
    // machine down before it can report why -- so they are measured first.
    use brainix_kernel::arch::aarch64::registers;
    put(4, registers::midr());
    put(5, registers::mpidr());
    put(6, registers::counter_frequency_hz());
    put(7, registers::sctlr_el1());
    put(8, registers::id_aa64mmfr0_el1());

    let model = brainix_kernel::arch::aarch64::memory_model();
    put(9, u64::from(model.physical_address_bits.unwrap_or(0)));
    put(
        10,
        u64::from(model.granule_4k) | (u64::from(model.granule_16k) << 1) | (u64::from(model.granule_64k) << 2),
    );
    put(11, u64::from(registers::el1_mmu_enabled()));

    // Exception vectors, proved by catching a fault rather than by installing
    // a table. An installed table that is never reached looks identical to a
    // working one until the first real fault, at which point the machine is
    // gone and there is nothing to read.
    //
    // SAFETY: `trap` is executed strictly inside `with_vectors`, which installs
    // a handler that advances past the `brk` and restores the previous
    // `VBAR_EL2` afterwards. Without that pairing this wedges the machine.
    let caught = unsafe {
        brainix_kernel::arch::aarch64::with_vectors(|| {
            brainix_kernel::arch::aarch64::vectors::trap();
            brainix_kernel::arch::aarch64::last_exception()
        })
    };
    put(12, caught.index);
    put(13, caught.esr);
    put(14, caught.count);
    put(15, caught.elr);
    put(16, caught.far);
    put(19, caught.spsr);
    // The cross-check: ESR_EL2 read *outside* the handler, after the trap.
    // Nothing clears it until the next exception, so if the handler reported
    // zero and this does not, the handler's read is at fault rather than the
    // hardware never recording it. Two readings of the same register beat any
    // amount of reasoning about which one ought to be right.
    put(18, registers::esr_el2());
    put(20, registers::elr_el2());
    let (bss_start, bss_end) = brainix_kernel::arch::aarch64::bss::region();
    put(21, bss_start);
    put(22, bss_end);
    // The address of the trap site, so ELR can be checked against it rather
    // than merely reported.
    put(17, brainix_kernel::arch::aarch64::vectors::table_address());

    KERNEL_PROBE_MAGIC
}

/// Keeps [`kernel_probe`] in the image; `#[no_mangle]` alone does not survive
/// LTO when nothing in the binary calls it.
#[cfg(target_arch = "aarch64")]
#[used]
static KERNEL_PROBE_KEEPALIVE: unsafe extern "C" fn(*const u8, *mut u64) -> u64 = kernel_probe;
