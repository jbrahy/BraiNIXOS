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

    // MMU: walk the LIVE tables and check the answer against the MMU's own.
    //
    // Nothing here writes a control register. Enabling translation is the one
    // operation on this machine that can fail with no way to report it, and
    // there is no reason to risk it before the walker is known correct. The
    // hardware is already running with translation on, which makes its tables a
    // free, fully populated test case and its `AT` instruction a free oracle.
    let tcr = registers::tcr_el2();
    let ttbr0 = registers::ttbr0_el2();
    put(23, tcr);
    put(24, ttbr0);

    // Translate this function's own address: guaranteed mapped, and if the
    // walker disagrees about the page it is executing from, it is wrong in the
    // least ambiguous way possible.
    let probe_va = kernel_probe as usize as u64;
    let par = registers::translate_el2_read(probe_va);
    put(25, probe_va);
    put(26, par);

    // Watchdog: locate it and check our answer against m1n1's own.
    //
    // Read-only. m1n1 printed "Primary WDT register @ 0x29e2c4000" on this
    // machine, so there is a known-good answer to check the ADT lookup
    // against before anything is ever written to that block -- and what would
    // be written to it is a reset command, so the wrong address is expensive.
    if !boot_args.is_null() {
        // SAFETY: firmware guarantees the structure; the read is bounded and
        // every field access inside it is bounds-checked by `brainix_adt`.
        let header = unsafe { core::slice::from_raw_parts(boot_args, 0x100) };
        if let Ok(window) = brainix_adt::adt_window(header) {
            // SAFETY: `adt_window` validated the range lies inside the DRAM
            // window firmware reported, is aligned, and does not overflow.
            let blob = unsafe {
                core::slice::from_raw_parts(
                    window.phys_addr as usize as *const u8,
                    window.len as usize,
                )
            };
            if let Some(wdt) = brainix_kernel::arch::aarch64::watchdog::locate(blob) {
                put(53, wdt);
                // SAFETY: a read of the control register; changes nothing.
                put(
                    54,
                    u64::from(unsafe { brainix_kernel::arch::aarch64::watchdog::control(wdt) }),
                );
            }
        }
    }

    // Can we even survive at EL1? Read-only pre-check, before any transition.
    //
    // Dropping to EL1 means instruction fetch uses EL1's translation regime.
    // If SCTLR_EL1.M is set and this address does not translate there, the
    // landing pad never executes and there is nothing left to report it. Three
    // conditions decide it: HCR_EL2.RW must select AArch64 for EL1, HCR_EL2.TGE
    // must be clear or EL1 is not really there, and the code must resolve.
    let hcr = registers::hcr_el2();
    put(48, hcr);
    put(49, registers::sctlr_el1());
    put(50, registers::tcr_el1());
    put(51, registers::ttbr0_el1());
    put(52, registers::translate_el1_read(probe_va));

    // CPU features. Reads only, and each gates something the kernel would
    // otherwise assume: using RNDR without FEAT_RNG raises an
    // undefined-instruction exception at the first call for entropy, during
    // early boot, before a console.
    let isar0 = registers::id_aa64isar0_el1();
    let isar1 = registers::id_aa64isar1_el1();
    let pfr1 = registers::id_aa64pfr1_el1();
    put(40, isar0);
    put(41, isar1);
    put(42, pfr1);

    let rng = brainix_kernel::aarch64_features::RandomSupport::from_isar0(isar0);
    let cf = brainix_kernel::aarch64_features::ControlFlowSupport::from_id_registers(isar1, pfr1);
    put(43, u64::from(rng.present));
    put(
        44,
        u64::from(cf.address_auth_qarma)
            | (u64::from(cf.address_auth_impdef) << 1)
            | (u64::from(cf.generic_auth_qarma) << 2)
            | (u64::from(cf.generic_auth_impdef) << 3)
            | (u64::from(cf.branch_target_identification) << 4),
    );

    if rng.present {
        // Two draws, so the report can show the source varies. One value
        // proves the instruction executed; two different ones begin to
        // suggest it is a generator rather than a constant.
        // SAFETY: guarded by the FEAT_RNG check immediately above.
        let first = unsafe { registers::random() };
        let second = unsafe { registers::random() };
        put(45, first.unwrap_or(0));
        put(46, second.unwrap_or(0));
        put(47, u64::from(first.is_some() && second.is_some()));
    }

    // Generic timer: arm a 1 ms countdown, masked, and see it fire.
    if let Some(timer) = brainix_kernel::arch::aarch64::Timer::current() {
        let one_millisecond = timer.frequency_hz() / 1000;
        // SAFETY: arms the physical timer with the interrupt masked, so the
        // condition fires and ISTATUS reports it without signalling anything.
        // The previous control value is restored before returning.
        let countdown = unsafe { timer.armed_countdown(one_millisecond, 50_000_000) };
        put(36, u64::from(countdown.fired));
        put(37, countdown.requested_ticks);
        put(38, countdown.elapsed_ticks);
        put(39, timer.ticks_to_micros(countdown.elapsed_ticks));
    }

    // Timer interrupt DELIVERY is NOT exercised here. See
    // `arch::aarch64::timer::wait_for_interrupt`: it was attempted on the
    // target and did not work, and running it corrupted the surrounding
    // measurements, so it stays out of the read-only probe until it is
    // understood.

    // Program TTBR0_EL2 with a table this image owns, and read through it.
    //
    // SAFETY: at EL2 with translation already on, and the installed root is a
    // copy of the live one, so every address that resolved before resolves
    // after -- including the instruction stream doing the switching. That
    // invariant is what makes this survivable; see `mmu::switch_to_copied_root`.
    let switch = unsafe { brainix_kernel::arch::aarch64::mmu::switch_to_copied_root(probe_va) };
    put(32, switch.original_root);
    put(33, switch.installed_root);
    put(34, switch.probe_value);
    put(35, switch.restored_root);

    if let Some(config) = brainix_kernel::aarch64_walk::WalkConfig::from_tcr(tcr) {
        put(27, u64::from(config.granule_bits));
        put(28, u64::from(config.levels()));
        // SAFETY: reading a descriptor from a physical address that the live
        // tables themselves point at. Translation is on with an identity
        // mapping over this memory (measured), so the physical address is
        // directly readable.
        let walked = brainix_kernel::aarch64_walk::walk(ttbr0, probe_va, config, |pa| unsafe {
            core::ptr::read_volatile(pa as usize as *const u64)
        });
        match walked {
            Ok(translation) => {
                put(29, translation.physical_address);
                put(30, translation.descriptor);
                put(31, u64::from(translation.level));
            }
            Err(_) => put(29, u64::MAX),
        }
    }
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

/// Arm the watchdog so the machine resets, and return.
///
/// # Why this is a separate entry point
///
/// `kernel_probe` is read-only by design and is run dozens of times; arming a
/// reset inside it would make every measurement cost a reboot. This is
/// deliberate, called on purpose, and named so that nobody invokes it by
/// accident.
///
/// # Why it exists at all
///
/// Two reasons. It proves the watchdog driver works, which nothing short of an
/// actual reset does. And it is the **signalling channel** for anything running
/// after m1n1 has been chainloaded away: this rig's SBU serial path delivers
/// nothing, the framebuffer given to a boot object is a dummy that is never
/// scanned out, and m1n1's USB gadget leaves with m1n1. A payload that reaches
/// a chosen point and arms the watchdog reports that point by *when the machine
/// reboots*, which the workstation sees as the USB port disappearing and coming
/// back. `BRINGUP_PLAN.md` named this fallback before there was any way to use
/// it.
///
/// Returns the watchdog base it armed, or 0 if it could not find one -- in
/// which case nothing was written and no reset is coming.
///
/// # Safety
///
/// Resets the machine. `boot_args` must be the firmware pointer.
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn kernel_watchdog_arm(boot_args: *const u8, alarm_ticks: u64) -> u64 {
    // SAFETY: first thing at an entry point, before any static is read.
    unsafe { brainix_kernel::arch::aarch64::bss::zero() };

    if boot_args.is_null() {
        return 0;
    }
    // SAFETY: as in kernel_probe.
    let header = unsafe { core::slice::from_raw_parts(boot_args, 0x100) };
    let Ok(window) = brainix_adt::adt_window(header) else {
        return 0;
    };
    // SAFETY: `adt_window` validated the range.
    let blob = unsafe {
        core::slice::from_raw_parts(window.phys_addr as usize as *const u8, window.len as usize)
    };
    let Some(base) = brainix_kernel::arch::aarch64::watchdog::locate(blob) else {
        return 0;
    };

    // SAFETY: `base` is the translated reg of /arm-io/wdt, verified against the
    // address m1n1 independently reported for this machine.
    unsafe {
        brainix_kernel::arch::aarch64::watchdog::arm_reset(
            base,
            u32::try_from(alarm_ticks).unwrap_or(u32::MAX),
        )
    };
    base
}

/// Keeps [`kernel_watchdog_arm`] in the image under LTO.
#[cfg(target_arch = "aarch64")]
#[used]
static WATCHDOG_ARM_KEEPALIVE: unsafe extern "C" fn(*const u8, u64) -> u64 = kernel_watchdog_arm;
