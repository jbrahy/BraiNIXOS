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
/// The real entry point: four instructions of assembly that Rust cannot write.
///
/// # Why this exists, and why it did not before
///
/// The Rust function below was `_start` and was entered directly. Its compiled
/// prologue begins `sub sp, sp, #0x40` -- it *uses* the stack before anything
/// has set one. That was invisible for as long as the only way this kernel ever
/// ran was under m1n1, which enters payloads with a valid `sp` already
/// installed. Entered cold by iBoot, `sp` is whatever firmware left in it, and
/// the first instruction of the kernel writes through it.
///
/// So the entry point is assembly, exactly as `src/boot-stub-apple/src/start.S`
/// is, and for exactly the same reason. It sets `sp` from the linker's
/// `__stack_top` -- which the linker script has always emitted and nothing has
/// ever used -- and only then enters Rust.
///
/// Every address is PC-relative. The image is linked at 0 and iBoot loads it
/// wherever it likes, so an absolute reference would resolve to nothing.
///
/// Placed in `.text.boot`, which `linker-aarch64.ld` KEEPs first. A raw boot
/// object is entered at **offset 0** of the flat image, so whatever lands there
/// is what runs; the linker put a random function there once already.
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    r#"
.section .text.boot, "ax"
.globl _start
_start:
    // boot_args, into a callee-saved register, before anything can clobber it.
    mov  x19, x0
    // The stack the linker script reserves. 16-byte aligned by that script,
    // which the AArch64 ABI requires and which a misaligned `sp` punishes with
    // a fault on the first push rather than an obvious error.
    adrp x1, __stack_top
    add  x1, x1, :lo12:__stack_top
    mov  sp, x1
    mov  x0, x19
    bl   brainix_kernel_main
    // `brainix_kernel_main` is `-> !`. Reaching here means it returned anyway,
    // so spin rather than fall through into whatever bytes follow.
1:  wfe
    b 1b
"#
);

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn brainix_kernel_main(boot_args: *const u8) -> ! {
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

    // Say how far we got in the only language this machine currently speaks.
    //
    // Everything above writes to DockChannel, and on this rig DockChannel
    // delivers zero bytes at the host -- measured, and measured with m1n1's own
    // output too, so it is the path and not our driver. Parking here therefore
    // produces exactly one observable: the machine goes quiet, which is what a
    // crash on the first instruction also produces.
    //
    // So before parking, arm the watchdog. The machine then power-cycles on a
    // cadence *we* chose, which is observable from the workstation as the USB
    // device disappearing and coming back, and which nothing else on this
    // machine does. See `arch::aarch64::watchdog`.
    // SAFETY: the caller's `boot_args` contract; null is handled inside.
    let reached = unsafe { signal_progress(boot_args) };
    console.write_line(match reached {
        Progress::Silent => "     signal       NONE -- no watchdog, this boot is unobservable",
        Progress::Watchdog => "     signal       watchdog armed, 5s",
        Progress::Cpus => "     signal       cpu topology read, 9s",
        Progress::Pmgr => "     signal       pmgr located, 13s",
        Progress::Smp => "     signal       second cpu released, 17s",
        Progress::TablesBuilt => "     signal       own page tables built, 21s",
        Progress::Translating => "     signal       MMU AND CACHES ON, 25s",
    });

    brainix_kernel::arch::aarch64::park()
}

/// How far [`signal_progress`] got, which is what the reboot cadence encodes.
///
/// Each stage re-arms the watchdog for two seconds longer than the last, so the
/// interval between resets *is* the report. Reading it needs a stopwatch and
/// nothing else, which matters because on this machine there is nothing else.
#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Progress {
    /// No watchdog could be located, so this boot cannot report anything. The
    /// machine sits there, and sitting there is also what a kernel that faulted
    /// on its first instruction does.
    Silent,
    /// Device tree parsed and the watchdog found and armed. 5s.
    Watchdog,
    /// The CPU topology read out of the tree: more than one core described. 7s.
    Cpus,
    /// The PMGR block located and its CPU-start register base derived. 9s.
    ///
    /// Split from [`Progress::Smp`] because the first run of this ladder
    /// stopped at `Cpus` and two different failures produced that one interval:
    /// the PMGR lookup failing, and the core failing to start. One interval that
    /// means two things is the failure mode this whole scheme exists to avoid.
    Pmgr,
    /// A second CPU taken out of reset, which reported its own MPIDR back. 11s.
    Smp,
    /// Our own translation tables built, cold, into a `.bss` arena. 13s.
    ///
    /// Pure computation over a host-tested builder, so this rung failing would
    /// mean the geometry read out of `ID_AA64MMFR0_EL1` is one this builder
    /// refuses -- not that the hardware disagreed with us.
    TablesBuilt,
    /// The MMU and caches ON, under tables this kernel wrote. 15s.
    ///
    /// **This is the rung that makes a cold boot worth anything.** Measured
    /// earlier on this machine: a core reading memory with its caches off
    /// manages 0.09 GB/s against 11.4 GB/s with them on. A kernel that boots
    /// standalone and stays untranslated is 131x too slow to serve anything.
    Translating,
}

#[cfg(target_arch = "aarch64")]
impl Progress {
    /// Seconds this stage arms the watchdog for.
    ///
    /// Five, then **four** per rung.
    ///
    /// It was two, and two is not enough. Measured overhead between arming and
    /// the device leaving the bus ran from one second to three across runs, so
    /// a 13-second arm and a 15-second arm both produce a reset at +16 and the
    /// reading is ambiguous exactly where it matters most. Three consecutive
    /// runs decoded as two different rungs, which looked like a flaky kernel
    /// and was a flaky ruler.
    ///
    /// Four seconds is wider than any spread observed, so each rung owns a band
    /// nothing else can land in.
    const fn seconds(self) -> u64 {
        match self {
            Progress::Silent => 0,
            Progress::Watchdog => 5,
            Progress::Cpus => 9,
            Progress::Pmgr => 13,
            Progress::Smp => 17,
            Progress::TablesBuilt => 21,
            Progress::Translating => 25,
        }
    }
}

/// Locate the watchdog through firmware's tree and arm it.
///
/// # Why the counter frequency is used as the tick rate
///
/// It is a guess, and it is a *measuring* guess. If the watchdog counts at the
/// system counter's rate the machine cycles every five seconds; if it counts at
/// some other rate the period is wrong by exactly that ratio, and the observed
/// period divided by five is the watchdog's real clock. Either outcome is a
/// reading. Hardcoding a rate nobody has measured would turn a wrong guess into
/// a silent one.
///
/// # Safety
///
/// `boot_args` must be the pointer firmware placed in `x0`, or null. Arms a
/// hardware reset: the machine must be ours.
#[cfg(target_arch = "aarch64")]
unsafe fn signal_progress(boot_args: *const u8) -> Progress {
    if boot_args.is_null() {
        return Progress::Silent;
    }
    // SAFETY: firmware guarantees the structure; every field access inside is
    // bounds-checked by `brainix_adt`.
    let header = unsafe { core::slice::from_raw_parts(boot_args, 0x100) };
    let Ok(window) = brainix_adt::adt_window(header) else {
        return Progress::Silent;
    };
    // SAFETY: `adt_window` validated the range lies inside the DRAM window
    // firmware reported, is aligned, and does not overflow.
    let blob = unsafe {
        core::slice::from_raw_parts(window.phys_addr as usize as *const u8, window.len as usize)
    };
    let Some(base) = brainix_kernel::arch::aarch64::watchdog::locate(blob) else {
        return Progress::Silent;
    };

    // Arm before attempting anything, and re-arm after each stage succeeds.
    //
    // **The watchdog is the hang recovery as well as the signal, and that is
    // what makes this ladder safe to climb on a cold machine.** A stage that
    // wedges does not take the report with it: the previous stage's alarm is
    // already counting, so the machine still resets and still resets on that
    // stage's interval. What arrives is "it got this far and then stopped",
    // which is exactly the thing a payload with no output device otherwise
    // cannot say.
    let mut reached = Progress::Watchdog;
    // SAFETY: `base` is the translated `reg[0]` of `/arm-io/wdt`, resolved by
    // the same host-tested path the probe checks against this machine's own
    // tree. This resets the machine, which is the entire point.
    unsafe { rearm(base, reached) };

    // Stage 2: the CPU topology, which is pure parsing over the same blob and
    // touches no hardware at all.
    let mut cpus = [brainix_kernel::aarch64_cpus::Cpu::default(); 16];
    let found = brainix_kernel::aarch64_cpus::cpus(blob, &mut cpus);
    if found < 2 {
        return reached;
    }
    reached = Progress::Cpus;
    // SAFETY: as above.
    unsafe { rearm(base, reached) };

    // Stage 3: take a second core out of reset.
    //
    // This works on a cold machine for the reason it is interesting: the
    // secondary runs with its MMU off, which is the state it arrives in anyway,
    // so nothing here depends on a translation regime the boot core has not
    // built yet.
    let Some(pmgr) = brainix_kernel::aarch64_devices::translated_reg(blob, b"/arm-io/pmgr", 0)
    else {
        return reached;
    };
    let start_base = pmgr.wrapping_add(brainix_kernel::aarch64_cpus::CPU_START_OFFSET_T6020);
    reached = Progress::Pmgr;
    // SAFETY: as above.
    unsafe { rearm(base, reached) };

    let Some(target) =
        brainix_kernel::aarch64_cpus::first_waiting_cpu(cpus.get(..found).unwrap_or(&[]))
    else {
        return reached;
    };
    // A second of ticks. Bounded, because a core that never reports must not
    // take this one with it -- and here "taking it with it" would mean losing
    // the stage-2 reading that has already been armed.
    let timeout = brainix_kernel::arch::aarch64::registers::counter_frequency_hz();
    // SAFETY: `target` is a core the tree says is waiting, `start_base` came
    // from the ADT with its translation checked, and this core is running
    // under firmware's identity mapping so the secondary resolves the same
    // addresses with its MMU off.
    let released =
        unsafe { brainix_kernel::arch::aarch64::smp::release(&target, start_base, timeout) };
    if !released.started {
        return reached;
    }
    reached = Progress::Smp;
    // SAFETY: as above.
    unsafe { rearm(base, reached) };

    // Stage 4: our own translation, built and installed on a cold machine.
    //
    // Every other MMU path in this kernel reads `TCR_EL2` and `TTBR0_EL2` to
    // learn the geometry it should match, because under m1n1 there is already a
    // regime installed to match. Here there is not: those registers hold reset
    // values, and the configuration has to come from what the hardware says it
    // supports rather than from what firmware happened to choose.
    let model = brainix_kernel::arch::aarch64::memory_model();
    // 16 KiB, which is what this part prefers and what m1n1 itself uses. The
    // builder rejects 13 and 15, so a part that only offered those would fail
    // at the next line rather than silently building something unusable.
    let granule_bits = if model.granule_16k { 14 } else { 12 };
    // 48-bit input, which is what firmware itself configures.
    //
    // m1n1's live `TCR_EL2` on this machine reads 0x37510b510: T0SZ 16, so a
    // 48-bit VA; TG0 2, so a 16 KiB granule; IPS 3, so a 42-bit output. The
    // first version of this used the *physical* width for the input too, which
    // is a different number and produced a T0SZ the tables were not built for.
    // The output width still comes from `ID_AA64MMFR0_EL1`, because that is
    // what bounds a physical address.
    const INPUT_BITS: u32 = 48;
    let Some(pa_bits) = model.physical_address_bits else {
        return reached;
    };
    let input_bits = INPUT_BITS;

    // SAFETY: `_start` runs once, nothing else has a reference to the arena,
    // and the secondary released above does not touch it.
    let arena = unsafe { &mut *core::ptr::addr_of_mut!(TABLE_ARENA) };

    // **Align at run time. `#[repr(align)]` on the static is not enough.**
    //
    // That attribute aligns the arena within the image; it says nothing about
    // where the image itself lands. m1n1's `chainload.py` allocates with a bare
    // `u.malloc(image_size)` and iBoot promises nothing either, so `.bss` --
    // and the arena in it -- starts wherever the loader felt like. A root table
    // that is not granule-aligned is rejected by the builder, which is correct
    // and which presented here as the tables rung simply never arriving.
    //
    // `bin/as-kernel-probe.sh` already carries this scar: it aligns its load
    // address by hand because `u.malloc` does not. Depending on the loader for
    // it once was enough.
    let granule = 1u64 << granule_bits;
    let raw = arena.0.as_mut_ptr() as u64;
    let aligned = raw.next_multiple_of(granule);
    let skip_words = (aligned.saturating_sub(raw) / 8) as usize;
    let Some(cells) = arena.0.get_mut(skip_words..) else {
        return reached;
    };
    let Ok(mut builder) =
        brainix_kernel::aarch64_tables::TableBuilder::new(cells, aligned, granule_bits, input_bits)
    else {
        return reached;
    };

    // Identity-map what firmware says is there, rather than what this code
    // guessed. `boot_args` carries `phys_base` at 0x10 and `mem_size` at 0x18,
    // and the first version of this hardcoded 0x10_0000_0000 -- which is a real
    // Apple DRAM base and is not this machine's. Everything below the DRAM base
    // is MMIO on this architecture, so the split needs no second constant.
    let phys_base = read_u64(header, 0x10);
    let mem_size = read_u64(header, 0x18);
    if phys_base == 0 || mem_size == 0 {
        return reached;
    }

    let block = builder.block_size();

    // MMIO: a fixed low window, NOT everything below DRAM.
    //
    // Measured on this machine, `phys_base` is 0x10001020000 -- DRAM starts a
    // little past **one terabyte**. Mapping all of [0, phys_base) as Device is
    // 32768 block descriptors, which at 2048 blocks per table is sixteen leaf
    // tables, and it quietly exhausted the arena. Everything this kernel
    // actually touches is far lower: `/arm-io/pmgr` resolved to 0x28e080000,
    // about 11 GiB. Sixteen covers it with room and costs one table.
    const MMIO_WINDOW: u64 = 16 << 30;
    // Device rather than merely uncached: Device ordering is what keeps the
    // watchdog's three register writes in the order `arm_reset` issues them,
    // and a reordering that put the control write first would arm the alarm
    // against whatever the alarm register happened to hold.
    if builder.map_blocks(0, 0, MMIO_WINDOW, MMIO_ATTRS).is_err() {
        return reached;
    }

    // DRAM, rounded OUT to block boundaries at both ends.
    //
    // `phys_base` is not block-aligned on this machine -- it sits 0x1020000
    // above a 32 MiB boundary -- and `map_blocks` rejects a misaligned range
    // rather than silently rounding, which is the right call and means the
    // rounding has to happen here.
    let dram_start = phys_base & !block.wrapping_sub(1);
    let dram_end = phys_base.saturating_add(mem_size).next_multiple_of(block);
    let dram_len = dram_end.saturating_sub(dram_start);
    if dram_start < MMIO_WINDOW
        || builder
            .map_blocks(dram_start, dram_start, dram_len, DRAM_ATTRS)
            .is_err()
    {
        return reached;
    }
    let root = builder.root();

    // Push the tables out to memory before anything walks them.
    //
    // They were written with the caches OFF, so the stores went straight to
    // DRAM. The walker, once enabled, reads them with the *cacheable*
    // attributes `TCR_EL2.IRGN0`/`ORGN0` select -- and m1n1 ran with its caches
    // on over this same memory moments ago. A stale line surviving that is a
    // walk that reads a descriptor nobody wrote.
    //
    // This is the third appearance of the same bug in this file's history: the
    // secondary's report buffer and its stack both needed exactly this, and
    // both presented as something else entirely.
    let table_bytes = (builder.tables_used() as u64).saturating_mul(granule);
    // SAFETY: the arena is in this image and `table_bytes` covers only what the
    // builder actually used.
    unsafe { clean_range(aligned, table_bytes) };

    reached = Progress::TablesBuilt;
    // SAFETY: as above.
    unsafe { rearm(base, reached) };

    // SAFETY: `root` is a table this code just built, identity-mapping the DRAM
    // this image and its stack live in and the MMIO the watchdog lives in. If
    // any of that is wrong the core faults on its next fetch -- and the alarm
    // armed one line above is already counting, so the machine still reports
    // that it got exactly this far.
    unsafe { enable_translation(root, granule_bits, input_bits, pa_bits) };

    // Reached only if the core is still executing after the `isb`, which means
    // it fetched this instruction through tables this kernel wrote.
    reached = Progress::Translating;
    // SAFETY: as above. The watchdog block is mapped Device in those tables.
    unsafe { rearm(base, reached) };
    reached
}

/// Clean a range to the point of coherency, so a walker reading it cacheably
/// sees what was written to it non-cacheably.
///
/// # Safety
///
/// `start` must be mapped and `len` must not run past it.
#[cfg(target_arch = "aarch64")]
unsafe fn clean_range(start: u64, len: u64) {
    // 64-byte lines on this part. A smaller step is wasteful and safe; a larger
    // one skips lines, which is not.
    let mut address = start & !63;
    let end = start.saturating_add(len);
    while address < end {
        // SAFETY: cache maintenance by virtual address. Reads and writes
        // nothing, and cannot fault on a mapped address.
        unsafe {
            core::arch::asm!("dc civac, {addr}", addr = in(reg) address, options(nostack));
        }
        address = address.saturating_add(64);
    }
    // SAFETY: ordering the maintenance against the enable that follows.
    unsafe { core::arch::asm!("dsb sy", "isb", options(nostack)) };
}

/// Read a little-endian `u64` out of the `boot_args` prefix.
///
/// Returns 0 rather than panicking on a short buffer: this runs on a machine
/// with no output device, where a panic is silence and a zero is a value the
/// caller can test.
#[cfg(target_arch = "aarch64")]
fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let Some(window) = bytes.get(offset..offset.saturating_add(8)) else {
        return 0;
    };
    let mut buffer = [0u8; 8];
    buffer.copy_from_slice(window);
    u64::from_le_bytes(buffer)
}

/// Normal, inner-shareable, accessed. `AttrIndx = 0`.
///
/// Bit 10 is the access flag: without it the first touch takes an access-flag
/// fault, and on a core with no vector table that is indistinguishable from a
/// hang. Bits 9:8 are inner-shareable, which is what makes the second CPU's
/// view of this memory coherent with ours.
#[cfg(target_arch = "aarch64")]
const DRAM_ATTRS: u64 = (1 << 10) | (0b11 << 8);

/// Device-nGnRnE, accessed. `AttrIndx = 1`.
///
/// Not merely uncached: Device ordering is what keeps the watchdog's three
/// register writes in the order `arm_reset` issues them. Normal-uncacheable
/// would permit reordering the control write ahead of the alarm write, which
/// arms the watchdog against whatever the alarm register happened to hold.
#[cfg(target_arch = "aarch64")]
const MMIO_ATTRS: u64 = (1 << 10) | (1 << 2);

/// Arena the cold page tables are built in.
///
/// `.bss`. Sized with slack, not to the count.
///
/// The first attempt was 64 KiB, which at a 16 KiB granule is exactly four
/// tables -- and the arithmetic said four were needed: a root, one at the next
/// level, and one each for the level that holds DRAM's blocks and MMIO's. It
/// stopped one rung short of building them. Sizing an arena to the exact count
/// a hand calculation predicts means any error in that calculation presents as
/// a silent allocation failure, and on a machine with no output device that is
/// a rung that simply never arrives. 256 KiB is sixteen tables and costs
/// nothing that is not `.bss`.
#[cfg(target_arch = "aarch64")]
#[repr(align(16384))]
struct TableArena([u64; 32768]);

#[cfg(target_arch = "aarch64")]
static mut TABLE_ARENA: TableArena = TableArena([0; 32768]);

/// Install `root` and turn the MMU and caches on.
///
/// # Safety
///
/// `root` must identity-map this code, its stack, and any MMIO reached
/// afterwards. Getting that wrong faults on the next instruction fetch with no
/// vector table to catch it.
#[cfg(target_arch = "aarch64")]
unsafe fn enable_translation(root: u64, granule_bits: u32, input_bits: u32, pa_bits: u8) {
    // TG0 encoding is neither the granule size nor its log: 4 KiB is 0, 16 KiB
    // is 2, 64 KiB is 1. Ordered that way in the architecture, and writing the
    // obvious thing instead configures a granule the tables were not built for.
    let tg0: u64 = match granule_bits {
        14 => 0b10,
        16 => 0b01,
        _ => 0b00,
    };
    let t0sz = u64::from(64u32.saturating_sub(input_bits));
    // IPS is the *output* width and must not exceed what the part implements.
    // An earlier version pinned 0b101 (48-bit) on a part that reports 42, which
    // the architecture leaves CONSTRAINED UNPREDICTABLE.
    let ips: u64 = match pa_bits {
        32 => 0b000,
        36 => 0b001,
        40 => 0b010,
        42 => 0b011,
        44 => 0b100,
        52 => 0b110,
        _ => 0b101,
    };

    // **EL1 layout, because `HCR_EL2.E2H` stays set.**
    //
    // With E2H set, `TCR_EL2` takes the TCR_EL1 shape: IPS moves to bits 34:32,
    // and 18:16 become part of T1SZ. An earlier attempt cleared E2H so the
    // classic one-TTBR layout would apply. That is a bigger change than it
    // looks -- it moves the whole EL2 regime out from under firmware's
    // configuration -- and it did not work. Matching what is already there is
    // both smaller and closer to the state iBoot hands a boot object.
    //
    // EPD1 disables TTBR1 walks. Nothing here sets TTBR1, and leaving walks
    // enabled against whatever it holds is a translation of any high address
    // into a table that does not exist.
    const EPD1: u64 = 1 << 23;
    let tcr = t0sz | (0b01 << 8) | (0b01 << 10) | (0b11 << 12) | (tg0 << 14) | EPD1 | (ips << 32);
    // Attr0 Normal write-back read/write-allocate, Attr1 Device-nGnRnE.
    let mair: u64 = 0xFF;

    // SAFETY: installs a translation regime and enables it. Sound only under
    // this function's contract; unrecoverable if that contract is broken, which
    // is why the caller arms the watchdog first.
    unsafe {
        core::arch::asm!(
            "msr MAIR_EL2,  {mair}",
            "msr TCR_EL2,   {tcr}",
            "msr TTBR0_EL2, {root}",
            "isb",
            "tlbi alle2",
            "dsb sy",
            "isb",
            // Read-modify-write rather than a constant: SCTLR_EL2 holds bits
            // firmware set that this code has no business clearing.
            "mrs {tmp}, SCTLR_EL2",
            // M (translation), C (data cache), I (instruction cache).
            "orr {tmp}, {tmp}, #(1 << 0)",
            "orr {tmp}, {tmp}, #(1 << 2)",
            "orr {tmp}, {tmp}, #(1 << 12)",
            "msr SCTLR_EL2, {tmp}",
            "isb",
            mair = in(reg) mair,
            tcr = in(reg) tcr,
            root = in(reg) root,
            tmp = out(reg) _,
            options(nostack)
        );
    }
}

/// Re-arm the watchdog for `stage`'s interval, restarting its count.
///
/// # Why the counter frequency is used as the tick rate
///
/// It was a guess, and it was a *measuring* guess: a 5-second constant produced
/// a reset at +7s and a 15-second constant at +16s, so a ten-second change moved
/// the reset by ten seconds and the watchdog does count at the system counter's
/// rate. Measured by chainload on 2026-08-17.
///
/// # Safety
///
/// `base` must be the watchdog's translated register base. Resets the machine.
#[cfg(target_arch = "aarch64")]
unsafe fn rearm(base: u64, stage: Progress) {
    let ticks = brainix_kernel::arch::aarch64::registers::counter_frequency_hz()
        .saturating_mul(stage.seconds())
        .min(u64::from(u32::MAX)) as u32;
    // SAFETY: delegated to this function's contract. `arm_reset` writes the
    // alarm, then zeroes the count, so each call measures from now.
    unsafe { brainix_kernel::arch::aarch64::watchdog::arm_reset(base, ticks) };
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
    let mut console =
        unsafe { brainix_kernel::arch::aarch64::Console::from_boot_args(core::ptr::null()) };
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
    let put =
        |index: usize, value: u64| unsafe { core::ptr::write_volatile(out.add(index), value) };

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
        u64::from(model.granule_4k)
            | (u64::from(model.granule_16k) << 1)
            | (u64::from(model.granule_64k) << 2),
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

    // Timer interrupt DELIVERY. Needs no AIC: on Apple Silicon the generic
    // timer is wired straight to FIQ.
    //
    // The first attempt corrupted its neighbours because the handler saved only
    // x29/x30 and clobbered x0-x7. A synchronous trap tolerates that, since the
    // trap site declares clobber_abi("C"); an asynchronous one does not, because
    // the interrupted code never agreed to anything. The handler now saves every
    // caller-saved register.
    //
    // SAFETY: unmasks FIQ strictly inside `with_vectors`, so it lands on a table
    // that handles and returns from it, and DAIF plus the timer control are
    // restored before the window closes.
    if let Some(timer) = brainix_kernel::arch::aarch64::Timer::current() {
        let quarter_ms = timer.frequency_hz() / 4000;
        let report = unsafe {
            brainix_kernel::arch::aarch64::with_vectors(|| {
                timer.wait_for_interrupt(quarter_ms, 20_000_000)
            })
        };
        put(55, u64::from(report.taken));
        put(56, report.vector_index);
        put(57, report.elapsed_ticks);
        put(58, report.saved_daif);
    }

    // BISECT step 1: can TGE be cleared and restored at all, with no level
    // change? Two attempts at the full excursion hung, and a hang is one bit.
    //
    // SAFETY: toggles one HCR_EL2 bit and restores it; nothing changes level.
    let (hcr_before, hcr_cleared, hcr_restored) =
        unsafe { brainix_kernel::arch::aarch64::el::toggle_tge() };
    put(59, hcr_before);
    put(60, hcr_cleared);
    put(61, hcr_restored);

    // BISECT step 2: can EL1's regime be programmed through the _EL12 aliases?
    // The read-back also proves the raw encoding names the register we mean.
    //
    // SAFETY: writes EL1's translation state; nothing executes at EL1.
    let (ttbr_written, ttbr_readback) =
        unsafe { brainix_kernel::arch::aarch64::el::program_el1_regime() };
    put(62, ttbr_written);
    put(63, ttbr_readback);

    // BISECT step 3: does exception return work at all, without changing level?
    //
    // SAFETY: erets to a label two instructions ahead, at the current level.
    put(64, unsafe {
        brainix_kernel::arch::aarch64::el::eret_to_self()
    });

    // Everything to do with EL1 now lives in `el1_probe`, deliberately.
    //
    // This entry point is the project's evidence base: forty-odd measurements
    // that are read back and reasoned from. Any experiment that can hang belongs
    // somewhere else, because a hang takes m1n1's proxy with it and the run
    // returns *nothing* -- every measurement that had already succeeded included.
    //
    // That was not a hypothetical. Adding one EL1 question here turned a probe
    // that reported forty values into a probe that reported none, and cost a
    // reboot to find out. `el1_probe` takes a stage argument so each step is its
    // own returning call, and only the step that actually fails is lost.

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

/// The stack EL1 runs on during the excursion.
///
/// Named rather than inlined because two callers need the identical address:
/// the reachability check asks whether EL1 can reach *this* stack, and the drop
/// then runs on it. A second literal would let the question and the experiment
/// drift apart.
#[cfg(target_arch = "aarch64")]
fn el1_stack_top() -> u64 {
    #[repr(align(16))]
    struct El1Stack([u8; 4096]);
    static mut EL1_STACK: El1Stack = El1Stack([0; 4096]);
    // SAFETY: single-threaded probe; only the address is taken.
    unsafe { (core::ptr::addr_of_mut!(EL1_STACK) as u64).wrapping_add(4096) & !0xF }
}

/// `SP_EL0` for the user excursion.
///
/// The EL0 code makes two `SVC`s and no memory access, so this is never
/// dereferenced. It is set anyway, and to memory this image owns: `SP_EL0` is
/// otherwise whatever was left in it, and a stray access at EL0 would then land
/// on an arbitrary address instead of faulting somewhere attributable.
///
/// Its own allocation rather than a slice of EL1's, so that when EL0 does need
/// a writable stack it can be mapped without also handing userspace the page
/// holding the kernel's saved registers.
#[cfg(target_arch = "aarch64")]
fn el0_stack_top() -> u64 {
    #[repr(align(16384))]
    struct El0Stack([u8; 16384]);
    static mut EL0_STACK: El0Stack = El0Stack([0; 16384]);
    // SAFETY: single-threaded probe; only the address is taken.
    unsafe { (core::ptr::addr_of_mut!(EL0_STACK) as u64).wrapping_add(16384) & !0xF }
}

/// The device tree as a slice, from the firmware `boot_args` pointer.
///
/// # Safety
///
/// `boot_args` must be the firmware pointer or null. The returned slice aliases
/// live firmware memory.
#[cfg(target_arch = "aarch64")]
unsafe fn adt_blob<'a>(boot_args: *const u8) -> Option<&'a [u8]> {
    if boot_args.is_null() {
        return None;
    }
    // SAFETY: firmware guarantees the structure; every field access inside it
    // is bounds-checked by `brainix_adt`.
    let header = unsafe { core::slice::from_raw_parts(boot_args, 256) };
    let window = brainix_adt::adt_window(header).ok()?;
    // SAFETY: `adt_window` validated that this range lies entirely inside the
    // DRAM window firmware reported, is aligned, and does not overflow.
    Some(unsafe {
        core::slice::from_raw_parts(window.phys_addr as usize as *const u8, window.len as usize)
    })
}

/// Magic returned by [`el1_probe`].
#[cfg(target_arch = "aarch64")]
pub const EL1_PROBE_MAGIC: u64 = 0x4B72_6E6C_4E49_5803; // "Krnl NIX\x03"

/// The EL1 experiments, one stage per call.
///
/// # Why a stage argument rather than one function
///
/// These are the only operations in this image that can fail by **hanging**, and
/// a hang takes m1n1's proxy with it: the call never returns, so nothing written
/// to `out` before it can be read. Anything sharing a call with a step that hangs
/// is lost with it.
///
/// A returning call, by contrast, leaves m1n1 running and ready for the next one.
/// So each stage is its own call, made in order, and a hang costs exactly the
/// stage that hung -- not the ones that had already answered.
///
/// | stage | what it does | can it hang |
/// | --- | --- | --- |
/// | 1 | programme EL1's regime, ask `AT S1E1R` what EL1 could reach | no; `AT` cannot fault |
/// | 2 | drop to EL1, read `CurrentEL`, return via `HVC` | yes; this is the experiment |
/// | 3 | enable pointer authentication and prove a forged signature is rejected | yes; writes `SCTLR` |
/// | 4 | stage 2, and `SVC` at EL1 with a return to the instruction after it | yes |
/// | 5 | install page tables this repository built | yes; writes `TTBR0_EL2` |
/// | 6 | look at the boot seed **without** consuming it | no |
///
/// Stage 6 exists apart from stage 3 because stage 3 **erases** the seed. A
/// measurement that destroys what it measures cannot be repeated, and every run
/// after the first would report "no entropy" and read as a regression.
///
/// # Report layout
///
/// Stage 1: `[magic, HCR while asking, PAR code, PAR vectors, PAR stack]`.
///
/// Stages 2 and 4: `[magic, observed EL, HCR before, HCR after, return vector,
/// EL1 fault index, ESR_EL1, ELR_EL1, FAR_EL1, SVC count, SVC ESR_EL1,
/// SVC ELR_EL1]`.
///
/// Stage 3: `[magic, SCTLR before, SCTLR enabled, SCTLR after, APCTL, signed as
/// found, signed, recovered, authenticated tampered, plain, vector,
/// keys installed, verdict]`.
///
/// # Safety
///
/// `out` must have room for thirteen `u64`s. Stages 1 and 2 write EL1's
/// registers and briefly clear `HCR_EL2.TGE`; stage 2 additionally executes at
/// EL1; stage 3 writes `SCTLR` and the key A registers. All restore what they
/// changed except the authentication keys, which are not read back before being
/// written -- see `arch::aarch64::pac`.
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn el1_probe(stage: u64, boot_args: *const u8, out: *mut u64) -> u64 {
    // This entry point never passes through `_start` either, and the redirect
    // slots it depends on live in `.bss`.
    //
    // SAFETY: at an entry point, nothing else is using this image's `.bss`.
    unsafe { brainix_kernel::arch::aarch64::bss::zero() };

    // SAFETY: the caller guarantees `out` has room for nine `u64`s.
    let put =
        |index: usize, value: u64| unsafe { core::ptr::write_volatile(out.add(index), value) };
    put(0, EL1_PROBE_MAGIC);

    match stage {
        1 => {
            // `AT S1E1R` asks the MMU exactly what an instruction fetch at EL1
            // would ask, and cannot fault -- an unreachable address is reported
            // in `PAR_EL1.F` rather than raised. Free answer to the question the
            // drop otherwise answers by hanging.
            //
            // SAFETY: writes EL1's registers and briefly clears TGE. Nothing
            // executes at EL1 and no instruction in it can fault.
            let reach = unsafe {
                brainix_kernel::arch::aarch64::el::el1_reachability(
                    el1_probe as *const () as u64,
                    el1_stack_top(),
                )
            };
            put(1, reach.hcr_while_asking);
            put(2, reach.par_code);
            put(3, reach.par_vectors);
            put(4, reach.par_stack);
        }
        2 | 4 => {
            // Stage 4 is stage 2 plus a system call. Same code path, so the
            // drop that was verified on hardware is still exercised in the form
            // it was verified in, and a regression in SVC dispatch cannot
            // present as the drop breaking.
            let issue_svc = stage == 4;
            // SAFETY: inside `with_vectors` so the HVC home has an EL2 handler,
            // and `VBAR_EL12` points at the EL1-only table, which reads no EL2
            // registers.
            let excursion = unsafe {
                brainix_kernel::arch::aarch64::with_vectors(|| {
                    brainix_kernel::arch::aarch64::el::drop_to_el1_and_return(
                        el1_stack_top(),
                        issue_svc,
                    )
                })
            };
            put(1, excursion.observed_el);
            put(2, excursion.hcr_before);
            put(3, excursion.hcr_after);
            put(4, excursion.return_vector);
            put(5, excursion.el1_fault[0]);
            put(6, excursion.el1_fault[1]);
            put(7, excursion.el1_fault[2]);
            put(8, excursion.el1_fault[3]);
            put(9, excursion.el1_svc[0]);
            put(10, excursion.el1_svc[1]);
            put(11, excursion.el1_svc[2]);
        }
        3 => {
            // A value shaped like a pointer this image owns. The signature goes
            // in the bits above the address, so signing something that is not
            // pointer-shaped would put it somewhere the hardware does not use
            // and prove less than it appears to.
            let plain = el1_probe as *const () as u64;
            // SAFETY: inside `with_vectors`, which stage 3 requires: it
            // deliberately authenticates a forged signature, and on a part
            // implementing FEAT_FPAC that is a synchronous exception rather
            // than a poisoned pointer.
            let report = unsafe {
                brainix_kernel::arch::aarch64::with_vectors(|| {
                    brainix_kernel::arch::aarch64::pac::enable_and_verify(plain, 0, boot_args)
                })
            };
            put(1, report.sctlr_before);
            put(2, report.sctlr_while_enabled);
            put(3, report.sctlr_after);
            put(4, report.apctl);
            put(5, report.signed_as_found);
            put(6, report.signed);
            put(7, report.recovered);
            put(8, report.authenticated_tampered);
            put(9, report.plain);
            put(10, report.vector);
            put(
                11,
                u64::from(report.keys_installed) | (u64::from(report.random_present) << 1),
            );
            put(12, u64::from(report.authentication_works()));
        }
        5 => {
            // Install tables this repository built. The last untested step of
            // MMU bring-up, and the most dangerous operation here: between the
            // `msr` and the restore, every instruction fetch and every stack
            // access goes through descriptors this code wrote.
            let probe_va = el1_probe as *const () as u64;
            let stack_pointer: u64;
            // SAFETY: reading SP has no effects. It is included in the checked
            // set because `p.call` runs this on **m1n1's** stack, not ours, and
            // a mapping that omits it faults on the first push after the switch.
            unsafe {
                core::arch::asm!("mov {}, sp", out(reg) stack_pointer, options(nomem, nostack));
            }
            let check = [
                probe_va,
                stack_pointer,
                brainix_kernel::arch::aarch64::vectors::table_address(),
                brainix_kernel::arch::aarch64::vectors::el1_table_address(),
                el1_stack_top().wrapping_sub(8),
            ];
            // SAFETY: at EL2 with translation on and an identity mapping over
            // DRAM, which is what m1n1 leaves. The switch is refused unless our
            // walker and the MMU agree on every address above.
            let built = unsafe {
                brainix_kernel::arch::aarch64::mmu::switch_to_built_root(probe_va, &check)
            };
            put(
                1,
                u64::from(built.granule_bits) | (u64::from(built.levels) << 8),
            );
            put(2, built.block_size);
            put(3, built.live_descriptor);
            put(4, built.attributes);
            put(5, built.built_root);
            put(6, built.tables_used as u64);
            put(
                7,
                (built.checked as u64) | ((built.mismatches as u64) << 32),
            );
            put(8, u64::from(built.switched));
            put(9, built.probe_value);
            put(10, built.expected_value);
            put(11, built.restored_root);
            put(12, built.error);
        }
        6 => {
            // Look at the boot seed WITHOUT consuming it.
            //
            // Separate from stage 3 on purpose. Stage 3 erases the seed, and a
            // measurement that destroys what it measures cannot be repeated --
            // every run after the first would report "no entropy" and look like
            // a regression. This stage answers the only question that matters
            // about the source, which is whether it changes between boots, and
            // leaves it intact for stage 3 to spend.
            //
            // SAFETY: the caller supplies the firmware `boot_args` pointer, and
            // `peek` neither writes nor retains the slice.
            let seed = unsafe { brainix_kernel::arch::aarch64::entropy::peek(boot_args) };
            put(1, u64::from(seed.present));
            put(2, seed.len as u64);
            put(3, seed.nonzero as u64);
            put(4, seed.distinct as u64);
            put(5, u64::from(seed.usable));
            // Eight bytes, not sixty-four. Enough to see the value change
            // between boots; not enough to reconstruct a key from a transcript
            // of this probe, which is printed and scrolled back through.
            put(6, seed.first_eight);
            put(7, u64::from(seed.erased));
        }
        7 => {
            // EL0. The first time anything in this project runs unprivileged.
            //
            // SAFETY: inside `with_vectors` so the HVC home has an EL2 handler,
            // and the excursion refuses to `eret` unless the MMU has confirmed
            // that EL0 can reach its page and CANNOT reach the kernel's.
            let user = unsafe {
                brainix_kernel::arch::aarch64::with_vectors(|| {
                    brainix_kernel::arch::aarch64::el::drop_to_el0_and_return(
                        el1_stack_top(),
                        el0_stack_top(),
                    )
                })
            };
            put(1, user.user_root);
            put(2, user.tables_used as u64);
            put(3, user.user_page);
            put(4, user.par_kernel_from_el1);
            put(5, user.par_user_from_el0);
            put(6, user.par_kernel_from_el0);
            put(7, u64::from(user.entered));
            put(8, user.svc[0]);
            put(9, user.svc[1]);
            put(10, user.svc[3]);
            put(11, user.fault[1]);
            put(12, user.error);
            put(13, user.hcr_after);
        }
        8 => {
            // BTI enforcement. `SCTLR.BT` was already set in stage 3 and did
            // nothing, because BTI constrains branches only into pages carrying
            // `GP` and until this kernel owned its own tables there was no way
            // to set that on anything.
            //
            // SAFETY: inside `with_vectors`, which is required -- one of the two
            // branches exists to raise a Branch Target Exception, and its target
            // ends in `ret` so the handler's advance returns from it.
            let bti = unsafe {
                brainix_kernel::arch::aarch64::with_vectors(|| {
                    brainix_kernel::arch::aarch64::bti::enable_and_verify()
                })
            };
            put(1, u64::from(bti.supported));
            put(2, bti.guarded_root);
            put(3, bti.tables_used as u64);
            put(4, bti.guarded_page);
            put(5, bti.descriptor);
            put(6, bti.sctlr_while_enabled);
            put(7, bti.sctlr_after);
            put(8, bti.bad_branch_esr);
            put(9, u64::from(bti.bad_branch_faulted));
            put(10, u64::from(bti.good_branch_faulted));
            put(11, bti.restored_root);
            put(12, bti.error);
            put(13, u64::from(bti.enforcement_works()));
        }
        9 => {
            // Release a second CPU. The first thing in this project that runs
            // on hardware the boot core does not control, and the first that
            // cannot be undone: nothing here can stop a core once started --
            // m1n1 does not know it exists and this kernel has no IPI.
            use brainix_kernel::aarch64_cpus;

            // SAFETY: the caller supplies the firmware `boot_args` pointer.
            let Some(blob) = (unsafe { adt_blob(boot_args) }) else {
                put(1, u64::MAX);
                return EL1_PROBE_MAGIC;
            };
            let mut list = [aarch64_cpus::Cpu::default(); 16];
            let found = aarch64_cpus::cpus(blob, &mut list);
            put(1, found as u64);

            // `/arm-io/pmgr` reg[0], translated through `/arm-io`'s ranges. An
            // untranslated address here is a valid-looking physical address
            // pointing at the wrong block, and what gets written to it starts
            // a CPU.
            let Some(pmgr) =
                brainix_kernel::aarch64_devices::translated_reg(blob, b"/arm-io/pmgr", 0)
            else {
                put(2, u64::MAX);
                return EL1_PROBE_MAGIC;
            };
            let start_base = pmgr.wrapping_add(aarch64_cpus::CPU_START_OFFSET_T6020);
            put(2, pmgr);
            put(3, start_base);

            // Eight extra cores, which is every non-boot core this part has
            // and the width of the report block reserved for them.
            const MAX_EXTRA_CORES: u64 = 8;

            let Some(target) = aarch64_cpus::first_waiting_cpu(list.get(..found).unwrap_or(&[]))
            else {
                put(4, u64::MAX);
                return EL1_PROBE_MAGIC;
            };

            // A second of ticks at the measured frequency. Generous: the core
            // has to power up. Bounded because a core that never reports must
            // not take this one with it -- a timeout is a reading, a hang is not.
            let timeout = brainix_kernel::arch::aarch64::registers::counter_frequency_hz();
            // SAFETY: `target` is a core the tree says is not running, the start
            // base came from the ADT with translation checked, and the boot core
            // is under an identity map so the secondary resolves the same
            // addresses with its MMU off.
            // The report as the image ships it, read before any other core can
            // have touched it. Every slot below is compared against what the
            // secondary leaves behind, and a slot that reads wrong *here* is a
            // boot-core problem -- a bad address or a bad index -- not a
            // secondary that misbehaved. Without this the two are
            // indistinguishable, and an hour went into telling them apart.
            let first_slot =
                brainix_kernel::aarch64_cpus::slot_for_cpu(target.cluster, target.core);
            let before_release = brainix_kernel::arch::aarch64::smp::report(first_slot);
            put(
                43,
                brainix_kernel::arch::aarch64::smp::report_address(first_slot),
            );
            put(44, before_release[9]);
            put(45, before_release[10]);
            put(46, before_release[12]);
            put(47, before_release[13]);

            let released = unsafe {
                brainix_kernel::arch::aarch64::smp::release(&target, start_base, timeout)
            };
            put(4, u64::from(released.cpu_id));
            put(5, released.impl_reg);
            put(6, released.rvbar_before);
            put(7, released.rvbar_after);
            put(8, u64::from(released.rvbar_accepted));
            put(9, released.entry);
            put(10, u64::from(released.started));
            put(11, released.waited_ticks);
            put(12, released.mpidr);
            put(13, released.exception_level);
            put(14, released.sctlr);

            // The doorbell. Last night the released core parked with
            // no way to recall it; FastIPI is that way, and it is three system
            // registers rather than an interrupt controller.
            if released.started {
                // SAFETY: the target is the core just released, running the
                // `wfe` loop in `brainix_secondary_entry` -- exactly the code
                // that expects a doorbell.
                let (doorbells, ticks) = unsafe {
                    brainix_kernel::arch::aarch64::smp::ring_and_confirm(
                        released.mpidr,
                        4,
                        brainix_kernel::arch::aarch64::registers::counter_frequency_hz(),
                    )
                };
                put(15, doorbells);
                put(16, ticks);
                put(
                    17,
                    brainix_kernel::arch::aarch64::smp::report(released.slot)[5],
                );

                // Real work on the other core. `sum(1..=1000)` is 500500, which
                // the boot core knows without running it -- so a wrong answer is
                // distinguishable from no answer.
                use brainix_kernel::arch::aarch64::smp;
                let hz = brainix_kernel::arch::aarch64::registers::counter_frequency_hz();
                // SAFETY: the target is parked in the dispatch loop, and the
                // posted function touches no memory, so it is safe to run on a
                // core with the MMU and caches off.
                let dispatched = unsafe {
                    smp::dispatch(released.mpidr, smp::secondary_sum_address(), 1, 1000, hz)
                };
                match dispatched {
                    Some((result, ticks)) => {
                        put(18, 1);
                        put(19, result);
                        put(20, ticks);
                    }
                    None => put(18, 0),
                }

                // What the other core can do with MEMORY, which is the only
                // question that decides whether a matmul chunk belongs on it.
                //
                // `sum(1..=1000)` above proves the mechanism and nothing else:
                // it touches no memory, so it says nothing about a core whose
                // caches are off. The same read loop is run on both cores over
                // the same buffer, and the ratio between the two times is the
                // cost of running with the MMU off.
                //
                // SAFETY: nothing else is reading the buffer -- the secondary
                // is parked, and the work that will read it is posted after.
                let expected = unsafe { smp::fill_bench_buffer() };
                let base = smp::bench_buffer_address();
                let words = smp::BENCH_WORDS as u64;
                put(21, expected);
                put(22, words);

                // The boot core's own time over the same loop, so the
                // comparison is between two cores and not between two
                // different pieces of code.
                let before = brainix_kernel::arch::aarch64::registers::physical_counter();
                // SAFETY: the buffer was just filled and is `words` long.
                let local = unsafe { smp::brainix_secondary_checksum(base, words) };
                let local_ticks = brainix_kernel::arch::aarch64::registers::physical_counter()
                    .wrapping_sub(before);
                put(23, local);
                put(24, local_ticks);

                // SAFETY: the target is parked in the dispatch loop and the
                // buffer has been cleaned to the point of coherency, which is
                // what makes it readable by a core running without caches.
                let remote = unsafe {
                    smp::dispatch(
                        released.mpidr,
                        smp::secondary_checksum_address(),
                        base,
                        words,
                        // Generous: an uncached read of a megabyte is the thing
                        // being measured, and guessing its duration low would
                        // report a timeout as the answer.
                        hz.saturating_mul(8),
                    )
                };
                match remote {
                    Some((result, ticks)) => {
                        put(25, 1);
                        put(26, result);
                        put(27, ticks);
                    }
                    None => put(25, 0),
                }

                // Now give that core the MMU and the caches, and read the same
                // megabyte again. This is the whole point of the stage: the
                // number above says a core running the way a core arrives out
                // of reset cannot be given work worth having, and the number
                // below says whether adopting the boot core's translation
                // tables fixes it.
                //
                // SAFETY: at EL2, under the translation regime the secondary is
                // about to share.
                let handoff = unsafe { smp::publish_mmu_handoff() };
                // SAFETY: the target is parked in the dispatch loop, and the
                // handoff describes the identity map it is already resolving
                // its own addresses under. A wrong handoff costs a timeout
                // rather than a hang, which is why this is dispatched.
                let enabled = unsafe {
                    smp::dispatch(
                        released.mpidr,
                        smp::secondary_enable_mmu_address(),
                        handoff,
                        0,
                        hz,
                    )
                };
                // What the secondary's own vectors caught, if anything. Read
                // whether or not the enable returned: a timeout with a fault
                // recorded is a diagnosis, and a timeout without one is a
                // different problem entirely.
                let after = smp::report(released.slot);
                put(33, after[9]);
                put(34, after[6]);
                put(35, after[7]);
                put(36, after[8]);
                put(37, after[10]);
                put(38, after[11]);
                put(39, after[12]);
                put(40, after[13]);
                // The two addresses the loop could legitimately have been
                // handed, so "last fn" is identifiable rather than a number.
                put(41, smp::secondary_checksum_address());
                put(42, smp::secondary_sum_address());

                match enabled {
                    Some((sctlr, _)) => {
                        put(28, 1);
                        put(29, sctlr);

                        // SAFETY: as the first remote checksum. The buffer is
                        // unchanged and the core is back in the same loop.
                        let cached = unsafe {
                            smp::dispatch(
                                released.mpidr,
                                smp::secondary_checksum_address(),
                                base,
                                words,
                                hz.saturating_mul(8),
                            )
                        };
                        match cached {
                            Some((result, ticks)) => {
                                put(30, 1);
                                put(31, result);
                                put(32, ticks);
                            }
                            None => put(30, 0),
                        }
                    }
                    None => put(28, 0),
                }

                // Every remaining core, on the same path. One partner is a
                // mechanism; a pool is what the forward pass can actually use,
                // and the only way to know the mechanism generalises is to run
                // it on cores the first one's slot arithmetic did not choose.
                //
                // Each gets: released, checked that the slot the tree predicted
                // is the slot its own MPIDR selects, handed the MMU, and then
                // asked to read the same megabyte. Eight report slots each,
                // starting at 48.
                let mut released_count = 0u64;
                let mut at_full_rate = 0u64;
                let mut index = 0usize;
                // The cores that came all the way up, in release order, for the
                // concurrent sweep below. The first core is worker 0 there, so
                // it goes in first.
                let mut workers = [0u64; 16];
                let mut worker_count = 0usize;
                if released.started && released.slot_matches && enabled.is_some() {
                    workers[0] = released.mpidr;
                    worker_count = 1;
                }
                while index < found && released_count < MAX_EXTRA_CORES {
                    let cpu = list[index];
                    index += 1;
                    if cpu.running || cpu.cpu_id == target.cpu_id {
                        continue;
                    }
                    let out_base = 48 + (released_count as usize) * 8;
                    released_count += 1;

                    // SAFETY: as the first release -- a core the tree says is
                    // not running, a start base translated from the ADT, and a
                    // boot core under an identity map.
                    let extra = unsafe { smp::release(&cpu, start_base, timeout) };
                    put(out_base, u64::from(extra.cpu_id));
                    put(out_base + 1, u64::from(extra.started));
                    put(out_base + 2, extra.mpidr);
                    put(out_base + 3, u64::from(extra.slot_matches));

                    // A core whose two slot numbers disagree is a core writing
                    // buffers the boot core is not reading. Stop before it is
                    // handed anything, rather than collecting numbers from the
                    // wrong memory.
                    if !extra.started || !extra.slot_matches {
                        continue;
                    }

                    // SAFETY: the core is parked in the dispatch loop and the
                    // handoff describes the map it already resolves under.
                    let on = unsafe {
                        smp::dispatch(
                            extra.mpidr,
                            smp::secondary_enable_mmu_address(),
                            handoff,
                            0,
                            hz,
                        )
                    };
                    let Some((sctlr, _)) = on else {
                        continue;
                    };
                    put(out_base + 4, sctlr);

                    // SAFETY: the buffer is unchanged and this core is now
                    // translating the same way every other one is.
                    let read = unsafe {
                        smp::dispatch(
                            extra.mpidr,
                            smp::secondary_checksum_address(),
                            base,
                            words,
                            hz.saturating_mul(8),
                        )
                    };
                    if worker_count < workers.len() {
                        workers[worker_count] = extra.mpidr;
                        worker_count += 1;
                    }

                    if let Some((result, ticks)) = read {
                        put(out_base + 5, 1);
                        put(out_base + 6, u64::from(result == expected));
                        put(out_base + 7, ticks);
                        // "Full rate" measured against the boot core rather
                        // than against a constant, so a slower machine or a
                        // different buffer size cannot make this pass by
                        // accident. A tenth of slack covers an E core.
                        if result == expected && ticks <= local_ticks.saturating_mul(11) / 10 {
                            at_full_rate += 1;
                        }
                    }
                }
                // Past the per-core blocks, which run 48..112.
                put(112, released_count);
                put(113, at_full_rate);

                // ---------------------------------------------------------
                // What the machine does when every core pulls at once.
                //
                // Every number before this line was taken with one core
                // reading and the rest idle, which is not a workload. A decode
                // splits one matmul across all of them and they contend for
                // the same bus, so the question that decides how many workers
                // to use is not "how fast is a core" but "where does adding a
                // core stop adding throughput".
                //
                // The buffer is partitioned, not shared: worker i reads its own
                // disjoint slice, which is what a row-split matmul does. The
                // slices sum to the whole buffer, so the checksums summed must
                // equal the same closed-form total the single-core runs
                // produced -- a partition bug shows up as a wrong number rather
                // than as a suspiciously good time.
                //
                // Worker 0 is the boot core. It posts to the others, reads its
                // own slice while they read theirs, and only then collects.
                // Posting and collecting one at a time would serialise the
                // whole thing and measure nothing.
                let total_workers = worker_count + 1;
                let mut n = 1usize;
                while n <= total_workers && n <= 12 {
                    let chunk = smp::BENCH_WORDS / n;
                    let mut requests = [0u64; 16];

                    let sweep_start = brainix_kernel::arch::aarch64::registers::physical_counter();

                    let mut worker = 1usize;
                    while worker < n {
                        let offset = worker * chunk;
                        // The last slice absorbs the remainder, so the
                        // partition covers the buffer exactly.
                        let length = if worker == n - 1 {
                            smp::BENCH_WORDS - offset
                        } else {
                            chunk
                        };
                        // SAFETY: the core is parked in the dispatch loop with
                        // its MMU on, and the slice is inside the buffer.
                        requests[worker] = unsafe {
                            smp::post(
                                workers[worker - 1],
                                smp::secondary_checksum_address(),
                                base + (offset as u64) * 8,
                                length as u64,
                            )
                        };
                        worker += 1;
                    }

                    // The boot core's own slice, read while the others are
                    // reading theirs.
                    // SAFETY: slice 0 is inside the buffer.
                    let mut total = unsafe { smp::brainix_secondary_checksum(base, chunk as u64) };

                    let mut complete = true;
                    worker = 1;
                    while worker < n {
                        // SAFETY: the request was posted to this core above.
                        match unsafe {
                            smp::collect(
                                workers[worker - 1],
                                requests[worker],
                                hz.saturating_mul(8),
                            )
                        } {
                            Some(value) => total = total.wrapping_add(value),
                            None => complete = false,
                        }
                        worker += 1;
                    }

                    let sweep_ticks = brainix_kernel::arch::aarch64::registers::physical_counter()
                        .wrapping_sub(sweep_start);
                    let out_base = 114 + (n - 1) * 2;
                    put(out_base, sweep_ticks);
                    put(out_base + 1, u64::from(complete && total == expected));
                    n += 1;
                }
                put(138, total_workers as u64);

                // ---------------------------------------------------------
                // Equal slices are the wrong slices, and this proves it.
                //
                // The sweep above gets slower when the fifth worker joins:
                // aggregate falls from 39 GB/s to 21. Equal partitioning makes
                // wall time the SLOWEST worker's time, so one core running at
                // 4.3 GB/s while three run at 11.4 sets the pace for all of
                // them, and the fast three sit idle for two thirds of it.
                //
                // If that is the explanation, weighting each slice by the
                // worker's own measured rate should recover the loss. If it is
                // not -- if the cores are contending for something -- weighting
                // will change nothing and the number will say so.
                //
                // Rates are measured first, one worker at a time, each on a
                // DIFFERENT 4 MiB slice so no worker warms a cache for the next.
                const PROBE_WORDS: u64 = 1 << 19;
                let mut solo = [0u64; 16];
                let mut w = 0usize;
                while w < total_workers && w < 16 {
                    let offset = (w as u64) * PROBE_WORDS * 8;
                    let ticks = if w == 0 {
                        let t0 = brainix_kernel::arch::aarch64::registers::physical_counter();
                        // SAFETY: the slice is inside the buffer.
                        let _ =
                            unsafe { smp::brainix_secondary_checksum(base + offset, PROBE_WORDS) };
                        brainix_kernel::arch::aarch64::registers::physical_counter()
                            .wrapping_sub(t0)
                    } else {
                        // SAFETY: the core is parked with its MMU on and the
                        // slice is inside the buffer.
                        match unsafe {
                            smp::dispatch(
                                workers[w - 1],
                                smp::secondary_checksum_address(),
                                base + offset,
                                PROBE_WORDS,
                                hz.saturating_mul(8),
                            )
                        } {
                            Some((_, t)) => t,
                            None => 0,
                        }
                    };
                    solo[w] = ticks;
                    put(140 + w, ticks);
                    w += 1;
                }

                // Weight by 1/time. Fixed point, because there is no float here
                // and a rate expressed as ticks-per-slice is an integer that
                // divides the wrong way round.
                const SCALE: u64 = 1 << 20;
                let mut inverse = [0u64; 16];
                let mut total_inverse = 0u64;
                w = 0;
                while w < total_workers && w < 16 {
                    inverse[w] = if solo[w] == 0 { 0 } else { SCALE / solo[w] };
                    total_inverse = total_inverse.saturating_add(inverse[w]);
                    w += 1;
                }

                if total_inverse > 0 {
                    let mut requests = [0u64; 16];
                    let mut offsets = [0u64; 16];
                    let mut lengths = [0u64; 16];
                    let mut assigned = 0u64;
                    w = 0;
                    while w < total_workers && w < 16 {
                        offsets[w] = assigned;
                        lengths[w] = if w + 1 == total_workers {
                            (smp::BENCH_WORDS as u64).saturating_sub(assigned)
                        } else {
                            (smp::BENCH_WORDS as u64)
                                .saturating_mul(inverse[w])
                                .saturating_div(total_inverse)
                        };
                        assigned = assigned.saturating_add(lengths[w]);
                        w += 1;
                    }

                    let start = brainix_kernel::arch::aarch64::registers::physical_counter();
                    w = 1;
                    while w < total_workers && w < 16 {
                        // SAFETY: parked core, slice inside the buffer.
                        requests[w] = unsafe {
                            smp::post(
                                workers[w - 1],
                                smp::secondary_checksum_address(),
                                base + offsets[w] * 8,
                                lengths[w],
                            )
                        };
                        w += 1;
                    }
                    // SAFETY: slice 0 is inside the buffer.
                    let mut total = unsafe { smp::brainix_secondary_checksum(base, lengths[0]) };
                    let mut complete = true;
                    w = 1;
                    while w < total_workers && w < 16 {
                        // SAFETY: posted to this core above.
                        match unsafe {
                            smp::collect(workers[w - 1], requests[w], hz.saturating_mul(8))
                        } {
                            Some(value) => total = total.wrapping_add(value),
                            None => complete = false,
                        }
                        w += 1;
                    }
                    let ticks = brainix_kernel::arch::aarch64::registers::physical_counter()
                        .wrapping_sub(start);
                    put(156, ticks);
                    put(157, u64::from(complete && total == expected));
                }
            }
        }
        _ => {}
    }
    EL1_PROBE_MAGIC
}

/// Keeps [`el1_probe`] in the image, for the same reason as
/// [`KERNEL_PROBE_KEEPALIVE`].
#[cfg(target_arch = "aarch64")]
#[used]
static EL1_PROBE_KEEPALIVE: unsafe extern "C" fn(u64, *const u8, *mut u64) -> u64 = el1_probe;

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
