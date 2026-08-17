//! Releasing a secondary CPU, and hearing back from it.
//!
//! # Apple does not do this the standard way
//!
//! There is no PSCI here and there are no spin-tables. The other nine cores are
//! not parked in a loop waiting to be told where to go; they are **powered
//! down**, and starting one is two MMIO writes into the PMGR block plus a reset
//! vector written into that core's own register window.
//!
//! The sequence is reverse-engineered, not documented. m1n1's comment on the
//! first of the two writes -- *"Some kind of system level startup/status bit.
//! Without this, IRQs don't work"* -- is the state of public knowledge.
//!
//! # The secondary starts with the MMU off, and that is the whole difficulty
//!
//! Everything this kernel has built so far -- translation, vectors, `PAC`,
//! `BTI` -- applies to the boot core. A released core arrives with `SCTLR.M`
//! clear, caches off, no stack, and nothing in any register worth trusting.
//!
//! Two consequences, and both are cache-coherency problems rather than the
//! architectural ones you would expect:
//!
//! - **What the boot core wrote may not be visible.** With the MMU off, the
//!   secondary's accesses do not go through the data cache, while the boot
//!   core's writes may still be sitting dirty in it. So the stub and its report
//!   buffer are cleaned to the point of coherency (`dc civac`) before the core
//!   is released -- not `dc cvau`, which only reaches the point of unification
//!   and is enough for instruction fetch on a coherent core and not for this.
//! - **What the secondary writes may not be seen.** Its stores go straight to
//!   memory, so the boot core must invalidate before reading or it will hit a
//!   stale line it cached earlier. Every poll invalidates first.
//!
//! Neither of these fails loudly. They produce a report that never arrives, or
//! one that arrives holding what was in that memory beforehand -- which is why
//! the magic word is written **last**, after a `dsb sy`, and why the buffer is
//! poisoned before the attempt.
//!
//! # It is one shot per boot
//!
//! The stub parks in `wfe` forever. Nothing here can stop a core once started:
//! m1n1 does not know about it, and this kernel has no IPI. A second attempt in
//! the same session will time out, which is the honest outcome -- the core is
//! already running, just not listening.

#![allow(unsafe_code)]

use crate::aarch64_cpus::{start_core_bit, start_enable_bit, Cpu, RVBAR_ADDRESS, RVBAR_LOCK};
use core::sync::atomic::{AtomicU64, Ordering};

/// Written by the secondary once it has recorded everything else.
///
/// Grouped in sixteens to match the four `movz`/`movk` immediates that build it
/// in the stub, because the assembler cannot check the Rust constant and a
/// mismatch means the poll never terminates and the core looks dead. Written
/// `0x5EC0_11DA_B0_0757` at first, which is fourteen digits, and would have
/// produced exactly that.
pub const SECONDARY_MAGIC: u64 = 0x5EC0_11DA_00B0_0757;

/// Value the report starts at, so "never ran" is a value rather than an
/// inference.
const REPORT_POISON: u64 = 0x5EC0_DEAD_5EC0_DEAD;

core::arch::global_asm!(
    r#"
.section .text.secondary, "ax"
.balign 16384
.globl brainix_secondary_entry
brainix_secondary_entry:
    // Entered by a core that has just come out of reset.
    //
    // MMU off, caches off, no stack, no valid registers. `adrp` is PC-relative
    // so it resolves against the physical address this image was loaded at,
    // which is the same as its virtual address only because the boot core runs
    // under an identity map -- stated because it is load-bearing, not obvious.
    adrp x0, {report}
    add  x0, x0, :lo12:{report}

    mrs  x1, MPIDR_EL1
    str  x1, [x0, #8]
    mrs  x1, CurrentEL
    str  x1, [x0, #16]
    mrs  x1, SCTLR_EL1
    str  x1, [x0, #24]

    // The magic LAST, and after a barrier. A reader that sees it is guaranteed
    // to see the three values above; without the `dsb` it could observe the
    // magic while the rest is still poison, and report a core that started with
    // an MPIDR it never wrote.
    dsb  sy
    movz x1, #0x0757
    movk x1, #0xB0, lsl #16
    movk x1, #0x11DA, lsl #32
    movk x1, #0x5EC0, lsl #48
    str  x1, [x0, #0]
    dsb  sy

    // Park. There is no way to recall this core -- no IPI, and m1n1 does not
    // know it exists -- so it spins here until the machine reboots. `wfe`
    // rather than a tight branch so it is not burning the cluster's power
    // budget for the rest of the session.
1:  wfe
    b 1b
.balign 16384
"#,
    report = sym SECONDARY_REPORT,
);

extern "C" {
    /// The secondary entry point, defined above.
    static brainix_secondary_entry: u8;
}

/// `[magic, MPIDR_EL1, CurrentEL, SCTLR_EL1]`, written by the secondary.
///
/// In `.data` by virtue of the poison initialiser, so it is carried in the flat
/// image. A `.bss` buffer would start as whatever was in that memory, and the
/// difference between "the core wrote this" and "this was already here" is the
/// entire measurement.
static SECONDARY_REPORT: [AtomicU64; 4] = [
    AtomicU64::new(REPORT_POISON),
    AtomicU64::new(REPORT_POISON),
    AtomicU64::new(REPORT_POISON),
    AtomicU64::new(REPORT_POISON),
];

/// Address the released core begins executing at.
pub fn secondary_entry_address() -> u64 {
    // SAFETY: address of an `extern` symbol defined in this crate's assembly.
    unsafe { core::ptr::addr_of!(brainix_secondary_entry) as u64 }
}

/// What happened when a core was released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecondaryReport {
    /// `cpu-id` of the core that was targeted.
    pub cpu_id: u32,
    /// Its `cpu-impl-reg` window.
    pub impl_reg: u64,
    /// `RVBAR` before we touched it.
    pub rvbar_before: u64,
    /// `RVBAR` read back after writing the entry point.
    pub rvbar_after: u64,
    /// Whether the address field took the write and the lock cleared.
    pub rvbar_accepted: bool,
    /// The entry point written.
    pub entry: u64,
    /// CPU start register base.
    pub start_base: u64,
    /// Whether the magic arrived before the timeout.
    pub started: bool,
    /// Ticks spent waiting.
    pub waited_ticks: u64,
    /// `MPIDR_EL1` as the secondary read it.
    pub mpidr: u64,
    /// `CurrentEL` as the secondary read it, already shifted to a level number.
    pub exception_level: u64,
    /// `SCTLR_EL1` as the secondary read it.
    pub sctlr: u64,
}

/// Clean a range to the point of coherency.
///
/// `dc civac`, not `dc cvau`. The point of unification is enough for a
/// coherent observer fetching instructions; a core running with its MMU off is
/// not one, and its reads bypass the cache entirely.
///
/// # Safety
///
/// `start` must be a mapped address and `len` must not run past it.
unsafe fn clean_to_coherency(start: u64, len: u64) {
    // 64-byte lines on this part. Using a smaller step is wasteful and safe;
    // a larger one would skip lines, which is not.
    let mut address = start & !63;
    let end = start.saturating_add(len);
    while address < end {
        // SAFETY: a cache maintenance operation by virtual address; no memory
        // is read or written and it cannot fault on a mapped address.
        unsafe {
            core::arch::asm!("dc civac, {addr}", addr = in(reg) address, options(nostack));
        }
        address = address.saturating_add(64);
    }
    // SAFETY: ordering the maintenance against what follows.
    unsafe { core::arch::asm!("dsb sy", "isb", options(nostack)) };
}

/// Invalidate a range so a stale cached copy cannot be read.
///
/// # Safety
///
/// As [`clean_to_coherency`]. `dc civac` rather than `dc ivac` because the
/// latter discards dirty data, and this buffer was written by us before the
/// core started.
unsafe fn refresh_from_memory(start: u64, len: u64) {
    // SAFETY: delegated.
    unsafe { clean_to_coherency(start, len) };
}

/// Read what the secondary recorded.
pub fn report() -> [u64; 4] {
    [
        SECONDARY_REPORT[0].load(Ordering::Relaxed),
        SECONDARY_REPORT[1].load(Ordering::Relaxed),
        SECONDARY_REPORT[2].load(Ordering::Relaxed),
        SECONDARY_REPORT[3].load(Ordering::Relaxed),
    ]
}

/// Release `cpu` into [`secondary_entry_address`] and wait for it to report.
///
/// # Safety
///
/// Powers up and starts another CPU, which then runs forever. `start_base` must
/// be the CPU start register block and `cpu` must describe a core that is not
/// already running. The boot core must be under an identity mapping, because
/// the secondary resolves the same addresses with its MMU off.
pub unsafe fn release(cpu: &Cpu, start_base: u64, timeout_ticks: u64) -> SecondaryReport {
    let entry = secondary_entry_address();

    // Poison the report before anything can write it, so a value left over
    // from an earlier attempt cannot be mistaken for a fresh one.
    for slot in &SECONDARY_REPORT {
        slot.store(REPORT_POISON, Ordering::Relaxed);
    }

    let report_address = SECONDARY_REPORT.as_ptr() as u64;
    // SAFETY: both ranges are inside this image, which is mapped.
    unsafe {
        clean_to_coherency(report_address, 32);
        // The stub itself. The secondary fetches it with the MMU off, so it has
        // to be visible at the point of coherency, not merely at the point of
        // unification where the loader left it.
        clean_to_coherency(entry, 16384);
    }

    // SAFETY: reading this core's reset vector register. It is powered down and
    // m1n1 performs the same read before starting one.
    let rvbar_before = unsafe { core::ptr::read_volatile(cpu.impl_reg as *mut u64) };

    // SAFETY: writing the reset vector. Measured on this part: the address
    // field takes the write and the lock bit clears. Bits 47:44 are identity
    // and read back unchanged, which is why the check below masks them out.
    unsafe {
        core::ptr::write_volatile(cpu.impl_reg as *mut u64, entry);
        core::arch::asm!("dsb sy", options(nostack));
    }
    let rvbar_after = unsafe { core::ptr::read_volatile(cpu.impl_reg as *mut u64) };
    let rvbar_accepted =
        rvbar_after & RVBAR_ADDRESS == entry & RVBAR_ADDRESS && rvbar_after & RVBAR_LOCK == 0;

    let mut result = SecondaryReport {
        cpu_id: cpu.cpu_id,
        impl_reg: cpu.impl_reg,
        rvbar_before,
        rvbar_after,
        rvbar_accepted,
        entry,
        start_base,
        started: false,
        waited_ticks: 0,
        mpidr: 0,
        exception_level: 0,
        sctlr: 0,
    };
    // Refuse rather than start a core that will begin executing somewhere we
    // did not choose. That core cannot be stopped and would be running
    // arbitrary code alongside this one.
    if !rvbar_accepted {
        return result;
    }

    let cluster_word = start_base
        .saturating_add(8)
        .saturating_add(u64::from(cpu.cluster).saturating_mul(4));

    // SAFETY: the two writes m1n1 makes, in its order. The first is documented
    // in m1n1 only as "some kind of system level startup/status bit. Without
    // this, IRQs don't work"; the second releases the core.
    unsafe {
        core::ptr::write_volatile(
            start_base.saturating_add(4) as *mut u32,
            start_enable_bit(cpu),
        );
        core::arch::asm!("dsb sy", options(nostack));
        core::ptr::write_volatile(cluster_word as *mut u32, start_core_bit(cpu));
        core::arch::asm!("dsb sy", options(nostack));
    }

    // Poll, bounded. A core that never reports must not take this one with it.
    let start = super::registers::physical_counter();
    loop {
        // SAFETY: the report is inside this image.
        unsafe { refresh_from_memory(report_address, 32) };
        if SECONDARY_REPORT[0].load(Ordering::Relaxed) == SECONDARY_MAGIC {
            result.started = true;
            break;
        }
        result.waited_ticks = super::registers::physical_counter().wrapping_sub(start);
        if result.waited_ticks > timeout_ticks {
            break;
        }
    }

    let values = report();
    result.mpidr = values[1];
    result.exception_level = (values[2] >> 2) & 0b11;
    result.sctlr = values[3];
    result
}
