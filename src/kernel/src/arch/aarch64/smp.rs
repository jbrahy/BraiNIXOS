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
//! # The doorbell
//!
//! The stub parks in `WFI` and is recalled with Apple's fast IPI: a system
//! register write, no interrupt controller, no MMIO, no lock. **Measured on the
//! target: four rings, four wakes, 91 ticks -- about 0.95 us per round trip.**
//!
//! That number is the reason `Dispatch::minimum_split_bytes` is a method rather
//! than a constant. The host measurement that chose 4 MB was taken against a
//! `std::sync::Barrier` costing roughly 30 us; a doorbell thirty times cheaper
//! makes far smaller work worth splitting, and a threshold measured against the
//! wrong synchronization primitive would be wrong by that factor.

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

    // Park, and wake on the doorbell.
    //
    // **`WFI`, not `WFE`, and the difference is the whole thing.** An earlier
    // version of this loop used `WFE` on the belief that it wakes on a pending
    // interrupt whether or not `PSTATE` masks it. That is true of `WFI` and
    // false of `WFE`: `WFE`'s wake-up events include an interrupt only when it
    // would actually be taken, so with `DAIF` masked -- which is how a core
    // arrives out of reset -- the IPI asserted and the core slept through it.
    // The symptom was a doorbell that timed out with every report slot still
    // poisoned. m1n1's secondary loop uses `deep_wfi` and that was the clue.
    //
    // With `WFI` no vector table is needed on this core: the interrupt wakes it
    // without ever being delivered as an exception, which is why this loop can
    // be eleven instructions with no handler, no stack and no `VBAR`.
1:  wfi
    // SYS_IMP_APL_IPI_SR_EL1 -- s3_5_c15_c1_1, bit 0 is pending.
    mrs  x2, s3_5_c15_c1_1
    tst  x2, #1
    // A spurious wake is normal: `WFE` may return for reasons that are not
    // ours. Going back to sleep rather than counting it is what keeps the
    // count a count of doorbells.
    b.eq 1b
    str  x2, [x0, #40]
    // Acknowledge by writing the pending bit back. Until this happens the
    // condition stays asserted and the next `wfe` returns immediately, which
    // presents as a core spinning at 100% rather than as a missed wake.
    mov  x3, #1
    msr  s3_5_c15_c1_1, x3
    // Load, add, store -- see the note on the exclusive monitor in `vectors`.
    ldr  x3, [x0, #32]
    add  x3, x3, #1
    str  x3, [x0, #32]
    dsb  sy

    // Is there work, or was this doorbell only a wake?
    adrp x4, {work}
    add  x4, x4, :lo12:{work}
    ldr  x5, [x4, #0]           // request sequence
    ldr  x6, [x4, #40]          // completion sequence
    cmp  x5, x6
    b.eq 1b

    // A stack, established here rather than at entry because nothing before
    // this point needed one and a core that never runs work never touches it.
    adrp x7, {stack}
    add  x7, x7, :lo12:{stack}
    add  x7, x7, #16384
    mov  sp, x7

    ldr  x8, [x4, #8]           // function
    ldr  x0, [x4, #16]          // arg0
    ldr  x1, [x4, #24]          // arg1
    blr  x8
    // Result first, then the sequence that publishes it. A reader that sees
    // the sequence match is guaranteed to see this store.
    str  x0, [x4, #32]
    dsb  sy
    str  x5, [x4, #40]
    dsb  sy

    // x0 was the report base and the call clobbered it. Recover it rather than
    // carrying it in a callee-saved register the callee is entitled to use.
    adrp x0, {report}
    add  x0, x0, :lo12:{report}
    b 1b
.balign 16384
"#,
    report = sym SECONDARY_REPORT,
    work = sym WORK,
    stack = sym SECONDARY_STACK,
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
static SECONDARY_REPORT: [AtomicU64; 6] = [
    AtomicU64::new(REPORT_POISON),
    AtomicU64::new(REPORT_POISON),
    AtomicU64::new(REPORT_POISON),
    AtomicU64::new(REPORT_POISON),
    // Doorbell count, zeroed rather than poisoned: it is incremented from
    // zero, so a poison would have to be subtracted out and a reader could not
    // tell "never woken" from "woken a poison-sized number of times".
    AtomicU64::new(0),
    AtomicU64::new(REPORT_POISON),
];

/// Stack for the secondary, so it can call Rust.
///
/// A core out of reset has no stack. Everything it has done so far -- record
/// four registers, park, count doorbells -- fits in registers, which is why the
/// loop needed none. Running arbitrary work does not.
///
/// In `.bss`, which the boot core zeroes at entry. That is not a requirement --
/// a stack does not care what was in it -- but it does mean the whole region is
/// touched before the secondary reaches it, so no page is first-touched by a
/// core running with its MMU off.
#[repr(align(16384))]
struct SecondaryStack([u8; 16384]);

static mut SECONDARY_STACK: SecondaryStack = SecondaryStack([0; 16384]);

/// The work slot the two cores share.
///
/// | index | meaning |
/// | --- | --- |
/// | 0 | request sequence, incremented by the boot core |
/// | 1 | function pointer |
/// | 2 | first argument |
/// | 3 | second argument |
/// | 4 | return value |
/// | 5 | completion sequence, written by the secondary |
///
/// **The sequence pair is what makes this safe without a lock.** The boot core
/// writes the function and arguments *first*, then bumps the request; the
/// secondary copies the result *first*, then matches the completion to the
/// request it served. A reader that sees `completion == request` is guaranteed
/// to see the result that request produced, and a doorbell that arrives twice
/// for one request is idempotent rather than a double execution.
static WORK: [AtomicU64; 6] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
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
pub fn report() -> [u64; 6] {
    [
        SECONDARY_REPORT[0].load(Ordering::Relaxed),
        SECONDARY_REPORT[1].load(Ordering::Relaxed),
        SECONDARY_REPORT[2].load(Ordering::Relaxed),
        SECONDARY_REPORT[3].load(Ordering::Relaxed),
        SECONDARY_REPORT[4].load(Ordering::Relaxed),
        SECONDARY_REPORT[5].load(Ordering::Relaxed),
    ]
}

/// Rings another core's doorbell.
///
/// Apple's fast IPI is a system-register write, not an interrupt-controller
/// transaction: no AIC, no MMIO, no lock. `IPI_RR_GLOBAL_EL1` takes the target's
/// affinity as `aff0 | (aff1 << 16)`, which is why the `MPIDR` is taken apart
/// rather than passed whole.
///
/// # Safety
///
/// Wakes another CPU. The target must be running code that expects it -- here,
/// the `wfe` loop in `brainix_secondary_entry`.
pub unsafe fn ring(target_mpidr: u64) {
    let affinity = (target_mpidr & 0xFF) | ((target_mpidr & 0xFF00) << 8);
    // SAFETY: a single system-register write with no memory operands. `dsb`
    // first so anything the target is expected to observe is visible before it
    // is woken to look.
    unsafe {
        core::arch::asm!(
            "dsb sy",
            // SYS_IMP_APL_IPI_RR_GLOBAL_EL1 -- s3_5_c15_c0_1.
            "msr s3_5_c15_c0_1, {affinity}",
            "isb",
            affinity = in(reg) affinity,
            options(nostack)
        );
    }
}

/// Rings `target_mpidr` `count` times, waiting for each to be observed.
///
/// Returns `(doorbells observed, ticks waited)`. Each ring waits for the count
/// to advance before sending the next, so a coalesced pair cannot be reported as
/// two -- the doorbell is level-triggered and two rings before an acknowledge
/// are one wake.
///
/// # Safety
///
/// As [`ring`].
pub unsafe fn ring_and_confirm(target_mpidr: u64, count: u64, timeout_ticks: u64) -> (u64, u64) {
    let report_address = SECONDARY_REPORT.as_ptr() as u64;
    // The count slot is poisoned along with the rest of the report before the
    // core is released, so what matters is how far it advances, not its value.
    let baseline = SECONDARY_REPORT[4].load(Ordering::Relaxed);
    let start = super::registers::physical_counter();
    for _ in 0..count {
        let before = SECONDARY_REPORT[4].load(Ordering::Relaxed);
        // SAFETY: delegated to `ring`'s contract.
        unsafe { ring(target_mpidr) };
        loop {
            // SAFETY: the report lives in this image, which is mapped.
            unsafe { refresh_from_memory(report_address, 48) };
            if SECONDARY_REPORT[4].load(Ordering::Relaxed) != before {
                break;
            }
            if super::registers::physical_counter().wrapping_sub(start) > timeout_ticks {
                return (
                    SECONDARY_REPORT[4]
                        .load(Ordering::Relaxed)
                        .wrapping_sub(baseline),
                    super::registers::physical_counter().wrapping_sub(start),
                );
            }
        }
    }
    (
        SECONDARY_REPORT[4]
            .load(Ordering::Relaxed)
            .wrapping_sub(baseline),
        super::registers::physical_counter().wrapping_sub(start),
    )
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
        clean_to_coherency(report_address, 48);
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
        unsafe { refresh_from_memory(report_address, 48) };
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

/// Posts one unit of work to a parked core and waits for it.
///
/// `function` must be a `extern "C" fn(u64, u64) -> u64` that runs correctly on
/// a core with **the MMU off and caches off**. That is a real constraint, not a
/// formality: it may not touch anything the boot core has left dirty in cache,
/// and every address it uses is physical.
///
/// Returns `(result, ticks waited)`, or `None` on timeout.
///
/// # Safety
///
/// Runs `function` on another CPU. It must be safe to execute there under the
/// conditions above, and `target_mpidr` must name the core parked in
/// [`secondary_entry_address`]'s loop.
pub unsafe fn dispatch(
    target_mpidr: u64,
    function: u64,
    arg0: u64,
    arg1: u64,
    timeout_ticks: u64,
) -> Option<(u64, u64)> {
    let request = WORK[0].load(Ordering::Relaxed).wrapping_add(1);
    // Function and arguments before the request that publishes them. The
    // secondary reads the request first and only then the rest, so this order
    // is what makes the pair a handshake rather than a race.
    WORK[1].store(function, Ordering::Relaxed);
    WORK[2].store(arg0, Ordering::Relaxed);
    WORK[3].store(arg1, Ordering::Relaxed);
    WORK[0].store(request, Ordering::Release);

    let work_address = WORK.as_ptr() as u64;
    // SAFETY: `WORK` is in this image and the secondary reads it with its MMU
    // off, so it must be visible at the point of coherency before the doorbell.
    unsafe {
        clean_to_coherency(work_address, 48);
        ring(target_mpidr);
    }

    let start = super::registers::physical_counter();
    loop {
        // SAFETY: as above -- the secondary's stores bypass this core's cache.
        unsafe { refresh_from_memory(work_address, 48) };
        if WORK[5].load(Ordering::Acquire) == request {
            return Some((
                WORK[4].load(Ordering::Relaxed),
                super::registers::physical_counter().wrapping_sub(start),
            ));
        }
        if super::registers::physical_counter().wrapping_sub(start) > timeout_ticks {
            return None;
        }
    }
}

/// A work item that proves the mechanism: sums `start..start + count`.
///
/// Chosen because its answer is checkable in closed form -- the boot core knows
/// what it should be without running it -- so a wrong result is distinguishable
/// from no result. It touches no memory, which keeps this test about dispatch
/// rather than about cache coherency, and it is `extern "C"` because the stub
/// calls it through a raw pointer.
#[no_mangle]
pub extern "C" fn brainix_secondary_sum(start: u64, count: u64) -> u64 {
    let mut total = 0u64;
    let mut index = 0u64;
    while index < count {
        total = total.wrapping_add(start.wrapping_add(index));
        index = index.wrapping_add(1);
    }
    total
}

/// Address of [`brainix_secondary_sum`], for posting it as work.
pub fn secondary_sum_address() -> u64 {
    brainix_secondary_sum as *const () as u64
}
