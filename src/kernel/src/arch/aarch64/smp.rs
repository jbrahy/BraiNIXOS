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
//!
//! # A core with its caches off cannot be given work worth having
//!
//! Dispatch working is not the same as dispatch being useful, and the gap
//! between them is two orders of magnitude. Measured on the target, the same
//! read loop over the same 1 MiB buffer:
//!
//! | core | rate |
//! | --- | --- |
//! | boot core | **11.4 GB/s** |
//! | secondary, as it arrives out of reset | **0.09 GB/s** |
//! | secondary, sharing the boot core's translation | **11.4 GB/s** |
//!
//! **131x.** A matmul chunk handed to a core in the middle state loses to not
//! splitting the work at all -- by so much that every threshold in
//! `Dispatch::minimum_split_bytes` would be meaningless. So a secondary is not
//! a worker until it has adopted the boot core's `MMU`, and
//! [`brainix_secondary_enable_mmu`] is what makes it one. Sharing the tables
//! rather than building new ones is deliberate: the stub already depends on the
//! identity map to resolve its own `adrp`, and a private root would have to
//! reproduce that map exactly to keep it true.
//!
//! # Equal slices are the wrong slices
//!
//! Ten cores reading a partitioned 64 MiB buffer at the same time, each on its
//! own disjoint slice -- the shape a row-split matmul has. Adding workers in
//! release order, which fills the boot cluster first:
//!
//! | workers | aggregate |
//! | --- | --- |
//! | 1 | 11.3 GB/s |
//! | 3 | 34.2 GB/s |
//! | 4 | **39.2 GB/s** |
//! | 5 | **21.9 GB/s** |
//! | 10 | 43.0 GB/s |
//!
//! **The fifth worker makes the machine slower**, and ten workers barely beat
//! four. That is not contention. Measured one at a time, each on its own slice
//! so none warms a cache for the next, the cores are not the same speed:
//! everything in the boot cluster reads at ~11.3 GB/s and everything outside it
//! at ~4.3 GB/s. Equal slices make wall time the *slowest* worker's time, so
//! one 4.3 GB/s core sets the pace and the fast three idle for two thirds of
//! it.
//!
//! Weighting each slice by its worker's own measured rate, same ten cores, same
//! buffer: **60.1 GB/s, 1.40x the equal-slice result and 1.40x the best the
//! equal-slice sweep reached at any width.** So `Dispatch` has to weight rather
//! than divide, and `chunks()` returning a count is not enough of an interface
//! to express that.
//!
//! # The 2.7x is not cache locality, and probably is not the cores
//!
//! At 1 MiB the same split looked like L2 locality: the fast group was the boot
//! core's cluster and the buffer was sitting in its L2. At 64 MiB that
//! explanation is dead -- nothing that size fits in any level of this part's
//! cache -- and the gap is unchanged.
//!
//! What makes it suspicious is the direction. Cluster 0 has four cores and
//! clusters 1 and 2 have three each, which on this part means cluster 0 is the
//! **E** cluster and the slow six are the **P** cores. P cores streaming at
//! 38% of E cores is backwards.
//!
//! The leading explanation is clock: `DVFS` is per-cluster, the boot core's
//! cluster is at a running P-state because firmware left it there, and the two
//! clusters that were powered down come up at their reset minimum. Nothing in
//! this kernel has ever written a cluster P-state register. **That is a
//! hypothesis and it has not been measured.** If it is right, the six fastest
//! cores on the machine are currently the six slowest, and programming per-
//! cluster `DVFS` is worth more than any other core-count work.
//!
//! One more caveat on all of these numbers: 60 GB/s against a part that has
//! roughly 200 GB/s of memory bandwidth means this loop is issue-bound, not
//! bandwidth-bound. They measure what *this scalar read loop* achieves per
//! core, not what the machine's memory system can do.

#![allow(unsafe_code)]

use crate::aarch64_cpus::{
    slot_for_cpu, slot_for_mpidr, start_core_bit, start_enable_bit, Cpu, MAX_SLOTS,
    RVBAR_ADDRESS, RVBAR_LOCK,
};
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

/// Slots in the report, and the size every cache-maintenance site derives from.
///
/// **This is a constant because a literal here was wrong once and cost hours.**
/// The report was 6 slots and three sites cleaned "48". Growing it to 14 left
/// those three behind, and the consequence is not a missing value: the proxy
/// loads this image *through the boot core's caches*, so the tail of the report
/// sits dirty in cache while DRAM still holds whatever was there before. The
/// boot core reads its own cached copy and sees the shipped initialiser; the
/// secondary reads DRAM with its caches off and sees the previous run's
/// garbage. Both are self-consistent, neither is right, and they disagree only
/// past the 48th byte.
const REPORT_SLOTS: usize = 14;

/// The report's size in bytes.
const REPORT_BYTES: u64 = (REPORT_SLOTS * 8) as u64;

/// Bytes in one core's work slot: request, function, two arguments, result,
/// completion.
const WORK_BYTES: u64 = 48;

/// Bytes of stack per core.
const STACK_BYTES: u64 = 16384;

/// What every slot reads before a secondary has touched it.
///
/// One list, used both as the static's initialiser and as the reset before a
/// release, so the two cannot drift. They did: the reset poisoned all of them
/// including the two counters, and a counter that reads `poison + 1` does not
/// look like a counter at all.
const REPORT_INITIAL: [u64; REPORT_SLOTS] = [
    REPORT_POISON, // 0 magic
    REPORT_POISON, // 1 MPIDR_EL1
    REPORT_POISON, // 2 CurrentEL
    REPORT_POISON, // 3 SCTLR_EL1
    0,             // 4 doorbells observed
    REPORT_POISON, // 5 IPI_SR_EL1 as seen
    REPORT_POISON, // 6 ESR_EL2 at fault
    REPORT_POISON, // 7 ELR_EL2 at fault
    REPORT_POISON, // 8 FAR_EL2 at fault
    0,             // 9 faulted
    0,             // 10 calls entered
    REPORT_POISON, // 11 last function dispatched
    0,             // 12 calls returned
    REPORT_POISON, // 13 x21 at fault
];

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
    // Every core runs THIS code, so nothing here may name a single buffer.
    //
    // The report, the work slot and the stack are one per core, and a core
    // finds its own by computing a slot number from its `MPIDR` -- the only
    // thing it has that distinguishes it from its siblings. `aff0` is the core
    // within a cluster and `aff1` is the cluster; three bits and two bits give
    // 32 slots, which is more than this part has cores.
    //
    // It has to be computed rather than assigned because it has to be
    // recomputed after every `wfi` (see below), and anything handed to the core
    // once would have to survive the sleep to be useful.
    mrs  x22, MPIDR_EL1
    ubfx x23, x22, #0, #3
    ubfx x24, x22, #8, #2
    add  x23, x23, x24, lsl #3
    adrp x21, {reports}
    add  x21, x21, :lo12:{reports}
    mov  x25, {report_bytes}
    madd x21, x23, x25, x21

    mrs  x1, MPIDR_EL1
    str  x1, [x21, #8]
    mrs  x1, CurrentEL
    str  x1, [x21, #16]
    mrs  x1, SCTLR_EL1
    str  x1, [x21, #24]

    // The magic LAST, and after a barrier. A reader that sees it is guaranteed
    // to see the three values above; without the `dsb` it could observe the
    // magic while the rest is still poison, and report a core that started with
    // an MPIDR it never wrote.
    dsb  sy
    movz x1, #0x0757
    movk x1, #0xB0, lsl #16
    movk x1, #0x11DA, lsl #32
    movk x1, #0x5EC0, lsl #48
    str  x1, [x21, #0]
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
    // **Re-derive the bases after every wake. Registers do not survive `wfi`
    // on this part.**
    //
    // This was found the hard way. The loop kept its report base in x21 across
    // the sleep, and after a dispatched call returned and the core went back to
    // `wfi` for a few milliseconds, the next doorbell resumed with x21 as
    // *zero* -- so `ldr x3, [x21, #32]` read address 0x20 and took a
    // synchronous external abort. The callees were checked and exonerated:
    // both are leaf functions touching only x8-x10, and moving the bases from
    // caller-saved to callee-saved registers to protect them from callees did
    // not help, because the callee was never the problem.
    //
    // Apple's `wfi` can drop the core into a state deep enough that general
    // registers are not retained -- m1n1 names its own version `deep_wfi`. Two
    // instructions of `adrp`/`add` after each wake costs nothing next to the
    // sleep and removes the assumption entirely: nothing is carried across the
    // `wfi`, so nothing can be lost across it. That is also why the slot is
    // recomputed from `MPIDR` here rather than kept: `MPIDR` is not a general
    // register and does survive.
    mrs  x22, MPIDR_EL1
    ubfx x23, x22, #0, #3
    ubfx x24, x22, #8, #2
    add  x23, x23, x24, lsl #3
    adrp x21, {reports}
    add  x21, x21, :lo12:{reports}
    mov  x25, {report_bytes}
    madd x21, x23, x25, x21
    // SYS_IMP_APL_IPI_SR_EL1 -- s3_5_c15_c1_1, bit 0 is pending.
    mrs  x2, s3_5_c15_c1_1
    tst  x2, #1
    // A spurious wake is normal: `WFE` may return for reasons that are not
    // ours. Going back to sleep rather than counting it is what keeps the
    // count a count of doorbells.
    b.eq 1b
    str  x2, [x21, #40]
    // Acknowledge by writing the pending bit back. Until this happens the
    // condition stays asserted and the next `wfe` returns immediately, which
    // presents as a core spinning at 100% rather than as a missed wake.
    mov  x3, #1
    msr  s3_5_c15_c1_1, x3
    // Load, add, store -- see the note on the exclusive monitor in `vectors`.
    ldr  x3, [x21, #32]
    add  x3, x3, #1
    str  x3, [x21, #32]
    dsb  sy

    // Is there work, or was this doorbell only a wake? This core's work slot,
    // not the machine's -- x23 still holds the slot computed after the wake.
    adrp x19, {works}
    add  x19, x19, :lo12:{works}
    mov  x25, {work_bytes}
    madd x19, x23, x25, x19
    ldr  x20, [x19, #0]         // request sequence
    ldr  x6,  [x19, #40]        // completion sequence
    cmp  x20, x6
    b.eq 1b

    // A stack, established here rather than at entry because nothing before
    // this point needed one and a core that never runs work never touches it.
    // One per core: two cores sharing a stack is two cores writing each other's
    // saved registers, which is the same corruption this loop has already been
    // bitten by once from a different direction.
    adrp x7, {stacks}
    add  x7, x7, :lo12:{stacks}
    mov  x25, {stack_bytes}
    madd x7, x23, x25, x7
    add  x7, x7, {stack_bytes}
    mov  sp, x7

    ldr  x8, [x19, #8]          // function
    ldr  x0, [x19, #16]         // arg0
    ldr  x1, [x19, #24]         // arg1

    // Entered, and what was entered, recorded BEFORE the call. The boot core
    // sees one timeout for three different failures -- work that never
    // started, work that never returned, and work that returned an answer that
    // was lost on the way back -- and cannot tell them apart from the outside.
    // These two counters and the function pointer separate them.
    ldr  x9, [x21, #80]
    add  x9, x9, #1
    str  x9, [x21, #80]
    str  x8, [x21, #88]
    dsb  sy

    blr  x8
    // Re-derive rather than trust, for the same reason as after the `wfi`. A
    // callee is *required* to give x19-x21 back, but this loop has now been
    // wrong twice about which registers survive what, and the cost of not
    // relying on it is four instructions on a path that just ran a matmul.
    // x0 holds the result and nothing below touches it.
    mrs  x22, MPIDR_EL1
    ubfx x23, x22, #0, #3
    ubfx x24, x22, #8, #2
    add  x23, x23, x24, lsl #3
    adrp x19, {works}
    add  x19, x19, :lo12:{works}
    mov  x25, {work_bytes}
    madd x19, x23, x25, x19
    adrp x21, {reports}
    add  x21, x21, :lo12:{reports}
    mov  x25, {report_bytes}
    madd x21, x23, x25, x21
    ldr  x20, [x19, #0]         // the request being served, re-read
    // Result first, then the sequence that publishes it. A reader that sees
    // the sequence match is guaranteed to see this store.
    str  x0, [x19, #32]
    dsb  sy
    str  x20, [x19, #40]
    dsb  sy
    ldr  x9, [x21, #96]
    add  x9, x9, #1
    str  x9, [x21, #96]
    dsb  sy
    b 1b

// A vector table for the secondary, and the reason it exists.
//
// Until the MMU is turned on, this core cannot fault in any way it would
// survive: `VBAR_EL2` is 0 out of reset, so the first abort branches to
// address 0 and executes whatever is there. That is not a core that stops --
// it is a core running arbitrary instructions with full EL2 privilege beside
// the boot core, and it took the whole machine down once before this table
// existed. The symptom was not a fault report; it was the proxy going silent.
//
// All sixteen entries land in the same place. Distinguishing a synchronous
// abort from an SError is what `ESR_EL2` is for, and sixteen different
// handlers would be sixteen chances to get one wrong.
.balign 2048
.globl brainix_secondary_vectors
brainix_secondary_vectors:
.rept 16
    b brainix_secondary_fault
    .balign 128
.endr

brainix_secondary_fault:
    // x26-x28 so this cannot corrupt the loop's own state on the way to
    // recording why the loop failed -- including x21 and x23, which are the two
    // values most worth reading back.
    mrs  x26, MPIDR_EL1
    ubfx x27, x26, #0, #3
    ubfx x28, x26, #8, #2
    add  x27, x27, x28, lsl #3
    adrp x22, {reports}
    add  x22, x22, :lo12:{reports}
    mov  x28, {report_bytes}
    madd x22, x27, x28, x22
    mrs  x23, ESR_EL2
    str  x23, [x22, #48]
    mrs  x23, ELR_EL2
    str  x23, [x22, #56]
    mrs  x23, FAR_EL2
    str  x23, [x22, #64]
    // x21, the loop's own report base. If a fault says it read from a small
    // address, this says whether the base was destroyed or the offset was.
    str  x21, [x22, #104]
    // The flag last and after a barrier, for the same reason the magic is
    // written last: a reader that sees it must be guaranteed to see the three
    // registers that explain it.
    dsb  sy
    mov  x23, #1
    str  x23, [x22, #72]
    dsb  sy
    // Park for good. Returning would re-execute the faulting instruction and
    // fault again, and a core spinning through this handler is a core writing
    // to the report forever.
1:  wfi
    b 1b
.balign 16384
"#,
    reports = sym SECONDARY_REPORTS,
    works = sym WORKS,
    stacks = sym SECONDARY_STACKS,
    report_bytes = const REPORT_BYTES,
    work_bytes = const WORK_BYTES,
    stack_bytes = const STACK_BYTES,
);

extern "C" {
    /// The secondary entry point, defined above.
    static brainix_secondary_entry: u8;
    /// The secondary's vector table, defined above.
    static brainix_secondary_vectors: u8;
}

/// One report per core, laid out back to back so the stub can index it.
///
/// In `.bss` and therefore all zeros in the image, which is the opposite of
/// what a report wants -- "never wrote" has to be distinguishable from "wrote
/// zero". [`release`] writes [`REPORT_INITIAL`] into the slot it is about to
/// use and cleans it, which is a stronger guarantee than the image carrying the
/// poison: it is re-established immediately before each core starts rather than
/// once at load.
static SECONDARY_REPORTS: [AtomicU64; REPORT_SLOTS * MAX_SLOTS] =
    [const { AtomicU64::new(0) }; REPORT_SLOTS * MAX_SLOTS];

/// One stack per core, so it can call Rust.
///
/// A core out of reset has no stack. Everything it does before its first
/// dispatched call -- record four registers, park, count doorbells -- fits in
/// registers, which is why the loop needed none. Running arbitrary work does
/// not, and two cores running arbitrary work on one stack would each be
/// overwriting the other's saved registers.
#[repr(align(16384))]
struct SecondaryStacks([u8; STACK_BYTES as usize * MAX_SLOTS]);

static mut SECONDARY_STACKS: SecondaryStacks =
    SecondaryStacks([0; STACK_BYTES as usize * MAX_SLOTS]);

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
/// One per core: a request posted to one core must not be visible as work to
/// another, and two cores completing at once must not write the same slot.
static WORKS: [AtomicU64; 6 * MAX_SLOTS] = [const { AtomicU64::new(0) }; 6 * MAX_SLOTS];

/// The six `WORKS` entries belonging to `slot`.
fn work_for(slot: usize) -> &'static [AtomicU64] {
    let base = slot * 6;
    &WORKS[base..base + 6]
}

/// The report entries belonging to `slot`.
fn report_for(slot: usize) -> &'static [AtomicU64] {
    let base = slot * REPORT_SLOTS;
    &SECONDARY_REPORTS[base..base + REPORT_SLOTS]
}

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
    /// The per-core state slot this core was given, chosen from the tree.
    pub slot: usize,
    /// Whether the slot the reported `MPIDR` implies is the same one.
    ///
    /// False means the ADT's `cluster-id`/`cluster-core-id` and `MPIDR`'s
    /// `aff1`/`aff0` disagree on this part, and the boot core and the stub are
    /// indexing different buffers. Nothing downstream is trustworthy after
    /// that, which is why it is reported rather than assumed.
    pub slot_matches: bool,
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
///
/// Invalidates first. Before the secondary has its caches the stores bypassed
/// this core's cache; after it has them they may still be sitting in its own.
/// Either way a plain read can return a line this core cached earlier, and the
/// stale value is a plausible-looking number rather than an obvious error.
pub fn report(slot: usize) -> [u64; REPORT_SLOTS] {
    let entries = report_for(slot);
    // SAFETY: the report is in this image and `REPORT_BYTES` long.
    unsafe { refresh_from_memory(entries.as_ptr() as u64, REPORT_BYTES) };
    let mut out = [0u64; REPORT_SLOTS];
    let mut index = 0;
    while index < out.len() {
        out[index] = entries[index].load(Ordering::Relaxed);
        index += 1;
    }
    out
}

/// Where `slot`'s report lives, so a reader can check it is the buffer it means.
pub fn report_address(slot: usize) -> u64 {
    report_for(slot).as_ptr() as u64
}

/// Address of the secondary's vector table.
pub fn secondary_vectors_address() -> u64 {
    // SAFETY: address of an `extern` symbol defined in this crate's assembly.
    unsafe { core::ptr::addr_of!(brainix_secondary_vectors) as u64 }
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
    let entries = report_for(slot_for_mpidr(target_mpidr));
    let report_address = entries.as_ptr() as u64;
    // The count slot is reset along with the rest of the report before the core
    // is released, so what matters is how far it advances, not its value.
    let baseline = entries[4].load(Ordering::Relaxed);
    let start = super::registers::physical_counter();
    for _ in 0..count {
        let before = entries[4].load(Ordering::Relaxed);
        // SAFETY: delegated to `ring`'s contract.
        unsafe { ring(target_mpidr) };
        loop {
            // SAFETY: the report lives in this image, which is mapped.
            unsafe { refresh_from_memory(report_address, REPORT_BYTES) };
            if entries[4].load(Ordering::Relaxed) != before {
                break;
            }
            if super::registers::physical_counter().wrapping_sub(start) > timeout_ticks {
                return (
                    entries[4].load(Ordering::Relaxed).wrapping_sub(baseline),
                    super::registers::physical_counter().wrapping_sub(start),
                );
            }
        }
    }
    (
        entries[4].load(Ordering::Relaxed).wrapping_sub(baseline),
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

    // Reset the report before anything can write it, so a value left over from
    // an earlier attempt cannot be mistaken for a fresh one. To the *shipped*
    // values, not to poison across the board: two of these slots are counters
    // that start at zero, and blanket-poisoning them made "one call ran" read
    // as a number in the quintillions.
    // Which slot this core will use, predicted from the tree. Checked against
    // what it reports below rather than trusted: if `cluster-core-id` and
    // `MPIDR.aff0` ever disagree, two cores share a stack and the failure is
    // silent corruption rather than an error.
    let slot = slot_for_cpu(cpu.cluster, cpu.core);
    let entries = report_for(slot);
    let mut index = 0;
    while index < REPORT_SLOTS {
        entries[index].store(REPORT_INITIAL[index], Ordering::Relaxed);
        index += 1;
    }
    // A released core's work slot starts empty, so its first doorbell is a wake
    // and not a stale request left by a previous run.
    for entry in work_for(slot) {
        entry.store(0, Ordering::Relaxed);
    }

    let report_address = entries.as_ptr() as u64;
    let stack_base = core::ptr::addr_of!(SECONDARY_STACKS) as u64 + slot as u64 * STACK_BYTES;
    // SAFETY: all four ranges are inside this image, which is mapped.
    unsafe {
        clean_to_coherency(report_address, REPORT_BYTES);
        // The stub itself. The secondary fetches it with the MMU off, so it has
        // to be visible at the point of coherency, not merely at the point of
        // unification where the loader left it.
        clean_to_coherency(entry, 16384);
        // **The stack, and this one is not obvious.** The boot core zeroes
        // `.bss` at entry, which leaves the stack's lines *dirty in the boot
        // core's cache*. The secondary then pushes to that stack with its
        // caches off, so its stores land in DRAM -- and a later eviction of the
        // boot core's dirty zero-line writes zero straight over them.
        //
        // What that destroys is whatever a dispatched function saved there:
        // the callee-saved registers. The loop keeps its report base in x21
        // precisely so a callee cannot clobber it, and this turns the callee's
        // faithful save-and-restore into a restore of zero. The symptom was a
        // data abort at the next doorbell reading address 0x20 -- the loop's
        // own `[x21, #32]` with x21 handed back as nothing.
        clean_to_coherency(stack_base, STACK_BYTES);
        // Same reasoning for the work slot, which is also `.bss`.
        clean_to_coherency(work_for(slot).as_ptr() as u64, WORK_BYTES);
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
        slot,
        slot_matches: false,
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
        unsafe { refresh_from_memory(report_address, REPORT_BYTES) };
        if entries[0].load(Ordering::Relaxed) == SECONDARY_MAGIC {
            result.started = true;
            break;
        }
        result.waited_ticks = super::registers::physical_counter().wrapping_sub(start);
        if result.waited_ticks > timeout_ticks {
            break;
        }
    }

    let values = report(slot);
    result.mpidr = values[1];
    result.exception_level = (values[2] >> 2) & 0b11;
    result.sctlr = values[3];
    // The core wrote its own `MPIDR` into a slot chosen from the tree. If the
    // slot that `MPIDR` implies is a different one, the two indexings disagree
    // and every per-core buffer from here on is the wrong buffer.
    result.slot_matches = result.started && slot_for_mpidr(result.mpidr) == slot;
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
    // SAFETY: delegated to this function's contract.
    let request = unsafe { post(target_mpidr, function, arg0, arg1) };
    let start = super::registers::physical_counter();
    // SAFETY: `request` is the one just posted to this core.
    unsafe { collect(target_mpidr, request, timeout_ticks) }
        .map(|result| (result, super::registers::physical_counter().wrapping_sub(start)))
}

/// Posts work to a parked core and returns without waiting for it.
///
/// Split from [`dispatch`] so a caller can start every core before waiting for
/// any of them. Posting and collecting in one call serialises the pool: with
/// four cores it would run four chunks one after another and report the
/// slowest-plus-the-rest, which is exactly the shape of a parallel speedup that
/// is not there.
///
/// Returns the request sequence to hand to [`collect`].
///
/// # Safety
///
/// As [`dispatch`]. Additionally, the caller must not post again to the same
/// core until the previous request has been collected -- the slot holds one
/// request, and overwriting it loses the first.
pub unsafe fn post(target_mpidr: u64, function: u64, arg0: u64, arg1: u64) -> u64 {
    let work = work_for(slot_for_mpidr(target_mpidr));
    let request = work[0].load(Ordering::Relaxed).wrapping_add(1);
    // Function and arguments before the request that publishes them. The
    // secondary reads the request first and only then the rest, so this order
    // is what makes the pair a handshake rather than a race.
    work[1].store(function, Ordering::Relaxed);
    work[2].store(arg0, Ordering::Relaxed);
    work[3].store(arg1, Ordering::Relaxed);
    work[0].store(request, Ordering::Release);

    // SAFETY: the slot is in this image and a secondary without its MMU reads
    // it from memory, so it must be visible at the point of coherency before
    // the doorbell that sends it looking.
    unsafe {
        clean_to_coherency(work.as_ptr() as u64, WORK_BYTES);
        ring(target_mpidr);
    }
    request
}

/// Waits for a request posted by [`post`] and returns its result.
///
/// `None` on timeout.
///
/// # Safety
///
/// `target_mpidr` must be the core `request` was posted to.
pub unsafe fn collect(target_mpidr: u64, request: u64, timeout_ticks: u64) -> Option<u64> {
    let work = work_for(slot_for_mpidr(target_mpidr));
    let work_address = work.as_ptr() as u64;
    let start = super::registers::physical_counter();
    loop {
        // SAFETY: the secondary's stores may bypass this core's cache.
        unsafe { refresh_from_memory(work_address, WORK_BYTES) };
        if work[5].load(Ordering::Acquire) == request {
            return Some(work[4].load(Ordering::Relaxed));
        }
        if super::registers::physical_counter().wrapping_sub(start) > timeout_ticks {
            return None;
        }
    }
}

/// The four registers a secondary needs to translate the way the boot core does.
///
/// | index | register |
/// | --- | --- |
/// | 0 | `MAIR_EL2` |
/// | 1 | `TCR_EL2` |
/// | 2 | `TTBR0_EL2` |
/// | 3 | `SCTLR_EL2`, the value to install |
/// | 4 | `HCR_EL2`, which must be installed **first** |
/// | 5 | `TTBR1_EL2` |
/// | 6 | `VBAR_EL2`, the secondary's own, not the boot core's |
///
/// **The tables are shared, not copied.** Both cores point `TTBR0_EL2` at the
/// same root, which is what makes the identity map the secondary already relies
/// on stay true after it starts translating -- a private root would have to
/// reproduce m1n1's map exactly, and any discrepancy would show up as the
/// secondary faulting on an address the boot core can read.
///
/// **`HCR_EL2` is in this list because of VHE, and leaving it out is a silent
/// disaster.** m1n1 runs with `HCR_EL2.E2H` set, and with `E2H` set `TCR_EL2`
/// and `SCTLR_EL2` take the *EL1* layout -- different fields in different bits.
/// A core out of reset has `E2H` clear. Handing it the boot core's `TCR_EL2`
/// without first handing it the boot core's `HCR_EL2` gives it a value it will
/// decode under the other layout, which is not an error the hardware reports:
/// it is a translation regime configured out of the wrong bits, and the first
/// symptom is the core vanishing on its next instruction fetch.
/// `TTBR1_EL2` is copied even though nothing here uses a high address, because
/// with `E2H` set `TCR_EL2` configures both halves and a `TTBR1` left at its
/// reset value is a live root pointer into whatever happens to be at zero.
static MMU_HANDOFF: [AtomicU64; 7] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Captures this core's translation state for a secondary to adopt.
///
/// Returns the address to post as the argument to
/// [`brainix_secondary_enable_mmu`].
///
/// # Safety
///
/// Reads EL2 system registers. Must be called at EL2, with the translation
/// regime the secondary is meant to share already installed.
pub unsafe fn publish_mmu_handoff() -> u64 {
    use super::registers;
    MMU_HANDOFF[0].store(registers::mair_el2(), Ordering::Relaxed);
    MMU_HANDOFF[1].store(registers::tcr_el2(), Ordering::Relaxed);
    MMU_HANDOFF[2].store(registers::ttbr0_el2(), Ordering::Relaxed);
    MMU_HANDOFF[3].store(registers::sctlr_el2(), Ordering::Relaxed);
    MMU_HANDOFF[4].store(registers::hcr_el2(), Ordering::Relaxed);
    MMU_HANDOFF[5].store(registers::ttbr1_el2(), Ordering::Relaxed);
    MMU_HANDOFF[6].store(secondary_vectors_address(), Ordering::Release);
    let address = MMU_HANDOFF.as_ptr() as u64;
    // The secondary reads this with its MMU still off, so it must be at the
    // point of coherency. This is the last time that is true of anything it
    // reads, which is the point of the exercise.
    // SAFETY: the handoff is in this image and 56 bytes long.
    unsafe { clean_to_coherency(address, 56) };
    address
}

/// Turns the MMU and caches on, on the core that calls it.
///
/// Runs on the secondary as ordinary dispatched work. It is the last thing that
/// core does with its caches off: after the `msr`, every fetch and every load it
/// makes goes through the same translation tables the boot core uses, and the
/// cache-maintenance dance the rest of this module performs stops being
/// necessary for it.
///
/// Returns `SCTLR_EL2` read back, so the boot core sees the value that actually
/// took rather than the value that was requested.
///
/// # Why the barriers are where they are
///
/// `tlbi alle2` before enabling, because a core out of reset has no defined TLB
/// contents and a stale entry for an address this code is about to fetch from
/// would be fatal and silent. `isb` after the `msr` because the very next
/// instruction fetch is the first one translated, and without it the pipeline
/// may already hold instructions fetched under the old regime.
///
/// # Safety
///
/// `handoff` must point at four `u64`s written by [`publish_mmu_handoff`] on a
/// core whose translation tables identity-map this function's own address.
/// Anything else and this core faults on its next instruction fetch with no
/// vector table to catch it.
#[no_mangle]
pub unsafe extern "C" fn brainix_secondary_enable_mmu(handoff: u64, _unused: u64) -> u64 {
    let slots = handoff as *const u64;
    // SAFETY: the caller's contract says seven readable `u64`s live here.
    let (mair, tcr, ttbr0, sctlr, hcr, ttbr1, vbar) = unsafe {
        (
            core::ptr::read_volatile(slots),
            core::ptr::read_volatile(slots.add(1)),
            core::ptr::read_volatile(slots.add(2)),
            core::ptr::read_volatile(slots.add(3)),
            core::ptr::read_volatile(slots.add(4)),
            core::ptr::read_volatile(slots.add(5)),
            core::ptr::read_volatile(slots.add(6)),
        )
    };

    let installed: u64;
    // SAFETY: installs a translation regime this core is not yet using and then
    // enables it. Sound only under the contract above; unrecoverable if that
    // contract is broken, which is why the boot core dispatches this under a
    // timeout rather than assuming it returns.
    unsafe {
        core::arch::asm!(
            // E2H first, and alone, with an `isb` before anything else is
            // written: it decides which layout the three registers below are
            // read in. Writing them first would write them into the other
            // view's fields.
            "msr HCR_EL2,   {hcr}",
            "isb",
            // Vectors BEFORE translation, so the first thing that can go wrong
            // has somewhere to be recorded. Installed while the MMU is still
            // off means this is a physical address, which stays correct after
            // the switch only because the map is an identity map.
            "msr VBAR_EL2,  {vbar}",
            "msr MAIR_EL2,  {mair}",
            "msr TCR_EL2,   {tcr}",
            "msr TTBR0_EL2, {ttbr0}",
            // By encoding: `TTBR1_EL2` is gated on `FEAT_VHE` in the assembler
            // and this target is not built with `+vh`. The register exists on
            // the part -- `registers::ttbr1_el2` already reads it the same way.
            "msr s3_4_c2_c0_1, {ttbr1}",
            "isb",
            "tlbi alle2",
            "dsb sy",
            "isb",
            "msr SCTLR_EL2, {sctlr}",
            "isb",
            "mrs {out}, SCTLR_EL2",
            mair = in(reg) mair,
            tcr = in(reg) tcr,
            ttbr0 = in(reg) ttbr0,
            sctlr = in(reg) sctlr,
            hcr = in(reg) hcr,
            ttbr1 = in(reg) ttbr1,
            vbar = in(reg) vbar,
            out = out(reg) installed,
            options(nostack)
        );
    }
    installed
}

/// Address of [`brainix_secondary_enable_mmu`], for posting it as work.
pub fn secondary_enable_mmu_address() -> u64 {
    brainix_secondary_enable_mmu as *const () as u64
}

/// Words in the buffer the memory-rate measurement reads.
///
/// **64 MiB, and the size is the measurement.** At 1 MiB this buffer sat inside
/// the boot cluster's L2, and the consequence was a table that looked like a
/// story about cores: three secondaries at 11.4 GB/s and six at about 4.4. The
/// split was by cluster, and the fast group was the boot core's own -- they were
/// hitting its L2 while the rest paid a fabric hop for the same lines. Neither
/// number was a memory number.
///
/// A decode streams roughly 151 MB of weights per token and hits nothing. To
/// say anything about that, the buffer has to be past the last level that could
/// hold it: larger than the ~24 MB system cache, not merely larger than an L2.
pub const BENCH_WORDS: usize = 1 << 23;

/// Buffer for measuring what a core with its MMU off can actually read.
///
/// In `.bss`, so it costs nothing in the image. Its contents are written by the
/// boot core immediately before the measurement, which is also what makes the
/// answer checkable in closed form.
#[repr(align(64))]
struct BenchBuffer([u64; BENCH_WORDS]);

static mut BENCH_BUFFER: BenchBuffer = BenchBuffer([0; BENCH_WORDS]);

/// Fills the measurement buffer and returns the checksum a correct read yields.
///
/// Word `i` is set to `i`, so the sum is `n(n-1)/2` and the boot core knows the
/// answer without reading the buffer back. A checksum that comes out zero then
/// means "read memory that was never written", which is exactly the failure a
/// core with its caches off produces when the writes are still dirty elsewhere.
///
/// # Safety
///
/// Takes a mutable reference to a static. No other core may be reading the
/// buffer, which on the dispatch path means: call this before posting work.
pub unsafe fn fill_bench_buffer() -> u64 {
    let base = core::ptr::addr_of_mut!(BENCH_BUFFER) as *mut u64;
    let mut index = 0usize;
    let mut expected = 0u64;
    while index < BENCH_WORDS {
        // SAFETY: `index` is bounded by the buffer's length.
        unsafe { core::ptr::write_volatile(base.add(index), index as u64) };
        expected = expected.wrapping_add(index as u64);
        index += 1;
    }
    // The secondary reads with its MMU off, so these stores must have reached
    // the point of coherency. Without this the checksum comes back as whatever
    // was in that memory, which for a `.bss` buffer is zero -- a plausible
    // number that means the opposite of what it looks like.
    // SAFETY: the buffer is mapped and the length is its own.
    unsafe { clean_to_coherency(base as u64, (BENCH_WORDS * 8) as u64) };
    expected
}

/// Base address of the measurement buffer, for posting it as an argument.
pub fn bench_buffer_address() -> u64 {
    core::ptr::addr_of!(BENCH_BUFFER) as u64
}

/// Sums `words` `u64`s starting at `base`.
///
/// The point is the memory traffic, not the arithmetic: this is the smallest
/// thing that cannot run out of a register file, so the time it takes is the
/// time the core takes to pull `words * 8` bytes in. Volatile because the sum
/// is not the reason it is being called and an optimiser is entitled to notice
/// that.
///
/// # Safety
///
/// `base` must point at `words` readable `u64`s. Called on a core with its MMU
/// off, where that means a physical address.
#[no_mangle]
pub unsafe extern "C" fn brainix_secondary_checksum(base: u64, words: u64) -> u64 {
    let pointer = base as *const u64;
    let mut total = 0u64;
    let mut index = 0u64;
    while index < words {
        // SAFETY: delegated to the caller's contract on `base` and `words`.
        let value = unsafe { core::ptr::read_volatile(pointer.add(index as usize)) };
        total = total.wrapping_add(value);
        index = index.wrapping_add(1);
    }
    total
}

/// Address of [`brainix_secondary_checksum`], for posting it as work.
pub fn secondary_checksum_address() -> u64 {
    brainix_secondary_checksum as *const () as u64
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

