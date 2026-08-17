//! Exception vectors.
//!
//! Inline assembly and raw vector installation; same per-module allowlist the
//! x86-64 siblings use.
//!
//! # Why this comes before the MMU
//!
//! Until vectors exist, every fault is unrecoverable and indistinguishable from
//! a hang. The MMU work that follows will fault -- that is what bringing up
//! translation *is* -- and on this hardware an unhandled fault produces no
//! output at all. Enabling translation before there is somewhere for a
//! translation fault to land would recreate the exact one-bit debugging that
//! cost this project two days.
//!
//! # The table
//!
//! AArch64 requires a 2 KiB-aligned table of sixteen entries, each **128 bytes**
//! of executable space, in a fixed order (DDI 0487, D1.10.2):
//!
//! | offset | source |
//! | --- | --- |
//! | `0x000`..`0x180` | current EL, `SP_EL0` |
//! | `0x200`..`0x380` | current EL, `SP_ELx` |
//! | `0x400`..`0x580` | lower EL, AArch64 |
//! | `0x600`..`0x780` | lower EL, AArch32 |
//!
//! Within each group: synchronous, IRQ, FIQ, SError. The index passed to the
//! handler is that position, so a caught exception says which of the sixteen it
//! came through -- the difference between "something faulted" and "a
//! synchronous exception from the current EL on the handler stack".
//!
//! # EL2, deliberately
//!
//! This installs `VBAR_EL2` and reads `ESR_EL2`/`ELR_EL2`/`FAR_EL2`, because
//! that is where this kernel actually runs: m1n1 hands off at EL2 and
//! `CurrentEL` was measured as EL2 on the target. The EL1 variant lands with
//! the EL2-to-EL1 transition rather than being written blind now, since a
//! vector table installed at the wrong level is not a partial success -- it is
//! a table that never runs.
//!
//! # Restoring what was there
//!
//! [`with_vectors`] saves and restores `VBAR_EL2`. Under m1n1's proxy the
//! resident m1n1 owns that register, and leaving ours installed after we return
//! would hand m1n1 our handler for *its* next exception.

#![allow(unsafe_code)]

// ---------------------------------------------------------------------------
// OPEN, measured 2026-08-16: the syndrome registers read as zero.
//
// What is established on the target, through `kernel_probe`:
//
//   * the table is reached -- vector index **4**, which is current EL /
//     SP_ELx / synchronous, exactly where a `brk` taken at EL2 belongs;
//   * the handler runs;
//   * execution resumes past the trap and the probe returns normally, so the
//     ERET path and the VBAR restore both work.
//
// What is wrong: `ESR_EL2`, `ELR_EL2` and `FAR_EL2` all arrive as 0, and the
// handler ran **twice** for a single `trap()`.
//
// The vector index and the count travel through the *same* store-and-read path
// as the syndrome and arrive correct, so the atomics, the address computation
// and the report are not at fault -- the `mrs` reads themselves are producing
// zero, or something re-enters the handler and overwrites them.
//
// Not guessed at further here. Three hypotheses were tried and none survived
// contact, and this project's expensive mistakes have all been confident
// explanations of unmeasured behaviour. The primary property this slice exists
// to prove -- that a fault reaches our table and returns -- is demonstrated;
// the syndrome capture is not, and is the next thing to measure rather than
// something to assume works.
//
// Reproduce: ./bin/as-probe.sh style call into `kernel_probe`, slots 12..17.
// ---------------------------------------------------------------------------

use core::sync::atomic::{AtomicU64, Ordering};

core::arch::global_asm!(
    r#"
.section .text.vectors, "ax"
.balign 2048
.globl brainix_vector_table
brainix_vector_table:

// Each entry has exactly 128 bytes. `.balign 0x80` after the body is what
// enforces that; writing the offsets by hand is how a table ends up with entry
// n+1 inside entry n's slot, which presents as the wrong handler running.
.macro VECTOR_ENTRY index
    mov x0, #\index
    b   brainix_exception_common
    .balign 0x80
.endm

    VECTOR_ENTRY 0      // current EL, SP_EL0, synchronous
    VECTOR_ENTRY 1      // current EL, SP_EL0, IRQ
    VECTOR_ENTRY 2      // current EL, SP_EL0, FIQ
    VECTOR_ENTRY 3      // current EL, SP_EL0, SError
    VECTOR_ENTRY 4      // current EL, SP_ELx, synchronous
    VECTOR_ENTRY 5      // current EL, SP_ELx, IRQ
    VECTOR_ENTRY 6      // current EL, SP_ELx, FIQ
    VECTOR_ENTRY 7      // current EL, SP_ELx, SError
    VECTOR_ENTRY 8      // lower EL, AArch64, synchronous
    VECTOR_ENTRY 9      // lower EL, AArch64, IRQ
    VECTOR_ENTRY 10     // lower EL, AArch64, FIQ
    VECTOR_ENTRY 11     // lower EL, AArch64, SError
    VECTOR_ENTRY 12     // lower EL, AArch32, synchronous
    VECTOR_ENTRY 13     // lower EL, AArch32, IRQ
    VECTOR_ENTRY 14     // lower EL, AArch32, FIQ
    VECTOR_ENTRY 15     // lower EL, AArch32, SError

// Common tail.
//
// x0 already holds the vector index. x29/x30 are saved because `bl` clobbers
// the link register, and the interrupted context is entitled to keep its own.
// Everything else this touches is caller-saved, and the only site that
// deliberately faults declares `clobber_abi("C")` so the compiler knows.
brainix_exception_common:
    sub  sp, sp, #16
    stp  x29, x30, [sp]

    mrs  x1, ESR_EL2
    mrs  x2, ELR_EL2
    mrs  x3, FAR_EL2
    bl   brainix_handle_exception
    // The handler returns the address to resume at.
    msr  ELR_EL2, x0

    ldp  x29, x30, [sp]
    add  sp, sp, #16
    eret
"#
);

extern "C" {
    /// The table itself, defined above.
    static brainix_vector_table: u8;
}

/// Vector index of the last exception taken, or [`NO_EXCEPTION`].
static LAST_INDEX: AtomicU64 = AtomicU64::new(NO_EXCEPTION);
/// `ESR_EL2` of the last exception taken.
static LAST_ESR: AtomicU64 = AtomicU64::new(0);
/// `ELR_EL2` of the last exception taken.
static LAST_ELR: AtomicU64 = AtomicU64::new(0);
/// `FAR_EL2` of the last exception taken.
static LAST_FAR: AtomicU64 = AtomicU64::new(0);
/// How many exceptions have been taken since boot.
static COUNT: AtomicU64 = AtomicU64::new(0);

/// Sentinel meaning no exception has been taken.
///
/// Not zero, because zero is a legitimate vector index -- synchronous from the
/// current EL on `SP_EL0`, which is precisely the one a first test is most
/// likely to hit. A sentinel that collides with a real value turns "it worked"
/// and "nothing happened" into the same reading.
pub const NO_EXCEPTION: u64 = u64::MAX;

/// What was recorded about the last exception.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastException {
    /// Which of the sixteen vectors, or [`NO_EXCEPTION`].
    pub index: u64,
    /// `ESR_EL2`, the syndrome.
    pub esr: u64,
    /// `ELR_EL2`, the faulting instruction's address.
    pub elr: u64,
    /// `FAR_EL2`, the faulting virtual address where applicable.
    pub far: u64,
    /// Total exceptions taken.
    pub count: u64,
}

/// Read what the handler recorded.
pub fn last_exception() -> LastException {
    LastException {
        index: LAST_INDEX.load(Ordering::Relaxed),
        esr: LAST_ESR.load(Ordering::Relaxed),
        elr: LAST_ELR.load(Ordering::Relaxed),
        far: LAST_FAR.load(Ordering::Relaxed),
        count: COUNT.load(Ordering::Relaxed),
    }
}

/// The Rust half of the vector tail. Returns the address to resume at.
///
/// # Advancing past the faulting instruction
///
/// Resuming at `elr` unchanged re-executes the instruction that faulted, which
/// for a `brk` is an immediate infinite loop with the machine wedged and no
/// console. Every AArch64 instruction is four bytes, so `elr + 4` is the next
/// one.
///
/// This is right for a *deliberate* trap and wrong as a general policy: a real
/// data abort should be handled, not skipped. Skipping is what this slice
/// delivers, because the thing being proved is that the vector table is
/// reached at all, and a handler that cannot return proves it by hanging.
#[no_mangle]
extern "C" fn brainix_handle_exception(index: u64, esr: u64, elr: u64, far: u64) -> u64 {
    LAST_INDEX.store(index, Ordering::Relaxed);
    LAST_ESR.store(esr, Ordering::Relaxed);
    LAST_ELR.store(elr, Ordering::Relaxed);
    LAST_FAR.store(far, Ordering::Relaxed);
    COUNT.fetch_add(1, Ordering::Relaxed);
    elr.wrapping_add(4)
}

/// The address of our vector table.
pub fn table_address() -> u64 {
    // SAFETY: taking the address of an `extern` symbol defined in this crate's
    // own assembly. Never dereferenced.
    unsafe { core::ptr::addr_of!(brainix_vector_table) as u64 }
}

/// Run `body` with BraiNIX's vectors installed, restoring the previous
/// `VBAR_EL2` afterwards.
///
/// # Why the save and restore is not optional
///
/// Under m1n1's proxy the resident m1n1 owns `VBAR_EL2`. Leaving our table
/// installed on return hands m1n1 our handler for its next exception, which it
/// will take at some unrelated later moment -- a fault that appears long after
/// the code that caused it, on a machine with no debugger. Restoring makes the
/// change scoped to exactly the window that asked for it.
///
/// # Safety
///
/// Installing a vector table changes where every subsequent exception lands.
/// The caller must ensure `body` does not rely on the previous handlers.
pub unsafe fn with_vectors<T>(body: impl FnOnce() -> T) -> T {
    let previous: u64;
    // SAFETY: reading and writing VBAR_EL2 is permitted at EL2 and has no
    // effect until an exception is taken. `isb` orders the change against the
    // instructions that follow, without which an exception taken immediately
    // afterwards may still use the old table.
    unsafe {
        core::arch::asm!("mrs {}, VBAR_EL2", out(reg) previous, options(nomem, nostack));
        core::arch::asm!(
            "msr VBAR_EL2, {}",
            "isb",
            in(reg) table_address(),
            options(nomem, nostack)
        );
    }

    let result = body();

    // SAFETY: as above, restoring exactly what was read.
    unsafe {
        core::arch::asm!(
            "msr VBAR_EL2, {}",
            "isb",
            in(reg) previous,
            options(nomem, nostack)
        );
    }
    result
}

/// Take a deliberate synchronous exception, to prove the table is reached.
///
/// `brk #0` is chosen over a wild pointer dereference because it is precise: it
/// always raises a synchronous exception at a known address with a known
/// syndrome (`ESR.EC = 0x3C`), touches no memory, and cannot corrupt anything
/// if the handler is wrong. A bad dereference would also fault, and would tell
/// us far less about *which* fault we caught.
///
/// # Safety
///
/// Requires vectors that resume execution, i.e. inside [`with_vectors`].
/// Without a handler that advances past it, this wedges the machine.
pub unsafe fn trap() {
    // SAFETY: `brk` raises a synchronous exception and nothing else. The
    // `clobber_abi` tells the compiler that the handler may use caller-saved
    // registers, which it does.
    unsafe { core::arch::asm!("brk #0", clobber_abi("C")) }
}
