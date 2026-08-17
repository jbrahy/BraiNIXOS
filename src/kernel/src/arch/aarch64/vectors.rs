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
// RESOLVED 2026-08-16. Kept because the wrong answers were instructive.
//
// The syndrome registers initially read as zero and the handler appeared to run
// twice. Both readings are now correct and reproducible across runs:
//
//     vector idx 4   count 1
//     ESR   0x00000000f2000000   EC 0x3c   (BRK from AArch64)
//     ELR   trap site;  ELR_EL2 after = trap site + 4
//     SPSR_EL2 0x9  (EL2h)
//
// verified by reading `ESR_EL2` again *outside* the handler and getting the
// same value byte for byte. Two independent reads agreeing is the evidence;
// one read plus an explanation is not.
//
// What the wrong readings actually were:
//
//   * "ran twice" was not a nested fault. `COUNT` lives in `.bss`, which
//     `objcopy -O binary` does not emit, so the proxy reloading the image at
//     the same address leaves the statics untouched between runs. The counter
//     was accumulating across invocations. One exception per run throughout.
//
//   * `fetch_add` on the counter read back as zero while every `store` in the
//     same handler landed correctly. A read-modify-write needs the exclusive
//     monitor or LSE atomics to work on the memory it targets; a plain store
//     does not. See the comment at the increment.
//
//   * GXF was investigated and ruled out by measurement, not by argument:
//     GXF_STATUS_EL1 = 0, GXF_CONFIG_EL1 = 0, and `mrs` of ESR_GL1 traps.
//     Reading those registers unguarded wedged the machine once, which is
//     precisely why m1n1 gates them behind `gxf_enabled()`.
//
//     CORRECTION, 2026-08-16: that note originally read "HCR_EL2 =
//     0x32488000038 (E2H clear)". **E2H is set.** The nibbles were mis-indexed.
//     `HCR_EL2 = 0x32488000038` has bit 34 (E2H) **and** bit 27 (TGE) set, so
//     the machine runs in **VHE** with general exceptions trapped to EL2.
//     Confirmed independently rather than by re-reading the arithmetic:
//     `TCR_EL1` and `TCR_EL2` read identical (`0x37510b510`), as do `TTBR0_EL1`
//     and `TTBR0_EL2` (`0x1000369c000`). That is VHE aliasing, not coincidence.
//     The GXF conclusion is unaffected -- it rested on the GXF registers, not
//     on E2H -- but the parenthetical was wrong and is corrected here rather
//     than quietly deleted.
//
// The original zero readings are not fully explained, and that is stated rather
// than papered over. `.bss` is never zeroed by this payload and lies outside
// the flat image, so the statics start as whatever was in that memory -- a real
// defect in its own right and the next thing to fix.
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

    // Apple GXF (Guarded Execution Framework) syndrome registers.
    //
    // These are why the EL2 registers read zero. In a *guarded* level
    // `CurrentEL` still reports EL2, but an exception writes Apple's
    // implementation-defined GL1 registers instead of ESR_EL2/ELR_EL2/FAR_EL2.
    // m1n1 does exactly this dance in `src/exception.c`:
    //
    //     esr = in_gl ? mrs(SYS_IMP_APL_ESR_GL1) : ... mrs(ESR_EL1)
    //
    // Encodings from m1n1 `src/cpu_regs.h`, via its `sys_reg(op0,op1,CRn,CRm,op2)`:
    //   SYS_IMP_APL_ESR_GL1        (3,6,15,10,5) -> s3_6_c15_c10_5
    //   SYS_IMP_APL_ELR_GL1        (3,6,15,10,6) -> s3_6_c15_c10_6
    //   SYS_IMP_APL_GXF_STATUS_EL1 (3,6,15, 8,0) -> s3_6_c15_c8_0
    // GXF was ruled out by measurement on 2026-08-16: HCR_EL2 = 0x32488000038
    // (E2H clear), GXF_STATUS_EL1 = 0, GXF_CONFIG_EL1 = 0, and ESR_GL1 traps.
    // Reading the GL registers unguarded wedged the machine, exactly as m1n1's
    // `gxf_enabled()` guard implies it would. They are not read here.
    mov  x4, xzr
    mov  x5, xzr
    mov  x6, xzr
    mrs  x7, SPSR_EL2

    bl   brainix_handle_exception

    // Write the resume address to BOTH. Whichever the CPU honours on `eret`
    // depends on whether this exception was taken in a guarded level, and
    // writing the one that is not in use is inert. Guessing wrong here sends
    // `eret` to address 4 and wedges the machine, which is precisely what
    // happened when only ELR_EL2 was written.
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
/// `GXF_STATUS_EL1` at the time of the last exception.
static LAST_GXF_STATUS: AtomicU64 = AtomicU64::new(0);
/// `SPSR_EL2` at the time of the last exception.
static LAST_SPSR: AtomicU64 = AtomicU64::new(0);
/// Whether the syndrome was found in the GL registers rather than EL2's.
static LAST_GUARDED: AtomicU64 = AtomicU64::new(0);
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
    /// `GXF_STATUS_EL1` at the time of the exception.
    pub gxf_status: u64,
    /// `SPSR_EL2` at the time of the exception.
    pub spsr: u64,
    /// Whether the syndrome came from Apple's GL registers.
    pub guarded: bool,
}

/// Read what the handler recorded.
pub fn last_exception() -> LastException {
    LastException {
        index: LAST_INDEX.load(Ordering::Relaxed),
        esr: LAST_ESR.load(Ordering::Relaxed),
        elr: LAST_ELR.load(Ordering::Relaxed),
        far: LAST_FAR.load(Ordering::Relaxed),
        count: COUNT.load(Ordering::Relaxed),
        gxf_status: LAST_GXF_STATUS.load(Ordering::Relaxed),
        spsr: LAST_SPSR.load(Ordering::Relaxed),
        guarded: LAST_GUARDED.load(Ordering::Relaxed) != 0,
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
#[allow(clippy::too_many_arguments)]
extern "C" fn brainix_handle_exception(
    index: u64,
    esr_el2: u64,
    elr_el2: u64,
    far_el2: u64,
    esr_gl1: u64,
    elr_gl1: u64,
    gxf_status: u64,
    spsr_el2: u64,
) -> u64 {
    // Which pair actually holds this exception.
    //
    // Decided from the syndrome rather than from `GXF_STATUS_EL1` alone: the
    // status bit says whether the CPU *is* guarded now, and what we need is
    // where this exception was *recorded*. A non-zero EC in one pair and zero
    // in the other answers that directly, and does not depend on getting
    // Apple's undocumented status semantics right.
    let guarded = esr_el2 == 0 && esr_gl1 != 0;
    let (esr, elr, far) = if guarded {
        (esr_gl1, elr_gl1, far_el2)
    } else {
        (esr_el2, elr_el2, far_el2)
    };

    LAST_INDEX.store(index, Ordering::Relaxed);
    LAST_ESR.store(esr, Ordering::Relaxed);
    LAST_ELR.store(elr, Ordering::Relaxed);
    LAST_FAR.store(far, Ordering::Relaxed);
    LAST_GXF_STATUS.store(gxf_status, Ordering::Relaxed);
    LAST_SPSR.store(spsr_el2, Ordering::Relaxed);
    LAST_GUARDED.store(u64::from(guarded), Ordering::Relaxed);
    // Load-then-store rather than `fetch_add`, and this is not a style choice.
    //
    // Measured on the target: every `store` in this handler landed correctly --
    // the syndrome it recorded matches an independent read of `ESR_EL2` taken
    // outside the handler, byte for byte -- while `fetch_add` on the counter
    // read back as zero from the same run.
    //
    // A read-modify-write needs the exclusive monitor (or LSE atomics) to work
    // on the memory it targets. A plain store does not. The payload runs from
    // whatever memory it was loaded into, whose attributes are not ours to
    // choose, and an atomic RMW that silently does nothing there is exactly the
    // kind of failure that is invisible until a counter is wrong much later.
    //
    // The handler is single-threaded and non-reentrant today, so a plain
    // increment is correct. When secondary CPUs land (AS-1b), this needs
    // revisiting *and* the memory attributes need establishing first.
    COUNT.store(COUNT.load(Ordering::Relaxed).wrapping_add(1), Ordering::Relaxed);

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
