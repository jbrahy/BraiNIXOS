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
// Reserve the frame and save the interrupted x0/x1 BEFORE x0 is overwritten
// with the vector index. Doing the `mov` first would destroy the value we are
// obliged to give back.
.macro VECTOR_ENTRY index
    sub sp, sp, #(16 * 11)
    stp x0, x1, [sp, #(16 * 0)]
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
// Save every caller-saved register, not just the link register.
//
// This handler previously saved x29/x30 alone and clobbered x0-x7 freely. For a
// synchronous trap that is survivable, because the trap site declares
// `clobber_abi("C")` and the compiler plans around it. For an **asynchronous**
// exception it is a bug: the interrupted code is arbitrary, it never agreed to
// anything, and it resumes with registers silently altered.
//
// That is not theoretical. Enabling FIQ delivery produced a run whose report
// buffer came back holding values nothing in the payload ever wrote -- the
// interrupted poll loop had had its registers changed underneath it. An
// interrupt handler owes the interrupted context every register it touches.
brainix_exception_common:
    stp  x2, x3,   [sp, #(16 * 1)]
    stp  x4, x5,   [sp, #(16 * 2)]
    stp  x6, x7,   [sp, #(16 * 3)]
    stp  x8, x9,   [sp, #(16 * 4)]
    stp  x10, x11, [sp, #(16 * 5)]
    stp  x12, x13, [sp, #(16 * 6)]
    stp  x14, x15, [sp, #(16 * 7)]
    stp  x16, x17, [sp, #(16 * 8)]
    stp  x18, x29, [sp, #(16 * 9)]
    str  x30,      [sp, #(16 * 10)]

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

    // Install BOTH halves of the return: address in x0, processor state in x1.
    //
    // `ExceptionReturn` is a 16-byte `#[repr(C)]` pair and comes back in x0/x1.
    // Writing only `ELR_EL2` leaves `SPSR_EL2` holding whatever exception entry
    // put there, which is right exactly when the return resumes at the level the
    // exception came from -- and silently wrong otherwise.
    //
    // That is what hung the EL1 excursion, and why the bisect steps all passed:
    // `hvc` from EL1 enters with `SPSR_EL2` = EL1h, the redirect asks to resume
    // at EL2h, and without this store the `eret` landed back at **EL1**. The next
    // instruction there was the `msr HCR_EL2` that restores the excursion --
    // undefined at EL1 -- so the machine took a fault into an EL1 vector base
    // nothing had ever set. A `brk` taken at EL2 could never show it: there the
    // two levels agree and the stale `SPSR_EL2` happens to be correct.
    msr  ELR_EL2, x0
    msr  SPSR_EL2, x1

    ldp  x0, x1,   [sp, #(16 * 0)]
    ldp  x2, x3,   [sp, #(16 * 1)]
    ldp  x4, x5,   [sp, #(16 * 2)]
    ldp  x6, x7,   [sp, #(16 * 3)]
    ldp  x8, x9,   [sp, #(16 * 4)]
    ldp  x10, x11, [sp, #(16 * 5)]
    ldp  x12, x13, [sp, #(16 * 6)]
    ldp  x14, x15, [sp, #(16 * 7)]
    ldp  x16, x17, [sp, #(16 * 8)]
    ldp  x18, x29, [sp, #(16 * 9)]
    ldr  x30,      [sp, #(16 * 10)]
    add  sp, sp, #(16 * 11)
    eret
"#
);

extern "C" {
    /// The table itself, defined above.
    static brainix_vector_table: u8;
}

// ---------------------------------------------------------------------------
// A second table, for EL1.
//
// The EL2 table above cannot be reused at EL1. It reads `ESR_EL2`/`ELR_EL2`/
// `FAR_EL2`, all of which are undefined at EL1: pointing `VBAR_EL1` at it makes
// the first EL1 fault raise an undefined-instruction exception *inside the
// handler*, which re-enters the handler, forever. So the excursion originally
// left EL1's vectors alone -- and that turned any EL1 fault into a silent hang,
// because nothing had ever written `VBAR_EL1` on this machine either.
//
// This table reads only EL1 registers, and then splits on the syndrome:
//
//   * **`SVC` returns.** A system call is not a failure; the whole point of
//     dispatching one is to go back and carry on. It records the syndrome and
//     `eret`s, which means it owes the interrupted code every register it
//     touched -- the same debt the EL2 handler learned the hard way when a
//     timer FIQ corrupted its neighbours.
//   * **Everything else abandons EL1** via `hvc`, which the EL2 handler's
//     redirect turns into a normal return. An excursion that faulted is over,
//     so that path preserves nothing.
//
// The split is on `ESR_EL1.EC`, not on the vector index. Vector 4 is "current
// EL, SP_ELx, synchronous", which is `SVC` *and* every data abort, alignment
// fault and undefined instruction that EL1 can raise. Returning from those
// would re-execute the faulting instruction forever.
// ---------------------------------------------------------------------------

/// Value each slot of [`EL1_FAULT_RECORD`] starts at.
///
/// Not zero, and not in `.bss`. Zero would be indistinguishable from a handler
/// that ran and read genuine zeroes, and `.bss` is not emitted by
/// `objcopy -O binary` -- a zero-initialised static here would start as whatever
/// was in that memory. A recognisable non-zero initialiser puts the array in
/// `.data`, where the flat image carries it, and makes "never ran" a value you
/// can read rather than infer.
const EL1_FAULT_POISON: u64 = 0xE11F_A017_0000_0000;

/// What an EL1 fault recorded: vector index, `ESR_EL1`, `ELR_EL1`, `FAR_EL1`.
///
/// Written from assembly, which is why it is a plain array at a known layout
/// rather than a struct with accessors.
static EL1_FAULT_RECORD: [AtomicU64; 4] = [
    AtomicU64::new(EL1_FAULT_POISON),
    AtomicU64::new(EL1_FAULT_POISON),
    AtomicU64::new(EL1_FAULT_POISON),
    AtomicU64::new(EL1_FAULT_POISON),
];

/// What an `SVC` recorded: count, `ESR_EL1`, `ELR_EL1`, caller `SPSR.M`.
///
/// The count is first and is what distinguishes "no system call was made" from
/// "one was made and its syndrome happened to be zero". It is incremented with
/// a load, an add and a store rather than `fetch_add`: measured on this target,
/// every plain store in a handler landed correctly while `fetch_add` on a
/// counter read back as zero, because a read-modify-write needs the exclusive
/// monitor to work on the memory it targets and a plain store does not.
///
/// # The count is cumulative, and callers must treat it that way
///
/// The poison initialisers put this array in `.data`, not `.bss`, so
/// `bss::zero` does **not** reset it and the count accumulates for as long as
/// the image stays loaded -- across every `p.call` in a proxy session. That is
/// the same shape as the bug that made the first exception readings
/// unreproducible, arriving from the opposite direction: there, statics were
/// never initialised; here, they are never *re*-initialised.
///
/// It is left this way on purpose. Zeroing the count at every entry point would
/// hide a handler that ran when nothing asked it to. Excursions take a snapshot
/// before they start and report the difference, so each reports what it did
/// rather than what the session has done.
static EL1_SVC_RECORD: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(EL1_FAULT_POISON),
    AtomicU64::new(EL1_FAULT_POISON),
    AtomicU64::new(EL1_FAULT_POISON),
];

/// `ESR_ELx.EC` for an `SVC` executed in AArch64 state.
pub const EC_SVC_AARCH64: u64 = 0x15;

/// `SVC` immediate meaning "record this and put me back where I was".
pub const SVC_RESUME: u64 = 0x55;
/// `SVC` immediate meaning "record this and leave for EL2".
///
/// EL0 has no way to reach EL2 directly, so the way out of a user excursion is
/// for EL1's handler to make the `HVC` on its behalf. Distinguishing the two by
/// **immediate** rather than by a counter keeps the handler stateless: a
/// counter would make the handler's behaviour depend on how many times it had
/// run, which is exactly the property that made the exception statics
/// unreadable across probe runs before `.bss` was zeroed.
pub const SVC_LEAVE: u64 = 0x56;

core::arch::global_asm!(
    r#"
.section .text.vectors, "ax"
.balign 2048
.globl brainix_el1_vector_table
brainix_el1_vector_table:

// Reserve the frame and save the interrupted x0/x1 BEFORE x0 is overwritten
// with the vector index, exactly as the EL2 table does. The SVC path returns to
// EL1, so those two registers have to survive.
.macro EL1_VECTOR_ENTRY index
    sub sp, sp, #(16 * 2)
    stp x0, x1, [sp, #(16 * 0)]
    mov x0, #\index
    b   brainix_el1_common
    .balign 0x80
.endm

    EL1_VECTOR_ENTRY 0      // current EL, SP_EL0, synchronous
    EL1_VECTOR_ENTRY 1
    EL1_VECTOR_ENTRY 2
    EL1_VECTOR_ENTRY 3
    EL1_VECTOR_ENTRY 4      // current EL, SP_ELx, synchronous
    EL1_VECTOR_ENTRY 5
    EL1_VECTOR_ENTRY 6
    EL1_VECTOR_ENTRY 7
    EL1_VECTOR_ENTRY 8      // lower EL, AArch64, synchronous
    EL1_VECTOR_ENTRY 9
    EL1_VECTOR_ENTRY 10
    EL1_VECTOR_ENTRY 11
    EL1_VECTOR_ENTRY 12     // lower EL, AArch32, synchronous
    EL1_VECTOR_ENTRY 13
    EL1_VECTOR_ENTRY 14
    EL1_VECTOR_ENTRY 15

// `adrp`/`:lo12:` rather than a literal address: this image is loaded wherever
// the proxy's allocator put it, not where it was linked, so every reference to
// its own data has to be PC-relative or it addresses someone else's memory.
brainix_el1_common:
    stp x2, x3, [sp, #(16 * 1)]
    mrs x2, ESR_EL1
    lsr x3, x2, #26
    and x3, x3, #0x3F
    cmp x3, #0x15               // EC 0x15: SVC from AArch64
    b.eq 1f

    // ---- not a system call: record it and abandon EL1 --------------------
    // Nothing is restored, because nothing returns here. The `hvc` leaves EL1
    // for good and the EL2 redirect resumes at the landing pad.
    adrp x1, {fault}
    add  x1, x1, :lo12:{fault}
    str  x0, [x1, #0]
    str  x2, [x1, #8]
    mrs  x3, ELR_EL1
    str  x3, [x1, #16]
    mrs  x3, FAR_EL1
    str  x3, [x1, #24]
    hvc  #0

    // ---- a system call: record it, then resume or leave -------------------
1:
    adrp x1, {svc}
    add  x1, x1, :lo12:{svc}
    // Load, add, store. See EL1_SVC_RECORD: `fetch_add` does not work on the
    // memory this payload runs from.
    ldr  x3, [x1, #0]
    add  x3, x3, #1
    str  x3, [x1, #0]
    str  x2, [x1, #8]
    // ELR_EL1 already points at the instruction AFTER the `svc`. Advancing it
    // the way the EL2 handler advances past a `brk` would skip a real
    // instruction of the caller.
    mrs  x3, ELR_EL1
    str  x3, [x1, #16]
    // Record the level the call came from, taken from SPSR_EL1.M[3:0]: 0 is
    // EL0t, 4 is EL1t, 5 is EL1h. Without this, an SVC from EL0 and one from
    // EL1 produce identical records, and "userspace made a system call" is the
    // claim the whole excursion exists to support.
    mrs  x3, SPSR_EL1
    and  x3, x3, #0xF
    str  x3, [x1, #24]
    // SVC_LEAVE means the caller cannot get itself home: EL0 has no way to
    // reach EL2, so EL1 makes the HVC on its behalf. The redirect the excursion
    // registered is still pending, so this lands back at the EL2 landing pad.
    and  x3, x2, #0xFFFF
    cmp  x3, #0x56
    b.eq 2f
    ldp  x2, x3, [sp, #(16 * 1)]
    ldp  x0, x1, [sp, #(16 * 0)]
    add  sp, sp, #(16 * 2)
    eret
2:
    hvc  #0
"#,
    fault = sym EL1_FAULT_RECORD,
    svc = sym EL1_SVC_RECORD,
);

extern "C" {
    /// The EL1 table, defined above.
    static brainix_el1_vector_table: u8;
}

/// The address of the EL1 vector table, for `VBAR_EL12`.
pub fn el1_table_address() -> u64 {
    // SAFETY: taking the address of an `extern` symbol defined in this crate's
    // own assembly. Never dereferenced.
    unsafe { core::ptr::addr_of!(brainix_el1_vector_table) as u64 }
}

/// What an EL1 fault recorded, or all [`EL1_FAULT_POISON`] if none was taken.
pub fn el1_fault() -> [u64; 4] {
    [
        EL1_FAULT_RECORD[0].load(Ordering::Relaxed),
        EL1_FAULT_RECORD[1].load(Ordering::Relaxed),
        EL1_FAULT_RECORD[2].load(Ordering::Relaxed),
        EL1_FAULT_RECORD[3].load(Ordering::Relaxed),
    ]
}

/// What the last `SVC` recorded: `[count, ESR_EL1, ELR_EL1, caller SPSR.M]`.
///
/// A count of zero means no system call was dispatched. The caller mode is
/// `SPSR_EL1.M[3:0]`: **0 is EL0t**, 4 is EL1t, 5 is EL1h.
pub fn el1_svc() -> [u64; 4] {
    [
        EL1_SVC_RECORD[0].load(Ordering::Relaxed),
        EL1_SVC_RECORD[1].load(Ordering::Relaxed),
        EL1_SVC_RECORD[2].load(Ordering::Relaxed),
        EL1_SVC_RECORD[3].load(Ordering::Relaxed),
    ]
}

// ---------------------------------------------------------------------------
// Code that runs at EL0.
//
// In a section of its own, aligned to the 16 KiB granule at both ends, because
// the page containing it is going to be marked reachable from EL0. Anything
// sharing that page is handed to userspace along with it -- and at this granule
// a page holds four thousand instructions, so "it will probably be alone" is not
// a thing worth assuming. The trailing `.balign` pads the section out so the
// next function starts on the following page.
// ---------------------------------------------------------------------------

core::arch::global_asm!(
    r#"
.section .text.el0, "ax"
.balign 16384
.globl brainix_el0_entry
brainix_el0_entry:
    // Two calls, because one proves half of it. The first has to come back --
    // that is a system call returning to userspace, which is the thing a kernel
    // does constantly and a trap test never shows. The second is the way out.
    svc #0x55
    svc #0x56
    // Unreachable. A landing pad that falls through into whatever the linker
    // put next would run kernel code at EL0 with no indication it had happened.
1:  b 1b
.balign 16384
"#
);

extern "C" {
    /// The EL0 entry point, defined above.
    static brainix_el0_entry: u8;
}

/// Address of the code that runs at EL0.
pub fn el0_entry_address() -> u64 {
    // SAFETY: taking the address of an `extern` symbol defined in this crate's
    // own assembly. Never dereferenced.
    unsafe { core::ptr::addr_of!(brainix_el0_entry) as u64 }
}

// ---------------------------------------------------------------------------
// Branch targets for the BTI test.
//
// In a page of their own, for a different reason than the EL0 code: BTI
// constrains branches by the page **the target is in**, not the page the branch
// is in. Marking only this page Guarded means an indirect branch into it must
// land on a `BTI` instruction, while everything else -- including the exception
// handler that has to catch the resulting fault -- keeps branching normally.
//
// Guarding all of DRAM instead would have been simpler and would have applied
// BTI to the handler as well. A Branch Target Exception raised inside the
// handler for a Branch Target Exception is a hang, on a machine with no
// console, and it would have looked like BTI simply not working.
// ---------------------------------------------------------------------------

core::arch::global_asm!(
    r#"
.section .text.bti, "ax"
.balign 16384
.globl brainix_bti_no_landing
brainix_bti_no_landing:
    // Deliberately NOT a landing pad. A `blr` here from a Guarded page must
    // raise a Branch Target Exception, EC 0x0D.
    //
    // The exception is taken ON this instruction, so ELR points here; the
    // handler advances past it and the `ret` below returns to the caller. That
    // is what makes a *failed* branch recoverable and therefore measurable.
    nop
    ret
.balign 64
.globl brainix_bti_landing
brainix_bti_landing:
    // `hint #34` is `BTI c`, the landing pad a `BLR` requires. `BTI j`
    // (`hint #36`) accepts `BR` and would NOT accept this call -- the
    // distinction is the point of the instruction, and getting it wrong gives a
    // fault that looks like BTI being broken.
    //
    // Written as a HINT because the architecture puts it there so a part
    // without FEAT_BTI executes it as a NOP, and the raw form assembles without
    // the target enabling the feature.
    hint #34
    ret
.balign 16384
"#
);

extern "C" {
    /// A branch target that is not a landing pad.
    static brainix_bti_no_landing: u8;
    /// A branch target that is a valid `BLR` landing pad.
    static brainix_bti_landing: u8;
}

/// Address of the branch target that is **not** a landing pad.
pub fn bti_no_landing_address() -> u64 {
    // SAFETY: address of an `extern` symbol defined in this crate's assembly.
    unsafe { core::ptr::addr_of!(brainix_bti_no_landing) as u64 }
}

/// Address of the valid `BLR` landing pad.
pub fn bti_landing_address() -> u64 {
    // SAFETY: as above.
    unsafe { core::ptr::addr_of!(brainix_bti_landing) as u64 }
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

/// Where a lower-EL trap should resume, and with which `SPSR`.
///
/// Set before dropping to EL1 and consumed by the handler when the trap comes
/// back up. Zero means "no redirection pending", so an ordinary exception
/// returns where it came from.
static REDIRECT_PC: AtomicU64 = AtomicU64::new(0);
/// `SPSR` to install alongside [`REDIRECT_PC`].
static REDIRECT_SPSR: AtomicU64 = AtomicU64::new(0);

/// Arrange for the next lower-EL synchronous trap to resume at `pc` with `spsr`.
///
/// # Safety
///
/// The caller must ensure `pc` is a valid return site at the level `spsr`
/// selects. Getting it wrong lands execution at an arbitrary address with an
/// arbitrary level, which on this platform is a hang.
pub unsafe fn redirect_lower_el_trap(pc: u64, spsr: u64) {
    REDIRECT_SPSR.store(spsr, Ordering::Relaxed);
    REDIRECT_PC.store(pc, Ordering::Relaxed);
}

/// Raw slots for [`redirect_lower_el_trap`], for assembly that must register
/// its own return site.
///
/// A block that computes its landing pad with `adr` cannot hand that value to
/// Rust before it needs to be stored -- the label only exists inside the block.
/// Storing through these pointers keeps the registration and the `eret` in one
/// instruction stream, which matters because after `TGE` is cleared a stray
/// exception has nowhere else to go.
pub fn redirect_slots() -> (*mut u64, *mut u64) {
    (REDIRECT_PC.as_ptr(), REDIRECT_SPSR.as_ptr())
}

/// Clear any pending redirection.
pub fn clear_redirect() {
    REDIRECT_PC.store(0, Ordering::Relaxed);
    REDIRECT_SPSR.store(0, Ordering::Relaxed);
}

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
/// What the assembly tail installs before `eret`.
#[repr(C)]
pub struct ExceptionReturn {
    /// Address to resume at.
    pub elr: u64,
    /// Processor state to resume with.
    pub spsr: u64,
}

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
) -> ExceptionReturn {
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

    // Interrupts do not have a faulting instruction to step over.
    //
    // The table's sixteen entries run synchronous, IRQ, FIQ, SError within each
    // group of four, so `index % 4 == 0` is exactly the synchronous ones.
    // Advancing past an IRQ or FIQ would skip an instruction of the interrupted
    // code -- silently, and at whatever point the interrupt happened to land.
    let synchronous = index % 4 == 0;

    // A level-triggered timer interrupt stays asserted until the condition is
    // cleared. Returning without clearing it re-enters this handler
    // immediately and forever, which on this platform is a hang with no
    // console. Disabling the timer removes the condition.
    if index % 4 == 2 || index % 4 == 1 {
        // SAFETY: writing the timer control register; no memory effects.
        unsafe {
            core::arch::asm!("msr CNTP_CTL_EL0, xzr", "isb", options(nomem, nostack));
        }
    }

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
    COUNT.store(
        COUNT.load(Ordering::Relaxed).wrapping_add(1),
        Ordering::Relaxed,
    );

    // A lower-EL synchronous trap with a redirection pending is the way home
    // from EL1. Index 8 is that entry; anything else returns where it came
    // from, at the level it came from.
    let redirect = REDIRECT_PC.load(Ordering::Relaxed);
    if index == 8 && redirect != 0 {
        let spsr = REDIRECT_SPSR.load(Ordering::Relaxed);
        clear_redirect();
        return ExceptionReturn {
            elr: redirect,
            spsr,
        };
    }

    ExceptionReturn {
        elr: if synchronous {
            elr.wrapping_add(4)
        } else {
            elr
        },
        spsr: spsr_el2,
    }
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
