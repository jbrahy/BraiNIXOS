//! Dropping to EL1 and getting back.
//!
//! Raw exception-level manipulation.
//!
//! # Why this is intricate on this machine
//!
//! Measured, not assumed: `HCR_EL2 = 0x32488000038`, so `E2H=1` (VHE) and
//! `TGE=1`. Two consequences, both of which have to be handled before an `eret`
//! to EL1 can land anywhere:
//!
//! - **`TGE=1` means EL1 is not there.** General exceptions are trapped to EL2
//!   and EL0 runs under EL2's regime. It has to be cleared.
//! - **Under VHE the EL1-named registers are EL2's.** Writing `TTBR0_EL1` at
//!   EL2 writes `TTBR0_EL2`. The real EL1 registers are reached through the
//!   `_EL12` aliases, and if they are left unprogrammed then EL1 has no
//!   translation regime and the first instruction fetch there faults.
//!
//! Both were established by reading the machine before anything was written.
//! `TCR_EL1` and `TCR_EL2` reading identical is what proved the aliasing.
//!
//! # Bounded, and restored
//!
//! [`drop_to_el1_and_return`] clears `TGE`, drops, traps straight back with
//! `HVC`, and restores `HCR_EL2`. m1n1 is resident throughout and depends on
//! the configuration it set, so the window is made as short as it can be: the
//! only thing that runs at EL1 is a read of `CurrentEL` and the `hvc` home.

#![allow(unsafe_code)]

use super::{registers, vectors};

/// `HCR_EL2.TGE`, bit 27.
const HCR_TGE: u64 = 1 << 27;

/// `SPSR` value selecting EL1h with all interrupts masked.
///
/// `M[3:0] = 0b0101` is EL1h -- EL1 using `SP_EL1`. `DAIF` all set, because
/// arriving at a new exception level with interrupts live invites one before
/// there is anything able to service it.
const SPSR_EL1H_MASKED: u64 = 0x3C5;

/// `SPSR` value selecting EL2h with all interrupts masked.
///
/// `M[3:0] = 0b1001`. This is what the handler installs to send control back up
/// to EL2 rather than resuming at EL1 where the trap came from.
const SPSR_EL2H_MASKED: u64 = 0x3C9;

/// What the excursion observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Excursion {
    /// `CurrentEL >> 2` as read **at EL1**. 1 means the drop worked.
    pub observed_el: u64,
    /// `HCR_EL2` before the change.
    pub hcr_before: u64,
    /// `HCR_EL2` after restoring.
    pub hcr_after: u64,
    /// Vector the return trap arrived on. 8 is lower EL, AArch64, synchronous.
    pub return_vector: u64,
    /// `[index, ESR_EL1, ELR_EL1, FAR_EL1]` if EL1 faulted on the way.
    ///
    /// All four still poisoned means EL1 ran to its `hvc` without faulting,
    /// which is the outcome being aimed at.
    pub el1_fault: [u64; 4],
}

/// Drop to EL1, read `CurrentEL` there, and trap back to EL2.
///
/// # Safety
///
/// Changes `HCR_EL2` and the EL1 translation regime, and executes at EL1.
/// Must be called inside [`vectors::with_vectors`] so the `HVC` home has a
/// handler, and with `el1_stack` pointing at memory this image owns.
pub unsafe fn drop_to_el1_and_return(el1_stack: u64) -> Excursion {
    let hcr_before = registers::hcr_el2();

    // Give EL1 the same translation regime, attributes and vectors EL2 is using.
    // Without this the first fetch at EL1 has no mapping.
    //
    // SAFETY: the same programming `el1_reachability` measures, so what it
    // reported about this configuration describes the one running here.
    unsafe { program_el1_registers() };

    let (redirect_pc, redirect_spsr) = vectors::redirect_slots();
    let observed: u64;

    // SAFETY: the whole excursion, written as one block so no compiler-inserted
    // code lands between the eret and the landing pad. `2f` is where the
    // handler sends us; it is registered before TGE is cleared, because after
    // that point a stray exception has nowhere else to go.
    unsafe {
        core::arch::asm!(
            // Register the way home BEFORE clearing TGE. After that point a
            // stray exception has nowhere else to go, and the handler needs to
            // know where to send control back to.
            "adr {tmp}, 2f",
            "str {tmp}, [{redirect_pc}]",
            "str {el2_spsr}, [{redirect_spsr}]",
            // Clear TGE so EL1 exists at all.
            "mrs {tmp}, HCR_EL2",
            "bic {tmp}, {tmp}, {tge}",
            "msr HCR_EL2, {tmp}",
            "isb",
            // Clearing TGE moves EL1&0 from the EL2&0 regime to the EL1&0 one.
            // Every TLB entry describing the old regime is now stale, and a
            // stale entry is not a fault -- it is a *wrong translation*, which
            // is why skipping this appears to work and then fetches garbage at
            // the landing pad.
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            // Arrange the drop.
            "msr SP_EL1, {stack}",
            "msr SPSR_EL2, {spsr}",
            "adr {tmp}, 1f",
            "msr ELR_EL2, {tmp}",
            "isb",
            "eret",
            // ---- EL1 ----
            "1:",
            "mrs {observed}, CurrentEL",
            "hvc #0",
            // ---- back at EL2, via the handler's redirection ----
            "2:",
            tmp = out(reg) _,
            redirect_pc = in(reg) redirect_pc,
            redirect_spsr = in(reg) redirect_spsr,
            el2_spsr = in(reg) SPSR_EL2H_MASKED,
            tge = in(reg) HCR_TGE,
            stack = in(reg) el1_stack,
            spsr = in(reg) SPSR_EL1H_MASKED,
            observed = out(reg) observed,
            options(nostack)
        );
    }

    // SAFETY: restoring exactly what was read.
    unsafe {
        core::arch::asm!(
            "msr HCR_EL2, {hcr}",
            "isb",
            hcr = in(reg) hcr_before,
            options(nomem, nostack)
        );
    }

    Excursion {
        observed_el: (observed >> 2) & 0b11,
        hcr_before,
        hcr_after: registers::hcr_el2(),
        return_vector: vectors::last_exception().index,
        el1_fault: vectors::el1_fault(),
    }
}

/// What EL1 would be able to reach, asked without executing anything there.
///
/// # Why this is the right instrument
///
/// Every previous attempt at the drop failed by hanging, and a hang carries one
/// bit on a machine with no console. `AT S1E1R` asks the MMU the same question
/// the instruction fetch at EL1 would ask -- can this address be reached through
/// EL1's regime -- and **cannot fault**: an untranslatable address is reported
/// in `PAR_EL1.F`, not raised. So this converts the expensive question into a
/// free one. It is the same move that validated the page-table walker against
/// `AT S1E2R`, pointed one level down.
///
/// `TGE` has to be clear for the answer to mean anything. With `TGE` set,
/// `AT S1E1R` translates through the **EL2&0** regime -- it would confirm what
/// EL2 can already reach and say nothing at all about EL1.
///
/// Bit 0 of each `PAR` set means that address is not reachable from EL1, and is
/// the direct cause of a drop that lands nowhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct El1Reachability {
    /// `HCR_EL2` as it stood while the questions were asked, `TGE` clear.
    pub hcr_while_asking: u64,
    /// `PAR_EL1` for the payload's own code.
    pub par_code: u64,
    /// `PAR_EL1` for the EL1 vector table.
    pub par_vectors: u64,
    /// `PAR_EL1` for the stack EL1 would run on.
    pub par_stack: u64,
}

/// Ask the MMU what EL1 could reach, then put `TGE` back.
///
/// # Safety
///
/// Programmes EL1's translation registers and briefly clears `HCR_EL2.TGE`.
/// Nothing executes at EL1 and no instruction here can fault.
pub unsafe fn el1_reachability(code: u64, stack: u64) -> El1Reachability {
    let before = registers::hcr_el2();
    // SAFETY: writes EL1's regime, clears one HCR bit, issues three address
    // translations that cannot fault, and restores HCR_EL2.
    unsafe {
        program_el1_registers();
        core::arch::asm!(
            "mrs {tmp}, HCR_EL2",
            "bic {tmp}, {tmp}, {tge}",
            "msr HCR_EL2, {tmp}",
            "isb",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            tmp = out(reg) _,
            tge = in(reg) HCR_TGE,
            options(nomem, nostack)
        );
    }
    let hcr_while_asking = registers::hcr_el2();
    let par_code = registers::translate_el1_read(code);
    let par_vectors = registers::translate_el1_read(vectors::el1_table_address());
    let par_stack = registers::translate_el1_read(stack);
    // SAFETY: restoring exactly what was read.
    unsafe {
        core::arch::asm!(
            "msr HCR_EL2, {hcr}",
            "isb",
            hcr = in(reg) before,
            options(nomem, nostack)
        );
    }
    El1Reachability {
        hcr_while_asking,
        par_code,
        par_vectors,
        par_stack,
    }
}

/// Give EL1 the translation regime, attributes and vectors it needs to exist.
///
/// Factored out because two callers need exactly the same programming and a
/// second copy of it is a second thing to keep in step: [`el1_reachability`]
/// asks what this configuration permits, and [`drop_to_el1_and_return`] then
/// runs under it. If they diverge, the free measurement stops describing the
/// expensive one.
///
/// # Safety
///
/// Writes EL1's translation, attribute and vector registers. Nothing takes
/// effect until execution reaches EL1 or an `AT S1E1*` is issued with `TGE`
/// clear.
unsafe fn program_el1_registers() {
    // SAFETY: writing the EL1 view of registers whose EL2 values were read from
    // this same machine.
    unsafe {
        core::arch::asm!(
            // Raw encodings: this assembler does not know the _EL12 names.
            // They are the EL1 registers with op1 = 5 instead of 0, which is
            // how VHE exposes the *real* EL1 state from EL2. Using the EL1
            // names here would write EL2's own registers and leave EL1 with no
            // regime at all -- the failure would be an eret into nothing.
            "msr s3_5_c2_c0_0, {ttbr0}",    // TTBR0_EL12
            "msr s3_5_c2_c0_1, {ttbr1}",    // TTBR1_EL12
            "msr s3_5_c2_c0_2, {tcr}",      // TCR_EL12
            "msr s3_5_c1_c0_0, {sctlr}",    // SCTLR_EL12
            // MAIR_EL12. Copying the tables without copying this is the classic
            // way to arrive at EL1 with a translation regime that resolves and
            // still cannot be executed: descriptors carry an AttrIndx, and an
            // unprogrammed MAIR makes every index name Device-nGnRnE.
            "msr s3_5_c10_c2_0, {mair}",    // MAIR_EL12
            // VBAR_EL12. Not our EL2 table -- that one reads ESR_EL2/ELR_EL2/
            // FAR_EL2, undefined at EL1, so it would fault inside itself forever.
            // This is the EL1-only table from `vectors`, which reads EL1
            // registers, records them and leaves via `hvc`.
            //
            // Leaving this unset is what made the previous failure a hang: on
            // this machine nothing had ever written VBAR_EL1, so an EL1 fault
            // branched into whatever address happened to be in it.
            "msr s3_5_c12_c0_0, {vbar}",    // VBAR_EL12
            "isb",
            // The EL1 regime just changed underneath any cached translations.
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            ttbr0 = in(reg) registers::ttbr0_el2(),
            ttbr1 = in(reg) registers::ttbr1_el2(),
            tcr = in(reg) registers::tcr_el2(),
            sctlr = in(reg) registers::sctlr_el1(),
            mair = in(reg) registers::mair_el1(),
            vbar = in(reg) vectors::el1_table_address(),
            options(nomem, nostack)
        );
    }
}

/// Clear `TGE`, observe, and restore -- without dropping a level.
///
/// The first isolated step of [`drop_to_el1_and_return`]. If this survives,
/// clearing `TGE` at EL2 is not what hangs the machine and the fault is further
/// in; if it does not, everything after it is untestable until this is
/// understood.
///
/// Bisecting rather than guessing: two attempts at the whole excursion produced
/// two hangs, and a hang carries one bit. Splitting the sequence turns one
/// unusable bit into three usable ones.
///
/// # Safety
///
/// Changes `HCR_EL2` briefly and restores it. Nothing executes at another
/// exception level.
pub unsafe fn toggle_tge() -> (u64, u64, u64) {
    let before = registers::hcr_el2();
    let cleared: u64;
    // SAFETY: clearing a single bit of HCR_EL2 and putting it back. No level
    // change, no eret, no translation-regime switch for the code running here.
    unsafe {
        core::arch::asm!(
            "mrs {tmp}, HCR_EL2",
            "bic {tmp}, {tmp}, {tge}",
            "msr HCR_EL2, {tmp}",
            "isb",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            "mrs {cleared}, HCR_EL2",
            "msr HCR_EL2, {before}",
            "isb",
            tmp = out(reg) _,
            cleared = out(reg) cleared,
            tge = in(reg) HCR_TGE,
            before = in(reg) before,
            options(nomem, nostack)
        );
    }
    (before, cleared, registers::hcr_el2())
}

/// Programme the EL1 regime through the `_EL12` aliases, then undo it.
///
/// Bisect step 2. If this survives, writing EL1's translation state from EL2 is
/// not the fault and only the `eret` itself remains.
///
/// Returns what `TTBR0_EL12` read back as, which also confirms the raw
/// encoding addresses the register we think it does -- a wrong `msr` encoding
/// would write something else entirely and read back as something else.
///
/// # Safety
///
/// Writes EL1's translation registers. Nothing executes at EL1.
pub unsafe fn program_el1_regime() -> (u64, u64) {
    let ttbr = registers::ttbr0_el2();
    let readback: u64;
    // SAFETY: writing the EL1 view of registers whose EL2 values came from this
    // machine, then reading one back. No level change.
    unsafe {
        core::arch::asm!(
            "msr s3_5_c2_c0_0, {ttbr}",     // TTBR0_EL12
            "msr s3_5_c2_c0_2, {tcr}",      // TCR_EL12
            "msr s3_5_c1_c0_0, {sctlr}",    // SCTLR_EL12
            "isb",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            "mrs {readback}, s3_5_c2_c0_0",
            ttbr = in(reg) ttbr,
            tcr = in(reg) registers::tcr_el2(),
            sctlr = in(reg) registers::sctlr_el1(),
            readback = out(reg) readback,
            options(nomem, nostack)
        );
    }
    (ttbr, readback)
}

/// `eret` to the next instruction, staying at EL2.
///
/// Bisect step 3. Separates "can this code perform an exception return at all"
/// from "can it change exception level". Steps 1 and 2 cleared `TGE` and
/// programmed EL1's regime without incident, so the fault is in one of those
/// two, and they are worth telling apart before either is blamed.
///
/// # Safety
///
/// Performs an exception return to a label inside this function, at the level
/// it is already running at.
pub unsafe fn eret_to_self() -> u64 {
    let marker: u64;
    // SAFETY: SPSR selects EL2h -- the level already executing -- and ELR is a
    // label two instructions ahead. If exception return works at all, this
    // lands on `1f` and nothing about the machine has changed.
    unsafe {
        core::arch::asm!(
            "mov {marker}, #0",
            "msr SPSR_EL2, {spsr}",
            "adr {tmp}, 1f",
            "msr ELR_EL2, {tmp}",
            "isb",
            "eret",
            "1:",
            "mov {marker}, #1",
            marker = out(reg) marker,
            tmp = out(reg) _,
            spsr = in(reg) SPSR_EL2H_MASKED,
            options(nostack)
        );
    }
    marker
}
