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
    /// `[count, ESR_EL1, ELR_EL1, caller SPSR.M]` from the last `SVC`.
    ///
    /// Count zero when the excursion was asked not to make one. The caller mode
    /// is 0 for EL0t, 5 for EL1h.
    pub el1_svc: [u64; 4],
}

/// Immediate carried by the `SVC` the excursion issues.
///
/// Chosen to be recognisable in `ESR_EL1.ISS`, which is where the immediate
/// lands. A zero immediate would be indistinguishable from a syndrome that was
/// never written, which is the same mistake as a sentinel that collides with a
/// real value.
pub const PROBE_SVC_IMMEDIATE: u64 = 0x42;

/// Drop to EL1, read `CurrentEL` there, and trap back to EL2.
///
/// With `issue_svc`, EL1 also executes an `SVC` and **carries on afterwards**,
/// which is what makes it a system-call test rather than another trap test: the
/// EL1 handler has to dispatch it, record it, and return to the instruction
/// after it. Anything that merely reaches a handler proves dispatch; only
/// resuming proves the other half.
///
/// It is a parameter rather than unconditional so that the excursion which was
/// verified on hardware stays verifiable in exactly the form it was verified.
/// Folding a new experiment into a proven measurement means a regression in the
/// new one presents as the old one breaking.
///
/// # Safety
///
/// Changes `HCR_EL2` and the EL1 translation regime, and executes at EL1.
/// Must be called inside [`vectors::with_vectors`] so the `HVC` home has a
/// handler, and with `el1_stack` pointing at memory this image owns.
pub unsafe fn drop_to_el1_and_return(el1_stack: u64, issue_svc: bool) -> Excursion {
    let hcr_before = registers::hcr_el2();
    // See `vectors::EL1_SVC_RECORD`: the count is cumulative for the life of the
    // loaded image, so this excursion reports the difference rather than the
    // total.
    let svc_before = vectors::el1_svc()[0];

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
            "cbz {do_svc}, 3f",
            // The system call. Reaching the instruction after this one is the
            // measurement: it means EL1's handler dispatched the SVC, recorded
            // it, and returned here rather than abandoning the level.
            "svc #{imm}",
            "3:",
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
            do_svc = in(reg) u64::from(issue_svc),
            imm = const PROBE_SVC_IMMEDIATE,
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
        el1_svc: {
            let mut svc = vectors::el1_svc();
            svc[0] = svc[0].saturating_sub(svc_before);
            svc
        },
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

/// `SPSR` selecting EL0t with all interrupts masked.
///
/// `M[3:0] = 0b0000`. EL0 has only `SP_EL0`, so there is no `h` variant to
/// choose; the `t` is the whole of it.
const SPSR_EL0T_MASKED: u64 = 0x3C0;

/// What a trip through EL0 observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserExcursion {
    /// Root of the regime built for EL1 and EL0.
    pub user_root: u64,
    /// Tables it cost.
    pub tables_used: usize,
    /// The page made reachable from EL0.
    pub user_page: u64,
    /// `PAR_EL1` from `AT S1E1R` on the EL1 code. Must succeed.
    pub par_kernel_from_el1: u64,
    /// `PAR_EL1` from `AT S1E0R` on the user page. Must succeed.
    pub par_user_from_el0: u64,
    /// `PAR_EL1` from `AT S1E0R` on a **kernel** page.
    ///
    /// Must **fail**. This is the isolation check, and it is the only one of the
    /// three that can distinguish a working user mapping from one that simply
    /// made everything reachable. It costs nothing: `AT` cannot fault.
    pub par_kernel_from_el0: u64,
    /// Whether the excursion was actually run.
    pub entered: bool,
    /// `[count, ESR_EL1, ELR_EL1, caller SPSR.M]` of the last `SVC`.
    pub svc: [u64; 4],
    /// `[index, ESR_EL1, ELR_EL1, FAR_EL1]` if anything faulted.
    pub fault: [u64; 4],
    /// `HCR_EL2` after restoring.
    pub hcr_after: u64,
    /// Build failure code, or 0.
    pub error: u64,
}

/// Drop through EL1 to **EL0**, make two system calls, and come back.
///
/// # What this proves that the EL1 excursion does not
///
/// EL1 running our code means the kernel can change its own privilege level.
/// EL0 running our code means there is a *boundary*: a level that reaches one
/// page and not the rest, and a way across it that firmware does not mediate.
/// Everything this project is for lives on the far side of that line.
///
/// Two calls, deliberately. `SVC_RESUME` has to come back to EL0 -- a system
/// call that returns to userspace is what a kernel does constantly, and no trap
/// test shows it. `SVC_LEAVE` is the way out, made by EL1 on EL0's behalf
/// because EL0 cannot reach EL2 itself.
///
/// # The gate
///
/// Before the `eret`, three `AT` instructions ask the MMU what each level can
/// reach. Two must succeed and **one must fail** -- `AT S1E0R` on a kernel page.
/// Without that third question, a regime that accidentally made all of DRAM
/// EL0-accessible would pass every other check in this function.
///
/// # Safety
///
/// Changes `HCR_EL2`, installs a translation regime for EL1 and EL0, and
/// executes at both. Must be called inside [`vectors::with_vectors`], and
/// `el1_stack`/`el0_stack` must point at memory this image owns.
pub unsafe fn drop_to_el0_and_return(el1_stack: u64, el0_stack: u64) -> UserExcursion {
    let hcr_before = registers::hcr_el2();
    let svc_before = vectors::el1_svc()[0];
    let user_page = vectors::el0_entry_address() & !((1u64 << 14) - 1);

    let mut excursion = UserExcursion {
        user_root: 0,
        tables_used: 0,
        user_page,
        par_kernel_from_el1: 0,
        par_user_from_el0: 0,
        par_kernel_from_el0: 0,
        entered: false,
        svc: [0; 4],
        fault: vectors::el1_fault(),
        hcr_after: hcr_before,
        error: 0,
    };

    let tcr = registers::tcr_el2();
    let Some(config) = crate::aarch64_walk::WalkConfig::from_tcr(tcr) else {
        excursion.error = 5;
        return excursion;
    };

    // Attributes from a live descriptor, not invented. Memory type is an index
    // into MAIR, so a plausible constant produces a regime that resolves and
    // cannot be executed -- the mistake that made the first EL1 drop look
    // impossible.
    let live_root = registers::ttbr0_el2() & 0x0000_FFFF_FFFF_FFFE;
    let granule = 1u64 << config.granule_bits;
    let address_mask = ((1u64 << 48) - 1) & !(granule - 1);
    // SAFETY: reading descriptors from physical addresses the live tables point
    // at, under the identity mapping m1n1 leaves in force.
    let live = crate::aarch64_walk::walk(live_root, user_page, config, |pa| unsafe {
        core::ptr::read_volatile(pa as usize as *const u64)
    });
    let Ok(live) = live else {
        excursion.error = 3;
        return excursion;
    };
    let kernel_attributes = live.descriptor & !address_mask & !0b11;

    // SAFETY: nothing has this root installed yet.
    match unsafe {
        super::mmu::build_user_root(
            user_page,
            config.granule_bits,
            config.input_address_bits(),
            kernel_attributes,
        )
    } {
        Ok((root, tables)) => {
            excursion.user_root = root;
            excursion.tables_used = tables;
        }
        Err(error) => {
            excursion.error = super::mmu::build_error_code(error);
            return excursion;
        }
    }

    // Install it as EL1's regime, with TGE clear so the _EL12 registers and the
    // `AT S1E*` instructions describe EL1&0 rather than EL2&0.
    //
    // SAFETY: EL2 keeps walking TTBR0_EL2 throughout; only EL1's and EL0's
    // regime changes, and nothing is executing there yet.
    unsafe {
        core::arch::asm!(
            "msr s3_5_c2_c0_0, {ttbr0}",    // TTBR0_EL12
            "msr s3_5_c2_c0_2, {tcr}",      // TCR_EL12
            "msr s3_5_c1_c0_0, {sctlr}",    // SCTLR_EL12
            "msr s3_5_c10_c2_0, {mair}",    // MAIR_EL12
            "msr s3_5_c12_c0_0, {vbar}",    // VBAR_EL12
            "mrs {tmp}, HCR_EL2",
            "bic {tmp}, {tmp}, {tge}",
            "msr HCR_EL2, {tmp}",
            "isb",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            tmp = out(reg) _,
            ttbr0 = in(reg) excursion.user_root,
            tcr = in(reg) tcr,
            sctlr = in(reg) registers::sctlr_el1(),
            mair = in(reg) registers::mair_el1(),
            vbar = in(reg) vectors::el1_table_address(),
            tge = in(reg) HCR_TGE,
            options(nomem, nostack)
        );
    }

    excursion.par_kernel_from_el1 = registers::translate_el1_read(el1_stack.wrapping_sub(8));
    excursion.par_user_from_el0 = registers::translate_el0_read(user_page);
    excursion.par_kernel_from_el0 = registers::translate_el0_read(el1_stack.wrapping_sub(8));

    let gate_passed = excursion.par_kernel_from_el1 & 1 == 0
        && excursion.par_user_from_el0 & 1 == 0
        // MUST fail. A regime that lets EL0 read the kernel stack is not
        // isolation, and every other check here would still pass.
        && excursion.par_kernel_from_el0 & 1 == 1;

    if gate_passed {
        let (redirect_pc, redirect_spsr) = vectors::redirect_slots();
        // SAFETY: the excursion as one block, so nothing the compiler inserts
        // lands between an `eret` and its landing pad.
        unsafe {
            core::arch::asm!(
                "adr {tmp}, 3f",
                "str {tmp}, [{redirect_pc}]",
                "str {el2_spsr}, [{redirect_spsr}]",
                // EL2 -> EL1.
                "msr SP_EL1, {el1_stack}",
                "msr SPSR_EL2, {el1_spsr}",
                "adr {tmp}, 1f",
                "msr ELR_EL2, {tmp}",
                "isb",
                "eret",
                // ---- EL1 ----
                "1:",
                "msr SP_EL0, {el0_stack}",
                "msr SPSR_EL1, {el0_spsr}",
                "msr ELR_EL1, {el0_entry}",
                "isb",
                "eret",
                // ---- EL0 runs `brainix_el0_entry`, and never comes back here.
                // Its second SVC is SVC_LEAVE, which EL1's handler turns into an
                // HVC, which the EL2 redirect lands at `3f`. ----
                "3:",
                tmp = out(reg) _,
                redirect_pc = in(reg) redirect_pc,
                redirect_spsr = in(reg) redirect_spsr,
                el2_spsr = in(reg) SPSR_EL2H_MASKED,
                el1_stack = in(reg) el1_stack,
                el1_spsr = in(reg) SPSR_EL1H_MASKED,
                el0_stack = in(reg) el0_stack,
                el0_spsr = in(reg) SPSR_EL0T_MASKED,
                el0_entry = in(reg) vectors::el0_entry_address(),
                options(nostack)
            );
        }
        excursion.entered = true;
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

    excursion.hcr_after = registers::hcr_el2();
    excursion.svc = vectors::el1_svc();
    // The raw count is cumulative for the life of the loaded image -- see
    // `EL1_SVC_RECORD`. Reporting it directly would mean this excursion's result
    // depended on which stages ran before it, which is how a passing check turns
    // into a failing one for no reason connected to what it tests.
    excursion.svc[0] = excursion.svc[0].saturating_sub(svc_before);
    excursion.fault = vectors::el1_fault();
    excursion
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
