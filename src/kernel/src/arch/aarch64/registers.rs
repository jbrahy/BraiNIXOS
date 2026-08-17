//! System-register access, and what the silicon says about itself.
//!
//! Inline assembly is unsafe by definition; same per-module allowlist the
//! x86-64 siblings use.
//!
//! # Why identification comes before configuration
//!
//! AS-1b's next steps program `TCR_EL1` and `TTBR*_EL1`. Both are constrained
//! by what the implementation supports: the physical address size, and which
//! translation granules exist at all. Writing a plausible `TCR_EL1` and finding
//! out afterwards is not debuggable on this platform, because a bad translation
//! configuration takes the machine down before it can report anything.
//!
//! `ID_AA64MMFR0_EL1` answers both, and it is a **read**, so it costs nothing
//! and cannot hang. The values below were read off the target rather than taken
//! from the manual, which is the same discipline that caught the s5l/DockChannel
//! mistake and the `checked_sub` mistake.
//!
//! # Exception level
//!
//! m1n1 hands control at **EL2** (observed). Code that assumes EL1 fails at its
//! first `EL1`-only system-register write, which presents as a hang rather than
//! as a fault, so every accessor here states which levels can execute it.

#![allow(unsafe_code)]

/// Reads a 64-bit system register by name.
///
/// Every register read through this macro is architecturally side-effect free
/// at the exception levels this kernel runs at, which is why the unsafety is
/// discharged here rather than pushed to callers.
macro_rules! read_sysreg {
    ($name:literal) => {{
        let value: u64;
        // SAFETY: `mrs` from an identification or configuration register has no
        // memory operands and no side effects. Traps are possible only at lower
        // exception levels than this kernel is entered at.
        unsafe {
            core::arch::asm!(
                concat!("mrs {}, ", $name),
                out(reg) value,
                options(nomem, nostack)
            )
        }
        value
    }};
}

/// `MIDR_EL1` — the CPU implementer, part number and revision.
pub fn midr() -> u64 {
    read_sysreg!("MIDR_EL1")
}

/// `MPIDR_EL1` — which core this is.
///
/// Needed before secondary-CPU release, because the boot core must be able to
/// recognise itself.
pub fn mpidr() -> u64 {
    read_sysreg!("MPIDR_EL1")
}

/// `CNTFRQ_EL0` — generic timer frequency, in Hz.
pub fn counter_frequency_hz() -> u64 {
    read_sysreg!("CNTFRQ_EL0")
}

/// `CNTPCT_EL0` — the physical counter.
pub fn physical_counter() -> u64 {
    read_sysreg!("CNTPCT_EL0")
}

/// `SCTLR_EL1` — system control, including whether the MMU is on.
pub fn sctlr_el1() -> u64 {
    read_sysreg!("SCTLR_EL1")
}

/// `ESR_EL2` — the syndrome of the last exception taken to EL2.
///
/// Readable outside a handler because nothing clears it until the next
/// exception. That is what makes it usable as a cross-check on what a handler
/// reported.
pub fn esr_el2() -> u64 {
    read_sysreg!("ESR_EL2")
}

/// `ELR_EL2` — the return address of the last exception taken to EL2.
pub fn elr_el2() -> u64 {
    read_sysreg!("ELR_EL2")
}

/// `ID_AA64MMFR0_EL1` — the memory-model feature register.
pub fn id_aa64mmfr0_el1() -> u64 {
    read_sysreg!("ID_AA64MMFR0_EL1")
}

/// Whether `SCTLR_EL1.M` is set, i.e. EL1 translation is enabled.
///
/// Worth checking rather than assuming: a boot object is entered with the MMU
/// **off**, but m1n1 enables it for itself, so a payload's assumptions depend
/// on how it was reached. Physical addresses are only directly usable while
/// this is false.
pub fn el1_mmu_enabled() -> bool {
    sctlr_el1() & 1 != 0
}

/// Read and decode `ID_AA64MMFR0_EL1` from the running CPU.
///
/// The decode itself lives in [`crate::aarch64_ident`], not here. It is a pure
/// function over a `u64` and therefore host-testable, while the `mrs` that
/// produces the `u64` is not -- the same split this project applies everywhere
/// under the Track C rule: write everything that is a pure function over bytes,
/// host-test it, and stop at the hardware.
///
/// Keeping it in this module would have made it reachable only from a
/// bare-metal build, so the one part with a checkable contract would have had
/// no tests at all.
pub fn memory_model() -> crate::aarch64_ident::MemoryModel {
    crate::aarch64_ident::MemoryModel::from_id_register(id_aa64mmfr0_el1())
}

/// `TCR_EL2` — translation control for EL2.
pub fn tcr_el2() -> u64 {
    read_sysreg!("TCR_EL2")
}

/// `TTBR0_EL2` — the stage-1 table base for EL2.
pub fn ttbr0_el2() -> u64 {
    read_sysreg!("TTBR0_EL2")
}

/// Ask the MMU itself to translate `virtual_address` for an EL2 read.
///
/// Returns `PAR_EL1`. Bit 0 set means the translation **failed**, which is
/// information rather than an error: it says the address is genuinely not
/// mapped, and a software walker that produces an address for it is wrong.
///
/// # Why this exists
///
/// It is the only independent oracle available for a page-table walker. A
/// walker checked against tables this repository also built confirms nothing
/// except self-consistency; checked against the MMU's own answer for the same
/// address on the same live tables, it is checked against the thing it is
/// modelling.
///
/// `isb` after the `at` because `PAR_EL1` is not architecturally guaranteed to
/// be readable until the address translation completes.
pub fn translate_el2_read(virtual_address: u64) -> u64 {
    let par: u64;
    // SAFETY: `at s1e2r` performs a translation-table lookup and writes
    // `PAR_EL1`. It has no memory side effects and cannot fault; an
    // untranslatable address is reported in `PAR_EL1.F` rather than raised.
    unsafe {
        core::arch::asm!(
            "at s1e2r, {va}",
            "isb",
            "mrs {par}, PAR_EL1",
            va = in(reg) virtual_address,
            par = out(reg) par,
            options(nostack)
        )
    }
    par
}
