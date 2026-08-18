//! Branch target identification, enforced rather than announced.
//!
//! # Two halves, and only one of them is a register
//!
//! `SCTLR.BT` is the half everyone sets. On its own it does **nothing**: BTI
//! constrains indirect branches only into pages whose descriptors carry `GP`,
//! and until this project owned its own page tables there was no way to set
//! that bit on anything. A kernel that sets `SCTLR.BT` on firmware's tables has
//! enabled a feature that cannot fire, and every test of it passes.
//!
//! So this builds a regime in which one page is Guarded, installs it, and then
//! branches into that page twice: once to an instruction that is not a landing
//! pad, and once to a `BTI c`. The first must fault. The second must not.
//!
//! # Why only one page is Guarded
//!
//! BTI is decided by the page **the branch target is in**, not the page the
//! branch is in. Guarding all of DRAM would therefore apply BTI to the
//! exception handler as well -- and a Branch Target Exception raised inside the
//! handler for a Branch Target Exception is an unrecoverable loop, on a machine
//! with no console, which would present as BTI simply not working.
//!
//! Guarding exactly the page under test keeps the handler, m1n1, and every
//! compiler-generated indirect branch outside the feature's reach.
//!
//! # `BTI c` and `BTI j` are not interchangeable
//!
//! `BLR` requires `BTI c` (or `jc`); `BR` requires `BTI j` (or `jc`). Landing a
//! `BLR` on a `BTI j` faults, and the fault looks exactly like BTI being broken.
//! The test uses `BLR` and a `BTI c`, written as `hint #34` -- the architecture
//! puts these in the HINT space so a part without `FEAT_BTI` treats them as
//! NOPs, and the raw form assembles without the target enabling the feature,
//! which this build must not do because support is a run-time question.
//!
//! # Recoverable by construction
//!
//! The failing branch targets `nop; ret`. The exception is taken **on** the
//! `nop`, so `ELR` points at it, the handler advances four bytes as it does for
//! any synchronous trap, and the `ret` returns to the caller. A test whose
//! failure case wedges the machine measures nothing.

#![allow(unsafe_code)]

use super::{registers, vectors};

/// `SCTLR.BT`, bit 36. At EL2 with `E2H=1` this governs EL2's own execution.
const SCTLR_BT: u64 = 1 << 36;

/// `ESR_ELx.EC` for a Branch Target Exception.
pub const EC_BRANCH_TARGET: u64 = 0x0D;

/// What the enforcement test observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtiReport {
    /// `ID_AA64PFR1_EL1.BT` is non-zero.
    pub supported: bool,
    /// Root of the regime with one Guarded page.
    pub guarded_root: u64,
    /// Tables it cost.
    pub tables_used: usize,
    /// The page marked Guarded.
    pub guarded_page: u64,
    /// The descriptor for that page, read back through the walker.
    ///
    /// Evidence that `GP` reached the leaf rather than being assumed. A builder
    /// that dropped the bit would produce a test in which nothing faults, which
    /// is indistinguishable from BTI being unsupported.
    pub descriptor: u64,
    /// `SCTLR` as found.
    pub sctlr_before: u64,
    /// `SCTLR` with `BT` set, read back -- the bit is `RES0` where unsupported.
    pub sctlr_while_enabled: u64,
    /// `SCTLR` after restoring.
    pub sctlr_after: u64,
    /// `ESR_EL2` after branching to an instruction that is not a landing pad.
    pub bad_branch_esr: u64,
    /// Whether that branch raised an exception at all.
    pub bad_branch_faulted: bool,
    /// Whether the branch to a valid `BTI c` raised one. Must be false.
    pub good_branch_faulted: bool,
    /// `TTBR0_EL2` after restoring.
    pub restored_root: u64,
    /// Build failure code, or 0.
    pub error: u64,
}

impl BtiReport {
    /// Whether this run proves BTI is being enforced.
    ///
    /// Both halves. A branch that faults proves the feature fires; a branch
    /// that does **not** fault proves it is discriminating rather than
    /// rejecting everything -- which a mis-set `SCTLR`, a wrong landing-pad
    /// encoding, or an unrelated fault on the same vector would all produce.
    pub fn enforcement_works(&self) -> bool {
        self.supported
            && self.sctlr_while_enabled & SCTLR_BT != 0
            && self.descriptor & super::mmu::GP != 0
            && self.bad_branch_faulted
            && (self.bad_branch_esr >> 26) & 0x3F == EC_BRANCH_TARGET
            && !self.good_branch_faulted
    }
}

/// Call `target` with `SCTLR.BT` set, then put `SCTLR` back.
///
/// The window is one instruction wide on purpose. While `BT` is set, every
/// indirect branch into a Guarded page is constrained, and the less that runs
/// in that state the fewer ways there are for an unrelated branch to fault and
/// be mistaken for the measurement.
///
/// # Safety
///
/// Must run inside [`vectors::with_vectors`]: the whole point of one of the two
/// calls is to raise a Branch Target Exception. `target` must be a valid code
/// address that ends in `ret`.
///
/// Returns `SCTLR` as it actually read back while the call was made, rather
/// than the value written. `SCTLR` bits for features a part does not
/// implement are `RES0`: the write is accepted and discarded.
unsafe fn call_with_bti(target: u64, sctlr: u64) -> u64 {
    let observed: u64;
    // Three blocks rather than one, because `clobber_abi` forbids generic
    // outputs and the call needs `clobber_abi` -- the handler behind it uses
    // caller-saved registers freely.
    //
    // Splitting is safe here in a way it would not be for the EL1 excursion:
    // BTI constrains only **indirect branches**, and whatever the compiler may
    // place between these blocks is register moves and spills. There is no
    // `eret` whose landing pad has to be the next instruction.
    //
    // SAFETY: sets one SCTLR bit and reads it back. No branch.
    unsafe {
        core::arch::asm!(
            "mrs {observed}, SCTLR_EL1",
            "orr {observed}, {observed}, {bt}",
            "msr SCTLR_EL1, {observed}",
            "isb",
            // Read back rather than reuse the value written: bits for features
            // the part does not implement are RES0 and are silently discarded.
            "mrs {observed}, SCTLR_EL1",
            observed = out(reg) observed,
            bt = in(reg) SCTLR_BT,
            options(nomem, nostack)
        );
    }

    // SAFETY: one indirect call, into a target the caller guarantees ends in
    // `ret`. `clobber_abi` tells the compiler the callee and any exception
    // handler reached from it may use every caller-saved register.
    unsafe {
        core::arch::asm!("blr {target}", target = in(reg) target, clobber_abi("C"));
    }

    // SAFETY: restoring exactly what was read.
    unsafe {
        core::arch::asm!(
            "msr SCTLR_EL1, {sctlr}",
            "isb",
            sctlr = in(reg) sctlr,
            options(nomem, nostack)
        );
    }
    observed
}

/// Install a Guarded page, branch into it twice, and restore everything.
///
/// # Safety
///
/// Writes `TTBR0_EL2` and `SCTLR`, and executes an indirect branch that is
/// expected to fault. Must be called inside [`vectors::with_vectors`]. The
/// caller must be at EL2 with translation on and an identity mapping over DRAM.
pub unsafe fn enable_and_verify() -> BtiReport {
    let pfr1 = registers::id_aa64pfr1_el1();
    let sctlr_before = registers::sctlr_el1();
    // Captured BEFORE anything is installed. Reading it back at the end would
    // return the root this function installed, and "restored" would be a
    // tautology -- the register put back would be the one under test.
    let root_before = registers::ttbr0_el2();
    let guarded_page = vectors::bti_landing_address() & !((1u64 << 14) - 1);

    let mut report = BtiReport {
        supported: crate::aarch64_features::ControlFlowSupport::from_id_registers(0, pfr1)
            .branch_target_identification,
        guarded_root: 0,
        tables_used: 0,
        guarded_page,
        descriptor: 0,
        sctlr_before,
        sctlr_while_enabled: 0,
        sctlr_after: sctlr_before,
        bad_branch_esr: 0,
        bad_branch_faulted: false,
        good_branch_faulted: false,
        restored_root: root_before,
        error: 0,
    };
    if !report.supported {
        return report;
    }

    let tcr = registers::tcr_el2();
    let Some(config) = crate::aarch64_walk::WalkConfig::from_tcr(tcr) else {
        report.error = 5;
        return report;
    };

    // Attributes from a live descriptor, for the same reason every other table
    // in this tree takes them from the machine: memory type is an index into
    // MAIR, and a plausible constant yields a regime that resolves and cannot
    // be executed.
    let live_root = registers::ttbr0_el2() & 0x0000_FFFF_FFFF_FFFE;
    let granule = 1u64 << config.granule_bits;
    let address_mask = ((1u64 << 48) - 1) & !(granule - 1);
    // SAFETY: reading descriptors from physical addresses the live tables point
    // at, under the identity mapping in force.
    let live = crate::aarch64_walk::walk(live_root, guarded_page, config, |pa| unsafe {
        core::ptr::read_volatile(pa as usize as *const u64)
    });
    let Ok(live) = live else {
        report.error = 3;
        return report;
    };
    let kernel_attributes = live.descriptor & !address_mask & !0b11;

    // SAFETY: nothing has this root installed yet.
    match unsafe {
        super::mmu::build_guarded_root(
            guarded_page,
            config.granule_bits,
            config.input_address_bits(),
            kernel_attributes,
        )
    } {
        Ok((root, tables)) => {
            report.guarded_root = root;
            report.tables_used = tables;
        }
        Err(error) => {
            report.error = super::mmu::build_error_code(error);
            return report;
        }
    }

    // Confirm `GP` actually reached the leaf before trusting a test whose whole
    // signal is a fault. Without this, a builder that dropped the bit produces
    // a run in which nothing faults, and "BTI is not enforced" and "BTI was
    // never switched on" are the same reading.
    // SAFETY: reading descriptors from the table just built, through the
    // identity mapping still in force.
    if let Ok(built) =
        crate::aarch64_walk::walk(report.guarded_root, guarded_page, config, |pa| unsafe {
            core::ptr::read_volatile(pa as usize as *const u64)
        })
    {
        report.descriptor = built.descriptor;
    }
    if report.descriptor & super::mmu::GP == 0 {
        return report;
    }

    // SAFETY: the architecturally required sequence, and the same one
    // `mmu::switch_to_built_root` documents. The regime is an identity map of
    // DRAM, so the instruction after the `isb` fetches exactly as before.
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "msr TTBR0_EL2, {root}",
            "isb",
            "tlbi alle2is",
            "dsb ish",
            "isb",
            root = in(reg) report.guarded_root,
            options(nostack)
        );
    }

    let before = vectors::last_exception().count;

    // The branch that must fault.
    // SAFETY: inside `with_vectors`, and the target ends in `ret`, so the
    // handler advancing past the faulting instruction returns here.
    report.sctlr_while_enabled =
        unsafe { call_with_bti(vectors::bti_no_landing_address(), sctlr_before) };
    let after_bad = vectors::last_exception();
    report.bad_branch_faulted = after_bad.count != before;
    report.bad_branch_esr = after_bad.esr;

    // The branch that must not.
    // SAFETY: as above; this target begins with a valid `BTI c`.
    unsafe { call_with_bti(vectors::bti_landing_address(), sctlr_before) };
    report.good_branch_faulted = vectors::last_exception().count != after_bad.count;

    // SAFETY: restoring exactly what was read, with the same barriers.
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "msr TTBR0_EL2, {root}",
            "isb",
            "tlbi alle2is",
            "dsb ish",
            "isb",
            "msr SCTLR_EL1, {sctlr}",
            "isb",
            root = in(reg) root_before,
            sctlr = in(reg) sctlr_before,
            options(nostack)
        );
    }
    report.sctlr_after = registers::sctlr_el1();
    report.restored_root = registers::ttbr0_el2();
    report
}
