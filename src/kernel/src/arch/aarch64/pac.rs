//! Pointer authentication, and proving it does something.
//!
//! # Detection is not enabling
//!
//! `aarch64_features::ControlFlowSupport` already reports that this part
//! implements address authentication -- through Apple's implementation-defined
//! field, `ID_AA64ISAR1_EL1.API`, not the QARMA one. Reporting it changes
//! nothing: until `SCTLR.EnIA` is set, `PACIA` and `AUTIA` are architecturally
//! **NOPs**. A kernel that reads the feature bit, logs "PAC available" and stops
//! has exactly the control-flow integrity of one that never looked.
//!
//! Worse, the failure is silent in the direction that matters. Sign a pointer
//! with PAC disabled and you get the pointer back unchanged; authenticate it and
//! it still matches. Every test passes. The mitigation is absent.
//!
//! So this module does not report a capability. It enables the feature, signs a
//! value, authenticates it back, and then **tampers with the signature and
//! checks that authentication rejects it**. Only the last of those three can
//! tell a working PAC from a disabled one.
//!
//! # HINT-space encodings
//!
//! `PACIA1716` and `AUTIA1716` are written as `hint #8` and `hint #12`. The
//! architecture puts them in the HINT space precisely so that a part without
//! `FEAT_PAuth` executes them as NOPs rather than faulting, and the raw form
//! assembles without the target enabling the feature -- which this build does
//! not do, because whether the feature exists is a run-time question answered
//! from `ID_AA64ISAR1_EL1`. Same reasoning as the `RNDR` encoding in
//! `registers`, and the `_EL12` encodings in `el`.
//!
//! `1716` names the operands: `X17` is the pointer, `X16` the modifier.
//!
//! # Keys
//!
//! This part has **no `RNDR`** -- `ID_AA64ISAR0_EL1 = 0x0221100110212120`, the
//! field is zero -- so the key comes from the boot seed instead: 64 bytes iBoot
//! leaves at `/chosen/random-seed`, measured to differ on every boot, hashed
//! with a domain separator. See [`crate::aarch64_entropy`] for why it is hashed
//! rather than sliced, and [`super::entropy`] for why it is erased on use.
//!
//! Enabling PAC on a key this kernel did not choose is the failure this avoids.
//! A fixed key authenticates perfectly, passes every test in this module, and
//! protects nobody: it is the same key on every machine and every boot, so a
//! signature forged once is valid everywhere. `keys_installed` reports whether
//! a key was actually installed, and refusing is the correct outcome when no
//! entropy is available -- an all-zero key that looks like a mitigation is worse
//! than none.
//!
//! m1n1 does not use pointer authentication -- it neither writes the key
//! registers nor emits a signing instruction; the only mention in its source is
//! mapping Apple's `APCTL` for its own hypervisor mode. So installing keys here
//! cannot invalidate a pointer m1n1 signed, because there are none.
//!
//! The keys are **not read back before being written**. Apple's
//! implementation-defined system registers are not uniformly readable at EL2 --
//! reading the `GXF` syndrome registers unguarded wedged this machine once
//! already -- and a save/restore that hangs on the save is worse than no
//! save/restore. `SCTLR` is restored, which is what governs whether the
//! instructions do anything at all.

#![allow(unsafe_code)]

use super::{registers, vectors};

/// `SCTLR.EnIA`, bit 31: instruction pointer authentication, key A.
const SCTLR_ENIA: u64 = 1 << 31;
/// `SCTLR.EnIB`, bit 30: instruction pointer authentication, key B.
const SCTLR_ENIB: u64 = 1 << 30;
/// `SCTLR.EnDA`, bit 27: data pointer authentication, key A.
const SCTLR_ENDA: u64 = 1 << 27;
/// `SCTLR.EnDB`, bit 13: data pointer authentication, key B.
const SCTLR_ENDB: u64 = 1 << 13;
/// `SCTLR.BT1`, bit 36: branch target identification for this level.
///
/// Inert on its own, and deliberately included anyway -- see
/// [`PacReport::sctlr_while_enabled`]. BTI only constrains branches into pages
/// whose descriptors set `GP`, and this image runs on m1n1's tables, which do
/// not. Setting the bit here is what makes the *other* half a page-table
/// question rather than an unexplored one.
const SCTLR_BT1: u64 = 1 << 36;

/// Bit flipped in a signature to prove authentication rejects it.
///
/// 55 is inside the PAC field for every `TCR` configuration this platform uses:
/// with a 47-bit input address the signature occupies bits [63:56] and [54:47],
/// and bit 55 is the sign-extension bit that `AUTIA` reconstructs. Flipping a
/// bit of the *address* instead would be a different and much weaker test --
/// it would prove the address is covered, not that the signature is checked.
const TAMPER_BIT: u64 = 1 << 55;

/// What the round trip observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacReport {
    /// `SCTLR` as found.
    pub sctlr_before: u64,
    /// `SCTLR` while the round trip ran, read back rather than assumed.
    ///
    /// Read back because a bit that does not stick is the whole failure mode:
    /// `SCTLR` bits for features the part does not implement are `RES0`, so the
    /// write is accepted and discarded, and the round trip that follows measures
    /// a feature that was never on.
    pub sctlr_while_enabled: u64,
    /// `SCTLR` after restoring.
    pub sctlr_after: u64,
    /// Apple's `APCTL_EL1`, or [`UNREADABLE`] if reading it trapped.
    pub apctl: u64,
    /// The value signed.
    pub plain: u64,
    /// What signing produced with `SCTLR` as found, before anything was enabled.
    ///
    /// Equal to `plain` is the expected reading, and it is the control: it says
    /// the instructions really were NOPs beforehand, so a difference afterwards
    /// is attributable to enabling them.
    pub signed_as_found: u64,
    /// What signing produced with authentication enabled.
    pub signed: u64,
    /// What authenticating the signature produced. Must equal `plain`.
    pub recovered: u64,
    /// The signature with [`TAMPER_BIT`] flipped.
    pub tampered: u64,
    /// What authenticating the tampered signature produced.
    ///
    /// Must **not** equal `plain`. On a part implementing `FEAT_FPAC` the
    /// authentication faults instead, which the vector table catches; then this
    /// reads back as `tampered` unchanged and `vector` names the entry.
    pub authenticated_tampered: u64,
    /// Vector index of any exception taken during the run, or
    /// [`vectors::NO_EXCEPTION`].
    pub vector: u64,
    /// Whether keys were installed from the hardware entropy source.
    pub keys_installed: bool,
    /// Whether `FEAT_RNG` was reported present when keys were wanted.
    ///
    /// Separates "the part has no entropy source" from "it has one and it
    /// declined to produce a number", which need different responses and are
    /// otherwise the same reading.
    pub random_present: bool,
    /// What the boot seed looked like, when one was consulted.
    ///
    /// `None` when `RNDR` supplied the key and the seed was never touched,
    /// which also means it was not erased.
    pub seed: Option<super::entropy::SeedReport>,
}

impl PacReport {
    /// Whether this run proves authentication is actually operating.
    ///
    /// All three conditions, not any of them. Signing that changes the value
    /// proves the instruction is no longer a NOP; authentication returning the
    /// original proves it is the inverse; and rejection of a tampered signature
    /// is the only one of the three that a broken-but-plausible implementation
    /// could not also produce.
    pub fn authentication_works(&self) -> bool {
        self.signed != self.plain
            && self.recovered == self.plain
            && self.authenticated_tampered != self.plain
    }
}

/// Sentinel for a system register whose read trapped.
///
/// Distinct from zero, which is a legitimate value for `APCTL_EL1` and is
/// exactly what a trapped-and-skipped `mrs` would otherwise be indistinguishable
/// from.
pub const UNREADABLE: u64 = 0xDEAD_0000_DEAD_0000;

/// Sign `plain` with key A and modifier `modifier`, then authenticate it back.
///
/// Returns `(signed, recovered)`. With authentication disabled both equal
/// `plain`, which is the point of measuring it before enabling anything.
///
/// # Safety
///
/// The instructions are HINT-space and are NOPs where the feature is absent.
/// With `FEAT_FPAC` implemented, authenticating a bad signature raises a
/// synchronous exception, so callers that tamper must run inside
/// [`vectors::with_vectors`].
unsafe fn round_trip(plain: u64, modifier: u64) -> (u64, u64) {
    let signed: u64;
    let recovered: u64;
    // SAFETY: x16 and x17 are declared as operands, so the compiler is not
    // holding anything in them. No memory is touched.
    unsafe {
        core::arch::asm!(
            "mov x16, {modifier}",
            "mov x17, {plain}",
            "hint #8",              // PACIA1716: sign X17 with key A, modifier X16
            "mov {signed}, x17",
            "hint #12",             // AUTIA1716: authenticate X17 with key A
            "mov {recovered}, x17",
            plain = in(reg) plain,
            modifier = in(reg) modifier,
            signed = out(reg) signed,
            recovered = out(reg) recovered,
            out("x16") _,
            out("x17") _,
            options(nomem, nostack)
        );
    }
    (signed, recovered)
}

/// Authenticate `candidate` with key A and modifier `modifier`.
///
/// # Safety
///
/// Must run inside [`vectors::with_vectors`]: on a part implementing
/// `FEAT_FPAC` a failed authentication is a synchronous exception, and the
/// entire purpose of calling this is to fail one.
unsafe fn authenticate(candidate: u64, modifier: u64) -> u64 {
    let result: u64;
    // SAFETY: as `round_trip`. If the `hint #12` faults, the handler advances
    // past it and the following `mov` reports x17 unchanged, which is a reading
    // rather than a crash.
    unsafe {
        core::arch::asm!(
            "mov x16, {modifier}",
            "mov x17, {candidate}",
            "hint #12",             // AUTIA1716
            "mov {result}, x17",
            candidate = in(reg) candidate,
            modifier = in(reg) modifier,
            result = out(reg) result,
            out("x16") _,
            out("x17") _,
            options(nomem, nostack)
        );
    }
    result
}

/// Read Apple's `APCTL_EL1`, returning [`UNREADABLE`] if the read traps.
///
/// # Safety
///
/// Must run inside [`vectors::with_vectors`]. This is an Apple
/// implementation-defined register and not all of them are readable at EL2 --
/// reading the `GXF` syndrome registers unguarded wedged this machine once. The
/// sentinel is loaded first so that a trapped-and-skipped `mrs` is legible as
/// such rather than reporting a stale register.
unsafe fn apctl() -> u64 {
    let value: u64;
    // SAFETY: the sentinel is in place before the `mrs`, so a fault that skips
    // the read leaves a value that says so.
    unsafe {
        core::arch::asm!(
            "mov {value}, {sentinel}",
            // s3_4_c15_c0_4, from m1n1 `src/cpu_regs.h`:
            //   #define SYS_IMP_APL_APCTL_EL1 sys_reg(3, 4, 15, 0, 4)
            "mrs {value}, s3_4_c15_c0_4",
            value = out(reg) value,
            sentinel = in(reg) UNREADABLE,
            options(nomem, nostack)
        );
    }
    value
}

/// Enable pointer authentication, prove it works, and restore `SCTLR`.
///
/// `plain` should be a value shaped like a pointer this image owns; its top
/// bits are where the signature goes.
///
/// # Safety
///
/// Writes `SCTLR` and the key A registers, **erases the boot seed**, and
/// executes authentication instructions that can fault. Must be called inside
/// [`vectors::with_vectors`], and `boot_args` must be the firmware pointer or
/// null. `SCTLR` is restored; the keys are not, for the reason given in the
/// module documentation.
pub unsafe fn enable_and_verify(plain: u64, modifier: u64, boot_args: *const u8) -> PacReport {
    let sctlr_before = registers::sctlr_el1();
    // SAFETY: inside `with_vectors` per this function's contract.
    let apctl_value = unsafe { apctl() };

    // The control. With authentication disabled these instructions are NOPs, so
    // this should come back equal to `plain` -- and if it does not, the feature
    // was already on and nothing below is attributable to enabling it.
    //
    // SAFETY: HINT-space instructions with a valid signature; cannot fault.
    let (signed_as_found, _) = unsafe { round_trip(plain, modifier) };

    // Install key A from the hardware entropy source.
    //
    // A key of zero authenticates perfectly well and protects nothing: it is the
    // same key on every machine and every boot, so a signature forged once is
    // valid everywhere. Enabling PAC with a fixed key is the kind of mitigation
    // that passes its own tests and stops nobody.
    // `RNDR` is checked first and is expected to be absent: measured on this
    // part, `ID_AA64ISAR0_EL1.RNDR` is zero. It is still checked rather than
    // assumed away, because this module should do the right thing on a part
    // that has one.
    //
    // SAFETY: guarded by the FEAT_RNG check.
    let random_present =
        crate::aarch64_features::RandomSupport::from_isar0(registers::id_aa64isar0_el1()).present;
    let from_rndr = if random_present {
        match (unsafe { registers::random() }, unsafe { registers::random() }) {
            (Some(lo), Some(hi)) => Some((lo, hi)),
            _ => None,
        }
    } else {
        None
    };

    // Otherwise the boot seed. `/chosen/random-seed` is 64 bytes iBoot leaves in
    // the device tree, measured to differ on every boot, hashed with a domain
    // separator rather than sliced -- see `crate::aarch64_entropy`. `consume`
    // erases it before returning, so this is the only thing that gets to use it.
    //
    // SAFETY: the caller supplies the firmware `boot_args` pointer, and the
    // device tree is not in use by anything else during a probe.
    let (key_source, seed_report) = match from_rndr {
        Some(pair) => (Some(pair), None),
        None => match unsafe { super::entropy::consume(boot_args, b"pac.apia") } {
            Some((pair, report)) => (Some(pair), Some(report)),
            // SAFETY: as above; a non-consuming look, so the report can say
            // *why* there was no key.
            None => (None, Some(unsafe { super::entropy::peek(boot_args) })),
        },
    };

    let keys_installed = match key_source {
        Some((lo, hi)) => {
            // SAFETY: `APIAKeyLo_EL1`/`APIAKeyHi_EL1` are writable at EL2 and
            // affect only the key A computation. m1n1 signs nothing, so no live
            // signature is invalidated.
            unsafe {
                core::arch::asm!(
                    "msr s3_0_c2_c1_0, {lo}",   // APIAKeyLo_EL1
                    "msr s3_0_c2_c1_1, {hi}",   // APIAKeyHi_EL1
                    "isb",
                    lo = in(reg) lo,
                    hi = in(reg) hi,
                    options(nomem, nostack)
                );
            }
            true
        }
        // Deliberately not falling back to a constant. Refusing to install a key
        // leaves PAC measurably in whatever state it was in, which is honest;
        // installing a known one would look like success.
        None => false,
    };

    // SAFETY: setting the enable bits. Bits for features the part does not
    // implement are RES0 and are discarded, which is why the value is read back.
    unsafe {
        core::arch::asm!(
            "mrs {tmp}, SCTLR_EL1",
            "orr {tmp}, {tmp}, {bits}",
            "msr SCTLR_EL1, {tmp}",
            "isb",
            tmp = out(reg) _,
            bits = in(reg) SCTLR_ENIA | SCTLR_ENIB | SCTLR_ENDA | SCTLR_ENDB | SCTLR_BT1,
            options(nomem, nostack)
        );
    }
    let sctlr_while_enabled = registers::sctlr_el1();

    // SAFETY: a valid sign-then-authenticate pair; cannot fault.
    let (signed, recovered) = unsafe { round_trip(plain, modifier) };

    let tampered = signed ^ TAMPER_BIT;
    // SAFETY: inside `with_vectors`, which is required here -- this call exists
    // to fail authentication, and on a part with FEAT_FPAC that is an exception.
    let authenticated_tampered = unsafe { authenticate(tampered, modifier) };

    // SAFETY: restoring exactly what was read.
    unsafe {
        core::arch::asm!(
            "msr SCTLR_EL1, {sctlr}",
            "isb",
            sctlr = in(reg) sctlr_before,
            options(nomem, nostack)
        );
    }

    PacReport {
        sctlr_before,
        sctlr_while_enabled,
        sctlr_after: registers::sctlr_el1(),
        apctl: apctl_value,
        plain,
        signed_as_found,
        signed,
        recovered,
        tampered,
        authenticated_tampered,
        vector: vectors::last_exception().index,
        keys_installed,
        random_present,
        seed: seed_report,
    }
}
