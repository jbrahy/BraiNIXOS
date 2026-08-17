//! Programming translation: `TTBR`, TLB maintenance, and the switch.
//!
//! # The order this is being built in, and why
//!
//! Enabling translation is the one operation on this platform that fails with
//! no way to report why: get `TCR` or the tables wrong and the next instruction
//! fetch faults through a mapping that no longer describes the code doing the
//! faulting. There is no console left, and the vectors we installed are
//! themselves at an address that may no longer resolve.
//!
//! So the dangerous *mechanism* is exercised first with tables that are already
//! known good -- the ones the machine is running on -- rather than debugging a
//! new table builder and a `TTBR` switch simultaneously. This module does the
//! switch. Building our own tables is a separate step, checked by the walker
//! that was already validated against the MMU's own `AT` instruction.
//!
//! # Why a copy rather than the same pointer
//!
//! [`switch_to_copied_root`] copies the live root table into memory this image
//! owns and points `TTBR0_EL2` at the copy. The lower levels are still the
//! machine's, reached through the copied descriptors, so every address that
//! resolved before resolves after -- but the register now holds *our* address
//! and the hardware is walking *our* table. That is the whole of the mechanism
//! under test, with the mapping held constant.
//!
//! Changing the register and the mapping at once would mean a fault could not
//! be attributed to either.

#![allow(unsafe_code)]

use super::registers;
use crate::aarch64_tables::{BuildError, TableBuilder};
use crate::aarch64_walk::{walk, WalkConfig};

/// A root table this image owns, aligned to the 16 KiB granule the target uses.
///
/// In `.bss`, which is zeroed at every entry point -- see `arch::aarch64::bss`.
/// An unzeroed table is full of whatever was in that memory, and a stale low
/// bit pair is a descriptor the MMU will follow.
#[repr(align(16384))]
struct RootTable([u64; 2048]);

static mut ROOT_COPY: RootTable = RootTable([0; 2048]);

/// What happened during a switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwitchReport {
    /// `TTBR0_EL2` before the switch.
    pub original_root: u64,
    /// The root actually installed.
    pub installed_root: u64,
    /// A value read back through the new mapping, to prove it resolves.
    pub probe_value: u64,
    /// `TTBR0_EL2` after restoring.
    pub restored_root: u64,
    /// How many descriptors were copied.
    pub entries_copied: usize,
}

/// Copy the live root table, run on it, then restore.
///
/// # What is proved
///
/// That we can program `TTBR0_EL2`, invalidate the TLBs correctly, and have the
/// hardware walk a table this image placed -- verified by reading memory back
/// through the new mapping *while it is installed*.
///
/// # Safety
///
/// The caller must be at EL2 with translation already enabled, and the copy
/// must describe the currently-executing code, or the instruction after the
/// switch will not fetch. Both hold when the root is a copy of the live one.
pub unsafe fn switch_to_copied_root(probe_address: u64) -> SwitchReport {
    let original_root = registers::ttbr0_el2();
    // TTBR holds the table's physical address in bits [47:1]; the low bit is
    // CnP and the top bits are ASID, none of which belong in a pointer.
    let live_table = original_root & 0x0000_FFFF_FFFF_FFFE;

    let entries = 2048usize;

    // SAFETY: `ROOT_COPY` is ours and 16 KiB aligned; `live_table` is the root
    // the machine is walking right now, so it is mapped and readable. The
    // mapping is identity over this memory, measured, so the physical address
    // is directly usable.
    let installed_root = unsafe {
        let destination = core::ptr::addr_of_mut!(ROOT_COPY) as *mut u64;
        for index in 0..entries {
            let descriptor = core::ptr::read_volatile((live_table as *const u64).add(index));
            core::ptr::write_volatile(destination.add(index), descriptor);
        }
        destination as u64
    };

    // SAFETY: the sequence below is the architecturally required one. Each
    // barrier is load-bearing:
    //
    //   dsb ishst  - the descriptor writes above must be visible to the table
    //                walker before it is told to use them. Without it the
    //                walker may read a partially written table.
    //   msr + isb  - the new TTBR must be in effect before any later
    //                instruction is fetched through it.
    //   tlbi + dsb - stale entries describe the OLD table. Skipping this
    //                appears to work, because the TLB still holds correct
    //                translations, and fails later at an unrelated address.
    //   isb        - the invalidation must complete before execution continues.
    let probe_value = unsafe {
        core::arch::asm!(
            "dsb ishst",
            "msr TTBR0_EL2, {root}",
            "isb",
            "tlbi alle2is",
            "dsb ish",
            "isb",
            root = in(reg) installed_root,
            options(nostack)
        );

        // Read through the new mapping while it is installed. If the copy were
        // wrong this would fault -- and so would the fetch of this very
        // instruction, which is why the copy holds the mapping constant.
        let value = core::ptr::read_volatile(probe_address as *const u64);

        core::arch::asm!(
            "dsb ishst",
            "msr TTBR0_EL2, {root}",
            "isb",
            "tlbi alle2is",
            "dsb ish",
            "isb",
            root = in(reg) original_root,
            options(nostack)
        );
        value
    };

    SwitchReport {
        original_root,
        installed_root,
        probe_value,
        restored_root: registers::ttbr0_el2(),
        entries_copied: entries,
    }
}

// ---------------------------------------------------------------------------
// Tables this repository built, rather than a copy of the machine's.
//
// The copied-root switch above deliberately held the mapping constant so a
// fault would be attributable to the register change alone. This is the other
// half, and the last untested step of MMU bring-up: the register AND the
// mapping are ours.
//
// It is the most dangerous operation in the kernel. Between `msr TTBR0_EL2` and
// the restore, every instruction fetch, every stack access and every load goes
// through a table this code wrote. A single wrong descriptor is not a fault
// that gets reported -- there is no console, and the vector table is itself at
// an address that may no longer resolve.
//
// Three things make it survivable, and none of them is care.
// ---------------------------------------------------------------------------

/// DRAM base on this target, from m1n1's own `MMU: RAM base` line.
const DRAM_BASE: u64 = 0x100_0000_0000;
/// DRAM size: `mem_size_act` from `boot_args`, 32 GiB.
const DRAM_SIZE: u64 = 0x8_0000_0000;

/// Tables for the built root.
///
/// **All of DRAM costs three tables.** At a 16 KiB granule the block level
/// resolves 32 MiB per descriptor, one level-2 table spans 2048 of them (64 GiB)
/// and 32 GiB of DRAM is 1024 entries inside a single one. So the whole of
/// memory is a root, one intermediate and one leaf table: 48 KiB.
///
/// That is what makes mapping *everything* the safe choice rather than the
/// expensive one. `p.call` runs this on **m1n1's stack**, not ours, and
/// `boot_args`, m1n1's own code and the payload are scattered across its heap;
/// a mapping sized to "what we think we need" is a guess, and the failure mode
/// of guessing wrong is a hang with no console. Mapping all of DRAM removes the
/// guess for less memory than the arena's alignment padding.
///
/// Six tables rather than three so that a mapping request which needs more
/// levels than expected returns [`BuildError::OutOfTables`] instead of running
/// off the end.
#[repr(align(16384))]
struct TableArena([u64; 2048 * 6]);

static mut BUILT_TABLES: TableArena = TableArena([0; 2048 * 6]);

/// A second arena, for the EL1/EL0 regime.
///
/// Separate from [`BUILT_TABLES`] rather than shared, because the two are
/// installed in different registers and one of them is live while the other is
/// being built. Reusing one arena would mean the EL0 excursion overwrites the
/// table `TTBR0_EL2` is walking.
///
/// Seven tables: root, intermediate, the leaf holding DRAM's blocks, and one
/// more for the 32 MiB the user page lives in, split into 16 KiB pages. Plus
/// slack.
#[repr(align(16384))]
struct UserArena([u64; 2048 * 7]);

static mut USER_TABLES: UserArena = UserArena([0; 2048 * 7]);

/// `AP[1]`, bit 6: the mapping is reachable from EL0.
pub const AP_EL0: u64 = 1 << 6;
/// `PXN`, bit 53: privileged execute never.
pub const PXN: u64 = 1 << 53;
/// `UXN`, bit 54: unprivileged execute never.
pub const UXN: u64 = 1 << 54;

/// Build an EL1 regime in which exactly one page is reachable from EL0.
///
/// # The shape, and why it is not simpler
///
/// All of DRAM as kernel-only blocks, except the 32 MiB containing `user_page`,
/// which is laid out as individual granule-sized pages so that one of them --
/// and only one -- carries `AP[1]`. Marking the *block* accessible instead would
/// be one line shorter and would hand userspace 32 MiB of whatever else lives
/// nearby, which here is the kernel's own code.
///
/// The user page also gets `PXN`: EL1 must not execute memory EL0 can write.
/// Everything else gets `UXN`, so EL0 cannot execute the kernel even if a
/// permission bug ever made it readable.
///
/// Returns the root and how many tables it cost.
///
/// # Safety
///
/// Writes `USER_TABLES`. Single-threaded, and the caller must not have this
/// root installed while calling.
pub unsafe fn build_user_root(
    user_page: u64,
    granule_bits: u32,
    input_bits: u32,
    kernel_attributes: u64,
) -> Result<(u64, usize), BuildError> {
    // SAFETY: `USER_TABLES` is ours, 16 KiB aligned, single-threaded here.
    let arena: &mut [u64] = unsafe { &mut (*core::ptr::addr_of_mut!(USER_TABLES)).0 };
    let arena_base = arena.as_ptr() as u64;
    let mut builder = TableBuilder::new(arena, arena_base, granule_bits, input_bits)?;

    let granule = 1u64 << granule_bits;
    let block = builder.block_size();
    let split_start = user_page & !(block.saturating_sub(1));
    if split_start < DRAM_BASE || split_start >= DRAM_BASE.saturating_add(DRAM_SIZE) {
        return Err(BuildError::AddressOutOfRange);
    }

    // The fine-grained region FIRST. `map_blocks` refuses to overwrite a table
    // descriptor, and `map_pages` refuses to split a live block, so the order is
    // forced -- which is the intended shape of both refusals rather than an
    // inconvenience. See `aarch64_tables::map_pages`.
    let mut offset = 0u64;
    while offset < block {
        let page = split_start.saturating_add(offset);
        let attributes = if page == user_page {
            // Reachable from EL0, executable by EL0, and NOT executable by EL1.
            (kernel_attributes | AP_EL0 | PXN) & !UXN
        } else {
            // Kernel-only, and not executable from EL0 even if that changes.
            kernel_attributes | UXN
        };
        builder.map_pages(page, page, granule, attributes)?;
        offset = offset.saturating_add(granule);
    }

    // Then DRAM either side of it, in blocks.
    let before = split_start.saturating_sub(DRAM_BASE);
    if before > 0 {
        builder.map_blocks(DRAM_BASE, DRAM_BASE, before, kernel_attributes | UXN)?;
    }
    let after_start = split_start.saturating_add(block);
    let dram_end = DRAM_BASE.saturating_add(DRAM_SIZE);
    if after_start < dram_end {
        builder.map_blocks(
            after_start,
            after_start,
            dram_end.saturating_sub(after_start),
            kernel_attributes | UXN,
        )?;
    }

    Ok((builder.root(), builder.tables_used()))
}

/// What building and installing our own tables produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltRootReport {
    /// Granule the live `TCR` selects, decoded rather than assumed.
    pub granule_bits: u32,
    /// Levels the walk traverses.
    pub levels: u32,
    /// Bytes one block descriptor covers.
    pub block_size: u64,
    /// A live block descriptor, from the machine's own tables.
    pub live_descriptor: u64,
    /// Attribute bits lifted from it.
    pub attributes: u64,
    /// Physical base of the built root table.
    pub built_root: u64,
    /// Tables the build consumed.
    pub tables_used: usize,
    /// Addresses cross-checked against the hardware before switching.
    pub checked: usize,
    /// How many of them disagreed. Anything but zero and no switch happens.
    pub mismatches: usize,
    /// Whether the switch was actually performed.
    pub switched: bool,
    /// A value read through the built mapping while it was installed.
    pub probe_value: u64,
    /// The same address read before the switch.
    pub expected_value: u64,
    /// `TTBR0_EL2` after restoring.
    pub restored_root: u64,
    /// Build failure, as [`build_error_code`], or 0.
    pub error: u64,
}

/// Numeric code for a [`BuildError`], for a report that crosses into Python.
///
/// Zero means no error, so the codes start at one.
pub fn build_error_code(error: BuildError) -> u64 {
    match error {
        BuildError::OutOfTables => 1,
        BuildError::MisalignedArena => 2,
        BuildError::AddressOutOfRange => 3,
        BuildError::MisalignedRange => 4,
        BuildError::UnsupportedConfiguration => 5,
        BuildError::AlreadyMapped => 6,
    }
}

/// Build an identity map of DRAM, check it against the hardware, install it.
///
/// # Why it cannot simply be built and switched to
///
/// A table builder that is subtly wrong does not produce a table that fails to
/// build. It produces one that resolves to a plausible wrong page, and the only
/// symptom is that the machine stops. So this refuses to install anything it has
/// not first checked against an independent oracle:
///
/// 1. **The attributes are the machine's, not invented.** They are lifted from a
///    live block descriptor covering the address we are about to run through.
///    Memory type is expressed as an `AttrIndx` into `MAIR`, so a plausible
///    constant here yields a mapping that resolves and cannot be executed.
/// 2. **Every checked address is walked twice.** Once by
///    [`crate::aarch64_walk`] over the table just built, and once by the MMU
///    itself via `AT S1E2R` on the live tables. Two independent implementations
///    of opposite directions of the same specification, and `AT` cannot fault.
/// 3. **A single disagreement aborts the switch.** `mismatches` is reported and
///    `TTBR0_EL2` is never written. A refused switch costs nothing; a wrong one
///    costs the machine.
///
/// # Safety
///
/// The caller must be at EL2 with translation enabled and an identity mapping
/// over DRAM, which is what the target runs under m1n1. `check` should include
/// the currently-executing code and anything the window touches.
pub unsafe fn switch_to_built_root(probe_address: u64, check: &[u64]) -> BuiltRootReport {
    let original_root = registers::ttbr0_el2();
    let tcr = registers::tcr_el2();

    let mut report = BuiltRootReport {
        granule_bits: 0,
        levels: 0,
        block_size: 0,
        live_descriptor: 0,
        attributes: 0,
        built_root: 0,
        tables_used: 0,
        checked: 0,
        mismatches: 0,
        switched: false,
        probe_value: 0,
        expected_value: 0,
        restored_root: original_root,
        error: 0,
    };

    let Some(config) = WalkConfig::from_tcr(tcr) else {
        report.error = build_error_code(BuildError::UnsupportedConfiguration);
        return report;
    };
    report.granule_bits = config.granule_bits;
    report.levels = config.levels();

    let live_root = original_root & 0x0000_FFFF_FFFF_FFFE;
    // SAFETY: reading descriptors from physical addresses the live tables
    // themselves point at, under the identity mapping this function's contract
    // requires.
    let live = walk(live_root, probe_address, config, |pa| unsafe {
        core::ptr::read_volatile(pa as usize as *const u64)
    });
    let Ok(live) = live else {
        report.error = build_error_code(BuildError::AddressOutOfRange);
        return report;
    };
    report.live_descriptor = live.descriptor;

    // Everything the descriptor says except where it points and what kind it is.
    // That is access flag, shareability, permissions, AttrIndx and the upper
    // attributes -- the parts this module has no business inventing.
    let granule = 1u64 << config.granule_bits;
    let address_mask = ((1u64 << 48) - 1) & !(granule - 1);
    report.attributes = live.descriptor & !address_mask & !0b11;

    // SAFETY: `BUILT_TABLES` is ours, 16 KiB aligned, and single-threaded here.
    let arena: &mut [u64] = unsafe { &mut (*core::ptr::addr_of_mut!(BUILT_TABLES)).0 };
    let arena_base = arena.as_ptr() as u64;

    let mut builder = match TableBuilder::new(
        arena,
        arena_base,
        config.granule_bits,
        config.input_address_bits(),
    ) {
        Ok(builder) => builder,
        Err(error) => {
            report.error = build_error_code(error);
            return report;
        }
    };
    report.block_size = builder.block_size();

    if let Err(error) = builder.map_blocks(DRAM_BASE, DRAM_BASE, DRAM_SIZE, report.attributes) {
        report.error = build_error_code(error);
        return report;
    }
    report.tables_used = builder.tables_used();
    report.built_root = builder.root();

    // ---- the gate ---------------------------------------------------------
    // Our walker against the MMU's own answer, for every address the window
    // will touch. Disagreement here is a table that would have hung the machine.
    for &address in check {
        report.checked = report.checked.saturating_add(1);
        // SAFETY: as above -- reading descriptors from the table just built,
        // through the identity mapping still in force.
        let ours = walk(report.built_root, address, config, |pa| unsafe {
            core::ptr::read_volatile(pa as usize as *const u64)
        });
        let par = registers::translate_el2_read(address);
        let agrees = match ours {
            // PAR_EL1 bit 0 set means the hardware could not translate it, so
            // there is nothing to agree with and our mapping is the wrong one.
            Ok(translation) if par & 1 == 0 => {
                let hardware = (par & 0x0000_FFFF_FFFF_F000) | (address & 0xFFF);
                translation.physical_address == hardware
            }
            _ => false,
        };
        if !agrees {
            report.mismatches = report.mismatches.saturating_add(1);
        }
    }
    if report.mismatches != 0 {
        return report;
    }

    // SAFETY: the address is one the caller listed and the check above proved
    // both mappings resolve it to the same place.
    report.expected_value = unsafe { core::ptr::read_volatile(probe_address as *const u64) };

    // SAFETY: same barrier sequence and same reasoning as
    // `switch_to_copied_root`, with one difference that matters: the mapping is
    // ours as well as the register, so the fetch of the instruction after the
    // `isb` is the first real test of the table.
    report.probe_value = unsafe {
        core::arch::asm!(
            "dsb ishst",
            "msr TTBR0_EL2, {root}",
            "isb",
            "tlbi alle2is",
            "dsb ish",
            "isb",
            root = in(reg) report.built_root,
            options(nostack)
        );

        let value = core::ptr::read_volatile(probe_address as *const u64);

        core::arch::asm!(
            "dsb ishst",
            "msr TTBR0_EL2, {root}",
            "isb",
            "tlbi alle2is",
            "dsb ish",
            "isb",
            root = in(reg) original_root,
            options(nostack)
        );
        value
    };
    report.switched = true;
    report.restored_root = registers::ttbr0_el2();
    report
}
