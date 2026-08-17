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
