//! `boot_args` parsing and the ADT physical-window derivation — AS-0-T4.
//!
//! At the firmware entry point, register `x0` holds the physical address of
//! an XNU `boot_args` structure (spec §3). This module reads the five fields
//! that structure needs to hand over — `virt_base`, `phys_base`, `mem_size`,
//! `devtree`, `devtree_size` — derives the ADT's physical window from them,
//! and applies every check spec §9.1 requires of that derivation. It never
//! reads or interprets any other `boot_args` field.
//!
//! # Offset basis
//!
//! Unlike [`crate::DeviceTree`], this module reads **fixed, absolute offsets**
//! into the `boot_args` structure itself — it is not the ADT, and the
//! buffer-relative-offset discipline of spec §3.1 does not apply to it. Its
//! output, [`AdtWindow`], is exactly the physical address and length the
//! caller must use to obtain the `&[u8]` that *is* handed to
//! [`crate::DeviceTree::parse`].
//!
//! # What this module deliberately does not do
//!
//! It does not read `revision`, `version`, `top_of_kernel_data`, `video`,
//! `machine_type`, or `cmdline` — none of them bear on deriving or validating
//! the ADT window, and `cmdline`'s offset is disputed (spec §10, OQ-1). It
//! also does not dereference any physical address: the caller owns turning an
//! [`AdtWindow`] into the `&[u8]` slice the ADT decoder receives.

use crate::raw::{read_u32_le, read_u64_le};

/// Byte offset of `boot_args.virt_base` (spec §3).
const VIRT_BASE_OFFSET: usize = 0x08;
/// Byte offset of `boot_args.phys_base` (spec §3).
const PHYS_BASE_OFFSET: usize = 0x10;
/// Byte offset of `boot_args.mem_size` (spec §3).
const MEM_SIZE_OFFSET: usize = 0x18;
/// Byte offset of `boot_args.devtree` (spec §3).
const DEVTREE_OFFSET: usize = 0x60;
/// Byte offset of `boot_args.devtree_size` (spec §3).
const DEVTREE_SIZE_OFFSET: usize = 0x68;
/// Bytes of `boot_args` this module reads: through the end of `devtree_size`.
const MIN_BOOT_ARGS_LEN: usize = DEVTREE_SIZE_OFFSET + 4;

/// Alignment mask for a 4-byte-aligned quantity. Bitwise, not `%`, so the
/// check cannot be read as arithmetic that could overflow.
const ALIGN_MASK_U32: u32 = 0x3;
/// As [`ALIGN_MASK_U32`], for the 64-bit physical address.
const ALIGN_MASK_U64: u64 = 0x3;

/// Every way `boot_args` or the ADT window derived from it can be refused.
///
/// One variant per failure mode (spec §9.0's distinct-reason requirement), so
/// a rejected `boot_args` can be audited for *why*. Deliberately not
/// `#[non_exhaustive]` — see [`crate::AdtError`]'s equivalent note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootArgsError {
    /// Fewer than [`MIN_BOOT_ARGS_LEN`] bytes were supplied — the buffer ends
    /// before `devtree_size` does.
    TruncatedBootArgs,

    /// `devtree_size` is zero (spec §9.1).
    ZeroDevtreeSize,

    /// `devtree_size` is less than 8 — the claimed blob cannot hold even a
    /// root node header (spec §9.1).
    DevtreeSizeBelowRootHeader,

    /// `devtree_size` is not a multiple of 4 (spec §3.1, §9.1). Every record
    /// in a well-formed tree is 4-byte aligned, so a well-formed tree can
    /// never claim a length that is not.
    DevtreeSizeMisaligned,

    /// `devtree − virt_base` underflowed: the ADT's claimed virtual address
    /// lies before iBoot's own mapping base (spec §9.1).
    VirtualAddressUnderflow,

    /// `(devtree − virt_base) + phys_base` overflowed a 64-bit address
    /// (spec §9.1).
    PhysicalAddressOverflow,

    /// The derived `adt_phys` is not 4-byte aligned. Required for the §9.7
    /// offset-alignment check to have a well-defined meaning (spec §3.1).
    AdtPhysMisaligned,

    /// `adt_phys + devtree_size` overflowed a 64-bit address (spec §9.1).
    AdtWindowOverflow,

    /// `phys_base + mem_size` overflowed while computing the DRAM window
    /// against which the ADT window is checked (spec §9.1).
    DramWindowOverflow,

    /// The ADT window `[adt_phys, adt_phys + devtree_size)` is not entirely
    /// inside the DRAM window `[phys_base, phys_base + mem_size)` (spec
    /// §9.1).
    AdtWindowOutsideDram,
}

/// The ADT's validated location in physical memory.
///
/// Holding one of these means every check spec §9.1 requires of the
/// `boot_args` → ADT-window derivation has already passed. It is not a claim
/// that the bytes at `phys_addr` form a well-formed tree — only
/// [`crate::DeviceTree::parse`] establishes that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdtWindow {
    /// Physical address of the first byte of the ADT blob.
    pub phys_addr: u64,
    /// Length of the ADT blob in bytes. Always at least 8 and a multiple of 4.
    pub len: u32,
}

/// Derives and validates the ADT's physical window from a `boot_args` buffer.
///
/// `boot_args` must be at least [`MIN_BOOT_ARGS_LEN`] bytes — the prefix
/// through `devtree_size` — starting at the address `x0` holds at firmware
/// entry. Trailing bytes (`cmdline` and beyond) are never read.
///
/// # Example
///
/// ```
/// use brainix_adt::{adt_window, AdtWindow};
///
/// fn locate_adt(boot_args: &[u8]) -> Result<AdtWindow, brainix_adt::BootArgsError> {
///     adt_window(boot_args)
/// }
/// ```
pub fn adt_window(boot_args: &[u8]) -> Result<AdtWindow, BootArgsError> {
    if boot_args.len() < MIN_BOOT_ARGS_LEN {
        return Err(BootArgsError::TruncatedBootArgs);
    }

    // Every read below is in-bounds by the length check above, but each still
    // goes through the same bounds-checked primitive the ADT decoder uses
    // rather than an unchecked slice index (defence in depth, not a
    // substitute for the length check).
    let virt_base =
        read_u64_le(boot_args, VIRT_BASE_OFFSET).ok_or(BootArgsError::TruncatedBootArgs)?;
    let phys_base =
        read_u64_le(boot_args, PHYS_BASE_OFFSET).ok_or(BootArgsError::TruncatedBootArgs)?;
    let mem_size =
        read_u64_le(boot_args, MEM_SIZE_OFFSET).ok_or(BootArgsError::TruncatedBootArgs)?;
    let devtree = read_u64_le(boot_args, DEVTREE_OFFSET).ok_or(BootArgsError::TruncatedBootArgs)?;
    let devtree_size =
        read_u32_le(boot_args, DEVTREE_SIZE_OFFSET).ok_or(BootArgsError::TruncatedBootArgs)?;

    if devtree_size == 0 {
        return Err(BootArgsError::ZeroDevtreeSize);
    }
    if devtree_size < 8 {
        return Err(BootArgsError::DevtreeSizeBelowRootHeader);
    }
    if devtree_size & ALIGN_MASK_U32 != 0 {
        return Err(BootArgsError::DevtreeSizeMisaligned);
    }

    let virt_offset = devtree
        .checked_sub(virt_base)
        .ok_or(BootArgsError::VirtualAddressUnderflow)?;
    let adt_phys = virt_offset
        .checked_add(phys_base)
        .ok_or(BootArgsError::PhysicalAddressOverflow)?;

    if adt_phys & ALIGN_MASK_U64 != 0 {
        return Err(BootArgsError::AdtPhysMisaligned);
    }

    let adt_end = adt_phys
        .checked_add(u64::from(devtree_size))
        .ok_or(BootArgsError::AdtWindowOverflow)?;

    let dram_end = phys_base
        .checked_add(mem_size)
        .ok_or(BootArgsError::DramWindowOverflow)?;

    // adt_phys < phys_base cannot happen given the derivation above (adt_phys
    // = virt_offset + phys_base, and virt_offset is a checked-non-negative
    // u64), but the check is kept as defence in depth against the derivation
    // ever changing, per spec §9.1's "entirely inside" requirement.
    if adt_phys < phys_base || adt_end > dram_end {
        return Err(BootArgsError::AdtWindowOutsideDram);
    }

    Ok(AdtWindow {
        phys_addr: adt_phys,
        len: devtree_size,
    })
}
