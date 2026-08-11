//! Adversarial fixtures for the `boot_args` → ADT-window derivation (AS-0-T4,
//! spec §3 and §9.1).
//!
//! Each test states the attacker-controlled value it corrupts and asserts the
//! exact reason `adt_window` denies. Nothing here may panic.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cognitive_complexity,
    clippy::useless_vec
)]

mod common;

use brainix_adt::{AdtWindow, BootArgsError};

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
/// One byte past `devtree_size` — the shortest buffer `adt_window` reads.
const MIN_LEN: usize = DEVTREE_SIZE_OFFSET + 4;

/// Builds the `boot_args` prefix `adt_window` reads: `virt_base`, `phys_base`,
/// `mem_size`, `devtree`, and `devtree_size`, at their documented offsets,
/// zero-filled elsewhere.
fn boot_args(
    virt_base: u64,
    phys_base: u64,
    mem_size: u64,
    devtree: u64,
    devtree_size: u32,
) -> Vec<u8> {
    let mut bytes = vec![0u8; MIN_LEN];
    bytes[VIRT_BASE_OFFSET..VIRT_BASE_OFFSET + 8].copy_from_slice(&virt_base.to_le_bytes());
    bytes[PHYS_BASE_OFFSET..PHYS_BASE_OFFSET + 8].copy_from_slice(&phys_base.to_le_bytes());
    bytes[MEM_SIZE_OFFSET..MEM_SIZE_OFFSET + 8].copy_from_slice(&mem_size.to_le_bytes());
    bytes[DEVTREE_OFFSET..DEVTREE_OFFSET + 8].copy_from_slice(&devtree.to_le_bytes());
    bytes[DEVTREE_SIZE_OFFSET..DEVTREE_SIZE_OFFSET + 4]
        .copy_from_slice(&devtree_size.to_le_bytes());
    bytes
}

/// A worked example with plausible, hand-checked values:
/// `virt_base = 0x1000`, `phys_base = 0x8000_0000`, `mem_size = 0x8000_0000`,
/// `devtree = 0x1100` ⇒ `adt_phys = 0x8000_0100`, `devtree_size = 288` (the
/// existing golden ADT fixture's length) ⇒ `adt_end = 0x8000_0220`, entirely
/// inside the DRAM window `[0x8000_0000, 0x1_0000_0000)`.
fn golden() -> Vec<u8> {
    boot_args(0x1000, 0x8000_0000, 0x8000_0000, 0x1100, 288)
}

#[test]
fn a_well_formed_boot_args_buffer_derives_the_worked_adt_window() {
    let window = brainix_adt::adt_window(&golden()).expect("golden boot_args must derive a window");
    assert_eq!(
        window,
        AdtWindow {
            phys_addr: 0x8000_0100,
            len: 288,
        }
    );
}

#[test]
fn a_boot_args_buffer_shorter_than_devtree_size_denies() {
    let full = golden();
    for length in 0..full.len() {
        assert_eq!(
            brainix_adt::adt_window(&full[..length]).unwrap_err(),
            BootArgsError::TruncatedBootArgs,
            "length {length}"
        );
    }
    assert!(brainix_adt::adt_window(&full).is_ok());
}

#[test]
fn a_zero_devtree_size_denies() {
    let bytes = boot_args(0x1000, 0x8000_0000, 0x8000_0000, 0x1100, 0);
    assert_eq!(
        brainix_adt::adt_window(&bytes).unwrap_err(),
        BootArgsError::ZeroDevtreeSize
    );
}

#[test]
fn a_devtree_size_below_the_root_header_denies() {
    for devtree_size in 1..8 {
        let bytes = boot_args(0x1000, 0x8000_0000, 0x8000_0000, 0x1100, devtree_size);
        assert_eq!(
            brainix_adt::adt_window(&bytes).unwrap_err(),
            BootArgsError::DevtreeSizeBelowRootHeader,
            "devtree_size {devtree_size}"
        );
    }
}

#[test]
fn a_devtree_size_not_a_multiple_of_four_denies() {
    let bytes = boot_args(0x1000, 0x8000_0000, 0x8000_0000, 0x1100, 9);
    assert_eq!(
        brainix_adt::adt_window(&bytes).unwrap_err(),
        BootArgsError::DevtreeSizeMisaligned
    );
}

#[test]
fn a_devtree_address_below_virt_base_denies() {
    // devtree - virt_base underflows: the ADT is "before" iBoot's own mapping base.
    let bytes = boot_args(0x1000, 0x8000_0000, 0x8000_0000, 0, 288);
    assert_eq!(
        brainix_adt::adt_window(&bytes).unwrap_err(),
        BootArgsError::VirtualAddressUnderflow
    );
}

#[test]
fn an_adt_physical_address_that_would_overflow_denies() {
    // virt_offset = u64::MAX - 10 (devtree - virt_base, no underflow); adding
    // phys_base = 20 overflows a 64-bit address.
    let bytes = boot_args(0, 20, 0x8000_0000, u64::MAX - 10, 8);
    assert_eq!(
        brainix_adt::adt_window(&bytes).unwrap_err(),
        BootArgsError::PhysicalAddressOverflow
    );
}

#[test]
fn an_unaligned_adt_physical_address_denies() {
    // adt_phys = 0 + 1 + 0x100 = 0x101, not a multiple of 4.
    let bytes = boot_args(0, 1, 0x1_0000, 0x100, 8);
    assert_eq!(
        brainix_adt::adt_window(&bytes).unwrap_err(),
        BootArgsError::AdtPhysMisaligned
    );
}

#[test]
fn an_adt_window_end_that_would_overflow_denies() {
    // adt_phys = u64::MAX - 3 (4-byte aligned); + devtree_size (8) overflows.
    let bytes = boot_args(0, u64::MAX - 3, 0x1000, 0, 8);
    assert_eq!(
        brainix_adt::adt_window(&bytes).unwrap_err(),
        BootArgsError::AdtWindowOverflow
    );
}

#[test]
fn a_dram_window_whose_bounds_would_overflow_denies() {
    // phys_base + mem_size overflows, even though adt_phys + devtree_size does not.
    let bytes = boot_args(0, 0x10, u64::MAX, 0, 8);
    assert_eq!(
        brainix_adt::adt_window(&bytes).unwrap_err(),
        BootArgsError::DramWindowOverflow
    );
}

#[test]
fn an_adt_window_extending_past_the_dram_window_denies() {
    // adt_phys = 0x1000, adt_end = 0x1200, but the DRAM window is only
    // [0x1000, 0x1100) — the tree claims to run 0x100 bytes past DRAM.
    let bytes = boot_args(0, 0x1000, 0x100, 0, 0x200);
    assert_eq!(
        brainix_adt::adt_window(&bytes).unwrap_err(),
        BootArgsError::AdtWindowOutsideDram
    );
}

#[test]
fn trailing_bytes_after_devtree_size_are_ignored() {
    // adt_window only ever reads through the end of devtree_size (spec §3
    // documents cmdline afterwards, and its offset is disputed — OQ-1). A
    // longer buffer must parse identically to the minimal one.
    let mut bytes = golden();
    bytes.extend_from_slice(&[0xAA; 64]);
    assert_eq!(
        brainix_adt::adt_window(&bytes).unwrap(),
        brainix_adt::adt_window(&golden()).unwrap()
    );
}
