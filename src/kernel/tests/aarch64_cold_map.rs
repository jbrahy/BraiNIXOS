//! The identity map `_start` builds on a cold machine, checked on the host.
//!
//! # Why this exists
//!
//! The cold MMU bring-up was being debugged by chainloading to the mini and
//! reading the reboot interval, at about ninety seconds per attempt and one bit
//! per attempt. That is the right instrument when the question is "does the
//! hardware accept this", and the wrong one when the question is "does this map
//! contain the address the core is executing from".
//!
//! The builder and the walker are both pure over a byte array, so the second
//! question is answerable here in milliseconds. These tests build exactly what
//! `signal_progress` builds, with the geometry measured off the real machine,
//! and then walk it for the addresses that actually have to resolve.
//!
//! # The numbers, and where they came from
//!
//! Read through m1n1's proxy on the target, 2026-08-17:
//!
//! | value | reading |
//! | --- | --- |
//! | `boot_args.phys_base` | `0x10001020000` -- DRAM starts past **1 TiB** |
//! | `boot_args.mem_size` | `0x794674000` (30.3 GiB) |
//! | `ID_AA64MMFR0_EL1` | `0x110012120f100003`, so `PARange` 3 = 42 bits |
//! | firmware's `TCR_EL2` | `0x37510b510`: T0SZ 16, TG0 2, IPS 3 |
//!
//! The first version of this map hardcoded a DRAM base of `0x10_0000_0000`,
//! which is a real Apple DRAM base and is not this machine's -- wrong by a
//! factor of sixteen.

use brainix_kernel::aarch64_tables::TableBuilder;
use brainix_kernel::aarch64_walk::{walk, WalkConfig};

/// 16 KiB, which is what `ID_AA64MMFR0_EL1.TGran16` reports and what firmware
/// selects.
const GRANULE_BITS: u32 = 14;
/// 48-bit input, matching the T0SZ of 16 that firmware itself configures.
const INPUT_BITS: u32 = 48;

const PHYS_BASE: u64 = 0x1_0001_0200_00 >> 4 << 4; // 0x10001020000
const MEM_SIZE: u64 = 0x7_9467_4000;
const MMIO_WINDOW: u64 = 16 << 30;

/// Descriptor attributes, mirrored from `main.rs`.
const DRAM_ATTRS: u64 = (1 << 10) | (0b11 << 8);
const MMIO_ATTRS: u64 = (1 << 10) | (1 << 2);

/// Build the map exactly as the cold path does, into a caller-owned arena.
fn build(arena: &mut [u64]) -> u64 {
    let base = arena.as_ptr() as u64;
    // The runtime path aligns the base because the loader does not. Here the
    // arena is a Vec, so align the same way rather than assuming.
    let granule = 1u64 << GRANULE_BITS;
    let aligned = base.next_multiple_of(granule);
    let skip = ((aligned - base) / 8) as usize;
    let cells = &mut arena[skip..];

    let mut builder = TableBuilder::new(cells, aligned, GRANULE_BITS, INPUT_BITS)
        .expect("the geometry the machine reports must be one the builder accepts");
    let block = builder.block_size();

    builder
        .map_blocks(0, 0, MMIO_WINDOW, MMIO_ATTRS)
        .expect("MMIO window");

    let dram_start = PHYS_BASE & !block.wrapping_sub(1);
    let dram_end = (PHYS_BASE + MEM_SIZE).next_multiple_of(block);
    builder
        .map_blocks(dram_start, dram_start, dram_end - dram_start, DRAM_ATTRS)
        .expect("DRAM");

    builder.root()
}

/// A reader over the arena, for the walker.
fn reader(arena: &[u64]) -> impl Fn(u64) -> u64 + '_ {
    let base = arena.as_ptr() as u64;
    move |address: u64| {
        let offset = address.wrapping_sub(base);
        let index = (offset / 8) as usize;
        arena.get(index).copied().unwrap_or(0)
    }
}

fn config() -> WalkConfig {
    // T0SZ 16, TG0 0b10 (16 KiB), the shape firmware uses.
    let tcr = 16u64 | (0b10 << 14);
    WalkConfig::from_tcr(tcr).expect("firmware's own TCR shape must decode")
}

#[test]
fn every_address_the_cold_path_touches_resolves_to_itself() {
    let mut arena = vec![0u64; 1 << 16];
    let root = build(&mut arena);
    let read = reader(&arena);

    // The image, its stack and the table arena all live in DRAM, and the
    // watchdog lives in the MMIO window. If any of these does not resolve, the
    // core faults on its next access with no vector table to catch it.
    let cases: [(&str, u64); 5] = [
        ("image, as m1n1 loads it", 0x1_000e_0300_00),
        ("DRAM base itself", PHYS_BASE),
        ("last byte of DRAM", PHYS_BASE + MEM_SIZE - 1),
        ("/arm-io/pmgr", 0x2_8e08_0000),
        ("MMIO low", 0x2_0000_0000),
    ];

    for (what, address) in cases {
        let translation = walk(root, address, config(), &read)
            .unwrap_or_else(|error| panic!("{what} at {address:#x} did not resolve: {error:?}"));
        assert_eq!(
            translation.physical_address, address,
            "{what} must be identity-mapped"
        );
    }
}

#[test]
fn dram_is_normal_and_mmio_is_device() {
    let mut arena = vec![0u64; 1 << 16];
    let root = build(&mut arena);
    let read = reader(&arena);

    // AttrIndx is bits 4:2 of the descriptor. Index 0 is Attr0, which the cold
    // path programs as Normal write-back; index 1 is Attr1, Device-nGnRnE.
    // Getting these the wrong way round gives a machine whose watchdog writes
    // sit in a write buffer, which is the one register that must not be lazy.
    let dram = walk(root, PHYS_BASE, config(), &read).expect("DRAM resolves");
    assert_eq!((dram.descriptor >> 2) & 0b111, 0, "DRAM must use Attr0");

    let mmio = walk(root, 0x2_8e08_0000, config(), &read).expect("MMIO resolves");
    assert_eq!((mmio.descriptor >> 2) & 0b111, 1, "MMIO must use Attr1");

    // The access flag. Without it the first touch takes an access-flag fault,
    // which on a core with no vectors is indistinguishable from a hang.
    assert_ne!(dram.descriptor & (1 << 10), 0, "DRAM needs the access flag");
    assert_ne!(mmio.descriptor & (1 << 10), 0, "MMIO needs the access flag");
}

#[test]
fn the_arena_is_big_enough_with_room_to_spare() {
    let mut arena = vec![0u64; 1 << 16];
    let base = arena.as_ptr() as u64;
    let granule = 1u64 << GRANULE_BITS;
    let aligned = base.next_multiple_of(granule);
    let skip = ((aligned - base) / 8) as usize;
    let cells = &mut arena[skip..];

    let mut builder = TableBuilder::new(cells, aligned, GRANULE_BITS, INPUT_BITS).unwrap();
    let block = builder.block_size();
    builder.map_blocks(0, 0, MMIO_WINDOW, MMIO_ATTRS).unwrap();
    let dram_start = PHYS_BASE & !block.wrapping_sub(1);
    let dram_end = (PHYS_BASE + MEM_SIZE).next_multiple_of(block);
    builder
        .map_blocks(dram_start, dram_start, dram_end - dram_start, DRAM_ATTRS)
        .unwrap();

    // The kernel's arena is 32768 u64s, or 16 tables of 16 KiB. A count that
    // fits exactly is a count that fails the moment the geometry shifts, which
    // is how the 64 KiB first attempt died.
    let used = builder.tables_used();
    assert!(
        used <= 8,
        "cold map wants {used} tables; the kernel's arena holds 16 and that \
         margin is deliberate"
    );
}
