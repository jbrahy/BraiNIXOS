//! Table construction, checked by the walker that the MMU validated.
//!
//! Build with `aarch64_tables`, resolve with `aarch64_walk`. They are
//! independent implementations of opposite directions of the same
//! specification, and `aarch64_walk` has been checked against the MMU's own
//! `AT s1e2r` on real hardware. A builder verified only by re-reading its own
//! output would confirm nothing.

use brainix_kernel::aarch64_tables::{BuildError, TableBuilder};
use brainix_kernel::aarch64_walk::{walk, WalkConfig};

/// The target's configuration: 16 KiB granule, T0SZ 16.
const GRANULE_BITS: u32 = 14;
const INPUT_BITS: u32 = 48;

fn arena(tables: usize) -> Vec<u64> {
    vec![0u64; tables * (1 << (GRANULE_BITS - 3))]
}

/// Access flag set, read/write. Without AF the first touch faults.
const ATTRS: u64 = 1 << 10;

#[test]
fn an_identity_map_resolves_every_address_to_itself() {
    const BASE: u64 = 0x4000_0000;
    let mut memory = arena(8);
    let mut builder =
        TableBuilder::new(&mut memory, BASE, GRANULE_BITS, INPUT_BITS).expect("builder");

    let block = builder.block_size();
    assert_eq!(block, 32 * 1024 * 1024, "16 KiB granule blocks are 32 MiB");

    let region_start = 0x1_0000_0000u64;
    builder
        .map_blocks(region_start, region_start, block * 4, ATTRS)
        .expect("identity map must build");

    let root = builder.root();
    let levels = builder.levels();
    let config = WalkConfig::from_tcr((0b10 << 14) | u64::from(64 - INPUT_BITS)).unwrap();
    assert_eq!(config.levels(), levels, "builder and walker must agree on depth");

    // Read descriptors back out of the arena the builder wrote.
    let read = |physical: u64| -> u64 {
        let index = ((physical - BASE) / 8) as usize;
        memory.get(index).copied().unwrap_or(0)
    };

    for offset in [0u64, 1, 0x1234, block - 1, block, block * 3 + 0x99] {
        let virtual_address = region_start + offset;
        let translation = walk(root, virtual_address, config, read)
            .unwrap_or_else(|e| panic!("{virtual_address:#x} must resolve: {e:?}"));
        assert_eq!(
            translation.physical_address, virtual_address,
            "identity map must resolve {virtual_address:#x} to itself"
        );
        assert!(translation.is_block, "should terminate on a block");
    }
}

#[test]
fn a_misaligned_range_denies_rather_than_rounding() {
    let mut memory = arena(8);
    let mut builder = TableBuilder::new(&mut memory, 0x4000_0000, GRANULE_BITS, INPUT_BITS).unwrap();
    let block = builder.block_size();

    // Rounding a misaligned request is how a mapping ends up covering memory
    // the caller did not ask for.
    assert_eq!(
        builder.map_blocks(block + 0x1000, 0, block, ATTRS).unwrap_err(),
        BuildError::MisalignedRange
    );
    assert_eq!(
        builder.map_blocks(0, 0, block - 1, ATTRS).unwrap_err(),
        BuildError::MisalignedRange
    );
}

#[test]
fn remapping_an_existing_block_denies() {
    let mut memory = arena(8);
    let mut builder = TableBuilder::new(&mut memory, 0x4000_0000, GRANULE_BITS, INPUT_BITS).unwrap();
    let block = builder.block_size();

    builder.map_blocks(0, 0, block, ATTRS).expect("first map");
    assert_eq!(
        builder.map_blocks(0, block, block, ATTRS).unwrap_err(),
        BuildError::AlreadyMapped,
        "silently replacing a live mapping is how two owners disagree about an \
         address and the loser finds out by corrupting memory"
    );
}

#[test]
fn an_exhausted_arena_denies_instead_of_running_past_the_end() {
    // One table is the root; mapping anything needs more.
    let mut memory = arena(1);
    let mut builder = TableBuilder::new(&mut memory, 0x4000_0000, GRANULE_BITS, INPUT_BITS).unwrap();
    let block = builder.block_size();
    assert_eq!(
        builder.map_blocks(0, 0, block, ATTRS).unwrap_err(),
        BuildError::OutOfTables
    );
}

#[test]
fn a_misaligned_arena_denies() {
    let mut memory = arena(4);
    // `TableBuilder` deliberately does not derive Debug -- it borrows the arena
    // mutably and printing it would print the whole page-table memory -- so the
    // error is matched rather than unwrapped.
    match TableBuilder::new(&mut memory, 0x4000_0001, GRANULE_BITS, INPUT_BITS) {
        Err(error) => assert_eq!(error, BuildError::MisalignedArena),
        Ok(_) => panic!("a misaligned arena must deny: descriptors would be truncated"),
    }
}

#[test]
fn the_block_size_matches_the_architecture_for_each_granule() {
    for (granule_bits, expected) in [(12u32, 2 << 20), (14, 32 << 20), (16u32, 512 << 20)] {
        let mut memory = vec![0u64; 4 * (1usize << (granule_bits - 3))];
        let builder = TableBuilder::new(&mut memory, 0x4000_0000, granule_bits, INPUT_BITS).unwrap();
        assert_eq!(
            builder.block_size(),
            expected,
            "granule {granule_bits}: blocks are legal at exactly one level"
        );
    }
}
