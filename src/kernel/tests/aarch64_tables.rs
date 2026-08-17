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

// ---------------------------------------------------------------------------
// Page mappings.
//
// Every one of these resolves through `aarch64_walk`, not by re-reading the
// descriptors this builder just wrote. The walker terminates on a page only at
// the final level and rejects a block there as a reserved encoding, so it will
// catch a page written one level too high -- which is the mistake that matters,
// because `0b11` is a *table* descriptor above the last level and a *page* on
// it. The same bits, two meanings, and the wrong one is a pointer the hardware
// follows into the middle of nothing.
// ---------------------------------------------------------------------------

fn config() -> WalkConfig {
    WalkConfig::from_tcr((0b10 << 14) | u64::from(64 - INPUT_BITS)).unwrap()
}

fn resolve(memory: &[u64], root: u64, base: u64, address: u64) -> Result<(u64, bool), ()> {
    let translation = walk(root, address, config(), |physical| {
        let index = ((physical - base) / 8) as usize;
        memory[index]
    })
    .map_err(|_| ())?;
    Ok((translation.physical_address, translation.is_block))
}

#[test]
fn a_page_mapping_resolves_and_terminates_on_a_page() {
    const BASE: u64 = 0x4000_0000;
    let mut memory = arena(8);
    let mut builder =
        TableBuilder::new(&mut memory, BASE, GRANULE_BITS, INPUT_BITS).expect("builder");

    let granule = 1u64 << GRANULE_BITS;
    let virtual_address = 0x1_0000_0000u64;
    builder
        .map_pages(virtual_address, virtual_address, granule * 4, ATTRS)
        .expect("page map must build");
    let root = builder.root();

    for page in 0..4u64 {
        let address = virtual_address + page * granule;
        let (physical, is_block) = resolve(&memory, root, BASE, address).expect("resolves");
        assert_eq!(physical, address, "identity mapping");
        assert!(!is_block, "must terminate on a page, not a block");
    }
}

#[test]
fn a_page_mapping_carries_the_offset_within_the_page() {
    const BASE: u64 = 0x4000_0000;
    let mut memory = arena(8);
    let mut builder =
        TableBuilder::new(&mut memory, BASE, GRANULE_BITS, INPUT_BITS).expect("builder");
    let granule = 1u64 << GRANULE_BITS;
    builder
        .map_pages(0x1_0000_0000, 0x2_0000_0000, granule, ATTRS)
        .expect("build");
    let root = builder.root();

    // Not identity: the offset has to come from the virtual address and the
    // page base from the descriptor. A walker that took both from one of them
    // would still pass an identity-only test.
    let (physical, _) = resolve(&memory, root, BASE, 0x1_0000_0000 + 0x1234).expect("resolves");
    assert_eq!(physical, 0x2_0000_0000 + 0x1234);
}

#[test]
fn pages_and_blocks_coexist_when_the_pages_come_first() {
    const BASE: u64 = 0x4000_0000;
    let mut memory = arena(12);
    let mut builder =
        TableBuilder::new(&mut memory, BASE, GRANULE_BITS, INPUT_BITS).expect("builder");
    let granule = 1u64 << GRANULE_BITS;
    let block = builder.block_size();

    // The fine-grained region first, then coarse blocks either side of it. This
    // is the order the EL0 mapping needs: one page userspace can reach, inside
    // a range the kernel otherwise owns.
    builder
        .map_pages(0x1_0000_0000, 0x1_0000_0000, granule, ATTRS)
        .expect("page first");
    builder
        .map_blocks(0x1_0000_0000 + block, 0x1_0000_0000 + block, block, ATTRS)
        .expect("block beside it");

    // The builder borrows the arena mutably, so the root has to be taken before
    // the walk reads it back.
    let root = builder.root();
    drop(builder);

    let (page_physical, page_is_block) =
        resolve(&memory, root, BASE, 0x1_0000_0000).expect("page resolves");
    assert_eq!(page_physical, 0x1_0000_0000);
    assert!(!page_is_block);

    let (block_physical, block_is_block) =
        resolve(&memory, root, BASE, 0x1_0000_0000 + block).expect("block resolves");
    assert_eq!(block_physical, 0x1_0000_0000 + block);
    assert!(block_is_block);
}

#[test]
fn a_page_inside_an_existing_block_denies_rather_than_splitting() {
    const BASE: u64 = 0x4000_0000;
    let mut memory = arena(8);
    let mut builder =
        TableBuilder::new(&mut memory, BASE, GRANULE_BITS, INPUT_BITS).expect("builder");
    let block = builder.block_size();
    builder
        .map_blocks(0x1_0000_0000, 0x1_0000_0000, block, ATTRS)
        .expect("block");

    // Splitting a live block needs break-before-make against a running machine.
    // Doing it silently in a builder leaves the range briefly unmapped under
    // the code doing the mapping.
    assert_eq!(
        builder
            .map_pages(0x1_0000_0000, 0x1_0000_0000, 1 << GRANULE_BITS, ATTRS)
            .unwrap_err(),
        BuildError::AlreadyMapped
    );
}

#[test]
fn mapping_the_same_page_twice_denies() {
    const BASE: u64 = 0x4000_0000;
    let mut memory = arena(8);
    let mut builder =
        TableBuilder::new(&mut memory, BASE, GRANULE_BITS, INPUT_BITS).expect("builder");
    let granule = 1u64 << GRANULE_BITS;
    builder
        .map_pages(0x1_0000_0000, 0x1_0000_0000, granule, ATTRS)
        .expect("first");
    assert_eq!(
        builder
            .map_pages(0x1_0000_0000, 0x2_0000_0000, granule, ATTRS)
            .unwrap_err(),
        BuildError::AlreadyMapped,
        "silently repointing a live mapping is how two owners disagree"
    );
}

#[test]
fn a_misaligned_page_range_denies() {
    const BASE: u64 = 0x4000_0000;
    let mut memory = arena(8);
    let mut builder =
        TableBuilder::new(&mut memory, BASE, GRANULE_BITS, INPUT_BITS).expect("builder");
    let granule = 1u64 << GRANULE_BITS;
    for (va, pa, len) in [
        (0x1_0000_0000 + 8, 0x1_0000_0000, granule),
        (0x1_0000_0000, 0x1_0000_0000 + 8, granule),
        (0x1_0000_0000, 0x1_0000_0000, granule - 8),
    ] {
        assert_eq!(
            builder.map_pages(va, pa, len, ATTRS).unwrap_err(),
            BuildError::MisalignedRange
        );
    }
}

#[test]
fn the_attributes_reach_the_leaf_descriptor() {
    // The whole reason pages exist here: a permission expressible at page size.
    // AP[1] set is "accessible from EL0", and it has to survive into the
    // descriptor or the EL0 mapping silently stays kernel-only.
    const BASE: u64 = 0x4000_0000;
    const AP_EL0: u64 = 1 << 6;
    let mut memory = arena(8);
    let mut builder =
        TableBuilder::new(&mut memory, BASE, GRANULE_BITS, INPUT_BITS).expect("builder");
    let granule = 1u64 << GRANULE_BITS;
    builder
        .map_pages(0x1_0000_0000, 0x1_0000_0000, granule, ATTRS | AP_EL0)
        .expect("build");
    let root = builder.root();

    let translation = walk(root, 0x1_0000_0000, config(), |physical| {
        memory[((physical - BASE) / 8) as usize]
    })
    .expect("resolves");
    assert_eq!(translation.descriptor & AP_EL0, AP_EL0, "AP[1] survived");
    assert_eq!(translation.descriptor & 0b11, 0b11, "page encoding");
}
