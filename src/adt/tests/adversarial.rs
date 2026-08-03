//! Adversarial fixtures.
//!
//! The ADT is firmware-supplied and BraiNIX treats it as hostile input. Each
//! test below states the attack it encodes and asserts the exact reason the
//! decoder denies it. Nothing here may panic, hang, or return a partially
//! decoded tree.

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

use brainix_adt::{AdtError, CellCounts, DeviceTree, MAX_TREE_DEPTH};
use common::{cstr, node, patched_byte, patched_u32, property, two_cells, u32_value, GOLDEN};

// ---------------------------------------------------------------------------
// Degenerate inputs
// ---------------------------------------------------------------------------

#[test]
fn a_zero_length_input_denies() {
    assert_eq!(DeviceTree::parse(&[]).unwrap_err(), AdtError::EmptyBlob);
}

#[test]
fn a_blob_shorter_than_a_root_header_denies() {
    for length in 1..8 {
        assert_eq!(
            DeviceTree::parse(&GOLDEN[..length]).unwrap_err(),
            AdtError::BlobTooSmallForRoot,
            "length {length}"
        );
    }
}

// ---------------------------------------------------------------------------
// Truncation at every structural boundary
// ---------------------------------------------------------------------------

#[test]
fn truncating_the_golden_blob_at_any_length_denies() {
    // 288 distinct truncations: mid-header, mid-name, mid-length-word,
    // mid-value, and mid-padding, at every offset in the fixture. The full
    // 288 bytes are the only accepted prefix.
    for length in 0..GOLDEN.len() {
        let result = DeviceTree::parse(&GOLDEN[..length]);
        assert!(result.is_err(), "prefix of {length} bytes must deny");
    }
    assert!(DeviceTree::parse(&GOLDEN).is_ok());
}

#[test]
fn a_value_that_ends_one_byte_early_denies_rather_than_being_tolerated() {
    // The "last property may be unpadded at the very end" leniency found in
    // third-party parsers is a truncation hole under a threat model. The
    // fixture's final property value runs to 0x0120; cutting the blob to 0x011F
    // must deny even though only padding-free bytes are missing.
    assert_eq!(
        DeviceTree::parse(&GOLDEN[..0x11f]).unwrap_err(),
        AdtError::TruncatedPropertyValue
    );
}

// ---------------------------------------------------------------------------
// Length words
// ---------------------------------------------------------------------------

#[test]
fn a_length_field_larger_than_the_buffer_denies() {
    // The child's `reg` length word lives at 0x010C. Claim 0x1000 bytes of
    // value in a blob with 16 left.
    let blob = patched_u32(&GOLDEN, 0x10c, 0x1000);
    assert_eq!(
        DeviceTree::parse(&blob).unwrap_err(),
        AdtError::TruncatedPropertyValue
    );
}

#[test]
fn the_placeholder_flag_denies_with_its_own_distinct_reason() {
    // Bit 31 set means firmware handed over an unresolved template, not a tree
    // an OS was meant to see. It is refused as a tree, never masked and used,
    // and never skipped.
    let blob = patched_u32(&GOLDEN, 0x28, 0x8000_0007);
    assert_eq!(
        DeviceTree::parse(&blob).unwrap_err(),
        AdtError::PlaceholderFlagSet
    );
}

#[test]
fn the_policy_value_ceiling_is_distinct_from_the_placeholder_flag() {
    // Bits 30..20 set is a policy bound, and must be diagnosable separately
    // from the format rule about bit 31.
    for word in [0x7fff_ffffu32, 0x4000_0000, 0x0010_0000] {
        let blob = patched_u32(&GOLDEN, 0x28, word);
        assert_eq!(
            DeviceTree::parse(&blob).unwrap_err(),
            AdtError::ValueLengthExceedsCeiling,
            "length word {word:#x}"
        );
    }
    // Just under the ceiling is a length question, not a policy question.
    let blob = patched_u32(&GOLDEN, 0x28, 0x000f_ffff);
    assert_eq!(
        DeviceTree::parse(&blob).unwrap_err(),
        AdtError::TruncatedPropertyValue
    );
}

#[test]
fn a_length_whose_padding_would_wrap_on_addition_denies() {
    // The largest representable value length is 0x7FFF_FFFF, for which
    // `value_len + 3` must not be allowed to wrap into a small padded length
    // and land back inside the buffer. The policy ceiling denies it first;
    // the checked addition behind it is what makes the denial unconditional.
    let blob = patched_u32(&GOLDEN, 0x10c, 0x7fff_fffd);
    assert_eq!(
        DeviceTree::parse(&blob).unwrap_err(),
        AdtError::ValueLengthExceedsCeiling
    );
}

// ---------------------------------------------------------------------------
// Counts
// ---------------------------------------------------------------------------

#[test]
fn a_property_count_of_all_ones_is_denied_by_the_space_test() {
    // Not merely by the policy ceiling: the space test is the check that is
    // correct for small buffers, so it must be the one that fires.
    let blob = patched_u32(&GOLDEN, 0, 0xffff_ffff);
    assert_eq!(
        DeviceTree::parse(&blob).unwrap_err(),
        AdtError::PropertyCountExceedsBuffer
    );
}

#[test]
fn a_child_count_of_all_ones_is_denied_by_the_space_test() {
    let blob = patched_u32(&GOLDEN, 4, 0xffff_ffff);
    assert_eq!(
        DeviceTree::parse(&blob).unwrap_err(),
        AdtError::ChildCountExceedsBuffer
    );
}

#[test]
fn a_count_times_its_record_size_that_would_overflow_denies() {
    // 0x0800_0000 properties × 36 bytes is 2^32 bytes — the multiplication the
    // space test performs. It must deny, never wrap into a small requirement.
    let blob = patched_u32(&GOLDEN, 0, 0x0800_0000);
    assert_eq!(
        DeviceTree::parse(&blob).unwrap_err(),
        AdtError::PropertyCountExceedsBuffer
    );
    let blob = patched_u32(&GOLDEN, 4, 0x2000_0000);
    assert_eq!(
        DeviceTree::parse(&blob).unwrap_err(),
        AdtError::ChildCountExceedsBuffer
    );
}

#[test]
fn a_count_above_the_policy_ceiling_denies_even_when_the_buffer_is_large() {
    // A buffer big enough to satisfy the space test, so only the ceiling can
    // fire. 2049 × 36 + 8 fits easily in 200 000 bytes.
    let mut blob = vec![0u8; 200_000];
    blob[..4].copy_from_slice(&2049u32.to_le_bytes());
    assert_eq!(
        DeviceTree::parse(&blob).unwrap_err(),
        AdtError::PropertyCountExceedsCeiling
    );

    let mut blob = vec![0u8; 200_000];
    blob[..4].copy_from_slice(&1u32.to_le_bytes());
    blob[4..8].copy_from_slice(&2049u32.to_le_bytes());
    assert_eq!(
        DeviceTree::parse(&blob).unwrap_err(),
        AdtError::ChildCountExceedsCeiling
    );
}

#[test]
fn a_zero_property_count_denies() {
    let blob = patched_u32(&GOLDEN, 0, 0);
    assert_eq!(
        DeviceTree::parse(&blob).unwrap_err(),
        AdtError::ZeroPropertyCount
    );
}

#[test]
fn a_node_claiming_more_children_than_remain_denies() {
    // Two children declared, one present. The second decode lands exactly on
    // the buffer end, which is a valid *extent* but not a valid *read*.
    let blob = patched_u32(&GOLDEN, 4, 2);
    assert_eq!(
        DeviceTree::parse(&blob).unwrap_err(),
        AdtError::TruncatedNodeHeader
    );

    // Far more children than the remaining bytes could ever hold.
    let blob = patched_u32(&GOLDEN, 4, 100);
    assert_eq!(
        DeviceTree::parse(&blob).unwrap_err(),
        AdtError::ChildCountExceedsBuffer
    );
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

#[test]
fn an_unterminated_property_name_denies_before_the_name_is_read() {
    // Byte 31 of the root's first property name field is at 0x0027.
    let blob = patched_byte(&GOLDEN, 0x27, b'A');
    assert_eq!(
        DeviceTree::parse(&blob).unwrap_err(),
        AdtError::PropertyNameNotTerminated
    );
}

#[test]
fn a_name_property_value_with_no_nul_denies_rather_than_adopting_the_value() {
    // `name` value "arm-io\0" is at 0x002C..0x0033; overwrite its terminator.
    let blob = patched_byte(&GOLDEN, 0x32, b'X');
    let tree = DeviceTree::parse(&blob).expect("structure is still well formed");
    assert_eq!(
        tree.root().name().unwrap_err(),
        AdtError::UnterminatedStringValue
    );
}

#[test]
fn a_node_name_longer_than_63_characters_denies() {
    let long_name = "n".repeat(64);
    let leaf = node(&[property("name", &cstr(&long_name))], &[]);
    let root = node(&[property("name", &cstr("root"))], &[leaf]);
    let tree = DeviceTree::parse(&root).expect("structurally valid");
    let child = tree
        .root()
        .children()
        .expect("children")
        .next()
        .expect("one child")
        .expect("decodes");
    assert_eq!(child.name().unwrap_err(), AdtError::NodeNameTooLong);
}

#[test]
fn a_node_with_no_name_property_denies() {
    let leaf = node(&[property("device_type", &cstr("cpu"))], &[]);
    let root = node(&[property("name", &cstr("root"))], &[leaf]);
    let tree = DeviceTree::parse(&root).expect("structurally valid");
    let child = tree
        .root()
        .children()
        .expect("children")
        .next()
        .expect("one child")
        .expect("decodes");
    assert_eq!(child.name().unwrap_err(), AdtError::MissingNameProperty);
}

#[test]
fn a_duplicate_property_name_denies_rather_than_shadowing() {
    let root = node(
        &[
            property("name", &cstr("root")),
            property("chip-id", &u32_value(0x6020)),
            property("chip-id", &u32_value(0xdead)),
        ],
        &[],
    );
    let tree = DeviceTree::parse(&root).expect("structurally valid");
    assert_eq!(
        tree.root().property(b"chip-id").unwrap_err(),
        AdtError::DuplicateProperty
    );
}

// ---------------------------------------------------------------------------
// Depth
// ---------------------------------------------------------------------------

fn nested_chain(levels: usize) -> Vec<u8> {
    // `levels` counts nodes below the root, so the blob holds levels + 1 nodes.
    let mut blob = node(&[property("name", &cstr("leaf"))], &[]);
    for index in 0..levels {
        blob = node(&[property("name", &cstr(&format!("n{index}")))], &[blob]);
    }
    blob
}

#[test]
fn a_chain_exactly_at_the_depth_limit_is_accepted() {
    let blob = nested_chain(MAX_TREE_DEPTH);
    let tree = DeviceTree::parse(&blob).expect("16 levels below the root is legal");
    assert_eq!(tree.tree_len(), blob.len());
}

#[test]
fn a_nesting_depth_bomb_denies_and_terminates() {
    for levels in [MAX_TREE_DEPTH + 1, MAX_TREE_DEPTH + 64, 512] {
        let blob = nested_chain(levels);
        assert_eq!(
            DeviceTree::parse(&blob).unwrap_err(),
            AdtError::DepthLimitExceeded,
            "{levels} levels"
        );
    }
}

#[test]
fn child_iteration_below_the_depth_limit_denies_rather_than_descending() {
    // A tree that parses because it is exactly at the limit still refuses to
    // hand out a cursor below it.
    let blob = nested_chain(MAX_TREE_DEPTH);
    let tree = DeviceTree::parse(&blob).expect("parse");
    let mut current = tree.root();
    for _ in 0..MAX_TREE_DEPTH {
        current = current
            .children()
            .expect("children")
            .next()
            .expect("one child")
            .expect("decodes");
    }
    assert_eq!(current.depth(), MAX_TREE_DEPTH);
    assert_eq!(current.child_count().expect("count"), 0);
}

// ---------------------------------------------------------------------------
// Desynchronised and overlapping extents
// ---------------------------------------------------------------------------

#[test]
fn a_property_length_that_desynchronises_the_walk_denies() {
    // Inflate the root's last property length from 4 to 8. The "first child"
    // offset then lands four bytes late, inside what was the child's header,
    // where the property count reads as zero.
    let blob = patched_u32(&GOLDEN, 0x7c, 8);
    assert_eq!(
        DeviceTree::parse(&blob).unwrap_err(),
        AdtError::ZeroPropertyCount
    );
}

#[test]
fn a_child_whose_extent_swallows_its_sibling_denies() {
    // Two siblings. The first one's value length is inflated so that its
    // extent covers the second's header, and the walk then decodes a "node"
    // out of the middle of the second child's name property.
    //
    // Layout: root header 0..8, root `name` record 8..52, first child 52..100,
    // second child 100..148. The first child's length word is at 92.
    let first = node(&[property("name", &cstr("a"))], &[]);
    let second = node(&[property("name", &cstr("b"))], &[]);
    let root = node(&[property("name", &cstr("root"))], &[first, second]);
    assert_eq!(root.len(), 148);

    // Overlap that stays inside the buffer: the first child now ends at 140,
    // four bytes into the second child's name property.
    let overlapping = patched_u32(&root, 92, 44);
    assert_eq!(
        DeviceTree::parse(&overlapping).unwrap_err(),
        AdtError::PropertyCountExceedsBuffer
    );

    // Overlap that runs past the buffer end.
    let overrunning = patched_u32(&root, 92, 64);
    assert_eq!(
        DeviceTree::parse(&overrunning).unwrap_err(),
        AdtError::TruncatedPropertyValue
    );
}

// ---------------------------------------------------------------------------
// Termination
// ---------------------------------------------------------------------------

#[test]
fn iterators_are_bounded_by_a_count_read_once_and_then_stay_exhausted() {
    // The format has no terminator record, so an iterator that inspected the
    // bytes at its landing offset to decide whether to continue would walk off
    // the end of a node. Both iterators take exactly the count from the header
    // and then stay exhausted, however many times they are polled.
    let tree = DeviceTree::parse(&GOLDEN).expect("parse");
    let root = tree.root();

    let mut properties = root.properties().expect("iterator");
    let mut yielded = 0;
    for _ in 0..10_000 {
        match properties.next() {
            Some(item) => {
                item.expect("well-formed property");
                yielded += 1;
            }
            None => break,
        }
    }
    assert_eq!(yielded, 3);
    for _ in 0..1_000 {
        assert!(properties.next().is_none());
    }

    let mut children = root.children().expect("iterator");
    let mut seen = 0;
    for _ in 0..10_000 {
        match children.next() {
            Some(item) => {
                item.expect("well-formed child");
                seen += 1;
            }
            None => break,
        }
    }
    assert_eq!(seen, 1);
    for _ in 0..1_000 {
        assert!(children.next().is_none());
    }
}

#[test]
fn traversal_of_an_adversarial_tree_terminates() {
    // A wide, deep, maximally awkward tree: every parse below returns, and the
    // test completing at all is the termination assertion.
    let mut blobs: Vec<Vec<u8>> = vec![
        nested_chain(MAX_TREE_DEPTH + 1),
        patched_u32(&GOLDEN, 0, 0xffff_ffff),
        patched_u32(&GOLDEN, 4, 0xffff_ffff),
        patched_u32(&GOLDEN, 0x28, 0x8000_0007),
        vec![0xff; 4096],
        vec![0u8; 4096],
    ];
    for length in 0..GOLDEN.len() {
        blobs.push(GOLDEN[..length].to_vec());
    }
    for blob in blobs {
        // Only the outcome matters: it must be an outcome.
        let _ = DeviceTree::parse(&blob);
    }
}

#[test]
fn a_string_value_with_no_terminator_yields_no_entries() {
    // The value is five bytes with no NUL. The zero padding that follows is
    // not part of the value, so a terminator search bounded by the declared
    // length finds none — and the whole value is never adopted as the string.
    let root = node(
        &[
            property("name", &cstr("root")),
            property("compatible", b"nonul"),
        ],
        &[],
    );
    let tree = DeviceTree::parse(&root).expect("structurally valid");
    let compatible = tree.root().property(b"compatible").expect("property");
    assert_eq!(compatible.value().len(), 5);
    assert_eq!(
        compatible.as_c_str().unwrap_err(),
        AdtError::UnterminatedStringValue
    );
    let entries: Vec<&[u8]> = compatible.strings().collect();
    assert!(entries.is_empty());
}

// ---------------------------------------------------------------------------
// reg, ranges and translation
// ---------------------------------------------------------------------------

fn arm_io_tree(uart_address: u64, with_ranges: bool) -> Vec<u8> {
    let mut ranges_entry = Vec::new();
    ranges_entry.extend_from_slice(&two_cells(0));
    ranges_entry.extend_from_slice(&two_cells(0x2_1000_0000));
    ranges_entry.extend_from_slice(&two_cells(0x1_9000_0000));

    let mut uart_reg = Vec::new();
    uart_reg.extend_from_slice(&two_cells(uart_address));
    uart_reg.extend_from_slice(&two_cells(0x4000));

    let uart = node(
        &[
            property("name", &cstr("uart0")),
            property("compatible", &cstr("uart-1,samsung")),
            property("reg", &uart_reg),
        ],
        &[],
    );

    let mut arm_io_properties = vec![
        property("name", &cstr("arm-io")),
        property("#address-cells", &u32_value(2)),
        property("#size-cells", &u32_value(2)),
    ];
    if with_ranges {
        arm_io_properties.push(property("ranges", &ranges_entry));
    }
    let arm_io = node(&arm_io_properties, &[uart]);

    node(
        &[
            property("name", &cstr("root")),
            property("#address-cells", &u32_value(2)),
            property("#size-cells", &u32_value(2)),
        ],
        &[arm_io],
    )
}

#[test]
fn translation_through_ranges_matches_the_specifications_worked_check() {
    let blob = arm_io_tree(0x1_4100_0000, true);
    let tree = DeviceTree::parse(&blob).expect("parse");
    let path = tree.resolve(b"/arm-io/uart0").expect("resolve");
    assert_eq!(path.reg(0).expect("reg").address, 0x1_4100_0000);
    let translated = path.translated_reg(0).expect("translated");
    assert_eq!(translated.address, 0x3_5100_0000);
    assert_eq!(translated.size, 0x4000);
}

#[test]
fn an_address_outside_every_ranges_window_denies_rather_than_passing_through() {
    let blob = arm_io_tree(0x9_0000_0000, true);
    let tree = DeviceTree::parse(&blob).expect("parse");
    let path = tree.resolve(b"/arm-io/uart0").expect("resolve");
    assert_eq!(path.reg(0).expect("untranslated").address, 0x9_0000_0000);
    assert_eq!(
        path.translated_reg(0).unwrap_err(),
        AdtError::NoMatchingRangesEntry
    );
}

#[test]
fn a_containment_test_that_would_overflow_denies() {
    // Address near the top of the space with a size that makes the end wrap.
    let blob = arm_io_tree(0xffff_ffff_ffff_f000, true);
    let tree = DeviceTree::parse(&blob).expect("parse");
    let path = tree.resolve(b"/arm-io/uart0").expect("resolve");
    // 0xFFFF_FFFF_FFFF_F000 + 0x4000 overflows 64 bits.
    assert_eq!(
        path.translated_reg(0).unwrap_err(),
        AdtError::TranslationOverflow
    );
}

#[test]
fn absence_of_ranges_terminates_translation_without_error() {
    let blob = arm_io_tree(0x1_4100_0000, false);
    let tree = DeviceTree::parse(&blob).expect("parse");
    let path = tree.resolve(b"/arm-io/uart0").expect("resolve");
    assert_eq!(
        path.translated_reg(0).expect("terminated").address,
        0x1_4100_0000
    );
}

#[test]
fn missing_cell_counts_deny_and_are_never_defaulted() {
    let uart = node(
        &[
            property("name", &cstr("uart0")),
            property("reg", &vec![0u8; 16]),
        ],
        &[],
    );
    let blob = node(&[property("name", &cstr("root"))], &[uart]);
    let tree = DeviceTree::parse(&blob).expect("parse");
    let path = tree.resolve(b"/uart0").expect("resolve");
    assert_eq!(path.reg(0).unwrap_err(), AdtError::MissingCellCounts);
}

#[test]
fn out_of_range_cell_counts_deny() {
    assert_eq!(
        CellCounts::new(0, 2).unwrap_err(),
        AdtError::InvalidAddressCells
    );
    assert_eq!(
        CellCounts::new(3, 2).unwrap_err(),
        AdtError::InvalidAddressCells
    );
    assert_eq!(
        CellCounts::new(2, 3).unwrap_err(),
        AdtError::InvalidSizeCells
    );
    assert!(CellCounts::new(1, 0).is_ok());
    assert!(CellCounts::new(2, 2).is_ok());
}

#[test]
fn a_reg_whose_length_disagrees_with_the_cell_counts_denies() {
    // The `memory` node trap: 8 bytes of `reg` while the parent declares
    // #address-cells = 2 and #size-cells = 2, which needs 32.
    let memory = node(
        &[
            property("name", &cstr("memory")),
            property("device_type", &cstr("memory")),
            property("reg", &vec![0u8; 8]),
        ],
        &[],
    );
    let blob = node(
        &[
            property("name", &cstr("root")),
            property("#address-cells", &u32_value(2)),
            property("#size-cells", &u32_value(2)),
        ],
        &[memory],
    );
    let tree = DeviceTree::parse(&blob).expect("parse");
    let path = tree.resolve(b"/memory").expect("resolve");
    assert_eq!(path.reg(0).unwrap_err(), AdtError::RegContainerOutOfRange);
}

#[test]
fn a_fixed_shape_property_of_the_wrong_length_denies() {
    let cpu = node(
        &[
            property("name", &cstr("cpu0")),
            property("cpu-impl-reg", &vec![0u8; 12]),
        ],
        &[],
    );
    let blob = node(&[property("name", &cstr("root"))], &[cpu]);
    let tree = DeviceTree::parse(&blob).expect("parse");
    let node_ref = tree.find_node(b"/cpu0").expect("cpu0");
    assert_eq!(
        node_ref
            .property(b"cpu-impl-reg")
            .expect("property")
            .as_address_size()
            .unwrap_err(),
        AdtError::PropertyLengthMismatch
    );
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

#[test]
fn malformed_paths_deny() {
    let tree = DeviceTree::parse(&GOLDEN).expect("parse");
    for path in [
        &b""[..],
        &b"uart0"[..],
        &b"//uart0"[..],
        &b"/uart0/"[..],
        &b"/uart0//"[..],
    ] {
        assert_eq!(
            tree.resolve(path).unwrap_err(),
            AdtError::MalformedPath,
            "{path:?}"
        );
    }
}

#[test]
fn a_path_at_the_depth_limit_resolves_and_going_deeper_denies() {
    // nested_chain(16) makes the outermost node the root, so the path to the
    // leaf has 16 components and the resolved chain holds 17 nodes.
    let blob = nested_chain(MAX_TREE_DEPTH);
    let tree = DeviceTree::parse(&blob).expect("parse");

    let mut path = String::new();
    for index in (0..MAX_TREE_DEPTH - 1).rev() {
        path.push('/');
        path.push_str(&format!("n{index}"));
    }
    path.push_str("/leaf");

    let resolved = tree.resolve(path.as_bytes()).expect("legal depth resolves");
    assert_eq!(resolved.len(), MAX_TREE_DEPTH + 1);
    assert_eq!(resolved.node().depth(), MAX_TREE_DEPTH);
    assert_eq!(resolved.node().name().expect("name"), b"leaf");

    let mut deeper = path.clone();
    deeper.push_str("/deeper");
    assert_eq!(
        tree.resolve(deeper.as_bytes()).unwrap_err(),
        AdtError::NodeNotFound
    );
}
