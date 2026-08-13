//! Golden-fixture tests against the specification's 288-byte worked example.
//!
//! Every offset asserted here was re-derived from the fixture's bytes with the
//! rules of §4–§6. The specification's walk-through table places the child's
//! `reg` record at `0x00E4`; that is wrong — `compatible` starts at `0x00B8`
//! with a value length of 15, padded to 16, so the next record is at
//! `0xB8 + 36 + 16 = 0xEC`, and only `0xEC + 36 + 16` reaches the documented
//! total of `0x0120`. The assertions below pin `0xEC`.

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

use brainix_adt::{AdtError, CellCounts, DeviceTree};
use common::{offset_of, GOLDEN};

#[test]
fn golden_blob_parses_and_ends_exactly_at_the_buffer_end() {
    let tree = DeviceTree::parse(&GOLDEN).expect("golden fixture must parse");
    assert_eq!(tree.tree_len(), 288);
    assert_eq!(tree.tree_len(), GOLDEN.len());
}

#[test]
fn root_header_reads_three_properties_and_one_child() {
    let tree = DeviceTree::parse(&GOLDEN).expect("parse");
    let root = tree.root();
    assert_eq!(root.offset(), 0);
    assert_eq!(root.depth(), 0);
    assert_eq!(root.property_count().expect("property count"), 3);
    assert_eq!(root.child_count().expect("child count"), 1);
}

#[test]
fn root_properties_are_in_layout_order_at_the_documented_offsets() {
    let tree = DeviceTree::parse(&GOLDEN).expect("parse");
    let root = tree.root();
    let properties: Vec<_> = root
        .properties()
        .expect("properties")
        .map(|item| item.expect("property"))
        .collect();
    assert_eq!(properties.len(), 3);

    // Property 0: record at 0x0008, value at 0x002C, length 7, padded to 8.
    assert_eq!(properties[0].name(), b"name");
    assert_eq!(properties[0].name_field().len(), 32);
    assert_eq!(properties[0].value(), b"arm-io\0");
    assert_eq!(properties[0].value().len(), 7);
    assert_eq!(offset_of(&GOLDEN, properties[0].value()), 0x2c);

    // Property 1: record at 0x0034, value at 0x0058, length 4, value 2.
    assert_eq!(properties[1].name(), b"#address-cells");
    assert_eq!(properties[1].value().len(), 4);
    assert_eq!(offset_of(&GOLDEN, properties[1].value()), 0x58);
    assert_eq!(properties[1].as_u32().expect("u32"), 2);

    // Property 2: record at 0x005C, value at 0x0080, length 4, value 2.
    assert_eq!(properties[2].name(), b"#size-cells");
    assert_eq!(properties[2].value().len(), 4);
    assert_eq!(offset_of(&GOLDEN, properties[2].value()), 0x80);
    assert_eq!(properties[2].as_u32().expect("u32"), 2);
}

#[test]
fn root_name_and_cell_counts_read_back() {
    let tree = DeviceTree::parse(&GOLDEN).expect("parse");
    let root = tree.root();
    assert_eq!(root.name().expect("name"), b"arm-io");
    assert_eq!(
        root.cell_counts().expect("cells"),
        CellCounts::new(2, 2).expect("valid cells")
    );
}

#[test]
fn the_first_child_starts_at_0x84_which_is_where_the_properties_end() {
    let tree = DeviceTree::parse(&GOLDEN).expect("parse");
    let child = tree
        .root()
        .children()
        .expect("children")
        .next()
        .expect("one child")
        .expect("child decodes");
    assert_eq!(child.offset(), 0x84);
    assert_eq!(child.depth(), 1);
    assert_eq!(child.property_count().expect("count"), 3);
    assert_eq!(child.child_count().expect("count"), 0);
}

#[test]
fn child_properties_land_at_0x8c_0xb8_and_0xec() {
    let tree = DeviceTree::parse(&GOLDEN).expect("parse");
    let child = tree.find_node(b"/uart0").expect("uart0");
    let properties: Vec<_> = child
        .properties()
        .expect("properties")
        .map(|item| item.expect("property"))
        .collect();
    assert_eq!(properties.len(), 3);

    // Record 0x008C, value 0x00B0, length 6, padded to 8.
    assert_eq!(properties[0].name(), b"name");
    assert_eq!(properties[0].value(), b"uart0\0");
    assert_eq!(offset_of(&GOLDEN, properties[0].value()), 0xb0);

    // Record 0x00B8, value 0x00DC, length 15, padded to 16.
    assert_eq!(properties[1].name(), b"compatible");
    assert_eq!(properties[1].value().len(), 15);
    assert_eq!(offset_of(&GOLDEN, properties[1].value()), 0xdc);
    assert_eq!(properties[1].as_c_str().expect("string"), b"uart-1,samsung");

    // Record 0x00EC — NOT 0x00E4 — value 0x0110, length 16.
    assert_eq!(properties[2].name(), b"reg");
    assert_eq!(properties[2].value().len(), 16);
    assert_eq!(offset_of(&GOLDEN, properties[2].value()), 0x110);
    // The value offset pins the record offset: 0x110 - 36 = 0xEC.
    assert_eq!(offset_of(&GOLDEN, properties[2].value()) - 36, 0xec);
}

#[test]
fn compatible_string_list_yields_exactly_one_entry_and_ignores_padding() {
    let tree = DeviceTree::parse(&GOLDEN).expect("parse");
    let child = tree.find_node(b"/uart0").expect("uart0");
    let compatible = child.property(b"compatible").expect("compatible");
    let entries: Vec<_> = compatible.strings().collect();
    assert_eq!(entries, vec![&b"uart-1,samsung"[..]]);
    assert!(compatible.has_string(b"uart-1,samsung"));
    assert!(!compatible.has_string(b"apple,s5l-uart"));
}

#[test]
fn reg_decodes_as_two_little_endian_u64_least_significant_cell_first() {
    let tree = DeviceTree::parse(&GOLDEN).expect("parse");
    let path = tree.resolve(b"/uart0").expect("resolve");
    let range = path.reg(0).expect("reg 0");
    assert_eq!(range.address, 0x7920_0000);
    assert_eq!(range.size, 0x4000);

    let reg = path.node().property(b"reg").expect("reg property");
    let cells = CellCounts::new(2, 2).expect("cells");
    assert_eq!(reg.reg_container_count(cells).expect("count"), 1);
    assert_eq!(
        reg.reg_container(cells, 1),
        Err(AdtError::RegContainerOutOfRange)
    );
}

#[test]
fn a_terminal_node_whose_extent_equals_the_buffer_end_is_accepted() {
    // The distinction the universal bounds rule needs: a *read* offset must be
    // strictly inside the buffer, but an *extent* offset may equal its end.
    let tree = DeviceTree::parse(&GOLDEN).expect("parse");
    let child = tree.find_node(b"/uart0").expect("uart0");
    assert_eq!(child.child_count().expect("count"), 0);
    assert_eq!(child.extent_end().expect("extent"), GOLDEN.len());
    assert_eq!(tree.root().extent_end().expect("extent"), GOLDEN.len());
}

#[test]
fn path_resolution_matches_the_name_property_exactly() {
    let tree = DeviceTree::parse(&GOLDEN).expect("parse");
    assert_eq!(tree.resolve(b"/").expect("root path").len(), 1);
    assert_eq!(tree.resolve(b"/uart0").expect("uart0").len(), 2);
    // No @unit-address suffix exists in the ADT, so the synthesised form must
    // not resolve.
    assert_eq!(
        tree.find_node(b"/uart0@79200000").unwrap_err(),
        AdtError::NodeNotFound
    );
    assert!(tree.node_exists(b"/uart0").expect("exists"));
    assert!(!tree.node_exists(b"/uart6").expect("absent"));
}

#[test]
fn translation_terminates_when_an_ancestor_has_no_ranges() {
    // The root of this fixture carries no `ranges`, so translation stops there
    // and returns the address unchanged. Absence is not identity by accident:
    // it is the documented terminator.
    let tree = DeviceTree::parse(&GOLDEN).expect("parse");
    let path = tree.resolve(b"/uart0").expect("resolve");
    assert_eq!(
        path.translated_reg(0).expect("translated").address,
        0x7920_0000
    );
}

#[test]
fn typed_accessors_reject_values_of_the_wrong_length() {
    let tree = DeviceTree::parse(&GOLDEN).expect("parse");
    let root = tree.root();
    let address_cells = root.property(b"#address-cells").expect("property");
    assert_eq!(
        address_cells.as_u64(),
        Err(AdtError::PropertyLengthMismatch)
    );
    assert_eq!(
        address_cells.as_address_size(),
        Err(AdtError::PropertyLengthMismatch)
    );

    let child = tree.find_node(b"/uart0").expect("uart0");
    let reg = child.property(b"reg").expect("reg");
    assert_eq!(reg.as_u32(), Err(AdtError::PropertyLengthMismatch));
    let pair = reg.as_address_size().expect("16-byte record");
    assert_eq!(pair.address, 0x7920_0000);
    assert_eq!(pair.size, 0x4000);
}

#[test]
fn absent_properties_and_nodes_have_a_defined_answer() {
    let tree = DeviceTree::parse(&GOLDEN).expect("parse");
    let root = tree.root();
    assert!(root
        .find_property(b"device-tree-tag")
        .expect("query")
        .is_none());
    assert_eq!(
        root.property(b"device-tree-tag").unwrap_err(),
        AdtError::PropertyNotFound
    );
    assert!(root.find_child(b"aic").expect("query").is_none());
    assert_eq!(root.child(b"aic").unwrap_err(), AdtError::NodeNotFound);
}

// ---------------------------------------------- accessors found by coverage

#[test]
fn the_tree_hands_back_the_slice_it_was_parsed_from() {
    let tree = DeviceTree::parse(&GOLDEN).expect("parse");
    // Callers translate a node offset into a byte range against this, so a tree
    // that returned a different slice than it parsed would place every field
    // somewhere else.
    assert_eq!(tree.blob().as_ptr(), GOLDEN.as_ptr());
    assert_eq!(tree.blob().len(), GOLDEN.len());
    assert!(
        tree.tree_len() <= tree.blob().len(),
        "the tree can never claim more than the slice holds"
    );
}

#[test]
fn a_resolved_path_always_holds_at_least_the_root() {
    let tree = DeviceTree::parse(&GOLDEN).expect("parse");

    let root_path = tree.resolve(b"/").expect("the root resolves");
    assert_eq!(root_path.len(), 1);
    assert!(!root_path.is_empty(), "a path always contains the root");
    assert_eq!(root_path.root().offset(), tree.root().offset());
    assert_eq!(root_path.node().offset(), tree.root().offset());
    assert_eq!(root_path.parent().map(|node| node.offset()), None);

    let child = tree.resolve(b"/uart0").expect("uart0 resolves");
    assert!(child.len() >= 2, "root plus the named node");
    assert!(!child.is_empty());
    assert_eq!(
        child.root().offset(),
        tree.root().offset(),
        "root() must report the chain's root, not its target"
    );
    assert_eq!(
        child.parent().map(|node| node.offset()),
        Some(tree.root().offset())
    );
}
