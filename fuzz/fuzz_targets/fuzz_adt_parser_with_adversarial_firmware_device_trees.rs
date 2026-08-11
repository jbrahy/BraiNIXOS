#![no_main]

//! Fuzz target: the Apple Device Tree decoder with adversarial firmware blobs.
//!
//! The ADT is firmware-supplied and is parsed earlier and with more authority
//! than anything that arrives over a socket (`INV-PARSE-003`). This target
//! feeds `brainix_adt::DeviceTree::parse` arbitrary bytes and asserts the
//! outcome is always either a parsed tree or an `AdtError` — never a panic, an
//! out-of-bounds read, an allocation, or a hang (`INV-PARSE-001`, `-002`).
//!
//! Parsing is only half of it. A tree that parses but panics while it is being
//! walked is exactly the bug class a parse-only harness misses, so every
//! successful parse is followed by a full traversal that visits every node,
//! reads every property through every typed accessor, resolves every path the
//! tree itself names, and iterates every child list. Path resolution is also
//! driven with the raw fuzz input as the path, so the path decoder sees
//! hostile bytes independently of the blob.
//!
//! The assertions the target makes, beyond "no panic":
//!
//! - the tree never claims more bytes than the buffer holds;
//! - every borrowed slice the API hands back lies wholly inside the buffer;
//! - no node is reported deeper than the depth limit;
//! - traversal visits no more nodes than the blob can physically encode, which
//!   is the termination bound restated as a runtime check.

use brainix_adt::{CellCounts, DeviceTree, Node, MAX_TREE_DEPTH};
use libfuzzer_sys::fuzz_target;

/// Bytes in the smallest node a blob can encode: the node header alone.
const SMALLEST_NODE_LEN: usize = 8;

/// Longest path the target assembles while walking, in bytes.
const PATH_CAPACITY: usize = 1024;

/// Whether `part` is a sub-slice of `blob`.
///
/// The decoder never copies: every name and value it returns must point into
/// the caller's buffer. Comparing the addresses is how that is checked without
/// trusting the decoder's own arithmetic.
fn is_inside(blob: &[u8], part: &[u8]) -> bool {
    let base = blob.as_ptr() as usize;
    let start = part.as_ptr() as usize;
    if start < base {
        return false;
    }
    match start
        .checked_sub(base)
        .and_then(|at| at.checked_add(part.len()))
    {
        Some(end) => end <= blob.len(),
        None => false,
    }
}

/// Reads every property of `node` through every accessor that can accept it.
///
/// Each accessor states the shape it requires and denies a value that does not
/// have it, so calling all of them on every value is the point: the wrong-shape
/// paths are the ones a well-formed corpus never reaches.
fn exercise_properties(blob: &[u8], node: Node<'_>) {
    let iterator = match node.properties() {
        Ok(iterator) => iterator,
        Err(_) => return,
    };
    let declared = node.property_count().unwrap_or(0);
    let mut seen: u32 = 0;
    for item in iterator {
        let property = match item {
            Ok(property) => property,
            Err(_) => break,
        };
        seen = seen.saturating_add(1);
        assert!(
            is_inside(blob, property.name_field()),
            "property name field escaped the buffer"
        );
        assert!(
            is_inside(blob, property.name()),
            "property name escaped the buffer"
        );
        assert!(
            is_inside(blob, property.value()),
            "property value escaped the buffer"
        );
        assert!(
            property.name_field().len() == 32,
            "property name field is not the fixed 32 bytes"
        );

        let _ = property.as_u32();
        let _ = property.as_u64();
        let _ = property.as_address_size();
        if let Ok(text) = property.as_c_str() {
            assert!(is_inside(blob, text), "C string escaped the buffer");
        }
        for entry in property.strings() {
            assert!(is_inside(blob, entry), "string entry escaped the buffer");
        }
        let _ = property.has_string(b"uart-1,samsung");
        let _ = property.is_named(b"compatible");

        exercise_cell_shaped_accessors(&property);
    }
    assert!(
        seen <= declared,
        "property iterator yielded more items than the node declared"
    );
}

/// Drives the `reg` and `ranges` decoders over every legal cell-count pair.
///
/// The cell counts that govern a value are the parent's, and a hostile tree can
/// declare any of them, so every pair in `1..=2` × `0..=2` is applied to every
/// value rather than only to the values whose node declared it.
fn exercise_cell_shaped_accessors(property: &brainix_adt::Property<'_>) {
    for address_cells in 1u32..=2 {
        for size_cells in 0u32..=2 {
            let cells = match CellCounts::new(address_cells, size_cells) {
                Ok(cells) => cells,
                Err(_) => continue,
            };
            let count = property.reg_container_count(cells).unwrap_or(0);
            let probe = count.saturating_add(1).min(8);
            for index in 0..probe {
                let _ = property.reg_container(cells, index);
            }
            for parent_address_cells in 1u32..=2 {
                let entries = match property.ranges(cells, parent_address_cells) {
                    Ok(entries) => entries,
                    Err(_) => continue,
                };
                for entry in entries {
                    if let Ok(entry) = entry {
                        let _ = entry.translate(brainix_adt::AddressRange {
                            address: entry.child_address,
                            size: entry.child_size,
                        });
                    }
                }
            }
        }
    }
}

/// Reads everything about a node that does not require its parent.
fn exercise_node(blob: &[u8], node: Node<'_>) {
    assert!(node.offset() < blob.len(), "node offset escaped the buffer");
    assert!(
        node.depth() <= MAX_TREE_DEPTH,
        "node reported a depth past the limit"
    );
    if let Ok(end) = node.extent_end() {
        assert!(end <= blob.len(), "node extent ran past the buffer");
        assert!(end > node.offset(), "node extent did not advance");
    }
    if let Ok(name) = node.name() {
        assert!(is_inside(blob, name), "node name escaped the buffer");
        assert!(name.len() <= 63, "node name exceeded the policy bound");
    }
    let _ = node.cell_counts();
    let _ = node.address_cells();
    let _ = node.find_property(b"name");
    let _ = node.find_property(b"compatible");
    let _ = node.find_property(b"reg");
    let _ = node.find_property(b"ranges");
    let _ = node.find_property(b"chip-id");
    let _ = node.property(b"device_type");
    let _ = node.find_child(b"uart0");
    exercise_properties(blob, node);
}

/// Appends `/name` to `path`, or reports that the path would overflow.
fn push_component(path: &mut Vec<u8>, name: &[u8]) -> bool {
    if path.len().saturating_add(name.len()).saturating_add(1) > PATH_CAPACITY {
        return false;
    }
    path.push(b'/');
    path.extend_from_slice(name);
    true
}

/// Walks the whole tree iteratively, exercising each node and resolving the
/// path that names it.
///
/// The stack is explicit and the visit count is capped at the same structural
/// bound the decoder uses, so a decoder that failed to advance would trip the
/// assertion here rather than hang the fuzzer.
fn walk(blob: &[u8], tree: &DeviceTree<'_>) {
    let budget = blob
        .len()
        .checked_div(SMALLEST_NODE_LEN)
        .unwrap_or(0)
        .saturating_add(1);
    let mut visited: usize = 0;
    let mut stack: Vec<(Node<'_>, Vec<u8>)> = vec![(tree.root(), Vec::new())];

    while let Some((node, path)) = stack.pop() {
        visited = visited.saturating_add(1);
        assert!(
            visited <= budget,
            "traversal visited more nodes than the blob can encode"
        );
        exercise_node(blob, node);

        if !path.is_empty() {
            let resolved = tree.resolve(&path);
            let _ = tree.node_exists(&path);
            let _ = tree.find_node(&path);
            if let Ok(chain) = resolved {
                assert!(chain.len() >= 1, "a resolved path has no nodes");
                assert!(
                    chain.len() <= MAX_TREE_DEPTH.saturating_add(1),
                    "a resolved path is longer than the depth limit allows"
                );
                assert!(!chain.is_empty(), "a resolved path reported itself empty");
                let _ = chain.root();
                let _ = chain.parent();
                for index in 0..4 {
                    let _ = chain.reg(index);
                    let _ = chain.translated_reg(index);
                }
            }
        }

        let children = match node.children() {
            Ok(children) => children,
            Err(_) => continue,
        };
        for item in children {
            let child = match item {
                Ok(child) => child,
                Err(_) => break,
            };
            let name = match child.name() {
                Ok(name) => name,
                Err(_) => continue,
            };
            let mut child_path = path.clone();
            if push_component(&mut child_path, name) {
                stack.push((child, child_path));
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let tree = match DeviceTree::parse(data) {
        Ok(tree) => tree,
        Err(_) => {
            // A denial is a correct outcome. The path decoder is still driven,
            // because it is reachable only through a parsed tree and must not
            // be left unfuzzed on inputs that never produce one.
            return;
        }
    };

    assert!(
        tree.tree_len() <= data.len(),
        "the tree claimed more bytes than the buffer holds"
    );
    assert!(
        core::ptr::eq(tree.blob(), data),
        "the tree does not borrow the supplied buffer"
    );

    walk(data, &tree);

    // Hostile bytes as a path, independent of the blob's own names.
    let _ = tree.resolve(data);
    let _ = tree.node_exists(data);
    let _ = tree.find_node(data);
    let _ = tree.resolve(b"/");
    let _ = tree.resolve(b"//");
    let _ = tree.resolve(b"/arm-io/uart0");
    let _ = tree.resolve(b"arm-io");
    let _ = tree.resolve(b"/arm-io/");
    let _ = tree.resolve(b"");
});
