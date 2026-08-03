//! Apple Device Tree (ADT) decoder — AS-0-T2.
//!
//! The ADT is the flattened tree Apple firmware (iBoot) hands to the booting
//! kernel on Apple Silicon. BraiNIX treats it as **hostile input on the same
//! footing as network bytes** (`INV-PARSE-003`): it is not signed to us, we
//! cannot verify it, and it is parsed earlier and with more authority than
//! anything that arrives over a socket.
//!
//! # What this crate guarantees
//!
//! - `#![no_std]`, the crate-level forbid attribute below, and **no allocation
//!   of any kind** —
//!   no heap, no arena, no growable buffer. Every working set is a fixed-size
//!   array or a borrowed slice (`INV-MEM`, `INV-PARSE-001`).
//! - **Total decoding.** Every malformed input returns an [`AdtError`]. There
//!   is no panicking index, no unchecked `Option` access, and no arithmetic that
//!   can wrap: every operation on a blob-supplied value is checked, and a value
//!   that does not fit **denies** — it never saturates and never wraps.
//! - **Fail closed.** A violation ends the operation. Nothing is skipped,
//!   nothing is clamped, and no length is truncated to what fits. A saturating
//!   clamp would turn "this tree is malformed" into "this tree is now silently
//!   different from what the firmware described", which is the worse state.
//! - **Bounds are checked immediately before each read**, not once after
//!   forming an offset. [`DeviceTree::parse`] additionally validates the whole
//!   structure up front so no caller ever holds a cursor into an unvalidated
//!   tree, but that pass is defence in depth on top of the per-read checks,
//!   never a substitute for them: a node's extent is unknowable without
//!   walking it, so no single pass can make later reads safe by itself.
//! - **Termination.** Both iterators are bounded by counts read once, before
//!   iterating, and stop permanently on their first error. The structural walk
//!   is iterative over a fixed-size stack with a visit budget, so it cannot
//!   recurse, cannot loop, and cannot overflow the boot stub's stack.
//!
//! # Offset basis
//!
//! The decoder works in **buffer-relative offsets** and takes a `&[u8]` and
//! nothing else. It never sees a physical address. Deriving the blob's
//! physical address from `boot_args`, validating `devtree_size`, and producing
//! the slice are the caller's obligations and belong to the boot-args parser
//! (AS-0-T4). A tree that ends before the end of the slice is normal —
//! trailing slack is not an error, and the slice is never extended to fit a
//! tree that claims more.
//!
//! # What this crate deliberately does not do
//!
//! It encodes **no per-SoC value**. No chip ID, no AIC version, no PMGR
//! CPU-start offset, no UART reference clock, no anticipated `compatible` string.
//! Those are discovered facts, and a discovered fact that is hardcoded is a
//! guess: the boot stub reads them from the tree at runtime through this API
//! and fails closed on anything it does not recognise. It also implements no
//! part of the CPU release sequence — that is AS-1 work; this crate exposes
//! only the data the tree carries.
//!
//! # Example
//!
//! ```
//! use brainix_adt::{AdtError, DeviceTree};
//!
//! fn boot_uart_base(blob: &[u8]) -> Result<u64, AdtError> {
//!     let tree = DeviceTree::parse(blob)?;
//!     let path = tree.resolve(b"/arm-io/uart0")?;
//!     Ok(path.translated_reg(0)?.address)
//! }
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod node;
mod property;
mod raw;

pub use crate::error::AdtError;
pub use crate::node::{ChildIter, Node, PropertyIter};
pub use crate::property::{
    AddressRange, CellCounts, Property, RangesEntry, RangesIter, StringIter,
    ADDRESS_SIZE_RECORD_LEN, MAX_NODE_NAME_LEN,
};

use crate::raw::{walk_node_end, NODE_HEADER_LEN};

/// Hard ceiling on a node's declared property count.
///
/// A policy bound, not a format rule. Real firmware stays far below it; the
/// space test in the header decoder is what refuses an absurd count on a small
/// buffer, and this ceiling is the backstop on a large one.
pub const MAX_PROPERTY_COUNT: u32 = 2048;

/// Hard ceiling on a node's declared child count. Policy, as above.
pub const MAX_CHILD_COUNT: u32 = 2048;

/// Hard ceiling on a property value length: 1 MiB − 1.
///
/// Equivalently, any of bits 30..20 of the length word set. A policy bound
/// with its own distinct failure reason
/// ([`AdtError::ValueLengthExceedsCeiling`]) so that it can be told apart in a
/// log from the format rule about bit 31.
pub const MAX_VALUE_LEN: usize = 0x000f_ffff;

/// Hard ceiling on nesting depth below the root.
///
/// A blob of N bytes can encode a chain of roughly N/8 nested nodes, so an
/// unbounded walk in a boot stub with a small fixed stack is a guaranteed
/// overflow. Real Apple trees are shallow. The limit is enforced by the size
/// of the traversal stack, so it is a property of the data structure rather
/// than of discipline.
pub const MAX_TREE_DEPTH: usize = 16;

/// Maximum number of nodes in a resolved path: the root plus one per level.
pub const MAX_PATH_NODES: usize = MAX_TREE_DEPTH + 1;

/// A parsed and structurally validated device tree.
///
/// Construction is the validation: holding one of these means the whole blob
/// walked cleanly under every rule this crate enforces.
#[derive(Debug, Clone, Copy)]
pub struct DeviceTree<'a> {
    blob: &'a [u8],
    tree_len: usize,
}

impl<'a> DeviceTree<'a> {
    /// Parses and fully validates a tree from a byte slice.
    ///
    /// The walk visits every node and every property, checking each count,
    /// length, offset and alignment against the buffer before use. It refuses
    /// a tree that nests too deeply, that declares more records than the
    /// buffer can hold, that carries an unresolved template property, or that
    /// is truncated at any structural boundary.
    ///
    /// A tree that ends before the end of `blob` is accepted: trailing slack
    /// is normal, and "the tree ended exactly at the buffer end" is never used
    /// as a validity signal.
    pub fn parse(blob: &'a [u8]) -> Result<Self, AdtError> {
        if blob.is_empty() {
            return Err(AdtError::EmptyBlob);
        }
        if blob.len() < NODE_HEADER_LEN {
            return Err(AdtError::BlobTooSmallForRoot);
        }
        let tree_len = walk_node_end(blob, 0, MAX_TREE_DEPTH)?;
        Ok(Self { blob, tree_len })
    }

    /// The bytes of `blob` the tree actually occupies.
    ///
    /// Never greater than the slice length. Any excess is trailing slack.
    pub fn tree_len(&self) -> usize {
        self.tree_len
    }

    /// The whole slice this tree was parsed from.
    pub fn blob(&self) -> &'a [u8] {
        self.blob
    }

    /// The root node, at offset 0. The leading `/` of a path denotes it, and
    /// it has no name of its own for path purposes.
    pub fn root(&self) -> Node<'a> {
        Node::new(self.blob, 0, 0)
    }

    /// Resolves an absolute path such as `/arm-io/uart0`, keeping the whole
    /// ancestor chain so that `reg` addresses can be translated afterwards.
    ///
    /// Each component is compared against a node's `name` **property value**
    /// exactly. ADT node names carry no `@unit-address` suffix, so no address
    /// is ever parsed out of a component.
    ///
    /// A path must be absolute, must not contain an empty component, and must
    /// not end in a separator.
    pub fn resolve(&self, path: &[u8]) -> Result<NodePath<'a>, AdtError> {
        let leading = path.first().ok_or(AdtError::MalformedPath)?;
        if *leading != b'/' {
            return Err(AdtError::MalformedPath);
        }
        let mut chain = NodePath::new(self.root());
        let mut rest = path.get(1..).ok_or(AdtError::MalformedPath)?;
        let empty: &[u8] = &[];

        while !rest.is_empty() {
            let (component, remainder) = match rest.iter().position(|byte| *byte == b'/') {
                Some(index) => {
                    let component = rest.get(..index).ok_or(AdtError::MalformedPath)?;
                    let after = index.checked_add(1).ok_or(AdtError::OffsetOverflow)?;
                    let remainder = rest.get(after..).ok_or(AdtError::MalformedPath)?;
                    if remainder.is_empty() {
                        return Err(AdtError::MalformedPath);
                    }
                    (component, remainder)
                }
                None => (rest, empty),
            };
            if component.is_empty() || component.len() > MAX_NODE_NAME_LEN {
                return Err(AdtError::MalformedPath);
            }
            let child = chain.node().child(component)?;
            chain.push(child)?;
            rest = remainder;
        }
        Ok(chain)
    }

    /// Resolves a path and returns only the node it names.
    pub fn find_node(&self, path: &[u8]) -> Result<Node<'a>, AdtError> {
        Ok(self.resolve(path)?.node())
    }

    /// Whether a node exists at `path`.
    ///
    /// The existence of a node is itself a signal in the ADT — the presence of
    /// `/arm-io/uart6/debug-console` is how the debug console is selected, and
    /// its contents are never read.
    pub fn node_exists(&self, path: &[u8]) -> Result<bool, AdtError> {
        match self.resolve(path) {
            Ok(_) => Ok(true),
            Err(AdtError::NodeNotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

/// A resolved path: the root, every intermediate node, and the target.
///
/// Fixed capacity, `Copy`, and allocation-free. It exists because address
/// translation needs the ancestor chain and the format stores no parent
/// pointer.
#[derive(Debug, Clone, Copy)]
pub struct NodePath<'a> {
    nodes: [Node<'a>; MAX_PATH_NODES],
    len: usize,
    target: Node<'a>,
}

impl<'a> NodePath<'a> {
    fn new(root: Node<'a>) -> Self {
        Self {
            nodes: [root; MAX_PATH_NODES],
            len: 1,
            target: root,
        }
    }

    fn push(&mut self, node: Node<'a>) -> Result<(), AdtError> {
        let slot = self.nodes.get_mut(self.len).ok_or(AdtError::PathTooDeep)?;
        *slot = node;
        self.len = self.len.checked_add(1).ok_or(AdtError::PathTooDeep)?;
        self.target = node;
        Ok(())
    }

    /// Number of nodes in the chain, root included. Always at least 1.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Always `false`: a resolved path always contains at least the root.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The node the path names.
    pub fn node(&self) -> Node<'a> {
        self.target
    }

    /// The root node of the chain.
    pub fn root(&self) -> Node<'a> {
        match self.nodes.first() {
            Some(node) => *node,
            None => self.target,
        }
    }

    /// The target's parent, or `None` when the target is the root.
    pub fn parent(&self) -> Option<Node<'a>> {
        let index = self.len.checked_sub(2)?;
        self.nodes.get(index).copied()
    }

    /// The `index`-th `reg` container of the target, untranslated.
    ///
    /// Decoded with the parent's `#address-cells` / `#size-cells`, which is
    /// what governs a `reg` — never the node's own.
    pub fn reg(&self, index: usize) -> Result<AddressRange, AdtError> {
        let parent = self.parent().ok_or(AdtError::MissingParentNode)?;
        self.node().reg(parent.cell_counts()?, index)
    }

    /// The `index`-th `reg` container of the target, translated up through
    /// every ancestor's `ranges` property.
    ///
    /// Translation is mandatory for anything under `/arm-io`: an untranslated
    /// address there is a valid-looking physical address pointing at the wrong
    /// place, which is exactly the input that makes a driver map the wrong
    /// device memory.
    ///
    /// Rules, as the specification states them:
    ///
    /// - a `ranges` entry applies only if it wholly contains the request;
    /// - if no entry contains it, translation **fails** — the untranslated
    ///   address is never passed through;
    /// - the **absence** of `ranges` on an ancestor terminates translation. It
    ///   does not mean identity and it does not mean error;
    /// - every containment sum and every substitution is checked for overflow
    ///   and underflow.
    pub fn translated_reg(&self, index: usize) -> Result<AddressRange, AdtError> {
        let mut range = self.reg(index)?;
        let mut level = self.len.checked_sub(2).ok_or(AdtError::MissingParentNode)?;

        loop {
            let ancestor = self.nodes.get(level).ok_or(AdtError::MissingParentNode)?;
            let ranges = match ancestor.find_property(b"ranges")? {
                Some(property) => property,
                None => return Ok(range),
            };
            let child_cells = ancestor.cell_counts()?;
            let grandparent_index = level.checked_sub(1).ok_or(AdtError::MissingParentNode)?;
            let grandparent = self
                .nodes
                .get(grandparent_index)
                .ok_or(AdtError::MissingParentNode)?;
            let parent_address_cells = grandparent.address_cells()?;

            let mut translated: Option<u64> = None;
            for item in ranges.ranges(child_cells, parent_address_cells)? {
                let entry = item?;
                if let Some(address) = entry.translate(range)? {
                    translated = Some(address);
                    break;
                }
            }
            let address = translated.ok_or(AdtError::NoMatchingRangesEntry)?;
            range = AddressRange {
                address,
                size: range.size,
            };
            level = grandparent_index;
        }
    }
}
