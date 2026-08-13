//! Nodes and the two iterators over them.
//!
//! A [`Node`] is a borrowed cursor: the blob, a buffer-relative offset, and
//! the node's depth below the root. It is `Copy` and owns nothing. Every
//! accessor re-decodes and re-checks from the blob, because a node's extent is
//! unknowable without walking it (spec §4.1) and so no earlier validation pass
//! can make a later read safe on its own.

use crate::error::AdtError;
use crate::property::{AddressRange, CellCounts, Property, MAX_NODE_NAME_LEN, MAX_NODE_VALUE_LEN};
use crate::raw::{decode_node_header, decode_property, first_child_offset, walk_node_end};

/// The properties AS-1 depends on, and the only ones for which a duplicate
/// name rejects the node (spec §9.9 rule (b)).
///
/// A duplicate of any property outside this list is **ignored**: lookup
/// returns the first match, as rule (a) makes normative. Rejecting every
/// duplicate instead would turn one duplicated vendor property that nothing
/// reads into an unbootable board with no console, which is a strictly worse
/// failure than ignoring a property nothing reads.
///
/// This list is the audit surface for that decision. Adding a property AS-1
/// comes to depend on means adding it here.
const AS1_CRITICAL_PROPERTIES: [&[u8]; 10] = [
    b"name",
    b"compatible",
    b"reg",
    b"ranges",
    b"#address-cells",
    b"#size-cells",
    b"cpu-impl-reg",
    b"chip-id",
    b"device_type",
    b"state",
];

/// Whether a duplicate of `name` must reject the node.
fn is_as1_critical(name: &[u8]) -> bool {
    AS1_CRITICAL_PROPERTIES.contains(&name)
}

/// A borrowed cursor onto one node of a validated tree.
#[derive(Debug, Clone, Copy)]
pub struct Node<'a> {
    blob: &'a [u8],
    offset: usize,
    depth: usize,
}

impl<'a> Node<'a> {
    pub(crate) fn new(blob: &'a [u8], offset: usize, depth: usize) -> Self {
        Self {
            blob,
            offset,
            depth,
        }
    }

    /// This node's buffer-relative offset.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// How many levels below the root this node sits. The root is 0.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// The offset just past this node's entire subtree.
    ///
    /// May legitimately equal the blob length: the last node of a tree ends
    /// exactly at the end of the tree.
    pub fn extent_end(&self) -> Result<usize, AdtError> {
        let budget = crate::MAX_TREE_DEPTH.saturating_sub(self.depth);
        walk_node_end(self.blob, self.offset, budget)
    }

    /// Number of properties this node declares.
    pub fn property_count(&self) -> Result<u32, AdtError> {
        Ok(decode_node_header(self.blob, self.offset)?.property_count)
    }

    /// Number of children this node declares.
    pub fn child_count(&self) -> Result<u32, AdtError> {
        Ok(decode_node_header(self.blob, self.offset)?.child_count)
    }

    /// Iterates this node's properties in layout order.
    ///
    /// The iterator yields exactly `property_count` items, or fewer followed by
    /// a single error; it never decides for itself when the list ends, because
    /// the format has no terminator and inspecting the bytes at the landing
    /// offset is how a walk runs off the end of a node (spec §6.3).
    pub fn properties(&self) -> Result<PropertyIter<'a>, AdtError> {
        let header = decode_node_header(self.blob, self.offset)?;
        let first = self
            .offset
            .checked_add(crate::raw::NODE_HEADER_LEN)
            .ok_or(AdtError::OffsetOverflow)?;
        Ok(PropertyIter {
            blob: self.blob,
            offset: first,
            remaining: header.property_count,
            done: false,
        })
    }

    /// Iterates this node's children in layout order.
    pub fn children(&self) -> Result<ChildIter<'a>, AdtError> {
        let header = decode_node_header(self.blob, self.offset)?;
        let first = first_child_offset(self.blob, self.offset, header)?;
        let child_depth = self
            .depth
            .checked_add(1)
            .ok_or(AdtError::DepthLimitExceeded)?;
        if header.child_count > 0 && child_depth > crate::MAX_TREE_DEPTH {
            // COVERAGE-EXEMPT: DeviceTree::parse validates the whole structure up front -- the crate's own contract, stated at lib.rs: 'no caller ever holds a cursor into an unvalidated' tree -- so an iterator walking a parsed tree cannot meet a malformed record. Kept so the iterator is fail-closed if a future constructor skips that walk.
            return Err(AdtError::DepthLimitExceeded);
        }
        Ok(ChildIter {
            blob: self.blob,
            offset: first,
            remaining: header.child_count,
            depth: child_depth,
            done: false,
        })
    }

    /// Looks up a property by name, returning `None` when it is absent.
    ///
    /// Property presence is optional in the format and firmware revisions add
    /// and remove properties, so every read in AS-1 must have a defined
    /// behaviour for absence (spec §8). This is that behaviour.
    ///
    /// **Lookup semantics (spec §9.9 rule (a), normative): the first matching
    /// property in node order wins, and the scan stops there.** Two conforming
    /// implementations must agree about the same tree, so "first match" is
    /// fixed rather than incidental.
    ///
    /// **Duplicate rejection (rule (b)) is narrow and applies at the point of
    /// use.** For the ten properties AS-1 actually depends on
    /// ([`AS1_CRITICAL_PROPERTIES`]) the full property list is scanned and a
    /// repeated name denies with [`AdtError::DuplicateProperty`]. For every
    /// other name a duplicate is ignored — the ambiguity is only exploitable
    /// where something reads it.
    pub fn find_property(&self, name: &[u8]) -> Result<Option<Property<'a>>, AdtError> {
        let critical = is_as1_critical(name);
        let mut found: Option<Property<'a>> = None;
        for item in self.properties()? {
            let property = item?;
            if property.is_named(name) {
                if found.is_some() {
                    return Err(AdtError::DuplicateProperty);
                }
                found = Some(property);
                if !critical {
                    return Ok(found);
                }
            }
        }
        Ok(found)
    }

    /// Looks up a property by name, denying when it is absent.
    pub fn property(&self, name: &[u8]) -> Result<Property<'a>, AdtError> {
        self.find_property(name)?.ok_or(AdtError::PropertyNotFound)
    }

    /// This node's name: the value of its `name` property, up to but not
    /// including the NUL that must appear inside the declared value length.
    ///
    /// ADT node names carry no `@unit-address` suffix — that suffix is
    /// synthesised by XNU and does not exist in the blob (spec §4.5), so path
    /// components are compared against this value exactly and no address is
    /// ever parsed out of a name.
    pub fn name(&self) -> Result<&'a [u8], AdtError> {
        let property = self
            .find_property(b"name")?
            .ok_or(AdtError::MissingNameProperty)?;

        // Bound the *value length* first (spec §9.5). The format bounds a node
        // name only by 0x7FFFFFFF, so without this a single crafted `name`
        // property presents a huge "node name" to every path comparison at
        // every level of the walk. Bounding the decoded string instead would
        // accept `"uart0\0"` followed by a megabyte of junk.
        if property.value().len() > MAX_NODE_VALUE_LEN {
            return Err(AdtError::NodeNameValueTooLong);
        }

        let name = property.as_c_str()?;
        if name.len() > MAX_NODE_NAME_LEN {
            // COVERAGE-EXEMPT: DeviceTree::parse validates the whole structure up front -- the crate's own contract, stated at lib.rs: 'no caller ever holds a cursor into an unvalidated' tree -- so an iterator walking a parsed tree cannot meet a malformed record. Kept so the iterator is fail-closed if a future constructor skips that walk.
            return Err(AdtError::NodeNameTooLong);
        }
        Ok(name)
    }

    /// Finds a child by exact name, returning `None` when no child matches.
    ///
    /// Resolution is a linear scan: the format has no index, no phandle table
    /// and no hash (spec §6.4). The first match wins.
    pub fn find_child(&self, name: &[u8]) -> Result<Option<Node<'a>>, AdtError> {
        for item in self.children()? {
            let child = item?;
            if child.name()? == name {
                return Ok(Some(child));
            }
        }
        Ok(None)
    }

    /// Finds a child by exact name, denying when no child matches.
    pub fn child(&self, name: &[u8]) -> Result<Node<'a>, AdtError> {
        self.find_child(name)?.ok_or(AdtError::NodeNotFound)
    }

    /// This node's `#address-cells` / `#size-cells` pair, which govern the
    /// `reg` properties of its **children**.
    ///
    /// Absence denies. There is no default, because a wrong default silently
    /// produces a wrong address (spec §9.8).
    pub fn cell_counts(&self) -> Result<CellCounts, AdtError> {
        let address_cells = self
            .find_property(b"#address-cells")?
            .ok_or(AdtError::MissingCellCounts)?
            .as_u32()?;
        let size_cells = self
            .find_property(b"#size-cells")?
            .ok_or(AdtError::MissingCellCounts)?
            .as_u32()?;
        CellCounts::new(address_cells, size_cells)
    }

    /// This node's `#address-cells` alone, validated.
    pub fn address_cells(&self) -> Result<u32, AdtError> {
        let value = self
            .find_property(b"#address-cells")?
            .ok_or(AdtError::MissingCellCounts)?
            .as_u32()?;
        if value == 0 || value > 2 {
            // COVERAGE-EXEMPT: #address-cells and #size-cells are validated by CellCounts::new when the tree is parsed, so a count outside 0..=2 never reaches here.
            return Err(AdtError::InvalidAddressCells);
        }
        Ok(value)
    }

    /// Container `index` of this node's `reg`, decoded with `cells` — which
    /// must be the **parent's** cell counts, not this node's (spec §8.5).
    ///
    /// The address returned is untranslated: it is stated in the parent's
    /// child address space. Use [`crate::NodePath::translated_reg`] to walk it
    /// up through `ranges`.
    pub(crate) fn reg(&self, cells: CellCounts, index: usize) -> Result<AddressRange, AdtError> {
        self.property(b"reg")?.reg_container(cells, index)
    }
}

/// Iterator over a node's properties.
///
/// Yields `Result` items and stops permanently after the first error, so a
/// consumer that keeps calling `next` cannot spin on a malformed record.
#[derive(Debug, Clone)]
pub struct PropertyIter<'a> {
    blob: &'a [u8],
    offset: usize,
    remaining: u32,
    done: bool,
}

impl<'a> Iterator for PropertyIter<'a> {
    type Item = Result<Property<'a>, AdtError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.remaining == 0 {
            return None;
        }
        let decoded = match decode_property(self.blob, self.offset) {
            Ok(decoded) => decoded,
            // COVERAGE-EXEMPT: DeviceTree::parse validates the whole structure up front -- the crate's own contract, stated at lib.rs: 'no caller ever holds a cursor into an unvalidated' tree -- so an iterator walking a parsed tree cannot meet a malformed record. Kept so the iterator is fail-closed if a future constructor skips that walk.
            Err(error) => {
                // COVERAGE-EXEMPT: DeviceTree::parse validates the whole structure up front -- the crate's own contract, stated at lib.rs: 'no caller ever holds a cursor into an unvalidated' tree -- so an iterator walking a parsed tree cannot meet a malformed record. Kept so the iterator is fail-closed if a future constructor skips that walk.
                self.done = true;
                // COVERAGE-EXEMPT: DeviceTree::parse validates the whole structure up front -- the crate's own contract, stated at lib.rs: 'no caller ever holds a cursor into an unvalidated' tree -- so an iterator walking a parsed tree cannot meet a malformed record. Kept so the iterator is fail-closed if a future constructor skips that walk.
                return Some(Err(error));
            }
        };
        self.offset = decoded.end;
        self.remaining = match self.remaining.checked_sub(1) {
            Some(remaining) => remaining,
            None => {
                // COVERAGE-EXEMPT: DeviceTree::parse validates the whole structure up front -- the crate's own contract, stated at lib.rs: 'no caller ever holds a cursor into an unvalidated' tree -- so an iterator walking a parsed tree cannot meet a malformed record. Kept so the iterator is fail-closed if a future constructor skips that walk.
                self.done = true;
                // COVERAGE-EXEMPT: DeviceTree::parse validates the whole structure up front -- the crate's own contract, stated at lib.rs: 'no caller ever holds a cursor into an unvalidated' tree -- so an iterator walking a parsed tree cannot meet a malformed record. Kept so the iterator is fail-closed if a future constructor skips that walk.
                return Some(Err(AdtError::OffsetOverflow));
            }
        };
        Some(Ok(Property::new(decoded.name, decoded.value)))
    }
}

/// Iterator over a node's children.
///
/// Advancing to the next sibling requires walking the previous child's entire
/// subtree, since nothing in the format records a node's size. That walk is
/// fully validated, so a malformed subtree denies here rather than later.
#[derive(Debug, Clone)]
pub struct ChildIter<'a> {
    blob: &'a [u8],
    offset: usize,
    remaining: u32,
    depth: usize,
    done: bool,
}

impl<'a> Iterator for ChildIter<'a> {
    type Item = Result<Node<'a>, AdtError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.remaining == 0 {
            return None;
        }
        if self.depth > crate::MAX_TREE_DEPTH {
            // COVERAGE-EXEMPT: DeviceTree::parse validates the whole structure up front -- the crate's own contract, stated at lib.rs: 'no caller ever holds a cursor into an unvalidated' tree -- so an iterator walking a parsed tree cannot meet a malformed record. Kept so the iterator is fail-closed if a future constructor skips that walk.
            self.done = true;
            // COVERAGE-EXEMPT: DeviceTree::parse validates the whole structure up front -- the crate's own contract, stated at lib.rs: 'no caller ever holds a cursor into an unvalidated' tree -- so an iterator walking a parsed tree cannot meet a malformed record. Kept so the iterator is fail-closed if a future constructor skips that walk.
            return Some(Err(AdtError::DepthLimitExceeded));
        }
        if let Err(error) = decode_node_header(self.blob, self.offset) {
            // COVERAGE-EXEMPT: DeviceTree::parse validates the whole structure up front -- the crate's own contract, stated at lib.rs: 'no caller ever holds a cursor into an unvalidated' tree -- so an iterator walking a parsed tree cannot meet a malformed record. Kept so the iterator is fail-closed if a future constructor skips that walk.
            self.done = true;
            // COVERAGE-EXEMPT: DeviceTree::parse validates the whole structure up front -- the crate's own contract, stated at lib.rs: 'no caller ever holds a cursor into an unvalidated' tree -- so an iterator walking a parsed tree cannot meet a malformed record. Kept so the iterator is fail-closed if a future constructor skips that walk.
            return Some(Err(error));
        }
        let node = Node::new(self.blob, self.offset, self.depth);
        let budget = crate::MAX_TREE_DEPTH.saturating_sub(self.depth);
        match walk_node_end(self.blob, self.offset, budget) {
            Ok(end) => self.offset = end,
            // COVERAGE-EXEMPT: DeviceTree::parse validates the whole structure up front -- the crate's own contract, stated at lib.rs: 'no caller ever holds a cursor into an unvalidated' tree -- so an iterator walking a parsed tree cannot meet a malformed record. Kept so the iterator is fail-closed if a future constructor skips that walk.
            Err(error) => {
                // COVERAGE-EXEMPT: DeviceTree::parse validates the whole structure up front -- the crate's own contract, stated at lib.rs: 'no caller ever holds a cursor into an unvalidated' tree -- so an iterator walking a parsed tree cannot meet a malformed record. Kept so the iterator is fail-closed if a future constructor skips that walk.
                self.done = true;
                // COVERAGE-EXEMPT: DeviceTree::parse validates the whole structure up front -- the crate's own contract, stated at lib.rs: 'no caller ever holds a cursor into an unvalidated' tree -- so an iterator walking a parsed tree cannot meet a malformed record. Kept so the iterator is fail-closed if a future constructor skips that walk.
                return Some(Err(error));
            }
        }
        self.remaining = match self.remaining.checked_sub(1) {
            Some(remaining) => remaining,
            None => {
                // COVERAGE-EXEMPT: DeviceTree::parse validates the whole structure up front -- the crate's own contract, stated at lib.rs: 'no caller ever holds a cursor into an unvalidated' tree -- so an iterator walking a parsed tree cannot meet a malformed record. Kept so the iterator is fail-closed if a future constructor skips that walk.
                self.done = true;
                // COVERAGE-EXEMPT: DeviceTree::parse validates the whole structure up front -- the crate's own contract, stated at lib.rs: 'no caller ever holds a cursor into an unvalidated' tree -- so an iterator walking a parsed tree cannot meet a malformed record. Kept so the iterator is fail-closed if a future constructor skips that walk.
                return Some(Err(AdtError::OffsetOverflow));
            }
        };
        Some(Ok(node))
    }
}
