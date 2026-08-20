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
        // Unreachable by arithmetic, not by the parse-time contract the rest
        // of this file cites. The check above bounds the VALUE at
        // `MAX_NODE_VALUE_LEN` (64) and `as_c_str` needs a NUL inside it, so
        // the longest decodable name is 63 -- exactly `MAX_NODE_NAME_LEN`,
        // never more. The guard stays because it is the one that still holds
        // if those two constants are ever set independently, and today they
        // are one apart by coincidence rather than by a stated rule.
        //
        // COVERAGE-EXEMPT: see the note above.
        if name.len() > MAX_NODE_NAME_LEN {
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
            Err(error) => {
                self.done = true;
                return Some(Err(error));
            }
        };
        self.offset = decoded.end;
        self.remaining = match self.remaining.checked_sub(1) {
            Some(remaining) => remaining,
            None => {
                // Kept although unreachable: the early return and this
                // subtraction are separated by a decode, so an edit that moves
                // either one must meet a denial rather than a wrap to
                // `u32::MAX` and an iterator that never terminates.
                // COVERAGE-EXEMPT: the `remaining == 0` early return at the top
                // of `next` leaves `remaining` at least 1 here, so this cannot
                // borrow. That is a property of this function, not of the tree
                // having been parsed.
                self.done = true;
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
            // COVERAGE-EXEMPT: `children` refuses to hand back an iterator
            // whose `child_count` is non-zero past the depth limit, and
            // `ChildIter`'s fields are private, so any cursor that yields
            // anything already has `depth <= MAX_TREE_DEPTH`. Kept fail-closed
            // because that refusal lives in the constructor: this is the
            // second place the limit is enforced, and the buffers sized from
            // `MAX_PATH_NODES` depend on both.
            self.done = true;
            return Some(Err(AdtError::DepthLimitExceeded));
        }
        if let Err(error) = decode_node_header(self.blob, self.offset) {
            self.done = true;
            return Some(Err(error));
        }
        let node = Node::new(self.blob, self.offset, self.depth);
        let budget = crate::MAX_TREE_DEPTH.saturating_sub(self.depth);
        match walk_node_end(self.blob, self.offset, budget) {
            Ok(end) => self.offset = end,
            Err(error) => {
                self.done = true;
                return Some(Err(error));
            }
        }
        self.remaining = match self.remaining.checked_sub(1) {
            Some(remaining) => remaining,
            None => {
                // COVERAGE-EXEMPT: as in `PropertyIter::next` -- the
                // `remaining == 0` early return means the subtraction cannot
                // borrow, which is a property of this function and not of the
                // tree having been parsed. Kept for the same reason: a wrap
                // here is an iterator that never terminates.
                self.done = true;
                return Some(Err(AdtError::OffsetOverflow));
            }
        };
        Some(Ok(node))
    }
}

/// Guards reached by constructing a cursor directly.
///
/// `Node::new` is `pub(crate)`, so from inside the crate a node can be built
/// over bytes that `DeviceTree::parse` would never have produced. That is
/// precisely the situation the fail-closed guards in this file exist for, and
/// until now nothing stood there -- every one of them was exempt from the
/// coverage gate on the grounds that a parsed tree cannot reach them, which is
/// true and is also why they were never executed.
///
/// The builder writes into a fixed array rather than a `Vec`: this crate is
/// `no_std` and stays that way in its own tests.
#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::expect_used
)]
mod tests {
    use super::*;

    /// A blob under construction, in a buffer big enough for these fixtures.
    struct Blob {
        bytes: [u8; 256],
        len: usize,
    }

    impl Blob {
        const fn new() -> Self {
            Self {
                bytes: [0u8; 256],
                len: 0,
            }
        }

        fn push(&mut self, bytes: &[u8]) {
            for byte in bytes {
                self.bytes[self.len] = *byte;
                self.len += 1;
            }
        }

        /// An 8-byte node header.
        fn header(&mut self, properties: u32, children: u32) {
            self.push(&properties.to_le_bytes());
            self.push(&children.to_le_bytes());
        }

        /// One property: 32-byte NUL-padded name, LE length, value, pad to 4.
        fn property(&mut self, name: &str, value: &[u8]) {
            let start = self.len;
            self.push(name.as_bytes());
            while self.len - start < 32 {
                self.push(&[0]);
            }
            self.push(&(value.len() as u32).to_le_bytes());
            self.push(value);
            while !(self.len - start).is_multiple_of(4) {
                self.push(&[0]);
            }
        }

        fn as_slice(&self) -> &[u8] {
            &self.bytes[..self.len]
        }
    }

    /// A node with a `name` and one child that has a `name`.
    fn parent_with_one_child() -> Blob {
        let mut blob = Blob::new();
        blob.header(1, 1);
        blob.property("name", b"deep\0");
        blob.header(1, 0);
        blob.property("name", b"leaf\0");
        blob
    }

    #[test]
    fn descending_past_the_depth_limit_is_refused_rather_than_followed() {
        // A node that HAS children, sitting at the deepest level the format
        // admits. Walking into them would make a path longer than
        // `MAX_PATH_NODES`, which every fixed-size path buffer in this crate is
        // sized from -- so the refusal is what keeps those buffers honest.
        let blob = parent_with_one_child();
        let at_limit = Node::new(blob.as_slice(), 0, crate::MAX_TREE_DEPTH);
        assert_eq!(
            at_limit.children().err(),
            Some(AdtError::DepthLimitExceeded),
            "a node at the depth limit must refuse to yield children"
        );

        // One shallower is fine, which is what makes the limit a limit rather
        // than an off-by-one.
        let below = Node::new(blob.as_slice(), 0, crate::MAX_TREE_DEPTH - 1);
        assert!(below.children().is_ok());
    }

    #[test]
    fn a_childless_node_at_the_limit_is_not_refused() {
        // The guard is on `child_count > 0`, not on depth alone. A leaf at the
        // limit is legal and its empty iterator must still be handed back --
        // refusing here would make the deepest level of every tree unreadable.
        let mut blob = Blob::new();
        blob.header(1, 0);
        blob.property("name", b"leaf\0");
        let at_limit = Node::new(blob.as_slice(), 0, crate::MAX_TREE_DEPTH);
        let mut children = at_limit.children().expect("a leaf adds no depth");
        assert!(children.next().is_none());
    }

    #[test]
    fn a_cell_count_outside_one_or_two_is_refused() {
        // `#address-cells` is how many 32-bit words an address occupies. Zero
        // means a `reg` entry has no address, and three or more would read past
        // the fixed-size buffers `AddressRange` uses. `CellCounts::new` rejects
        // both when a tree is parsed; this is the same rule at the accessor,
        // where a cursor built by other means arrives.
        for bad in [0u32, 3, 4, u32::MAX] {
            let mut blob = Blob::new();
            blob.header(2, 0);
            blob.property("name", b"bus\0");
            blob.property("#address-cells", &bad.to_le_bytes());
            let node = Node::new(blob.as_slice(), 0, 0);
            assert_eq!(
                node.address_cells().err(),
                Some(AdtError::InvalidAddressCells),
                "#address-cells = {bad} must be refused"
            );
        }

        // One and two are the only legal values, and both must pass.
        for good in [1u32, 2] {
            let mut blob = Blob::new();
            blob.header(2, 0);
            blob.property("name", b"bus\0");
            blob.property("#address-cells", &good.to_le_bytes());
            let node = Node::new(blob.as_slice(), 0, 0);
            assert_eq!(node.address_cells(), Ok(good));
        }
    }

    /// A header that promises more properties than the blob holds.
    ///
    /// `PropertyIter` trusts the count in the node header and decodes that many
    /// records. When the blob ends first, the decode must deny and the iterator
    /// must stay denied -- yielding `Some(Err(..))` once and `None` after, not
    /// re-reading the same bad offset forever.
    #[test]
    fn a_property_count_larger_than_the_record_run_denies_and_stays_denied() {
        let mut blob = Blob::new();
        blob.header(2, 0);
        blob.property("name", b"leaf\0");
        // A second record of the right length whose name never terminates, so
        // the header's count check is satisfied and the decode is not. An
        // absent record would be caught earlier, by `decode_node_header`.
        blob.push(&[0xFF; 32]);
        blob.push(&0u32.to_le_bytes());

        let node = Node::new(blob.as_slice(), 0, 0);
        let mut properties = node.properties().expect("the header itself is intact");

        let first = properties.next().expect("one record is present");
        assert_eq!(first.expect("well formed").name(), b"name");

        let denial = properties.next().expect("the iterator must speak once");
        assert!(
            denial.is_err(),
            "a record past the end of the blob must deny, got {denial:?}"
        );
        assert!(
            properties.next().is_none(),
            "a denied iterator is finished, not retried"
        );
    }

    /// A child count that points at a header which is not there.
    #[test]
    fn a_child_offset_past_the_blob_denies_and_stays_denied() {
        let mut blob = Blob::new();
        blob.header(1, 1);
        blob.property("name", b"deep\0");
        // A child header that is present, so the parent's child-count check
        // passes, but that claims more properties than the blob could hold.
        blob.header(u32::MAX, 0);

        let node = Node::new(blob.as_slice(), 0, 0);
        let mut children = node.children().expect("the parent header is intact");

        let denial = children.next().expect("the iterator must speak once");
        assert!(
            denial.is_err(),
            "a child header past the end of the blob must deny, got {denial:?}"
        );
        assert!(children.next().is_none(), "and then be finished");
    }

    /// A child whose header decodes but whose subtree does not.
    ///
    /// This is the arm that separates `ChildIter` from a simple offset walk:
    /// advancing to the next sibling means walking the current child's whole
    /// subtree, because nothing in the format records a node's size. A child
    /// that claims a property it does not have makes that walk fail.
    #[test]
    fn a_child_whose_subtree_walk_fails_denies_rather_than_advancing() {
        let mut blob = Blob::new();
        blob.header(1, 1);
        blob.property("name", b"deep\0");
        // A child header that decodes: it claims one property and one property
        // worth of bytes follows, so the count check is satisfied.
        blob.header(1, 0);
        // Those bytes are not a property. The child's header is fine and its
        // subtree is not, which is the only way to reach the walk.
        blob.push(&[0xFF; 32]);
        blob.push(&0u32.to_le_bytes());

        let node = Node::new(blob.as_slice(), 0, 0);
        let mut children = node.children().expect("the parent header is intact");

        let denial = children.next().expect("the iterator must speak once");
        assert!(
            denial.is_err(),
            "an unwalkable subtree must deny, got {denial:?}"
        );
        assert!(children.next().is_none(), "and then be finished");
    }
}
