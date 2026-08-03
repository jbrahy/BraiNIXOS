//! The single failure enum for the ADT decoder.
//!
//! One variant per failure mode, so that a rejected tree can be audited for
//! *why* it was rejected rather than merely *that* it was. Deliberately not
//! `#[non_exhaustive]`: callers inside BraiNIX are meant to match exhaustively
//! so that a newly added failure mode is a compile error, not a silent
//! wildcard arm.

/// Every way an Apple Device Tree blob can be refused.
///
/// There is no "warning" and no partial success. Any value of this type means
/// the operation denied and nothing was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdtError {
    /// The supplied blob was zero bytes long.
    EmptyBlob,

    /// The blob is shorter than the 8-byte root node header.
    BlobTooSmallForRoot,

    /// A node header or property record did not start on a 4-byte boundary.
    ///
    /// Every record in a well-formed tree is 4-byte aligned by construction
    /// (spec §4.3), so a misaligned landing offset means the walk has
    /// desynchronised.
    MisalignedRecord,

    /// Fewer than 8 bytes remained where a node header had to start.
    TruncatedNodeHeader,

    /// A node declared zero properties. Structurally invalid (spec §4.1): a
    /// well-formed node always carries at least its `name` property.
    ZeroPropertyCount,

    /// `property_count` × 36 plus the node header does not fit in the bytes
    /// remaining after the node's offset.
    PropertyCountExceedsBuffer,

    /// `property_count` is above the policy ceiling
    /// ([`MAX_PROPERTY_COUNT`](crate::MAX_PROPERTY_COUNT)).
    PropertyCountExceedsCeiling,

    /// `child_count` × 8 does not fit in the bytes remaining after the node's
    /// header and its minimum property extent.
    ChildCountExceedsBuffer,

    /// `child_count` is above the policy ceiling
    /// ([`MAX_CHILD_COUNT`](crate::MAX_CHILD_COUNT)).
    ChildCountExceedsCeiling,

    /// Fewer than 36 bytes remained where a property header had to start.
    TruncatedPropertyHeader,

    /// Byte 31 of a property's fixed 32-byte name field is not NUL.
    ///
    /// Checked before any string operation touches the name (spec §9.5).
    PropertyNameNotTerminated,

    /// Bit 31 of a property length word is set: the firmware handed over an
    /// unresolved ADT *template*, not a tree an OS was meant to receive
    /// (spec §5.3). Recorded distinctly from every other failure so that a
    /// future firmware that legitimately ships the bit is diagnosable.
    PlaceholderFlagSet,

    /// The masked value length is above the policy ceiling
    /// ([`MAX_VALUE_LEN`](crate::MAX_VALUE_LEN)), i.e. one of bits 30..20 of
    /// the length word is set. A policy bound, kept distinct from
    /// [`AdtError::PlaceholderFlagSet`] so a log can tell the two apart.
    ValueLengthExceedsCeiling,

    /// A property's value, or the zero padding that follows it, runs past the
    /// end of the blob. The "last property may be unpadded at the very end"
    /// leniency found in third-party parsers is deliberately not implemented.
    TruncatedPropertyValue,

    /// A checked addition, subtraction or multiplication on a value taken from
    /// the blob would have overflowed. Overflow denies; it never wraps and
    /// never saturates.
    OffsetOverflow,

    /// The tree nests deeper than [`MAX_TREE_DEPTH`](crate::MAX_TREE_DEPTH).
    DepthLimitExceeded,

    /// The structural walk visited more nodes than the blob can physically
    /// contain. Unreachable for any input given the monotonic-advance
    /// argument in `walk_node_end`; retained as a hard termination guarantee
    /// that is a property of the data structure rather than of an argument.
    WalkBudgetExhausted,

    /// The named property is not present on this node.
    PropertyNotFound,

    /// The node carries two or more properties with the same name. The format
    /// does not forbid it, but "first match" and "last match" readers would
    /// then disagree about the same tree, so it is refused (spec §9.9).
    DuplicateProperty,

    /// No child of the node has the requested name, or a path component did
    /// not resolve.
    NodeNotFound,

    /// A node has no `name` property. Malformed (spec §4.5).
    MissingNameProperty,

    /// A string-typed value contains no NUL within its declared length. The
    /// whole value is never adopted as the string (spec §9.5).
    UnterminatedStringValue,

    /// A node's `name` property has a value longer than 64 bytes — 63 name
    /// characters plus the terminator (spec §9.5). Bounding the *value* is
    /// what stops a crafted tree presenting a huge "node name" to every path
    /// comparison at every level. A policy bound with a distinct reason.
    NodeNameValueTooLong,

    /// A node name decodes to more than the 63 characters Apple's own
    /// declaration allows (spec §4.5). A policy bound with a distinct reason,
    /// kept separate from [`AdtError::NodeNameValueTooLong`] so a log can tell
    /// an over-long value from an over-long string inside a legal value.
    NodeNameTooLong,

    /// A fixed-shape property does not have the exact length its form requires
    /// — a `u32` that is not 4 bytes, a `u64` that is not 8, a
    /// `(base, size)` record that is not 16 (spec §9.9).
    PropertyLengthMismatch,

    /// `#address-cells` is outside `1..=2` (spec §8.5, §9.8).
    InvalidAddressCells,

    /// `#size-cells` is greater than 2 (spec §8.5, §9.8).
    InvalidSizeCells,

    /// `#address-cells` or `#size-cells` is absent where it is required.
    /// There is no default: a wrong default silently produces a wrong
    /// address, which is worse than not booting (spec §9.8).
    MissingCellCounts,

    /// The requested `reg` container index lies beyond the property value.
    RegContainerOutOfRange,

    /// A `ranges` entry stride is zero or exceeds the property value length.
    MalformedRangesEntry,

    /// No `ranges` entry contains the address being translated. The
    /// untranslated address is never passed through (spec §9.8).
    NoMatchingRangesEntry,

    /// Address translation arithmetic would underflow or overflow.
    TranslationOverflow,

    /// A path is not absolute, contains an empty component, or has a trailing
    /// separator.
    MalformedPath,

    /// A path names more components than [`MAX_TREE_DEPTH`](crate::MAX_TREE_DEPTH)
    /// permits.
    PathTooDeep,

    /// Translation reached a node with a `ranges` property but no parent to
    /// translate into — the root cannot have `ranges`.
    MissingParentNode,
}
