//! Kani proof harnesses for the Apple Device Tree decoder (`brainix-adt`).
//!
//! The decoder is a **Full tier** component under `SECURITY_INVARIANTS.md` §16
//! because it parses firmware-supplied bytes earlier and with more authority
//! than anything that arrives over a socket (`INV-PARSE-003`). §15's
//! `INV-PARSE-002` requires *both* a fuzz target and a Kani harness: the fuzz
//! target finds what these harnesses did not model, and these harnesses prove
//! what fuzzing cannot exhaust.
//!
//! This crate follows the repository's convention that proofs live in a
//! dedicated verify crate beside the crate they verify, as
//! `src/capability-verify/` does for the kernel's capability subsystem. It adds
//! no code to `brainix-adt` and changes none.
//!
//! # The first bound: length
//!
//! Kani is a **bounded** model checker. It cannot verify a `&[u8]` of unbounded
//! length, so every harness over a blob fixes the blob's length to a constant
//! and proves the property for *every* byte string of exactly that length.
//! The constants are [`SMALL_BLOB_LEN`], [`BOUNDED_BLOB_LEN`] and
//! [`NESTED_BLOB_LEN`], and each is chosen at a structural threshold of the
//! format rather than for round numbers:
//!
//! - **12 bytes** — a root header plus four bytes, below the size at which any
//!   property record can fit. Every input at this length must be refused, so
//!   this harness proves the *reject* path is total, and it is cheap enough
//!   that it completes even on a constrained runner.
//! - **48 bytes** — the smallest length at which a **well-formed** tree exists:
//!   an 8-byte node header, one 36-byte property header, and a 4-byte value.
//!   Both the accept and the reject path are reachable, so the no-panic proof
//!   at this length is not vacuously about rejection.
//! - **96 bytes** — the smallest length at which a **nested** tree exists: two
//!   48-byte nodes, a parent and one child. This is the length at which the
//!   child iterator, the depth counter, and path resolution become reachable,
//!   so the traversal-termination proof is stated here rather than at 48.
//!
//! **What remains unproven above the bound.** Nothing here says anything about
//! a 4 KiB or 1 MiB blob. Two behaviours in particular are bounded away and are
//! named rather than implied:
//!
//! - the **depth limit** (`MAX_TREE_DEPTH` = 8) cannot be reached at 96 bytes —
//!   a chain of 8 nested nodes needs at least 8 × 44 bytes — so
//!   `DepthLimitExceeded` is exercised by the test suite and the fuzz corpus,
//!   not by these proofs;
//! - the **policy ceilings** (2048 properties, 2048 children, 1 MiB − 1 value
//!   length) are unreachable at these lengths because the minimum-space test
//!   denies first, which is exactly the ordering the specification requires but
//!   which also means the ceiling branches themselves are unproven here.
//!
//! Two harnesses are **not** bounded and hold for every input:
//! [`proofs::adt_ranges_translation_arithmetic_never_wraps`] quantifies over
//! all six `u64` fields of a translation, and
//! [`proofs::adt_cell_counts_enforce_the_specification_bounds`] over both
//! `u32` cell counts.
//!
//! # The second bound: shape, and why it exists
//!
//! Three harnesses take a blob whose **structure** is concrete and whose
//! **content** is symbolic: the node headers, the 32-byte property name fields
//! and the property length words are written by the harness, while the
//! property values stay arbitrary. They are
//! [`proofs::adt_every_read_stays_within_the_supplied_buffer`],
//! `proofs::adt_traversal_terminates_on_all_inputs` and
//! `proofs::adt_path_resolution_never_panics_on_an_arbitrary_path`.
//!
//! **This bound is not a preference; it is what makes them finish.** Solver
//! cost here rises steeply with the unwind bound, and the longest loop in the
//! decoder is the scan for the NUL inside a property's fixed 32-byte name
//! field, which needs 33 iterations. A harness that reaches a name over a
//! fully symbolic blob therefore needs `unwind(34)`, and at that bound none of
//! these three completed: measured on this repository, the 12-byte reject-only
//! harness alone took 338s at `unwind(34)` against 6s at `unwind(3)`, and the
//! path-resolution harness ran for 27 minutes in CI without finishing, until
//! the runner was reclaimed. Proofs that never terminate are not a gate; they
//! are a job that always fails.
//!
//! Fixing the structure makes those scans short, so these harnesses run at
//! `unwind(6)` to `unwind(10)` and complete in seconds to a couple of minutes.
//!
//! **What the shape gives up, and what still covers it.** The header fields and
//! name-field bytes are not quantified over in those three. They *are*
//! quantified over in
//! [`proofs::adt_parse_never_panics_on_any_twelve_byte_input`] and
//! [`proofs::adt_parse_never_panics_on_any_forty_eight_byte_input`], which
//! stay fully symbolic — every count, every name byte, every length word — and
//! which are the harnesses that carry the headline "does not panic on hostile
//! input" property. The split is: *parse* is proved against arbitrary bytes;
//! the *accessors and the walk* are proved against arbitrary content in a
//! fixed shape. Neither statement is the other, and neither is stated more
//! broadly than it holds.
//!
//! # The third bound: cost, and what is not run in CI
//!
//! Two harnesses are behind the **`long-proofs`** feature and do not run on a
//! pull request: `adt_traversal_terminates_on_all_inputs` and
//! `adt_path_resolution_never_panics_on_an_arbitrary_path`. Both are the ones
//! that parse the 96-byte nested blob.
//!
//! **They are excluded because they have never been observed to terminate.**
//! Measured on an M2 Pro, with the shape above and a four-slot traversal stack:
//! parsing the nested blob *alone*, with no walk and no accessor call, takes
//! 264s; each of the two harnesses was killed at 12.5 minutes with no verdict,
//! at unwind bounds of 6 and 10, and again with the symbolic content reduced to
//! a single byte per node. Kani's cost here is dominated by symbolic execution
//! over a 96-byte buffer, and lowering the unwind bound does not reach it.
//!
//! What that costs, stated plainly: **the child iterator, the depth counter and
//! path resolution have no proof running in CI.** They have tests and a fuzz
//! target, and they are the reason `NESTED_BLOB_LEN` exists, but the gate on
//! every pull request is the five harnesses that finish. A proof that does not
//! terminate is not a gate; leaving it in the job only converts every run into
//! a timeout, which is what it did before this feature existed (CI run
//! 31721650927 spent 27 minutes inside the path harness and never reached the
//! BSP, transport-crypto or IPC proofs at all).
//!
//! They are kept in the tree, not deleted, because they state the property that
//! is wanted, and because the cost may not be permanent — a tighter shape, a
//! different solver, or a Kani release with better symex could bring them into
//! reach. Run them deliberately, with a budget, and expect to wait:
//!
//! ```text
//! cargo kani -p brainix-adt-verify --features long-proofs \
//!     --harness adt_traversal_terminates_on_all_inputs
//! ```

#![deny(unsafe_code)]
// kani is a cfg set by the Kani verification tool's dedicated CI image.
// On the host target it is not defined; this allow suppresses the warning.
#![allow(unexpected_cfgs)]

/// Blob length at which no property record can fit: proves the reject path.
pub const SMALL_BLOB_LEN: usize = 12;

/// Blob length of the smallest well-formed tree: header + one property.
pub const BOUNDED_BLOB_LEN: usize = 48;

/// Blob length of the smallest nested tree: a parent and one child.
pub const NESTED_BLOB_LEN: usize = 96;

#[cfg(all(kani, feature = "deny-allocation"))]
mod allocation {
    //! A global allocator that denies every request.
    //!
    //! `brainix-adt` is `#![no_std]`, has no dependencies, and never names
    //! `alloc`. That is an argument; this makes it a checked property. Under
    //! Kani the whole harness runs against this allocator, so if any path in
    //! the decoder reached a heap allocation the assertion below would be
    //! reachable and Kani would report it. The proof is that it is not.
    //!
    //! **Why this is behind a feature.** A global allocator is global: were
    //! Kani's own harness scaffolding ever to allocate, this assertion would
    //! fail in *every* harness in the crate and the failure would say nothing
    //! about the decoder. Gating it means the `deny-allocation` feature is the
    //! only configuration in which that can happen, and it enables exactly one
    //! harness. The other seven are unaffected by it.
    //!
    //! `GlobalAlloc` is an unsafe trait, so this is the one place the crate
    //! relaxes its `deny(unsafe_code)`. The relaxation is scoped to this
    //! module, the module exists only under `cfg(kani)`, and neither function
    //! dereferences anything.

    use core::alloc::{GlobalAlloc, Layout};

    /// Denies every allocation and deallocation.
    pub struct DenyAllocator;

    #[allow(unsafe_code)]
    unsafe impl GlobalAlloc for DenyAllocator {
        unsafe fn alloc(&self, _layout: Layout) -> *mut u8 {
            kani::assert(false, "the ADT decoder must never allocate");
            core::ptr::null_mut()
        }

        unsafe fn dealloc(&self, _pointer: *mut u8, _layout: Layout) {
            kani::assert(false, "the ADT decoder must never deallocate");
        }
    }

    #[global_allocator]
    static DENY_ALLOCATOR: DenyAllocator = DenyAllocator;
}

#[cfg(kani)]
mod proofs {
    use brainix_adt::{AddressRange, CellCounts, DeviceTree, Node, RangesEntry};
    #[cfg(feature = "long-proofs")]
    use brainix_adt::{MAX_PATH_NODES, MAX_TREE_DEPTH};

    #[cfg(feature = "long-proofs")]
    use crate::NESTED_BLOB_LEN;
    use crate::{BOUNDED_BLOB_LEN, SMALL_BLOB_LEN};

    // Every harness carries an explicit `#[kani::unwind(N)]`. The attribute
    // takes an integer literal, so the numbers cannot be given names; they are
    // explained once here.
    //
    // Each N is the smallest value at which the harness verifies, and it is
    // chosen by measurement rather than by argument, because solver cost rises
    // steeply with it -- the 12-byte harness takes 6s at 3 and 338s at 34. Too
    // small is not a silent unsoundness: Kani reports an unwinding-assertion
    // failure for a loop that could run past the bound, which is how each of
    // these numbers was found.
    //
    // **3** covers the two fully symbolic parse harnesses. Neither reaches a
    // property name, so the longest loop either runs is the property walk,
    // which the minimum-space test caps at one record at these lengths.
    //
    // **6, 8 and 10** cover the three shaped harnesses -- see the crate
    // documentation's *The second bound*. The scan for the NUL in a 32-byte
    // name field would need 33, which is exactly why those harnesses write the
    // name field rather than leaving it symbolic; what remains is the walk
    // (2 nodes), the value scan (4 bytes) and the path walk (4 components).

    /// Capacity of the harness's own traversal stack.
    ///
    /// Four, not sixteen: the shaped nested blob the traversal harness walks
    /// holds exactly two nodes, so four is the tree's size with margin, and the
    /// stack is symbolically indexed inside an unrolled loop — every unused
    /// slot is paid for on every path.
    #[cfg(feature = "long-proofs")]
    const TRAVERSAL_STACK_LEN: usize = 4;

    /// Whether `part` is a sub-slice of `blob`.
    ///
    /// The decoder never copies: every name and value it returns must borrow
    /// the caller's buffer. Comparing addresses is how that is checked without
    /// trusting the decoder's own arithmetic.
    fn is_inside(blob: &[u8], part: &[u8]) -> bool {
        let base = blob.as_ptr() as usize;
        let start = part.as_ptr() as usize;
        match start
            .checked_sub(base)
            .and_then(|at| at.checked_add(part.len()))
        {
            Some(end) => end <= blob.len(),
            None => false,
        }
    }

    /// Reads every property of `node` through every accessor, asserting that
    /// each borrowed slice lies inside `blob`.
    fn read_every_property(blob: &[u8], node: Node<'_>) {
        let iterator = match node.properties() {
            Ok(iterator) => iterator,
            Err(_) => return,
        };
        for item in iterator {
            let property = match item {
                Ok(property) => property,
                Err(_) => return,
            };
            kani::assert(
                is_inside(blob, property.name_field()),
                "a property name field escaped the supplied buffer",
            );
            kani::assert(
                is_inside(blob, property.name()),
                "a property name escaped the supplied buffer",
            );
            kani::assert(
                is_inside(blob, property.value()),
                "a property value escaped the supplied buffer",
            );
            let _ = property.as_u32();
            let _ = property.as_u64();
            let _ = property.as_address_size();
            if let Ok(text) = property.as_c_str() {
                kani::assert(
                    is_inside(blob, text),
                    "a decoded C string escaped the supplied buffer",
                );
            }
        }
    }

    /// **No panic on any input, at 12 bytes.**
    ///
    /// Twelve bytes cannot hold a node header and a property record, so every
    /// input at this length is refused. The proof is that the refusal is total:
    /// `parse` returns an `AdtError` for all 2^96 inputs and never panics,
    /// never reads out of bounds, and never overflows.
    ///
    /// The cheap tier. It completes where the wider harnesses may not.
    #[kani::proof]
    #[kani::unwind(3)]
    fn adt_parse_never_panics_on_any_twelve_byte_input() {
        let blob: [u8; SMALL_BLOB_LEN] = kani::any();
        let outcome = DeviceTree::parse(&blob);
        kani::assert(
            outcome.is_err(),
            "no twelve-byte blob can encode a well-formed tree",
        );
    }

    /// **No panic on any input, at 48 bytes. The headline property.**
    ///
    /// Forty-eight bytes is the smallest length at which a well-formed tree
    /// exists, so both the accept and the reject path are reachable and the
    /// proof is not vacuously about rejection. For every one of the 2^384
    /// inputs of this length, `parse` either returns a `DeviceTree` or returns
    /// an `AdtError` — it does not panic, does not index out of bounds, and
    /// does not wrap an arithmetic operation.
    ///
    /// Kani checks the panic, bounds and overflow properties by default; the
    /// explicit assertion adds the decoder's own contract, that a tree never
    /// claims more bytes than the buffer holds.
    #[kani::proof]
    #[kani::unwind(3)]
    fn adt_parse_never_panics_on_any_forty_eight_byte_input() {
        let blob: [u8; BOUNDED_BLOB_LEN] = kani::any();
        if let Ok(tree) = DeviceTree::parse(&blob) {
            kani::assert(
                tree.tree_len() <= blob.len(),
                "the tree claimed more bytes than the buffer holds",
            );
            kani::assert(
                tree.blob().len() == blob.len(),
                "the tree does not borrow the supplied buffer",
            );
        }
    }

    /// **Every read stays within the supplied buffer.**
    ///
    /// On a hardware platform with no console this is the property that matters
    /// most after "does not panic": an over-read in the boot stub is silent.
    /// The harness parses an arbitrary 48-byte blob and, on success, reads every
    /// property of the root through every accessor, asserting that every slice
    /// handed back — name field, name, value, decoded C string — lies wholly
    /// inside the input, and that the node's extent never runs past it.
    ///
    /// Kani's own out-of-bounds check covers reads the decoder performs
    /// internally; these assertions cover the slices it *returns*, which the
    /// caller will read later and which no internal check constrains.
    ///
    /// **Shaped, not arbitrary** — see the crate documentation's *The second
    /// bound* for why, and for what the fully arbitrary harnesses above still
    /// cover. The node header and the property's name field are concrete; the
    /// length word and the value are symbolic, so every accessor here runs on
    /// content it cannot predict.
    #[kani::proof]
    #[kani::unwind(6)]
    fn adt_every_read_stays_within_the_supplied_buffer() {
        let blob = shaped_blob();
        let tree = match DeviceTree::parse(&blob) {
            Ok(tree) => tree,
            Err(_) => return,
        };
        kani::assert(
            tree.tree_len() <= blob.len(),
            "the tree extent ran past the supplied buffer",
        );
        let root = tree.root();
        kani::assert(
            root.offset() < blob.len(),
            "the root offset is not a read offset",
        );
        if let Ok(end) = root.extent_end() {
            kani::assert(
                end <= blob.len(),
                "a node extent ran past the supplied buffer",
            );
        }
        if let Ok(name) = root.name() {
            kani::assert(
                is_inside(&blob, name),
                "a node name escaped the supplied buffer",
            );
        }
        read_every_property(&blob, root);
    }

    /// Writes one node at `at`: a concrete header declaring one property and
    /// `child_count` children, a concrete `name` name-field, a concrete length
    /// word of 4, and a **symbolic** four-byte value. Returns the offset just
    /// past it.
    ///
    /// Forty-eight bytes: 8 header + 32 name field + 4 length word + 4 value.
    /// Everything but the value is structure, and structure is what the shaped
    /// harnesses hold fixed — see the crate documentation's *The second bound*.
    fn write_shaped_node(blob: &mut [u8], at: usize, child_count: u8) -> usize {
        let put = |blob: &mut [u8], offset: usize, byte: u8| {
            if let Some(slot) = blob.get_mut(at.saturating_add(offset)) {
                *slot = byte;
            }
        };
        put(blob, 0, 1);
        put(blob, 4, child_count);
        put(blob, 8, b'n');
        put(blob, 9, b'a');
        put(blob, 10, b'm');
        put(blob, 11, b'e');
        put(blob, 40, 4);
        let value: [u8; 4] = kani::any();
        put(blob, 44, value[0]);
        put(blob, 45, value[1]);
        put(blob, 46, value[2]);
        put(blob, 47, value[3]);
        at.saturating_add(SHAPED_NODE_LEN)
    }

    /// Bytes one shaped node occupies: 8 header + 32 name field + 4 length
    /// word + 4 value.
    const SHAPED_NODE_LEN: usize = 48;

    /// The smallest well-formed tree: one node, one `name` property, no
    /// children. Structure concrete, record content symbolic.
    fn shaped_blob() -> [u8; BOUNDED_BLOB_LEN] {
        let mut blob = [0u8; BOUNDED_BLOB_LEN];
        let _ = write_shaped_node(&mut blob, 0, 0);
        blob
    }

    /// The smallest nested tree: a parent with one child, each shaped as
    /// [`write_shaped_node`] writes them.
    #[cfg(feature = "long-proofs")]
    fn shaped_nested_blob() -> [u8; NESTED_BLOB_LEN] {
        let mut blob = [0u8; NESTED_BLOB_LEN];
        let child = write_shaped_node(&mut blob, 0, 1);
        let _ = write_shaped_node(&mut blob, child, 0);
        blob
    }

    /// **No allocation.**
    ///
    /// The harness runs a parse-and-read under the deny-allocator in
    /// [`crate::allocation`]. Any heap allocation on any path it reaches —
    /// including one introduced by a future edit to the decoder — makes that
    /// allocator's assertion reachable, and Kani reports it. The proof is that
    /// it is unreachable.
    ///
    /// This is the machine-checked form of the crate's `#![no_std]`,
    /// zero-dependency claim (`INV-PARSE-001`, `INV-MEM`).
    ///
    /// **It does not call `cell_counts`.** That lookup compares against
    /// `#address-cells`, a fourteen-character name, and a comparison that long
    /// needs `unwind(15)`; at 16 this harness did not finish in ten minutes,
    /// against 92s at 6. The paths it drops are two `u32` property reads that
    /// `read_every_property` below already runs through `as_u32`, so what is
    /// lost is the lookup by a long name rather than any decoding the harness
    /// does not otherwise reach.
    ///
    /// Enabled by the `deny-allocation` feature, which also installs the
    /// allocator. Run it with
    /// `cargo kani -p brainix-adt-verify --features deny-allocation --harness
    /// adt_decoder_performs_no_allocation`.
    #[cfg(feature = "deny-allocation")]
    #[kani::proof]
    #[kani::unwind(6)]
    fn adt_decoder_performs_no_allocation() {
        let blob = shaped_blob();
        let tree = match DeviceTree::parse(&blob) {
            Ok(tree) => tree,
            Err(_) => return,
        };
        let root = tree.root();
        let _ = root.name();
        let _ = root.find_property(b"reg");
        read_every_property(&blob, root);
    }

    /// **Traversal terminates on all inputs, including nested ones.**
    ///
    /// Ninety-six bytes is the smallest length at which a parent and a child
    /// both fit, so the child iterator and the depth counter are reachable
    /// here and are not at 48. The harness walks the whole tree over a
    /// fixed-size stack, counting visits, and asserts the count never exceeds
    /// the structural bound `blob.len() / 8 + 1` — the same bound the decoder's
    /// own walk budget uses, restated as a property of the traversal rather
    /// than of the decoder's internals.
    ///
    /// Termination itself is proved by the unwinding assertions: a loop that
    /// could run past the harness's unwind bound would be reported as an
    /// unwinding failure, not silently accepted.
    ///
    /// **Shaped, not arbitrary** — the two node headers, both name fields and
    /// both length words are concrete; only the property values are symbolic.
    /// See the crate documentation's *The second bound*.
    ///
    /// The walk deliberately does **not** read properties. Three nested loops
    /// -- the walk, the child iterator and a property scan -- unroll
    /// multiplicatively, and at `unwind(8)` that did not finish in ten minutes.
    /// What a property read would add here is covered by
    /// [`adt_every_read_stays_within_the_supplied_buffer`], which does nothing
    /// else; this harness is about the shape of the walk.
    ///
    /// **Behind `long-proofs`, and not in CI** — see the crate documentation's
    /// *The third bound: cost*.
    #[cfg(feature = "long-proofs")]
    #[kani::proof]
    #[kani::unwind(3)]
    fn adt_traversal_terminates_on_all_inputs() {
        let blob = shaped_nested_blob();
        let tree = match DeviceTree::parse(&blob) {
            Ok(tree) => tree,
            Err(_) => return,
        };
        let budget = blob.len().checked_div(8).unwrap_or(0).saturating_add(1);

        let mut stack: [Node<'_>; TRAVERSAL_STACK_LEN] = [tree.root(); TRAVERSAL_STACK_LEN];
        let mut pending: usize = 1;
        let mut visited: usize = 0;

        while pending > 0 {
            pending = pending.saturating_sub(1);
            let node = match stack.get(pending) {
                Some(node) => *node,
                None => return,
            };
            visited = visited.saturating_add(1);
            kani::assert(
                visited <= budget,
                "traversal visited more nodes than the blob can encode",
            );
            kani::assert(
                node.depth() <= MAX_TREE_DEPTH,
                "a node reported a depth past the limit",
            );

            let children = match node.children() {
                Ok(children) => children,
                Err(_) => continue,
            };
            for item in children {
                let child = match item {
                    Ok(child) => child,
                    Err(_) => break,
                };
                let slot = match stack.get_mut(pending) {
                    Some(slot) => slot,
                    None => break,
                };
                *slot = child;
                pending = pending.saturating_add(1);
                if pending >= TRAVERSAL_STACK_LEN {
                    break;
                }
            }
        }
    }

    /// **Path resolution never panics on an arbitrary path.**
    ///
    /// The **path** is arbitrary: all 2^32 four-byte strings, so every
    /// separator arrangement is covered, including the leading, trailing,
    /// empty-component and all-separator cases the format rejects. The tree it
    /// resolves against is the shaped nested blob — a parent and one child, so
    /// that a *successful* resolution is reachable and the harness is not
    /// vacuously about rejection, with both node names symbolic so a match is
    /// decided on content the harness did not choose.
    ///
    /// **Four bytes, not eight**, because four is the width at which success is
    /// reachable: a child's name is the NUL-terminated prefix of its `name`
    /// property's four-byte value, so it is at most three characters, and
    /// `/abc` is the longest path that can match one. An eight-byte path over
    /// this tree could only ever be refused, which would make every assertion
    /// below unreachable and the harness a statement about rejection alone.
    ///
    /// On success the resolved chain is asserted to respect the fixed capacity
    /// that makes `NodePath` allocation-free.
    ///
    /// `node_exists` is not called separately: it is `resolve` plus a match on
    /// the error, so calling it would double the cost of this harness and prove
    /// nothing `resolve` does not.
    ///
    /// **Behind `long-proofs`, and not in CI** — see the crate documentation's
    /// *The third bound: cost*.
    #[cfg(feature = "long-proofs")]
    #[kani::proof]
    #[kani::unwind(10)]
    fn adt_path_resolution_never_panics_on_an_arbitrary_path() {
        let blob = shaped_nested_blob();
        let tree = match DeviceTree::parse(&blob) {
            Ok(tree) => tree,
            Err(_) => return,
        };
        let path: [u8; 4] = kani::any();
        if let Ok(chain) = tree.resolve(&path) {
            // Vacuity guard: an unsatisfiable cover is reported as a failure,
            // so this is the "success is reachable" claim above made
            // machine-checked rather than argued. A chain longer than the root
            // alone means the walk really did match the child's name.
            kani::cover!(
                chain.len() > 1,
                "no four-byte path reaches the child, so the assertions below never run"
            );
            kani::assert(chain.len() >= 1, "a resolved path holds no nodes");
            kani::assert(
                chain.len() <= MAX_PATH_NODES,
                "a resolved path exceeded the fixed NodePath capacity",
            );
            let _ = chain.parent();
            let _ = chain.reg(0);
            let _ = chain.translated_reg(0);
        }
    }

    /// **Address translation never wraps — unbounded.**
    ///
    /// Not bounded by a blob length: this quantifies over all six `u64` fields
    /// of a `ranges` entry and the range being translated, i.e. every input the
    /// function can ever receive. It proves that when translation succeeds,
    /// containment genuinely held and the substitution
    /// `address − child_address + parent_address` was computed without
    /// underflow or overflow — the arithmetic spec §9.8 requires to deny rather
    /// than wrap into an apparent match.
    #[kani::proof]
    fn adt_ranges_translation_arithmetic_never_wraps() {
        let entry = RangesEntry {
            child_address: kani::any(),
            parent_address: kani::any(),
            child_size: kani::any(),
        };
        let range = AddressRange {
            address: kani::any(),
            size: kani::any(),
        };
        if let Ok(Some(translated)) = entry.translate(range) {
            kani::assert(
                range.address >= entry.child_address,
                "translation succeeded below the window base",
            );
            kani::assert(
                range.address.checked_add(range.size).is_some(),
                "translation succeeded on a request whose end overflows",
            );
            kani::assert(
                entry.child_address.checked_add(entry.child_size).is_some(),
                "translation succeeded through a window whose end overflows",
            );
            let expected = range
                .address
                .checked_sub(entry.child_address)
                .and_then(|offset| offset.checked_add(entry.parent_address));
            kani::assert(
                expected == Some(translated),
                "the translated address is not the unwrapped substitution",
            );
        }
    }

    /// **Cell counts are validated exactly as the specification states —
    /// unbounded.**
    ///
    /// Quantifies over both `u32` cell counts. Proves that construction
    /// succeeds only for `#address-cells` in `1..=2` and `#size-cells` in
    /// `0..=2` (spec §8.5, §9.8), that the accepted pair's container length is
    /// between 4 and 16 bytes, and that every other pair denies. A wrong cell
    /// count silently produces a wrong address, so the bound is the check.
    #[kani::proof]
    fn adt_cell_counts_enforce_the_specification_bounds() {
        let address_cells: u32 = kani::any();
        let size_cells: u32 = kani::any();
        match CellCounts::new(address_cells, size_cells) {
            Ok(cells) => {
                kani::assert(
                    address_cells >= 1 && address_cells <= 2,
                    "an out-of-range #address-cells was accepted",
                );
                kani::assert(size_cells <= 2, "an out-of-range #size-cells was accepted");
                match cells.container_len() {
                    Ok(length) => kani::assert(
                        length >= 4 && length <= 16,
                        "a reg container length outside 4..=16 was produced",
                    ),
                    Err(_) => kani::assert(false, "a validated pair has no container length"),
                }
            }
            Err(_) => kani::assert(
                address_cells == 0 || address_cells > 2 || size_cells > 2,
                "an in-range cell-count pair was refused",
            ),
        }
    }
}
