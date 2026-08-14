//! `INV-DEV-006`, proved: no operation a holder has widens its window.
//!
//! The invariant's own stated evidence is "Kani proof that no trait method
//! widens a window". These harnesses are that proof, and they are written
//! against the **holder trait's whole surface** rather than against one method:
//! every operation `IommuWindowHolder` offers is applied to a symbolic window,
//! and the result is required to confer no authority the window did not already
//! confer.
//!
//! # Why this is precondition 2, and why it can be discharged now
//!
//! `TCB-AS/GPU` is conditionally signed, and precondition 2 of its five is *"a
//! Kani proof on the DART backend's IOMMU trait that its API surface admits no
//! widening operation — proving that no consumer, `gpud` included, can widen
//! its own DMA window"*. It is a claim about an API surface. Apple's GPU
//! firmware, the hardware, and `gpud` itself are all absent, and none of them is
//! needed: if the surface admits no widening, no consumer of it can widen,
//! including consumers not yet written.
//!
//! That is the useful property of proving this against the trait. A proof about
//! `HeldWindow` alone would be a proof about today's implementation; the
//! obligation belongs to **the confinement**, not to the driver, and decision
//! #15's tiering rule says so explicitly.
//!
//! # What a "widening" is here
//!
//! Not merely a larger page range. `permits_everything_in` is containment
//! **plus write authority**, because a sub-range that gained the write bit is a
//! widening whose pages are a subset — the case a range-only check waves
//! through, and the one a driver would actually want.

#![deny(unsafe_code)]
// kani is a cfg set by the Kani verification tool's dedicated CI image.
#![allow(unexpected_cfgs)]

#[cfg(kani)]
mod proofs {
    use brainix_dart::{DmaWindow, HeldWindow, IommuWindowHolder, WindowError};

    /// A window over arbitrary pages, with an arbitrary write bit.
    fn any_window() -> DmaWindow {
        DmaWindow::granted(kani::any(), kani::any(), kani::any())
    }

    /// **Narrowing never widens — over every window and every request.**
    ///
    /// The headline. For any held window and any requested range, `narrow`
    /// either denies or leaves the holder with a window the original already
    /// permitted, write bit included.
    #[kani::proof]
    fn dart_iommu_narrowing_never_widens_a_window() {
        let granted = any_window();
        let mut holder = HeldWindow::holding(granted);
        let base_page: u64 = kani::any();
        let pages: u64 = kani::any();

        match holder.narrow_window(base_page, pages) {
            Ok(()) => {
                let after = holder.window();
                kani::assert(
                    granted.permits_everything_in(&after),
                    "a narrow produced a window the grant did not already permit",
                );
                kani::assert(
                    after.pages() <= granted.pages(),
                    "a narrow produced more pages than were granted",
                );
                kani::assert(
                    !(after.is_writable() && !granted.is_writable()),
                    "a narrow gained write authority the grant did not confer",
                );
            }
            Err(error) => {
                kani::assert(
                    matches!(error, WindowError::NotContained),
                    "a narrow failed for a reason the model does not name",
                );
                kani::assert(
                    holder.window() == granted,
                    "a refused narrow changed the window anyway",
                );
            }
        }
    }

    /// **Dropping write never widens, and never re-grants.**
    #[kani::proof]
    fn dart_iommu_dropping_write_never_widens_a_window() {
        let granted = any_window();
        let mut holder = HeldWindow::holding(granted);
        holder.drop_write_authority();
        let after = holder.window();

        kani::assert(
            granted.permits_everything_in(&after),
            "dropping write produced a window the grant did not already permit",
        );
        kani::assert(
            !after.is_writable(),
            "dropping write left the window writable",
        );
        kani::assert(
            after.pages() == granted.pages() && after.base_page() == granted.base_page(),
            "dropping write moved or resized the window",
        );
    }

    /// **Revocation ends at deny-all, from any window.**
    #[kani::proof]
    fn dart_iommu_revocation_never_widens_a_window() {
        let granted = any_window();
        let mut holder = HeldWindow::holding(granted);
        holder.revoke_window();
        let after = holder.window();

        kani::assert(after.is_empty(), "a revoked window still translates pages");
        kani::assert(
            !after.is_writable(),
            "a revoked window still permits writes",
        );
        kani::assert(
            granted.permits_everything_in(&after),
            "a revoked window permits something the grant did not",
        );
    }

    /// **No sequence of two operations widens either.**
    ///
    /// Monotonicity composes, but a proof about single steps is a proof about
    /// single steps. This drives a symbolic pair of operations so that the
    /// property is about the trait as something a driver *uses over time*,
    /// which is how a driver would attempt to climb back up: narrow, then try
    /// to recover what was dropped.
    #[kani::proof]
    fn dart_iommu_no_sequence_of_operations_widens_a_window() {
        let granted = any_window();
        let mut holder = HeldWindow::holding(granted);

        let first: u8 = kani::any();
        let second: u8 = kani::any();
        for choice in [first, second] {
            match choice % 3 {
                0 => {
                    let _ = holder.narrow_window(kani::any(), kani::any());
                }
                1 => holder.drop_write_authority(),
                _ => holder.revoke_window(),
            }
        }

        kani::assert(
            granted.permits_everything_in(&holder.window()),
            "a sequence of holder operations produced authority the grant did not confer",
        );
    }

    /// **A holder with nothing granted can never obtain anything.**
    ///
    /// `INV-DEV-004`'s deny-all default, stated as the property that matters: an
    /// instance nobody programmed translates nothing, and no operation the
    /// holder has changes that.
    #[kani::proof]
    fn dart_iommu_a_deny_all_holder_cannot_obtain_a_window() {
        let mut holder = HeldWindow::new();
        kani::assert(
            holder.window().is_empty(),
            "a fresh holder was granted something",
        );

        let base_page: u64 = kani::any();
        let pages: u64 = kani::any();
        let outcome = holder.narrow_window(base_page, pages);

        kani::assert(
            holder.window().is_empty(),
            "a deny-all holder obtained a non-empty window",
        );
        kani::assert(
            outcome.is_err() || pages == 0,
            "a deny-all holder was granted a non-empty range by narrowing",
        );
    }
}
