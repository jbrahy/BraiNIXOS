//! The serving path's fixed reserved regions: weights and KV cache (P3-T2).
//!
//! `MEMORY_MODEL.md` §13 and the north star agree on the shape: **"give all
//! resources to the LLM" is satisfied by large fixed reserved regions, never by
//! adding an allocator.** The no-dynamic-kernel-heap rule is not relaxed for the
//! inference engine; it is the reason the inference engine gets regions instead
//! of a heap.
//!
//! # Everything here is counted in pages
//!
//! Not bytes. `INV-MEM-009` makes a page-size assumption in memory code a
//! defect, and the base page is 4 KiB on the frozen x86-64 reference and 16 KiB
//! on the only real platform. A region declared as "4 GiB" means two different
//! numbers of pages on those two machines and therefore two different layouts;
//! a region declared as 2^20 pages means the same *structure* on both, and its
//! byte size follows from the architecture rather than from a literal someone
//! typed while looking at one machine.
//!
//! The consequence is deliberate and worth stating rather than discovering: the
//! same page counts reserve **four times as many bytes** on Apple Silicon as on
//! the x86-64 reference. That is the correct direction — the reference is a
//! build check, and the platform is the machine with 32 GB of unified memory.
//!
//! # What this module is, and what P3-T2 still owes
//!
//! This is the **layout**: where the regions are, how big they are, how they are
//! partitioned, and the proof that nothing overlaps anything. It deliberately
//! maps nothing. Populating `WEIGHTS_REGION` is `modeld`'s (P3-T3a), sealing it
//! read-only is the page table's, and zeroizing a KV partition on teardown is
//! the session's (`INV-SERVE-004`). None of those exist yet, and a layout that
//! claims them would be claiming work nothing performs.

use crate::memory::virtual_address_layout::{
    DIRECT_MAP_REGION_END, DIRECT_MAP_REGION_START, KERNEL_STACK_REGION_END,
    KERNEL_STACK_REGION_START, PAGE_SIZE_IN_BYTES, POOL_REGION_END, POOL_REGION_START,
};

/// Start of `WEIGHTS_REGION`, the model's read-only home.
pub const WEIGHTS_REGION_START: u64 = 0xFFFF_9000_0000_0000;

/// Pages reserved for the served model's weights.
///
/// 2^20 pages: 4 GiB on the x86-64 reference, **16 GiB on Apple Silicon**,
/// against 32 GB of unified memory. Sized at build time from the model the
/// image is built to serve (§13), and a build for a larger model changes this
/// constant rather than growing anything at runtime.
pub const WEIGHTS_REGION_PAGES: usize = 1 << 20;

/// Start of `KV_REGION`, partitioned per session.
pub const KV_REGION_START: u64 = 0xFFFF_9800_0000_0000;

/// Pages reserved for one session's KV cache.
///
/// 2^14 pages: 64 MiB on the reference, 256 MiB on Apple Silicon.
pub const KV_PARTITION_PAGES: usize = 1 << 14;

/// How many sessions the KV region can hold at once.
///
/// **Eight, because `MAX_SESSIONS` is eight** (BSP v2 §9.1). This is an
/// unchecked duplicate of `brainix_bsp::MAX_SESSIONS` and is written down as
/// one: the kernel does not depend on the serving-protocol crate, and adding
/// that dependency to make one integer agree would be a worse trade than
/// recording the coupling. **P3-T7 closes it**, when `inferd` is wired and one
/// crate can see both. A partition count below `MAX_SESSIONS` would mean
/// admission hands out sessions that have nowhere to put their cache.
pub const KV_PARTITION_COUNT: usize = 8;

/// A reserved region: a base address and a length in pages.
///
/// Deliberately not a base and a byte length. The whole point of this module is
/// that a length in bytes is a page-size assumption in disguise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    /// First address in the region.
    pub start: u64,
    /// Length in architecture base pages.
    pub pages: usize,
}

impl Region {
    /// The region's length in bytes on *this* architecture.
    ///
    /// # Errors
    ///
    /// `None` if the length does not fit in a `u64`, which no constant here
    /// approaches — the check is here so that a future page count cannot
    /// silently wrap into a small region that overlaps its neighbour.
    #[must_use]
    pub const fn length_in_bytes(&self) -> Option<u64> {
        (self.pages as u64).checked_mul(PAGE_SIZE_IN_BYTES as u64)
    }

    /// The first address past the region.
    ///
    /// # Errors
    ///
    /// `None` on overflow, by the same argument as [`Self::length_in_bytes`].
    #[must_use]
    pub const fn end_exclusive(&self) -> Option<u64> {
        match self.length_in_bytes() {
            Some(length) => self.start.checked_add(length),
            None => None,
        }
    }

    /// Whether this region shares any address with `other`.
    ///
    /// A region whose extent does not compute is treated as overlapping
    /// everything: fail closed. An unrepresentable region is not a region that
    /// safely misses its neighbours, it is one nothing can reason about.
    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        let (Some(self_end), Some(other_end)) = (self.end_exclusive(), other.end_exclusive())
        else {
            return true;
        };
        self.start < other_end && other.start < self_end
    }
}

/// The weights region.
#[must_use]
pub const fn weights_region() -> Region {
    Region {
        start: WEIGHTS_REGION_START,
        pages: WEIGHTS_REGION_PAGES,
    }
}

/// The whole KV region, every partition end to end.
#[must_use]
pub const fn kv_region() -> Region {
    Region {
        start: KV_REGION_START,
        pages: KV_PARTITION_PAGES.saturating_mul(KV_PARTITION_COUNT),
    }
}

/// The KV partition belonging to session slot `index`.
///
/// Partitions are disjoint **by construction** — the address is computed from
/// the index, so there is no bookkeeping that could hand two sessions the same
/// slice (`INV-SERVE-001`). Nothing here grants access to one; that is the
/// session's capability, and this function is only arithmetic.
///
/// # Errors
///
/// `None` for an index past [`KV_PARTITION_COUNT`], and `None` if the partition
/// address does not compute. Both deny rather than clamp: a clamped index would
/// hand a session the *last* partition, which is another session's.
#[must_use]
pub const fn kv_partition(index: usize) -> Option<Region> {
    if index >= KV_PARTITION_COUNT {
        return None;
    }
    let Some(offset_pages) = KV_PARTITION_PAGES.checked_mul(index) else {
        return None;
    };
    let Some(offset_bytes) = (offset_pages as u64).checked_mul(PAGE_SIZE_IN_BYTES as u64) else {
        return None;
    };
    let Some(start) = KV_REGION_START.checked_add(offset_bytes) else {
        return None;
    };
    Some(Region {
        start,
        pages: KV_PARTITION_PAGES,
    })
}

/// Every region the kernel has already committed to, for the overlap check.
const fn established_regions() -> [Region; 3] {
    [
        span(KERNEL_STACK_REGION_START, KERNEL_STACK_REGION_END),
        span(POOL_REGION_START, POOL_REGION_END),
        span(DIRECT_MAP_REGION_START, DIRECT_MAP_REGION_END),
    ]
}

/// A region from an inclusive start/end pair, rounded down to whole pages.
///
/// The existing layout constants are inclusive byte ranges rather than page
/// counts, so this converts rather than pretending they were always pages.
const fn span(start: u64, end_inclusive: u64) -> Region {
    let length = end_inclusive.saturating_sub(start).saturating_add(1);
    // `checked_div` rather than `/`: the page size is architecture-selected, and
    // a division by a constant from another module is exactly the arithmetic the
    // kernel's `arithmetic_side_effects` lint exists to refuse on sight.
    let pages = match length.checked_div(PAGE_SIZE_IN_BYTES as u64) {
        Some(pages) => pages as usize,
        None => 0,
    };
    Region { start, pages }
}

/// Whether the serving regions are disjoint from each other and from every
/// region the kernel already uses.
///
/// The §13 non-overlap obligation, as a function anything can call rather than
/// a claim in a document. It is checked at compile time below and in the tests;
/// it is `pub` so a future mapping path can assert it before mapping anything.
#[must_use]
pub const fn reserved_regions_are_disjoint() -> bool {
    let weights = weights_region();
    let kv = kv_region();
    if weights.overlaps(&kv) {
        return false;
    }

    let established = established_regions();
    let mut index = 0;
    while index < established.len() {
        if weights.overlaps(&established[index]) || kv.overlaps(&established[index]) {
            return false;
        }
        index = index.saturating_add(1);
    }
    true
}

/// Non-overlap is a build error, not a test failure.
///
/// A layout that overlaps is not a bug to be found by whoever runs the suite;
/// it is an image that must not link. This is the cheapest form of the §13
/// obligation and it holds at both page sizes because everything above is
/// counted in pages.
const _: () = assert!(
    reserved_regions_are_disjoint(),
    "reserved regions overlap each other or an established kernel region"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_partition_is_inside_the_kv_region_and_disjoint_from_its_neighbours() {
        let region = kv_region();
        let region_end = region.end_exclusive().expect("the KV region has an extent");

        for index in 0..KV_PARTITION_COUNT {
            let partition = kv_partition(index).expect("index is in range");
            let end = partition
                .end_exclusive()
                .expect("a partition has an extent");
            assert!(partition.start >= region.start);
            assert!(end <= region_end);

            for other_index in 0..KV_PARTITION_COUNT {
                if other_index == index {
                    continue;
                }
                let other = kv_partition(other_index).expect("index is in range");
                assert!(
                    !partition.overlaps(&other),
                    "partitions {index} and {other_index} overlap"
                );
            }
        }
    }

    #[test]
    fn a_partition_index_past_the_count_denies_rather_than_clamping() {
        assert_eq!(kv_partition(KV_PARTITION_COUNT), None);
        assert_eq!(kv_partition(usize::MAX), None);
        // The last valid index does resolve, so the boundary is off by nothing.
        assert!(kv_partition(KV_PARTITION_COUNT - 1).is_some());
    }

    #[test]
    fn partitions_are_adjacent_with_no_gap_and_no_double_count() {
        let mut expected = KV_REGION_START;
        for index in 0..KV_PARTITION_COUNT {
            let partition = kv_partition(index).expect("in range");
            assert_eq!(partition.start, expected);
            expected = partition.end_exclusive().expect("has an extent");
        }
        assert_eq!(
            expected,
            kv_region().end_exclusive().expect("has an extent"),
            "the partitions must exactly fill the region they partition"
        );
    }

    #[test]
    fn the_serving_regions_miss_every_region_the_kernel_already_uses() {
        assert!(reserved_regions_are_disjoint());
    }

    #[test]
    fn regions_are_measured_in_pages_so_their_byte_size_follows_the_architecture() {
        let weights = weights_region();
        assert_eq!(
            weights.length_in_bytes(),
            Some(WEIGHTS_REGION_PAGES as u64 * PAGE_SIZE_IN_BYTES as u64)
        );
        // The property that matters is not the number, it is that the number is
        // derived: on a 16 KiB platform this same page count is four times the
        // bytes, and no constant in this module had to change to say so.
        assert_eq!(weights.pages, WEIGHTS_REGION_PAGES);
    }

    #[test]
    fn a_region_whose_extent_cannot_be_computed_overlaps_everything() {
        let unrepresentable = Region {
            start: u64::MAX - 1,
            pages: usize::MAX,
        };
        assert_eq!(unrepresentable.end_exclusive(), None);
        assert!(unrepresentable.overlaps(&weights_region()));
        assert!(weights_region().overlaps(&unrepresentable));
    }

    #[test]
    fn touching_regions_do_not_overlap_but_crossing_ones_do() {
        let first = Region {
            start: 0x1000_0000,
            pages: 2,
        };
        let second = Region {
            start: first.end_exclusive().expect("has an extent"),
            pages: 2,
        };
        assert!(!first.overlaps(&second), "adjacent regions do not overlap");

        let crossing = Region {
            start: first.start + PAGE_SIZE_IN_BYTES as u64,
            pages: 2,
        };
        assert!(first.overlaps(&crossing));
        assert!(crossing.overlaps(&first));
    }

    #[test]
    fn the_kv_region_holds_one_partition_for_every_session_admission_can_grant() {
        // MAX_SESSIONS is 8 (BSP v2 §9.1). A partition count below it would
        // mean admitting sessions with nowhere to put their cache.
        assert_eq!(KV_PARTITION_COUNT, 8);
    }
}
