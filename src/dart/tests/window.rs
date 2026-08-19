//! The window type at the boundaries the proofs quantify over abstractly.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
#![allow(clippy::cognitive_complexity)]

use brainix_dart::{DmaWindow, HeldWindow, IommuWindowHolder, WindowError};

#[test]
fn a_default_window_and_a_default_holder_translate_nothing() {
    assert!(DmaWindow::default().is_empty());
    assert!(!DmaWindow::default().is_writable());
    assert!(HeldWindow::default().window().is_empty());
    assert!(HeldWindow::new().window().is_empty());
}

#[test]
fn a_grant_whose_extent_overflows_grants_nothing() {
    // Kani found this: such a window contains nothing, not even itself, so a
    // holder could not reason about it at all. Fail closed at construction.
    let overflowing = DmaWindow::granted(u64::MAX, 2, true);
    assert!(overflowing.is_empty());
    assert!(!overflowing.is_writable());
    assert_eq!(overflowing.end_page(), Some(0));

    // The largest representable window is still a window.
    let maximal = DmaWindow::granted(u64::MAX - 1, 1, true);
    assert!(!maximal.is_empty());
    assert_eq!(maximal.end_page(), Some(u64::MAX));
}

#[test]
fn narrowing_outside_the_window_denies_rather_than_clamping() {
    let granted = DmaWindow::granted(100, 10, true);
    let mut holder = HeldWindow::holding(granted);

    // One page before, one page after, and a range that straddles the end.
    assert_eq!(holder.narrow_window(99, 2), Err(WindowError::NotContained));
    assert_eq!(
        holder.narrow_window(105, 10),
        Err(WindowError::NotContained)
    );
    assert_eq!(holder.narrow_window(110, 1), Err(WindowError::NotContained));
    // A refused narrow leaves the window untouched.
    assert_eq!(holder.window(), granted);

    // The exact window, and a strict sub-range, are both permitted.
    assert!(holder.narrow_window(100, 10).is_ok());
    assert!(holder.narrow_window(102, 3).is_ok());
    assert_eq!(holder.window().base_page(), 102);
    assert_eq!(holder.window().pages(), 3);
}

#[test]
fn a_read_only_grant_cannot_be_narrowed_into_a_writable_one() {
    let granted = DmaWindow::granted(0, 8, false);
    let mut holder = HeldWindow::holding(granted);
    holder.narrow_window(2, 2).expect("inside");
    assert!(!holder.window().is_writable());
}

#[test]
fn the_empty_window_is_contained_everywhere_and_contains_only_itself() {
    let empty = DmaWindow::deny_all();
    let window = DmaWindow::granted(4, 4, true);

    assert!(window.contains(&empty));
    assert!(empty.contains(&empty));
    assert!(!empty.contains(&window));
}

#[test]
fn a_subrange_that_gained_write_is_not_permitted_by_a_read_only_grant() {
    // The case a range-only containment check waves through, and the one a
    // driver would actually want.
    let read_only = DmaWindow::granted(0, 16, false);
    let writable_subrange = DmaWindow::granted(4, 4, true);

    assert!(read_only.contains(&writable_subrange));
    assert!(!read_only.permits_everything_in(&writable_subrange));

    let writable = DmaWindow::granted(0, 16, true);
    assert!(writable.permits_everything_in(&writable_subrange));
}

#[test]
fn dropping_write_and_revoking_leave_the_holder_no_better_off() {
    let granted = DmaWindow::granted(64, 8, true);
    let mut holder = HeldWindow::holding(granted);

    holder.drop_write_authority();
    assert!(!holder.window().is_writable());
    assert_eq!(holder.window().pages(), 8);
    assert!(granted.permits_everything_in(&holder.window()));

    holder.revoke_window();
    assert!(holder.window().is_empty());
    // And there is no way back: narrowing an empty window yields nothing.
    assert_eq!(holder.narrow_window(64, 8), Err(WindowError::NotContained));
}

/// The two early exits of `permits_everything_in`, which no test reached.
///
/// Both were invisible until `coverage-gate.py` learned to see single-file
/// crates: `brainix-dart`'s report has no filename header, so every uncovered
/// line in it was being dropped and the crate scored a clean zero.
#[test]
fn a_window_permits_nothing_of_a_window_it_does_not_contain() {
    let low = DmaWindow::granted(0, 8, true);
    let high = DmaWindow::granted(64, 8, true);

    // Disjoint: containment fails, so the authority question is already
    // answered and the write bits never get compared.
    assert!(!low.contains(&high));
    assert!(!low.permits_everything_in(&high));
    assert!(!high.permits_everything_in(&low));

    // Overlapping but not containing is the same answer, and is the case a
    // range check written as "starts inside" would wave through.
    let straddling = DmaWindow::granted(4, 8, true);
    assert!(!low.contains(&straddling));
    assert!(!low.permits_everything_in(&straddling));
}

#[test]
fn an_empty_window_asks_for_nothing_even_when_it_claims_write_authority() {
    let read_only = DmaWindow::granted(0, 16, false);
    let empty_writable = DmaWindow::granted(0, 0, true);

    // The empty window names no page, so there is no authority to widen -- and
    // this is the one case where a writable window is permitted by a read-only
    // one. Getting it wrong the other way would refuse a legitimate revoke.
    assert!(empty_writable.is_empty());
    assert!(read_only.contains(&empty_writable));
    assert!(read_only.permits_everything_in(&empty_writable));

    // The converse does not hold: an empty window contains only empty windows.
    assert!(!empty_writable.permits_everything_in(&read_only));
}
