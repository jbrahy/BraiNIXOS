//! Config spaces a malicious device would present.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
#![allow(clippy::cognitive_complexity)]

use brainix_pcie_config::{
    walk, Capability, WalkError, CAPABILITIES_POINTER, CONFIG_SPACE_LEN, MAX_CAPABILITIES,
    STATUS_CAPABILITIES_BIT,
};

fn blank() -> [u8; CONFIG_SPACE_LEN] {
    let mut space = [0u8; CONFIG_SPACE_LEN];
    space[0x06..0x08].copy_from_slice(&STATUS_CAPABILITIES_BIT.to_le_bytes());
    space
}

fn out() -> [Capability; MAX_CAPABILITIES] {
    [Capability { id: 0, offset: 0 }; MAX_CAPABILITIES]
}

#[test]
fn a_device_with_no_capability_list_yields_none() {
    let mut space = blank();
    space[0x06..0x08].copy_from_slice(&0u16.to_le_bytes());
    assert_eq!(walk(&space, &mut out()), Ok(0));
}

#[test]
fn an_honest_list_walks_to_its_end() {
    let mut space = blank();
    space[CAPABILITIES_POINTER] = 0x40;
    space[0x40] = 0x10; // PCI Express capability
    space[0x41] = 0x50; // next
    space[0x50] = 0x05; // MSI
    space[0x51] = 0x00; // end

    let mut found = out();
    assert_eq!(walk(&space, &mut found), Ok(2));
    assert_eq!(
        found[0],
        Capability {
            id: 0x10,
            offset: 0x40
        }
    );
    assert_eq!(
        found[1],
        Capability {
            id: 0x05,
            offset: 0x50
        }
    );
}

#[test]
fn a_capability_pointing_at_itself_is_a_cycle_and_not_a_hang() {
    // The one-line attack: point a capability at its own offset.
    let mut space = blank();
    space[CAPABILITIES_POINTER] = 0x40;
    space[0x40] = 0x10;
    space[0x41] = 0x40;

    assert_eq!(walk(&space, &mut out()), Err(WalkError::Cycle));
}

#[test]
fn a_longer_loop_is_caught_by_the_same_rule() {
    // Three capabilities in a ring. A step limit alone would catch this after
    // 96 iterations; the visited set catches it on the fourth.
    let mut space = blank();
    space[CAPABILITIES_POINTER] = 0x40;
    space[0x40] = 0x01;
    space[0x41] = 0x50;
    space[0x50] = 0x02;
    space[0x51] = 0x60;
    space[0x60] = 0x03;
    space[0x61] = 0x40;

    assert_eq!(walk(&space, &mut out()), Err(WalkError::Cycle));
}

#[test]
fn a_pointer_into_the_standard_header_is_refused() {
    // A device pointing its "capability" at its own vendor ID, so a driver
    // reads the header it already parsed as a capability header.
    let mut space = blank();
    space[CAPABILITIES_POINTER] = 0x00;
    // 0x00 terminates the list by definition, so use a non-zero header offset.
    space[CAPABILITIES_POINTER] = 0x04;
    assert_eq!(walk(&space, &mut out()), Err(WalkError::OutOfRange));
}

#[test]
fn a_misaligned_pointer_is_refused() {
    let mut space = blank();
    space[CAPABILITIES_POINTER] = 0x41;
    assert_eq!(walk(&space, &mut out()), Err(WalkError::Misaligned));
}

#[test]
fn a_capability_whose_next_pointer_falls_off_the_end_is_out_of_range() {
    // The last byte of config space: the id is readable and the next pointer
    // is not.
    let mut space = blank();
    space[CAPABILITIES_POINTER] = 0xFC;
    space[0xFC] = 0x10;
    space[0xFD] = 0xFF;
    // 0xFF is misaligned, so the walk denies on the following hop rather than
    // reading past the end.
    assert_eq!(walk(&space, &mut out()), Err(WalkError::Misaligned));
}

#[test]
fn a_short_config_space_is_refused_rather_than_padded() {
    let short = [0u8; 64];
    assert_eq!(walk(&short, &mut out()), Err(WalkError::ShortConfigSpace));
}

#[test]
fn a_full_list_of_distinct_capabilities_terminates_without_error() {
    // Every four-byte slot from 0x40 to 0xFC chained in order: the longest
    // honest list config space can hold. It must walk, not trip the limit.
    let mut space = blank();
    space[CAPABILITIES_POINTER] = 0x40;
    let mut offset = 0x40usize;
    while offset + 4 < CONFIG_SPACE_LEN {
        space[offset] = 0x09;
        space[offset + 1] = (offset + 4) as u8;
        offset += 4;
    }
    space[offset] = 0x09;
    space[offset + 1] = 0x00;

    let found = walk(&space, &mut out()).expect("an honest list of maximum length");
    assert!(found > 40, "walked {found} capabilities");
    assert!(found <= MAX_CAPABILITIES);
}

#[test]
fn an_output_buffer_smaller_than_the_list_still_counts_and_still_terminates() {
    let mut space = blank();
    space[CAPABILITIES_POINTER] = 0x40;
    space[0x40] = 0x01;
    space[0x41] = 0x50;
    space[0x50] = 0x02;
    space[0x51] = 0x00;

    let mut small = [Capability { id: 0, offset: 0 }; 1];
    assert_eq!(walk(&space, &mut small), Ok(2));
    assert_eq!(small[0].id, 0x01);
}
