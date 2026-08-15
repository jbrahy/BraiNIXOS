//! `boot_args.video` derivation — AS-1a2 / ROADMAP Track C row C7.
//!
//! Every case here treats `video` as what the threat model says it is:
//! firmware-supplied data, parsed with the same fail-closed discipline as
//! network bytes (`INV-PARSE-001`). The interesting tests are the denials,
//! because a framebuffer parser that accepts a bad extent drives a write
//! sized by an attacker-influenced number.

// Test-only, and matching the allow block the transport-crypto known-answer
// suite already carries. Fixture arithmetic on literal dimensions is not the
// arithmetic `arithmetic_side_effects` exists to catch; the parser under test
// is held to the unsuppressed bar and uses `checked_*` throughout.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cognitive_complexity
)]

use brainix_adt::{framebuffer, BootArgsError, MAX_FB_EXTENT};

const VIDEO_BASE: usize = 0x28;
const VIDEO_ROW_BYTES: usize = 0x38;
const VIDEO_WIDTH: usize = 0x40;
const VIDEO_HEIGHT: usize = 0x48;
const VIDEO_DEPTH: usize = 0x50;
const LEN: usize = 0x70;

/// A `boot_args` image describing a plausible 2560x1440 32-bit framebuffer.
fn good() -> Vec<u8> {
    let mut b = vec![0u8; LEN];
    put(&mut b, VIDEO_BASE, 0x9_0000_0000);
    put(&mut b, VIDEO_ROW_BYTES, 2560 * 4);
    put(&mut b, VIDEO_WIDTH, 2560);
    put(&mut b, VIDEO_HEIGHT, 1440);
    put(&mut b, VIDEO_DEPTH, 32);
    b
}

fn put(image: &mut [u8], at: usize, value: u64) {
    image[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn a_well_formed_video_block_is_accepted() {
    let fb = framebuffer(&good()).expect("well-formed video block");
    assert_eq!(fb.phys_addr, 0x9_0000_0000);
    assert_eq!(fb.width, 2560);
    assert_eq!(fb.height, 1440);
    assert_eq!(fb.row_bytes, 2560 * 4);
    assert_eq!(fb.depth, 32);
    assert_eq!(fb.span_bytes(), 2560 * 4 * 1440);
}

/// Apple reports 30 bits for the 10-bit-per-channel mode; it still occupies
/// four bytes, and refusing it would refuse the common configuration.
#[test]
fn a_thirty_bit_depth_is_accepted() {
    let mut b = good();
    put(&mut b, VIDEO_DEPTH, 30);
    assert_eq!(framebuffer(&b).unwrap().depth, 30);
}

#[test]
fn a_truncated_buffer_denies() {
    let b = good();
    for len in [0usize, 1, VIDEO_DEPTH, VIDEO_DEPTH + 7] {
        assert_eq!(
            framebuffer(&b[..len]),
            Err(BootArgsError::TruncatedVideo),
            "len {len} must deny"
        );
    }
}

#[test]
fn a_zero_base_address_denies_as_no_framebuffer() {
    let mut b = good();
    put(&mut b, VIDEO_BASE, 0);
    assert_eq!(framebuffer(&b), Err(BootArgsError::NoFramebuffer));
}

#[test]
fn a_misaligned_base_address_denies() {
    let mut b = good();
    put(&mut b, VIDEO_BASE, 0x9_0000_0001);
    assert_eq!(framebuffer(&b), Err(BootArgsError::FramebufferMisaligned));
}

#[test]
fn a_zero_extent_denies_in_either_axis() {
    for at in [VIDEO_WIDTH, VIDEO_HEIGHT] {
        let mut b = good();
        put(&mut b, at, 0);
        assert_eq!(framebuffer(&b), Err(BootArgsError::ZeroFramebufferExtent));
    }
}

/// The bound is the point: without it a corrupt extent drives an enormous
/// write, which is the `INV-MEM` failure this parser exists to prevent.
#[test]
fn an_oversized_extent_denies_in_either_axis() {
    for at in [VIDEO_WIDTH, VIDEO_HEIGHT] {
        let mut b = good();
        put(&mut b, at, MAX_FB_EXTENT + 1);
        put(&mut b, VIDEO_ROW_BYTES, (MAX_FB_EXTENT + 1) * 4);
        assert_eq!(
            framebuffer(&b),
            Err(BootArgsError::FramebufferExtentTooLarge)
        );
    }
}

#[test]
fn an_unsupported_depth_denies() {
    for depth in [0u64, 1, 8, 16, 24, 31, 64, u64::MAX] {
        let mut b = good();
        put(&mut b, VIDEO_DEPTH, depth);
        assert_eq!(
            framebuffer(&b),
            Err(BootArgsError::UnsupportedFramebufferDepth),
            "depth {depth} must deny"
        );
    }
}

/// A stride shorter than a row makes row n overlap row n+1. Denying beats
/// rendering garbage, because garbage looks like a bug in the caller.
#[test]
fn a_stride_below_one_row_denies() {
    let mut b = good();
    put(&mut b, VIDEO_ROW_BYTES, 2560 * 4 - 1);
    assert_eq!(framebuffer(&b), Err(BootArgsError::RowBytesBelowWidth));
}

/// Padding past the end of a row is normal and must not be refused.
#[test]
fn a_stride_above_one_row_is_accepted() {
    let mut b = good();
    put(&mut b, VIDEO_ROW_BYTES, 2560 * 4 + 256);
    assert_eq!(framebuffer(&b).unwrap().row_bytes, 2560 * 4 + 256);
}

#[test]
fn a_span_that_would_overflow_denies() {
    let mut b = good();
    put(&mut b, VIDEO_ROW_BYTES, u64::MAX);
    assert_eq!(framebuffer(&b), Err(BootArgsError::FramebufferSpanOverflow));
}

/// A base address near the top of the address space plus a legitimate span
/// still leaves the 64-bit range, and must deny rather than wrap.
///
/// The address must be 8-aligned or the alignment check fires first and this
/// tests nothing — which is exactly what the first version of it did.
/// `u64::MAX - 7` is `0xFFFF_FFFF_FFFF_FFF8`, the highest aligned address
/// there is.
#[test]
fn a_base_address_near_the_top_denies_rather_than_wrapping() {
    let mut b = good();
    let top_aligned = u64::MAX - 7;
    assert_eq!(
        top_aligned & 0x7,
        0,
        "the address under test must be aligned"
    );
    put(&mut b, VIDEO_BASE, top_aligned);
    assert_eq!(framebuffer(&b), Err(BootArgsError::FramebufferSpanOverflow));
}

#[test]
fn pixel_offsets_are_in_bounds_and_row_strided() {
    let fb = framebuffer(&good()).unwrap();
    assert_eq!(fb.pixel_offset(0, 0), Some(0));
    assert_eq!(fb.pixel_offset(1, 0), Some(4));
    assert_eq!(fb.pixel_offset(0, 1), Some(2560 * 4));
    assert_eq!(
        fb.pixel_offset(2559, 1439),
        Some(1439 * 2560 * 4 + 2559 * 4)
    );
}

/// Out-of-bounds returns `None` rather than clamping: a clamped write
/// silently corrupts a different pixel, and a caller cannot ignore an
/// `Option` without saying so.
#[test]
fn pixel_offsets_outside_the_visible_area_deny() {
    let fb = framebuffer(&good()).unwrap();
    assert_eq!(fb.pixel_offset(2560, 0), None);
    assert_eq!(fb.pixel_offset(0, 1440), None);
    assert_eq!(fb.pixel_offset(u64::MAX, u64::MAX), None);
}

/// The offsets are pinned on both sides by `devtree` at 0x60, which AS-0-T4
/// already validates against real firmware. If `Video` were not six 8-byte
/// fields at 0x28, `devtree` could not land where it does.
#[test]
fn the_video_block_ends_where_machine_type_begins() {
    assert_eq!(VIDEO_DEPTH + 8, 0x58);
}
