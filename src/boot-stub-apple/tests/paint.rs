//! Stage-stripe painting — AS-1a2.
//!
//! The whole point of this module is that it can be checked without hardware,
//! so these run against an ordinary byte buffer standing in for the panel.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use brainix_adt::Framebuffer;
use brainix_boot_stub_apple::{
    progress, stripe, Surface, DENIED_COLOUR, STAGE_COLOURS, STRIPE_HEIGHT,
};

/// A panel in memory. Records every write so tests can assert on placement,
/// not merely on a count.
struct Panel {
    pixels: Vec<u32>,
    row_pixels: u64,
}

impl Panel {
    fn new(fb: &Framebuffer) -> Self {
        let row_pixels = fb.row_bytes / 4;
        Self {
            pixels: vec![0u32; (row_pixels * fb.height) as usize],
            row_pixels,
        }
    }
    fn at(&self, x: u64, y: u64) -> u32 {
        self.pixels[(y * self.row_pixels + x) as usize]
    }
}

impl Surface for Panel {
    fn put_u32(&mut self, byte_offset: u64, value: u32) {
        let index = (byte_offset / 4) as usize;
        if let Some(slot) = self.pixels.get_mut(index) {
            *slot = value;
        }
    }
}

fn panel_fb(width: u64, height: u64) -> Framebuffer {
    Framebuffer {
        phys_addr: 0x9_0000_0000,
        width,
        height,
        row_bytes: width * 4,
        depth: 32,
    }
}

#[test]
fn one_stripe_covers_exactly_its_band() {
    let fb = panel_fb(640, 480);
    let mut panel = Panel::new(&fb);
    let written = stripe(&mut panel, &fb, 0, 0x00AB_CDEF);

    assert_eq!(written, 640 * STRIPE_HEIGHT);
    assert_eq!(panel.at(0, 0), 0x00AB_CDEF);
    assert_eq!(panel.at(639, STRIPE_HEIGHT - 1), 0x00AB_CDEF);
    // One row past the band must be untouched.
    assert_eq!(panel.at(0, STRIPE_HEIGHT), 0);
}

#[test]
fn stripes_do_not_overlap() {
    let fb = panel_fb(320, 480);
    let mut panel = Panel::new(&fb);
    stripe(&mut panel, &fb, 0, 0x0000_0001);
    stripe(&mut panel, &fb, 1, 0x0000_0002);

    assert_eq!(panel.at(0, 0), 1);
    assert_eq!(panel.at(0, STRIPE_HEIGHT), 2);
    assert_eq!(panel.at(0, STRIPE_HEIGHT - 1), 1);
}

/// A band past the bottom of the panel writes nothing. Without this it would
/// wrap onto rows belonging to another stripe, which on a real display looks
/// like a different failure than the one that happened.
#[test]
fn a_stripe_past_the_bottom_writes_nothing() {
    let fb = panel_fb(320, 100);
    let mut panel = Panel::new(&fb);
    assert_eq!(stripe(&mut panel, &fb, 5, 0x00FF_FFFF), 0);
    assert_eq!(panel.at(0, 0), 0);
}

/// The band straddling the bottom edge paints only the visible part.
#[test]
fn a_stripe_straddling_the_bottom_is_clipped() {
    let fb = panel_fb(320, STRIPE_HEIGHT + 10);
    let mut panel = Panel::new(&fb);
    assert_eq!(stripe(&mut panel, &fb, 1, 0x00FF_FFFF), 320 * 10);
}

#[test]
fn a_stripe_index_that_would_overflow_writes_nothing() {
    let fb = panel_fb(320, 480);
    let mut panel = Panel::new(&fb);
    assert_eq!(stripe(&mut panel, &fb, u64::MAX, 0x00FF_FFFF), 0);
}

#[test]
fn progress_paints_one_stripe_per_stage_reached() {
    let fb = panel_fb(320, 480);
    let mut panel = Panel::new(&fb);
    progress(&mut panel, &fb, 3, false);

    assert_eq!(panel.at(0, 0), STAGE_COLOURS[0]);
    assert_eq!(panel.at(0, STRIPE_HEIGHT), STAGE_COLOURS[1]);
    assert_eq!(panel.at(0, STRIPE_HEIGHT * 2), STAGE_COLOURS[2]);
    assert_eq!(panel.at(0, STRIPE_HEIGHT * 3), 0);
}

/// Zero stages reached paints nothing. Painting something would claim
/// progress the payload did not make.
#[test]
fn progress_of_zero_paints_nothing() {
    let fb = panel_fb(320, 480);
    let mut panel = Panel::new(&fb);
    assert_eq!(progress(&mut panel, &fb, 0, false), 0);
    assert_eq!(panel.at(0, 0), 0);
}

/// The denial marker lands on the stage that failed, not on the first one,
/// so the stripe count still says which stage it was.
#[test]
fn a_denial_reddens_only_the_last_stripe() {
    let fb = panel_fb(320, 480);
    let mut panel = Panel::new(&fb);
    progress(&mut panel, &fb, 2, true);

    assert_eq!(panel.at(0, 0), STAGE_COLOURS[0]);
    assert_eq!(panel.at(0, STRIPE_HEIGHT), DENIED_COLOUR);
}

#[test]
fn progress_beyond_the_known_stages_stops_at_the_last_one() {
    let fb = panel_fb(320, 480);
    let mut panel = Panel::new(&fb);
    let written = progress(&mut panel, &fb, 99, false);
    assert_eq!(written, 320 * STRIPE_HEIGHT * STAGE_COLOURS.len() as u64);
}

/// Stride padding is normal; painting must respect it rather than assuming
/// `row_bytes == width * 4`.
#[test]
fn a_padded_stride_is_respected() {
    let fb = Framebuffer {
        phys_addr: 0x9_0000_0000,
        width: 100,
        height: 200,
        row_bytes: 100 * 4 + 64,
        depth: 32,
    };
    let mut panel = Panel::new(&fb);
    stripe(&mut panel, &fb, 0, 0x0011_2233);

    assert_eq!(panel.at(0, 1), 0x0011_2233);
    // The padding past the visible width stays untouched.
    assert_eq!(panel.at(100, 0), 0);
}
