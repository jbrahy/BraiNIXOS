//! Framebuffer painting — AS-1a2, the display half of first light.
//!
//! # Why stripes and not text
//!
//! A banner needs a font, and a font is several hundred bytes of literal
//! glyph data that cannot be checked against anything except itself. This
//! module paints **one horizontal stripe per boot stage** instead. That is
//! unmissable on a display, needs no glyph table, and carries strictly more
//! information than a banner does: the number of stripes says *how far the
//! payload got* before it stopped.
//!
//! Reading the screen:
//!
//! | Stripes | Meaning |
//! |---|---|
//! | none, screen unchanged | the payload never ran, or never reached `paint` |
//! | 1 (white) | entry reached and `boot_args.video` parsed |
//! | 2 (+cyan) | the ADT window derived from `boot_args` |
//! | 3 (+green) | the ADT parsed and the UART was discovered |
//! | last stripe red | that stage denied; the count says which |
//!
//! This works whether or not the s5l UART reaches this machine's SBU pins,
//! which is the open question **OQ-5** that made a second output path worth
//! building at all.
//!
//! # Host-testable
//!
//! Everything here is written against [`Surface`], so the whole module is
//! exercised on the host against an ordinary byte buffer. The only part that
//! cannot be tested off-hardware is the implementation of `Surface` that
//! writes to real physical memory, which lives in `main.rs` and contains no
//! decisions.

use brainix_adt::Framebuffer;

/// A destination for 32-bit pixel writes.
///
/// Implementations are trusted to accept any offset this module produces.
/// Every offset comes from [`Framebuffer::pixel_offset`], which returns
/// `None` outside the visible area, so an out-of-range write is
/// unrepresentable rather than merely unlikely.
pub trait Surface {
    /// Writes one 32-bit pixel at `byte_offset` from the framebuffer base.
    fn put_u32(&mut self, byte_offset: u64, value: u32);
}

/// Stage colours, in the order the payload reaches them.
///
/// Chosen to be distinguishable on a bad monitor and from each other at a
/// glance: white, cyan, green. Red overrides whichever stage denied.
pub const STAGE_COLOURS: [u32; 3] = [0x00FF_FFFF, 0x0000_FFFF, 0x0000_FF00];

/// The colour a denied stage paints instead of its own.
pub const DENIED_COLOUR: u32 = 0x00FF_0000;

/// Height of one stage stripe, in pixels.
///
/// Large enough to be obvious across a room, small enough that three fit on
/// any panel this machine drives.
pub const STRIPE_HEIGHT: u64 = 64;

/// Paints stripe `index` across the full width of `fb`.
///
/// Returns the number of pixels written, which is what the host tests assert
/// on. A stripe whose band falls outside the panel writes nothing and returns
/// zero rather than wrapping onto another row — [`Framebuffer::pixel_offset`]
/// makes that structural.
pub fn stripe<S: Surface>(surface: &mut S, fb: &Framebuffer, index: u64, colour: u32) -> u64 {
    let top = match index.checked_mul(STRIPE_HEIGHT) {
        Some(top) => top,
        None => return 0,
    };
    let bottom = match top.checked_add(STRIPE_HEIGHT) {
        Some(bottom) => bottom.min(fb.height),
        None => return 0,
    };

    let mut written = 0u64;
    let mut y = top;
    while y < bottom {
        let mut x = 0u64;
        while x < fb.width {
            if let Some(offset) = fb.pixel_offset(x, y) {
                surface.put_u32(offset, colour);
                written = written.saturating_add(1);
            }
            x = x.saturating_add(1);
        }
        y = y.saturating_add(1);
    }
    written
}

/// Paints the stage stripe for `reached` stages, the last one red if `denied`.
///
/// `reached` is 1-based: `reached == 1` paints only the first stripe. A
/// `reached` of zero paints nothing, which is the honest rendering of "we did
/// not get far enough to say anything".
pub fn progress<S: Surface>(surface: &mut S, fb: &Framebuffer, reached: u64, denied: bool) -> u64 {
    let mut written = 0u64;
    let mut index = 0u64;
    while index < reached && index < STAGE_COLOURS.len() as u64 {
        let is_last = index.saturating_add(1) == reached;
        let colour = match (is_last && denied, STAGE_COLOURS.get(index as usize)) {
            (true, _) => DENIED_COLOUR,
            (false, Some(&colour)) => colour,
            (false, None) => break,
        };
        written = written.saturating_add(stripe(surface, fb, index, colour));
        index = index.saturating_add(1);
    }
    written
}
