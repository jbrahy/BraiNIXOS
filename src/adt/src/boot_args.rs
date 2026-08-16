//! `boot_args` parsing and the ADT physical-window derivation — AS-0-T4.
//!
//! At the firmware entry point, register `x0` holds the physical address of
//! an XNU `boot_args` structure (spec §3). This module reads the five fields
//! that structure needs to hand over — `virt_base`, `phys_base`, `mem_size`,
//! `devtree`, `devtree_size` — derives the ADT's physical window from them,
//! and applies every check spec §9.1 requires of that derivation. It never
//! reads or interprets any other `boot_args` field.
//!
//! # Offset basis
//!
//! Unlike [`crate::DeviceTree`], this module reads **fixed, absolute offsets**
//! into the `boot_args` structure itself — it is not the ADT, and the
//! buffer-relative-offset discipline of spec §3.1 does not apply to it. Its
//! output, [`AdtWindow`], is exactly the physical address and length the
//! caller must use to obtain the `&[u8]` that *is* handed to
//! [`crate::DeviceTree::parse`].
//!
//! # What this module deliberately does not do
//!
//! It does not read `revision`, `version`, `top_of_kernel_data`,
//! `machine_type`, or `cmdline` — none of them bear on deriving or validating
//! the ADT window, and `cmdline`'s offset is disputed (spec §10, OQ-1). It
//! also does not dereference any physical address: the caller owns turning an
//! [`AdtWindow`] into the `&[u8]` slice the ADT decoder receives.
//!
//! **`video` was on that list until 2026-08-14** and is now read by
//! [`framebuffer`], because AS-1a's serial banner may have nowhere to go on
//! this SoC (OQ-5) and a display is an independent output path. Same
//! discipline: fixed offsets, bounds-checked reads, fail closed, dereference
//! nothing.

use crate::raw::{read_u32_le, read_u64_le};

/// Byte offset of `boot_args.virt_base` (spec §3).
const VIRT_BASE_OFFSET: usize = 0x08;
/// Byte offset of `boot_args.phys_base` (spec §3).
const PHYS_BASE_OFFSET: usize = 0x10;
/// Byte offset of `boot_args.mem_size` (spec §3).
const MEM_SIZE_OFFSET: usize = 0x18;
/// Byte offset of `boot_args.devtree` (spec §3).
const DEVTREE_OFFSET: usize = 0x60;
/// Byte offset of `boot_args.devtree_size` (spec §3).
const DEVTREE_SIZE_OFFSET: usize = 0x68;
/// Bytes of `boot_args` this module reads: through the end of `devtree_size`.
const MIN_BOOT_ARGS_LEN: usize = DEVTREE_SIZE_OFFSET + 4;

/// Alignment mask for a 4-byte-aligned quantity. Bitwise, not `%`, so the
/// check cannot be read as arithmetic that could overflow.
const ALIGN_MASK_U32: u32 = 0x3;
/// As [`ALIGN_MASK_U32`], for the 64-bit physical address.
const ALIGN_MASK_U64: u64 = 0x3;

/// Every way `boot_args` or the ADT window derived from it can be refused.
///
/// One variant per failure mode (spec §9.0's distinct-reason requirement), so
/// a rejected `boot_args` can be audited for *why*. Deliberately not
/// `#[non_exhaustive]` — see [`crate::AdtError`]'s equivalent note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootArgsError {
    /// Fewer than [`MIN_BOOT_ARGS_LEN`] bytes were supplied — the buffer ends
    /// before `devtree_size` does.
    TruncatedBootArgs,

    /// `devtree_size` is zero (spec §9.1).
    ZeroDevtreeSize,

    /// `devtree_size` is less than 8 — the claimed blob cannot hold even a
    /// root node header (spec §9.1).
    DevtreeSizeBelowRootHeader,

    /// `devtree_size` is not a multiple of 4 (spec §3.1, §9.1). Every record
    /// in a well-formed tree is 4-byte aligned, so a well-formed tree can
    /// never claim a length that is not.
    DevtreeSizeMisaligned,

    /// `devtree − virt_base` underflowed: the ADT's claimed virtual address
    /// lies before iBoot's own mapping base (spec §9.1).
    VirtualAddressUnderflow,

    /// `(devtree − virt_base) + phys_base` overflowed a 64-bit address
    /// (spec §9.1).
    PhysicalAddressOverflow,

    /// The derived `adt_phys` is not 4-byte aligned. Required for the §9.7
    /// offset-alignment check to have a well-defined meaning (spec §3.1).
    AdtPhysMisaligned,

    /// `adt_phys + devtree_size` overflowed a 64-bit address (spec §9.1).
    AdtWindowOverflow,

    /// `phys_base + mem_size` overflowed while computing the DRAM window
    /// against which the ADT window is checked (spec §9.1).
    DramWindowOverflow,

    /// The ADT window `[adt_phys, adt_phys + devtree_size)` is not entirely
    /// inside the DRAM window `[phys_base, phys_base + mem_size)` (spec
    /// §9.1).
    AdtWindowOutsideDram,

    /// `boot_args` ends before the end of the `Boot_Video` structure.
    TruncatedVideo,

    /// `video.base_addr` is zero — firmware reports no framebuffer.
    NoFramebuffer,

    /// `video.base_addr` is not 8-byte aligned. A framebuffer that is not
    /// pixel-aligned is not one we will write to.
    FramebufferMisaligned,

    /// `video.width` or `video.height` is zero.
    ZeroFramebufferExtent,

    /// `video.width` or `video.height` exceeds [`MAX_FB_EXTENT`]. A hostile
    /// or corrupt value here would otherwise drive an enormous write.
    FramebufferExtentTooLarge,

    /// `video.depth` is not a bit depth this project renders into.
    UnsupportedFramebufferDepth,

    /// `video.row_bytes` is smaller than one row of pixels needs, so a
    /// row-strided write would overlap the following row.
    RowBytesBelowWidth,

    /// `row_bytes * height` overflowed, or the resulting span left the
    /// 64-bit address range.
    FramebufferSpanOverflow,
}

/// The ADT's validated location in physical memory.
///
/// Holding one of these means every check spec §9.1 requires of the
/// `boot_args` → ADT-window derivation has already passed. It is not a claim
/// that the bytes at `phys_addr` form a well-formed tree — only
/// [`crate::DeviceTree::parse`] establishes that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdtWindow {
    /// Physical address of the first byte of the ADT blob.
    pub phys_addr: u64,
    /// Length of the ADT blob in bytes. Always at least 8 and a multiple of 4.
    pub len: u32,
}

/// Derives and validates the ADT's physical window from a `boot_args` buffer.
///
/// `boot_args` must be at least [`MIN_BOOT_ARGS_LEN`] bytes — the prefix
/// through `devtree_size` — starting at the address `x0` holds at firmware
/// entry. Trailing bytes (`cmdline` and beyond) are never read.
///
/// # Example
///
/// ```
/// use brainix_adt::{adt_window, AdtWindow};
///
/// fn locate_adt(boot_args: &[u8]) -> Result<AdtWindow, brainix_adt::BootArgsError> {
///     adt_window(boot_args)
/// }
/// ```
pub fn adt_window(boot_args: &[u8]) -> Result<AdtWindow, BootArgsError> {
    if boot_args.len() < MIN_BOOT_ARGS_LEN {
        return Err(BootArgsError::TruncatedBootArgs);
    }

    // Every read below is in-bounds by the length check above, but each still
    // goes through the same bounds-checked primitive the ADT decoder uses
    // rather than an unchecked slice index (defence in depth, not a
    // substitute for the length check).
    let virt_base =
        read_u64_le(boot_args, VIRT_BASE_OFFSET).ok_or(BootArgsError::TruncatedBootArgs)?;
    let phys_base =
        read_u64_le(boot_args, PHYS_BASE_OFFSET).ok_or(BootArgsError::TruncatedBootArgs)?;
    let mem_size =
        read_u64_le(boot_args, MEM_SIZE_OFFSET).ok_or(BootArgsError::TruncatedBootArgs)?;
    let devtree = read_u64_le(boot_args, DEVTREE_OFFSET).ok_or(BootArgsError::TruncatedBootArgs)?;
    let devtree_size =
        read_u32_le(boot_args, DEVTREE_SIZE_OFFSET).ok_or(BootArgsError::TruncatedBootArgs)?;

    if devtree_size == 0 {
        return Err(BootArgsError::ZeroDevtreeSize);
    }
    if devtree_size < 8 {
        return Err(BootArgsError::DevtreeSizeBelowRootHeader);
    }
    if devtree_size & ALIGN_MASK_U32 != 0 {
        return Err(BootArgsError::DevtreeSizeMisaligned);
    }

    // `devtree - virt_base + phys_base`, in **wrapping** 64-bit arithmetic.
    //
    // This was `checked_sub` then `checked_add`, which looks safer and is
    // wrong: it denies valid firmware. Measured on the target 2026-08-16, with
    // our code running on the machine and reporting through m1n1's proxy:
    //
    //     virt_base   0xffffffffff020000     a sign-extended kernel VA
    //     phys_base   0x00010001020000
    //     devtree     0x0000000161c000
    //
    // `devtree` is far below `virt_base`, so `checked_sub` returns `None` and
    // the whole window is refused. The wrapping result is `0x1000361c000`,
    // which was read back from the machine and begins
    // `regulatory-model-number` -- the real ADT, byte-identical to the head of
    // `tests/fixtures/mac14-12-j474s-adt.bin`.
    //
    // Both forms occur on the same hardware: iBoot handed m1n1 a small
    // `virt_base` of `0x1020000`, while m1n1 hands a chainloaded payload the
    // kernel-VA form. A parser that only accepts the first works under iBoot
    // and denies under m1n1, which reads as "the payload is broken".
    //
    // Nothing is given up by wrapping here. The overflow checks were never the
    // safety property; the **containment check below is**, and it is unchanged:
    // the resulting window must lie entirely inside the DRAM range firmware
    // reported, be aligned, and not overflow its own end. An address that wraps
    // to somewhere unreasonable fails those, as it should.
    let virt_offset = devtree.wrapping_sub(virt_base);
    let adt_phys = virt_offset.wrapping_add(phys_base);

    if adt_phys & ALIGN_MASK_U64 != 0 {
        return Err(BootArgsError::AdtPhysMisaligned);
    }

    let adt_end = adt_phys
        .checked_add(u64::from(devtree_size))
        .ok_or(BootArgsError::AdtWindowOverflow)?;

    let dram_end = phys_base
        .checked_add(mem_size)
        .ok_or(BootArgsError::DramWindowOverflow)?;

    // Now load-bearing rather than defence in depth. With wrapping arithmetic
    // above, `adt_phys < phys_base` is genuinely reachable -- a hostile or
    // corrupt `devtree`/`virt_base` pair can land the window below the DRAM
    // base -- and this is the check that refuses it. Spec §9.1's "entirely
    // inside" requirement is enforced here and nowhere else.
    if adt_phys < phys_base || adt_end > dram_end {
        return Err(BootArgsError::AdtWindowOutsideDram);
    }

    Ok(AdtWindow {
        phys_addr: adt_phys,
        len: devtree_size,
    })
}

// ---------------------------------------------------------------------------
// Framebuffer — AS-1a2 / ROADMAP Track C row C7
// ---------------------------------------------------------------------------

/// Byte offset of `boot_args.video.base_addr`.
///
/// # Why these offsets are not a guess
///
/// `Boot_Video` is six `unsigned long` fields, and it sits between
/// `top_of_kernel_data` (`0x20`) and `machine_type`. Six 8-byte fields from
/// `0x28` end at `0x58`; `machine_type` is a `u32` there, and `devtree`
/// follows at `0x60` — which is the offset this module has been using since
/// AS-0-T4 and which is checked against real firmware. The `Video` layout is
/// therefore pinned on both sides by a value already known good, rather than
/// asserted on its own.
const VIDEO_BASE_ADDR_OFFSET: usize = 0x28;
/// Byte offset of `boot_args.video.row_bytes` — the stride, in bytes.
const VIDEO_ROW_BYTES_OFFSET: usize = 0x38;
/// Byte offset of `boot_args.video.width`, in pixels.
const VIDEO_WIDTH_OFFSET: usize = 0x40;
/// Byte offset of `boot_args.video.height`, in pixels.
const VIDEO_HEIGHT_OFFSET: usize = 0x48;
/// Byte offset of `boot_args.video.depth`, in bits per pixel.
const VIDEO_DEPTH_OFFSET: usize = 0x50;
/// Bytes of `boot_args` [`framebuffer`] reads: through the end of `depth`.
const MIN_VIDEO_LEN: usize = VIDEO_DEPTH_OFFSET + 8;

/// Largest width or height accepted, in pixels.
///
/// Not a hardware limit — a bound. `video` is firmware-supplied data and gets
/// the same treatment as network bytes, so a corrupt extent must deny rather
/// than drive a write sized by it (`INV-MEM`, `INV-PARSE-001`).
pub const MAX_FB_EXTENT: u64 = 16384;

/// Bytes per pixel this project renders. Apple reports `30` for the common
/// 10-bit-per-channel mode and `32` for 8-bit; both occupy four bytes.
const FB_BYTES_PER_PIXEL: u64 = 4;

/// A validated framebuffer handed over by iBoot.
///
/// Holding one means every check in [`framebuffer`] has passed: the span
/// `[phys_addr, phys_addr + row_bytes * height)` does not overflow, the
/// stride covers a full row, and the extents are within [`MAX_FB_EXTENT`].
/// It is **not** a claim that anything is mapped there — establishing that is
/// the MMU's job, not this parser's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Framebuffer {
    /// Physical address of pixel (0, 0).
    pub phys_addr: u64,
    /// Visible width in pixels.
    pub width: u64,
    /// Visible height in pixels.
    pub height: u64,
    /// Bytes between the start of one row and the next. May exceed
    /// `width * 4`; padding at the end of a row is normal and must not be
    /// assumed absent.
    pub row_bytes: u64,
    /// Bits per pixel as firmware reported it — `30` or `32`, both stored in
    /// four bytes.
    pub depth: u64,
}

impl Framebuffer {
    /// Total bytes spanned, `row_bytes * height`.
    ///
    /// Cannot overflow: [`framebuffer`] rejects any value that would.
    #[must_use]
    pub fn span_bytes(&self) -> u64 {
        self.row_bytes.saturating_mul(self.height)
    }

    /// Byte offset of pixel (`x`, `y`) from [`Self::phys_addr`], or `None` if
    /// the pixel lies outside the visible area.
    ///
    /// Returning `None` rather than clamping is deliberate: a clamped write
    /// silently corrupts the wrong pixel, and a caller that ignores the
    /// `Option` cannot compile.
    #[must_use]
    pub fn pixel_offset(&self, x: u64, y: u64) -> Option<u64> {
        if x >= self.width || y >= self.height {
            return None;
        }
        let row = y.checked_mul(self.row_bytes)?;
        let column = x.checked_mul(FB_BYTES_PER_PIXEL)?;
        row.checked_add(column)
    }
}

/// Derives and validates the framebuffer iBoot describes in `boot_args`.
///
/// # Why this exists
///
/// AS-1a's banner goes to the s5l UART, and whether that UART reaches the
/// machine's USB-C SBU pins on a `T6020` is unresolved — see **OQ-5** in
/// `docs/platform-specs/apple-s5l-uart.md`. A framebuffer is an *independent*
/// output path sharing none of that question's failure modes, so first light
/// can be observed on a display even if the console never speaks.
///
/// It does not replace the UART path. The serial console is bidirectional and
/// carries break-glass authority (`INV-BOOT-008`); a framebuffer is
/// output-only, which is why it is the safer of the two to add and cannot
/// substitute for the other.
///
/// # Example
///
/// ```
/// use brainix_adt::{framebuffer, BootArgsError};
///
/// fn first_light(boot_args: &[u8]) -> Result<(), BootArgsError> {
///     let fb = framebuffer(boot_args)?;
///     let _ = fb.pixel_offset(0, 0);
///     Ok(())
/// }
/// ```
pub fn framebuffer(boot_args: &[u8]) -> Result<Framebuffer, BootArgsError> {
    if boot_args.len() < MIN_VIDEO_LEN {
        return Err(BootArgsError::TruncatedVideo);
    }

    let phys_addr =
        read_u64_le(boot_args, VIDEO_BASE_ADDR_OFFSET).ok_or(BootArgsError::TruncatedVideo)?;
    let row_bytes =
        read_u64_le(boot_args, VIDEO_ROW_BYTES_OFFSET).ok_or(BootArgsError::TruncatedVideo)?;
    let width = read_u64_le(boot_args, VIDEO_WIDTH_OFFSET).ok_or(BootArgsError::TruncatedVideo)?;
    let height =
        read_u64_le(boot_args, VIDEO_HEIGHT_OFFSET).ok_or(BootArgsError::TruncatedVideo)?;
    let depth = read_u64_le(boot_args, VIDEO_DEPTH_OFFSET).ok_or(BootArgsError::TruncatedVideo)?;

    if phys_addr == 0 {
        return Err(BootArgsError::NoFramebuffer);
    }
    // Bitwise, not `%`, for the same reason the ADT window's alignment check
    // is bitwise: it cannot be misread as arithmetic that might overflow.
    if phys_addr & 0x7 != 0 {
        return Err(BootArgsError::FramebufferMisaligned);
    }
    if width == 0 || height == 0 {
        return Err(BootArgsError::ZeroFramebufferExtent);
    }
    if width > MAX_FB_EXTENT || height > MAX_FB_EXTENT {
        return Err(BootArgsError::FramebufferExtentTooLarge);
    }
    if depth != 30 && depth != 32 {
        return Err(BootArgsError::UnsupportedFramebufferDepth);
    }

    // A stride shorter than one row means row n's tail overlaps row n+1.
    // Writing under that assumption corrupts the display rather than failing,
    // which is exactly the kind of silent wrongness this project denies on.
    let row_pixels_bytes = width
        .checked_mul(FB_BYTES_PER_PIXEL)
        .ok_or(BootArgsError::FramebufferSpanOverflow)?;
    if row_bytes < row_pixels_bytes {
        return Err(BootArgsError::RowBytesBelowWidth);
    }

    let span = row_bytes
        .checked_mul(height)
        .ok_or(BootArgsError::FramebufferSpanOverflow)?;
    phys_addr
        .checked_add(span)
        .ok_or(BootArgsError::FramebufferSpanOverflow)?;

    Ok(Framebuffer {
        phys_addr,
        width,
        height,
        row_bytes,
        depth,
    })
}
