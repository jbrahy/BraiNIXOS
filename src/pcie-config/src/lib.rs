#![no_std]
#![deny(unsafe_code)]

//! Walking a PCIe capability list that a hostile device wrote (AS-4b1).
//!
//! `SECURITY_INVARIANTS.md` §16 puts this walker at **Full tier** inside a
//! Reduced-tier driver, and says why in one sentence: *"a malicious device can
//! present a cyclic capability list, and the walker must terminate and deny."*
//!
//! That is the whole specification of this module. The capability list is a
//! linked list stored in config space, every pointer in it is written by the
//! device, and a device that wants the driver to hang only has to point a
//! capability at itself.
//!
//! # Termination is structural, not a timeout
//!
//! Three independent bounds, and each denies rather than truncating quietly:
//!
//! - **A visited set.** A pointer that has already been walked ends the walk
//!   with [`WalkError::Cycle`]. This catches the self-pointing capability and
//!   the long loop equally, because a loop of any length revisits.
//! - **A hard step limit.** Config space is 256 bytes and a capability header
//!   is 2, so no honest list exceeds [`MAX_CAPABILITIES`] entries. A walk that
//!   reaches it denies, which covers any cycle the visited set could somehow
//!   miss.
//! - **Range and alignment.** A pointer outside config space, or into the first
//!   64 bytes where the standard header lives, or misaligned, is refused before
//!   it is followed.
//!
//! Any one of the three would terminate the walk. All three are here because
//! they fail differently, and the one that catches a given hostile list is not
//! the one a reader would predict.
//!
//! # Standard, not reverse-engineered
//!
//! The layout is PCI-SIG's, published, and the same on every platform. Nothing
//! here is Apple-specific and the clean-room procedure does not apply — unlike
//! the RTKit and ANS2 work beside it in AS-4, which needs a fact table first.

/// Bytes of type 0 configuration space.
pub const CONFIG_SPACE_LEN: usize = 256;

/// Where the standard header ends and capabilities may begin.
///
/// A capability pointer into the first 64 bytes would overlay the header the
/// driver has already parsed — a device could point its "capability" at its own
/// vendor ID and watch a driver interpret it as a capability header.
pub const HEADER_LEN: u8 = 0x40;

/// Offset of the capabilities pointer in the standard header.
pub const CAPABILITIES_POINTER: usize = 0x34;

/// Bit 4 of the status register: whether a capability list exists at all.
pub const STATUS_CAPABILITIES_BIT: u16 = 1 << 4;

/// The most capabilities an honest list can hold.
///
/// 256 bytes of config space, 64 of header, 2 bytes per capability header:
/// 96 is already generous, and a list longer than this is not a list.
pub const MAX_CAPABILITIES: usize = 96;

/// One capability, as the walker found it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    /// The capability's identifier byte.
    pub id: u8,
    /// Where it lives in config space.
    pub offset: u8,
}

/// Why a walk stopped early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkError {
    /// A pointer led to an offset already visited.
    Cycle,
    /// A pointer led outside config space or into the standard header.
    OutOfRange,
    /// A pointer was not four-byte aligned, as the specification requires.
    Misaligned,
    /// The walk reached [`MAX_CAPABILITIES`] without ending.
    TooManyCapabilities,
    /// The configuration space handed in was not [`CONFIG_SPACE_LEN`] bytes.
    ShortConfigSpace,
}

/// Walks the capability list, writing what it finds into `out`.
///
/// Returns how many capabilities were found. Stops at the first malformed
/// pointer and reports why, because a driver that continued past one would be
/// following a list the device has already shown it is lying about.
///
/// # Errors
///
/// [`WalkError`], one variant per way a device can misbehave.
pub fn walk(config_space: &[u8], out: &mut [Capability]) -> Result<usize, WalkError> {
    if config_space.len() != CONFIG_SPACE_LEN {
        return Err(WalkError::ShortConfigSpace);
    }

    // No capability list is not an error: most devices have none.
    let status = u16::from_le_bytes([
        *config_space.get(0x06).ok_or(WalkError::ShortConfigSpace)?,
        *config_space.get(0x07).ok_or(WalkError::ShortConfigSpace)?,
    ]);
    if status & STATUS_CAPABILITIES_BIT == 0 {
        return Ok(0);
    }

    let mut visited = [false; CONFIG_SPACE_LEN];
    let mut offset = *config_space
        .get(CAPABILITIES_POINTER)
        .ok_or(WalkError::ShortConfigSpace)?;
    let mut found = 0;

    while offset != 0 {
        // COVERAGE-EXEMPT: unreachable given the other checks, and kept
        // because it does not depend on them. An offset must be >= HEADER_LEN
        // (0x40), 4-byte aligned and inside 256 bytes, which allows 48 distinct
        // offsets; `visited` refuses a repeat. So a walk ends in `Cycle` by the
        // 49th entry and `found` cannot reach MAX_CAPABILITIES at 96. This is
        // the bound that survives if the alignment or header rules are relaxed.
        if found >= MAX_CAPABILITIES {
            return Err(WalkError::TooManyCapabilities);
        }
        if offset < HEADER_LEN {
            return Err(WalkError::OutOfRange);
        }
        if !offset.is_multiple_of(4) {
            return Err(WalkError::Misaligned);
        }
        let at = usize::from(offset);
        // The header is two bytes: an id and the next pointer. A capability
        // whose second byte falls outside config space is out of range even
        // though its first byte is inside.
        let next_at = at.checked_add(1).ok_or(WalkError::OutOfRange)?;
        // COVERAGE-EXEMPT: the largest offset passing the alignment and
        // header checks above is 252, so `next_at` is at most 253 and always
        // inside 256 bytes. Kept for the same reason as the capability bound:
        // it is the check that still holds if the alignment rule changes.
        if next_at >= CONFIG_SPACE_LEN {
            return Err(WalkError::OutOfRange);
        }
        let already = visited.get_mut(at).ok_or(WalkError::OutOfRange)?;
        if *already {
            return Err(WalkError::Cycle);
        }
        *already = true;

        let id = *config_space.get(at).ok_or(WalkError::OutOfRange)?;
        if let Some(slot) = out.get_mut(found) {
            *slot = Capability { id, offset };
        }
        found = found.saturating_add(1);

        offset = *config_space.get(next_at).ok_or(WalkError::OutOfRange)?;
    }

    Ok(found)
}
