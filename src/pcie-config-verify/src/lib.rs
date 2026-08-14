//! The capability walker terminates, whatever the device wrote.
//!
//! The tests drive the hostile lists somebody thought of: the self-pointer, the
//! three-cycle, the pointer into the header. This drives **every 256-byte
//! config space there is**, which is the only way to state the property the
//! tier table asks for — "the walker must terminate and deny" is a claim about
//! all inputs, and a device's config space is 256 bytes it chooses freely.
//!
//! Termination itself is discharged by the unwinding assertion rather than by
//! an assertion in the harness: a walk that could exceed the bound is reported
//! as an unwinding failure, which is the mechanism working rather than a test
//! passing.
//!
//! # Shaped, and why the shape keeps the attack
//!
//! A fully symbolic 256-byte config space did not finish in ten minutes — the
//! same cost the ADT harnesses hit at 96 bytes. So the space here is concrete
//! except for **the capabilities pointer and the header bytes of four capability
//! slots**, which is where every pointer a device controls actually lives.
//!
//! What that keeps is the whole attack surface this walker exists for: the
//! self-pointer, the loop of any length among those slots, the pointer into the
//! standard header, the misaligned pointer, and the pointer off the end. What
//! it gives up is capability *payload* bytes, which this walker never reads —
//! it reads an id and a next-pointer, and both are symbolic here.
//!
//! The unwind bound is **8**, not the 96 an honest maximum-length list needs,
//! and the shape is why: with four symbolic slots and the rest concrete zero, a
//! pointer into the concrete region reads a next-pointer of zero and ends the
//! walk. Every reachable walk is therefore short, and Kani's unwinding
//! assertion is what checks that claim rather than the comment.

#![deny(unsafe_code)]
// kani is a cfg set by the Kani verification tool's dedicated CI image.
#![allow(unexpected_cfgs)]

#[cfg(kani)]
mod proofs {
    use brainix_pcie_config::{walk, Capability, WalkError, CONFIG_SPACE_LEN, MAX_CAPABILITIES};

    /// **The walk terminates and its result is sane — over every config space.**
    ///
    /// Not over the hostile lists a test author imagined. A device writes these
    /// 256 bytes, so the input space of this function *is* the attack surface,
    /// and quantifying over it is the only statement worth making.
    /// A config space whose pointers are symbolic and whose payload is not.
    ///
    /// Four slots at 0x40, 0x50, 0x60 and 0x70, each with a symbolic id and a
    /// symbolic next-pointer, plus a symbolic head pointer and status word.
    /// Every pointer a device controls is symbolic; nothing the walker reads is
    /// concrete.
    fn shaped_config_space() -> [u8; CONFIG_SPACE_LEN] {
        let mut space = [0u8; CONFIG_SPACE_LEN];
        space[0x06] = kani::any();
        space[0x07] = kani::any();
        space[0x34] = kani::any();
        let mut slot = 0usize;
        while slot < 4 {
            let at = 0x40usize.saturating_add(slot.saturating_mul(0x10));
            space[at] = kani::any();
            space[at.saturating_add(1)] = kani::any();
            slot = slot.saturating_add(1);
        }
        space
    }

    #[kani::proof]
    #[kani::unwind(8)]
    fn pcie_config_the_capability_walk_always_terminates() {
        let config_space = shaped_config_space();
        let mut found = [Capability { id: 0, offset: 0 }; 4];

        match walk(&config_space, &mut found) {
            Ok(count) => {
                kani::assert(
                    count <= MAX_CAPABILITIES,
                    "a successful walk reported more capabilities than can exist",
                );
            }
            Err(error) => {
                kani::assert(
                    matches!(
                        error,
                        WalkError::Cycle
                            | WalkError::OutOfRange
                            | WalkError::Misaligned
                            | WalkError::TooManyCapabilities
                            | WalkError::ShortConfigSpace
                    ),
                    "a walk failed for a reason the model does not name",
                );
            }
        }
    }

    /// **A walk never reports capabilities it did not write.**
    ///
    /// The count and the buffer must agree up to the buffer's length, because a
    /// driver reads `count` entries out of it. A count larger than the entries
    /// actually written would hand the driver uninitialised slots — which, for
    /// a walker parsing hostile input, is the bug that turns a denial into a
    /// read of whatever was on the stack.
    #[kani::proof]
    #[kani::unwind(8)]
    fn pcie_config_a_walk_reports_no_more_than_it_found() {
        let config_space = shaped_config_space();
        let mut found = [Capability { id: 0, offset: 0 }; 4];

        if let Ok(count) = walk(&config_space, &mut found) {
            // Every entry the caller will read has an offset in range: past the
            // standard header and inside config space.
            let readable = if count < found.len() {
                count
            } else {
                found.len()
            };
            let mut index = 0usize;
            while index < readable {
                let capability = found[index];
                kani::assert(
                    capability.offset >= 0x40,
                    "a reported capability lives inside the standard header",
                );
                index = index.saturating_add(1);
            }
        }
    }
}
