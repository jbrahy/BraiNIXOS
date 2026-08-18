//! aarch64 identification-register decoding.
//!
//! Pure functions over register *values*. Nothing here executes an instruction,
//! which is why it lives outside `arch::aarch64` and is compiled on every
//! target: `arch` is gated to bare metal, correctly, because it contains `mrs`.
//! Gating the decode with it would leave the only part with a checkable
//! contract untested.
//!
//! The values these decode were read off the deployment machine, not taken from
//! the manual. See `tests/aarch64_registers.rs`.

/// What the implementation supports, decoded from `ID_AA64MMFR0_EL1`.
///
/// Decoded here rather than at the use site because the encodings are not
/// uniform: `PARange` is a lookup, and each granule field uses a *different*
/// sentinel for "not supported" (`0b1111` for 4K and 64K, `0b0000` for 16K).
/// Getting that backwards yields a `TCR_EL1` that selects an unsupported
/// granule, which is unrecoverable on this hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryModel {
    /// Physical address size in bits, or `None` if the encoding is reserved.
    pub physical_address_bits: Option<u8>,
    /// 4 KiB granule supported at stage 1.
    pub granule_4k: bool,
    /// 16 KiB granule supported at stage 1.
    pub granule_16k: bool,
    /// 64 KiB granule supported at stage 1.
    pub granule_64k: bool,
}

impl MemoryModel {
    /// Decode `ID_AA64MMFR0_EL1`.
    pub fn from_id_register(value: u64) -> Self {
        // PARange, bits [3:0]. Table D17-2; 0b0111 and above are reserved on
        // the revisions this targets.
        let physical_address_bits = match value & 0xF {
            0b0000 => Some(32),
            0b0001 => Some(36),
            0b0010 => Some(40),
            0b0011 => Some(42),
            0b0100 => Some(44),
            0b0101 => Some(48),
            0b0110 => Some(52),
            _ => None,
        };

        // TGran4  [31:28]: 0b1111 means NOT supported.
        // TGran64 [27:24]: 0b1111 means NOT supported.
        // TGran16 [23:20]: 0b0000 means NOT supported -- the odd one out, and
        // the reason this decode is a function with tests rather than three
        // inline comparisons.
        let tgran4 = (value >> 28) & 0xF;
        let tgran64 = (value >> 24) & 0xF;
        let tgran16 = (value >> 20) & 0xF;

        Self {
            physical_address_bits,
            granule_4k: tgran4 != 0b1111,
            granule_64k: tgran64 != 0b1111,
            granule_16k: tgran16 != 0b0000,
        }
    }
}
