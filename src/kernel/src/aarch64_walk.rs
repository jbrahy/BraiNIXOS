//! Stage-1 page-table walking, as a pure function.
//!
//! # Why this is not in `arch::aarch64`
//!
//! A walk is arithmetic over descriptors read from memory. The only part that
//! needs hardware is *reading* the memory, and that is a closure here. Keeping
//! the arithmetic out of the bare-metal module makes it host-testable, which
//! matters more here than almost anywhere else in the kernel: a walker that is
//! subtly wrong does not crash, it resolves to a plausible wrong page, and the
//! damage appears later somewhere unrelated.
//!
//! Same split as `aarch64_ident`, and the same rule the platform track has used
//! throughout: write everything that is a pure function over bytes, host-test
//! it, and stop at the hardware.
//!
//! # Verified against the CPU
//!
//! `kernel_probe` walks the *live* tables the machine is running on and
//! compares the result with the hardware's own answer, obtained from the `AT`
//! instruction. Agreement between an independent implementation and the MMU
//! itself is the only check worth having; a walker tested solely against tables
//! this repository also built would only confirm that we are self-consistent.

/// How translation is configured, decoded from `TCR_ELx`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalkConfig {
    /// Bits of the granule: 12 for 4 KiB, 14 for 16 KiB, 16 for 64 KiB.
    pub granule_bits: u32,
    /// `T0SZ`: the input address is `64 - t0sz` bits wide.
    pub t0sz: u32,
}

impl WalkConfig {
    /// Decode from a `TCR_ELx` value, for the `TTBR0` half.
    ///
    /// `TG0` is bits [15:14] and its encoding is **not** in size order:
    /// `0b00` is 4 KiB, `0b01` is **64 KiB**, `0b10` is 16 KiB. Reading it as
    /// ordered gives a walker that is wrong only on 16 and 64 KiB, which on
    /// Apple Silicon means wrong on the granule the platform actually favours.
    pub fn from_tcr(tcr: u64) -> Option<Self> {
        let granule_bits = match (tcr >> 14) & 0b11 {
            0b00 => 12,
            0b01 => 16,
            0b10 => 14,
            _ => return None,
        };
        let t0sz = u32::try_from(tcr & 0x3F).ok()?;
        // T0SZ outside 16..=39 is not a configuration this walker can describe.
        if !(16..=39).contains(&t0sz) {
            return None;
        }
        Some(Self { granule_bits, t0sz })
    }

    /// Number of table levels the walk will traverse.
    pub fn levels(&self) -> u32 {
        let index_bits = self.input_address_bits().saturating_sub(self.granule_bits);
        let stride = self.stride();
        // Ceiling division: a partial top level still costs a lookup.
        index_bits.div_ceil(stride).max(1)
    }

    /// Bits resolved per table level.
    pub fn stride(&self) -> u32 {
        self.granule_bits.saturating_sub(3)
    }

    /// Width of the input address, in bits.
    pub fn input_address_bits(&self) -> u32 {
        64u32.saturating_sub(self.t0sz)
    }
}

/// Why a walk did not produce an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkError {
    /// A descriptor's low bits marked it invalid.
    InvalidDescriptor { level: u32, descriptor: u64 },
    /// The virtual address has bits set above the configured input width.
    AddressOutOfRange,
    /// A block descriptor appeared at a level where the architecture does not
    /// permit one.
    BlockAtIllegalLevel { level: u32 },
    /// `TCR` did not decode.
    UnsupportedConfiguration,
}

/// A resolved translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Translation {
    /// The physical address the virtual address maps to.
    pub physical_address: u64,
    /// The descriptor that terminated the walk.
    pub descriptor: u64,
    /// Which level terminated it. Lower numbers are larger mappings.
    pub level: u32,
    /// Whether it terminated on a block rather than a page.
    pub is_block: bool,
}

/// Walk stage-1 tables from `root` and translate `virtual_address`.
///
/// `read_descriptor` is handed a physical address and must return the 64-bit
/// descriptor there. Passing it in rather than reading memory directly is what
/// makes every branch below reachable from a host test.
pub fn walk(
    root: u64,
    virtual_address: u64,
    config: WalkConfig,
    read_descriptor: impl Fn(u64) -> u64,
) -> Result<Translation, WalkError> {
    let input_bits = config.input_address_bits();
    if input_bits < 64 {
        let limit = 1u64.checked_shl(input_bits).unwrap_or(u64::MAX);
        // Compare against the low half only. A TTBR0 address has its high bits
        // clear by definition; anything else belongs to TTBR1 and this walk
        // would silently produce a wrong answer for it.
        if virtual_address >= limit {
            return Err(WalkError::AddressOutOfRange);
        }
    }

    let levels = config.levels();
    let stride = config.stride();
    let granule = 1u64 << config.granule_bits;
    // Output-address field: granule-aligned, and 48 bits wide on every
    // configuration this targets.
    let address_mask = ((1u64 << 48) - 1) & !(granule - 1);

    let mut table = root & address_mask;

    for step in 0..levels {
        // The top level may resolve fewer bits than a full stride when the
        // input width is not a whole multiple of it.
        let shift = config
            .granule_bits
            .saturating_add(stride.saturating_mul(levels.saturating_sub(step).saturating_sub(1)));
        let bits_here = if step == 0 {
            input_bits.saturating_sub(shift).min(stride)
        } else {
            stride
        };
        let index = (virtual_address >> shift) & ((1u64 << bits_here) - 1);

        let entry_address = table.saturating_add(index.saturating_mul(8));
        let descriptor = read_descriptor(entry_address);

        let is_last = step == levels.saturating_sub(1);
        match descriptor & 0b11 {
            // Table at a non-final level; page at the final one.
            0b11 => {
                if is_last {
                    let page_base = descriptor & address_mask;
                    let offset = virtual_address & (granule - 1);
                    return Ok(Translation {
                        physical_address: page_base | offset,
                        descriptor,
                        level: step,
                        is_block: false,
                    });
                }
                table = descriptor & address_mask;
            }
            // Block. Only legal above the final level; a `0b01` there is a
            // reserved encoding, not a large page.
            0b01 => {
                if is_last {
                    return Err(WalkError::BlockAtIllegalLevel { level: step });
                }
                let block_size = 1u64 << shift;
                let block_base = descriptor & address_mask & !(block_size - 1);
                let offset = virtual_address & (block_size - 1);
                return Ok(Translation {
                    physical_address: block_base | offset,
                    descriptor,
                    level: step,
                    is_block: true,
                });
            }
            _ => {
                return Err(WalkError::InvalidDescriptor {
                    level: step,
                    descriptor,
                })
            }
        }
    }

    Err(WalkError::UnsupportedConfiguration)
}
