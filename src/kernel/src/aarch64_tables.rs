//! Building stage-1 translation tables.
//!
//! Pure arithmetic over a caller-supplied arena, so all of it is host-testable
//! and is checked by [`crate::aarch64_walk`] -- the walker that was validated
//! against the MMU's own `AT` instruction on real hardware. Build with one,
//! walk with the other, and the two are independent implementations of opposite
//! directions of the same specification. That is the only reason to trust
//! either of them.
//!
//! # No allocator, by construction
//!
//! The kernel has none, and a page-table builder that allocates is one that can
//! fail at the worst possible moment. The caller hands over a slice; when it is
//! exhausted this returns [`BuildError::OutOfTables`] rather than doing
//! anything clever.
//!
//! # Granularity is a permissions question
//!
//! [`TableBuilder::map_blocks`] and [`TableBuilder::map_pages`] both exist
//! because the size of a mapping and the size of a *permission* are not the
//! same question. Blocks describe "all of DRAM belongs to the kernel" in a few
//! hundred descriptors. They cannot describe "this one page is reachable from
//! EL0", because the smallest thing a block can say anything about at this
//! granule is 32 MiB -- and 32 MiB of EL0-accessible memory here contains the
//! kernel's own code.
//!
//! # Blocks, not pages
//!
//! Identity-mapping the target's 32 GiB out of leaf pages at a 16 KiB granule
//! needs two million descriptors and 16 MiB of tables, to describe a mapping
//! that is entirely regular. Block descriptors one level up describe the same
//! thing in a few hundred entries.
//!
//! That is not only about memory. The boot path has to *finish*: a loop over
//! two million entries before the first line of output is a boot that looks
//! like a hang, on a machine where a hang is the failure mode we cannot
//! diagnose.
//!
//! # What this does not do
//!
//! It does not write `TTBR`, `TCR` or `SCTLR`. Building tables is safe and
//! checkable; installing them is not, and lives in `arch::aarch64::mmu` where
//! the barriers and the ordering are documented.

/// A table hierarchy under construction over caller-owned memory.
pub struct TableBuilder<'arena> {
    arena: &'arena mut [u64],
    /// Physical address that `arena[0]` lives at.
    base: u64,
    granule_bits: u32,
    input_bits: u32,
    levels: u32,
    tables_used: usize,
}

/// Why a table could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildError {
    /// The arena has no room for another table.
    OutOfTables,
    /// The arena's physical base is not granule-aligned.
    MisalignedArena,
    /// An address does not fit the configured input width.
    AddressOutOfRange,
    /// A range's start, target or length is not a multiple of the block size.
    MisalignedRange,
    /// The granule or input width is not one this builder supports.
    UnsupportedConfiguration,
    /// A descriptor already present would have been overwritten.
    ///
    /// Denies rather than replacing. Silently overwriting a live mapping is how
    /// two subsystems end up disagreeing about who owns an address, and the
    /// loser finds out by corrupting memory.
    AlreadyMapped,
}

impl<'arena> TableBuilder<'arena> {
    /// Create a builder over `arena`, which lives at physical address `base`.
    pub fn new(
        arena: &'arena mut [u64],
        base: u64,
        granule_bits: u32,
        input_bits: u32,
    ) -> Result<Self, BuildError> {
        if !(12..=16).contains(&granule_bits) || granule_bits == 13 || granule_bits == 15 {
            return Err(BuildError::UnsupportedConfiguration);
        }
        if !(16..=48).contains(&input_bits) {
            return Err(BuildError::UnsupportedConfiguration);
        }
        let granule = 1u64 << granule_bits;
        // Granule-aligned, spelled as the divisibility test it is. The
        // subtraction form is exact here -- `granule_bits` is checked above --
        // but `is_multiple_of` says what is being asked rather than how.
        if !base.is_multiple_of(granule) {
            return Err(BuildError::MisalignedArena);
        }

        // Cannot underflow: `granule_bits` is 12, 14 or 16 by the check above.
        let stride = granule_bits.saturating_sub(3);
        let levels = input_bits
            .saturating_sub(granule_bits)
            .div_ceil(stride)
            .max(1);

        let mut builder = Self {
            arena,
            base,
            granule_bits,
            input_bits,
            levels,
            tables_used: 0,
        };
        // The root is table zero. Allocating it here means `root()` is valid
        // before any mapping call, which keeps the "build then install" order
        // available even for an empty map.
        builder.allocate_table()?;
        Ok(builder)
    }

    /// Physical address of the root table, for `TTBR`.
    pub fn root(&self) -> u64 {
        self.base
    }

    /// Tables consumed so far.
    pub fn tables_used(&self) -> usize {
        self.tables_used
    }

    /// Levels the walk will traverse.
    pub fn levels(&self) -> u32 {
        self.levels
    }

    /// Bits resolved per level.
    fn stride(&self) -> u32 {
        self.granule_bits.saturating_sub(3)
    }

    /// Descriptors per table.
    fn entries_per_table(&self) -> usize {
        1usize << self.stride()
    }

    /// Size of a block at the level above the last.
    ///
    /// The architecture permits block descriptors at exactly one level for each
    /// granule: 2 MiB at 4 KiB, 32 MiB at 16 KiB, 512 MiB at 64 KiB. Mapping a
    /// block at any other level is a reserved encoding, not a bigger page.
    pub fn block_size(&self) -> u64 {
        1u64 << self.granule_bits.saturating_add(self.stride())
    }

    /// Index of the level blocks are written at.
    fn block_level(&self) -> u32 {
        self.levels.saturating_sub(2)
    }

    /// Shift for the index at `level`.
    fn shift_for(&self, level: u32) -> u32 {
        self.granule_bits
            .saturating_add(self.stride().saturating_mul(
                self.levels.saturating_sub(level).saturating_sub(1),
            ))
    }

    /// Take the next unused table, zero it, return its physical address.
    fn allocate_table(&mut self) -> Result<u64, BuildError> {
        let entries = self.entries_per_table();
        let start = self
            .tables_used
            .checked_mul(entries)
            .ok_or(BuildError::OutOfTables)?;
        let end = start.checked_add(entries).ok_or(BuildError::OutOfTables)?;
        if end > self.arena.len() {
            return Err(BuildError::OutOfTables);
        }
        // Zeroed, not assumed zero. An unzeroed table is full of whatever was
        // in that memory, and a stale low bit pair is a descriptor the MMU will
        // follow into nothing.
        for slot in self
            .arena
            .get_mut(start..end)
            .ok_or(BuildError::OutOfTables)?
        {
            *slot = 0;
        }
        let address = self
            .base
            .saturating_add((start as u64).saturating_mul(8));
        self.tables_used = self.tables_used.saturating_add(1);
        Ok(address)
    }

    /// Slice index of the descriptor at `table_address` + `index`.
    fn slot_of(&self, table_address: u64, index: u64) -> Result<usize, BuildError> {
        let byte_offset = table_address
            .checked_sub(self.base)
            .ok_or(BuildError::OutOfTables)?;
        let slot = (byte_offset / 8).saturating_add(index);
        usize::try_from(slot).map_err(|_| BuildError::OutOfTables)
    }

    /// Map `length` bytes at `virtual_address` to `physical_address`, using
    /// block descriptors.
    ///
    /// `attributes` supplies everything above bits [1:0] and the output
    /// address: access flag, permissions, shareability, memory type. This
    /// module owns *structure*, not policy; `brainix_aarch64_mmu` owns the bits
    /// that decide what a mapping permits, and keeping them apart is what stops
    /// this file from quietly inventing a W^X-violating descriptor.
    pub fn map_blocks(
        &mut self,
        virtual_address: u64,
        physical_address: u64,
        length: u64,
        attributes: u64,
    ) -> Result<(), BuildError> {
        let block = self.block_size();
        if !virtual_address.is_multiple_of(block)
            || !physical_address.is_multiple_of(block)
            || !length.is_multiple_of(block)
        {
            return Err(BuildError::MisalignedRange);
        }
        if self.input_bits < 64 {
            let limit = 1u64 << self.input_bits;
            let end = virtual_address
                .checked_add(length)
                .ok_or(BuildError::AddressOutOfRange)?;
            if end > limit {
                return Err(BuildError::AddressOutOfRange);
            }
        }

        let mut offset = 0u64;
        while offset < length {
            self.map_one_block(
                virtual_address.saturating_add(offset),
                physical_address.saturating_add(offset),
                attributes,
            )?;
            offset = offset.saturating_add(block);
        }
        Ok(())
    }

    fn map_one_block(
        &mut self,
        virtual_address: u64,
        physical_address: u64,
        attributes: u64,
    ) -> Result<(), BuildError> {
        let block_level = self.block_level();
        let mut table = self.base;

        // Descend, creating tables, to the level blocks live at.
        for level in 0..block_level {
            let index = self.index_at(virtual_address, level);
            let slot = self.slot_of(table, index)?;
            let existing = *self.arena.get(slot).ok_or(BuildError::OutOfTables)?;

            table = if existing & 0b11 == 0b11 {
                // Already a table descriptor; descend into it.
                existing & self.address_mask()
            } else if existing == 0 {
                let fresh = self.allocate_table()?;
                let descriptor = fresh | 0b11;
                *self.arena.get_mut(slot).ok_or(BuildError::OutOfTables)? = descriptor;
                fresh
            } else {
                // A block already covers this range at a higher level.
                return Err(BuildError::AlreadyMapped);
            };
        }

        let index = self.index_at(virtual_address, block_level);
        let slot = self.slot_of(table, index)?;
        let existing = *self.arena.get(slot).ok_or(BuildError::OutOfTables)?;
        if existing != 0 {
            return Err(BuildError::AlreadyMapped);
        }
        // 0b01 is the block encoding. Only legal at this level.
        *self.arena.get_mut(slot).ok_or(BuildError::OutOfTables)? =
            (physical_address & self.address_mask()) | attributes | 0b01;
        Ok(())
    }

    /// Map `length` bytes at page granularity rather than in blocks.
    ///
    /// # Why both exist
    ///
    /// Blocks describe a regular range in a few hundred descriptors and are the
    /// right tool for "all of DRAM belongs to the kernel". They are the wrong
    /// tool the moment a *smaller* region needs different permissions, because
    /// the smallest thing a block can say something about is 32 MiB at this
    /// granule. Giving EL0 access to a page by marking its block accessible
    /// hands userspace 32 MiB, which here contains the kernel's own code.
    ///
    /// So this maps leaf descriptors: one per granule, permissions expressible
    /// at the size the permission is actually about.
    ///
    /// # Splitting a block is not attempted
    ///
    /// If a block descriptor already covers this range, mapping returns
    /// [`BuildError::AlreadyMapped`] rather than replacing it with a table.
    /// Splitting a live block is a real operation, but it is one that has to
    /// happen with break-before-make and TLB maintenance against a running
    /// machine, and doing it silently inside a builder is how a range ends up
    /// briefly unmapped underneath the code doing the mapping. The caller maps
    /// the fine-grained region *before* the coarse one, or asks for a hole.
    pub fn map_pages(
        &mut self,
        virtual_address: u64,
        physical_address: u64,
        length: u64,
        attributes: u64,
    ) -> Result<(), BuildError> {
        let granule = 1u64 << self.granule_bits;
        if !virtual_address.is_multiple_of(granule)
            || !physical_address.is_multiple_of(granule)
            || !length.is_multiple_of(granule)
        {
            return Err(BuildError::MisalignedRange);
        }
        if self.input_bits < 64 {
            let limit = 1u64 << self.input_bits;
            let end = virtual_address
                .checked_add(length)
                .ok_or(BuildError::AddressOutOfRange)?;
            if end > limit {
                return Err(BuildError::AddressOutOfRange);
            }
        }

        let mut offset = 0u64;
        while offset < length {
            self.map_one_page(
                virtual_address.saturating_add(offset),
                physical_address.saturating_add(offset),
                attributes,
            )?;
            offset = offset.saturating_add(granule);
        }
        Ok(())
    }

    fn map_one_page(
        &mut self,
        virtual_address: u64,
        physical_address: u64,
        attributes: u64,
    ) -> Result<(), BuildError> {
        let last = self.levels.saturating_sub(1);
        let mut table = self.base;

        // Descend to the final level, creating tables. One level deeper than
        // `map_one_block`, which stops where blocks are legal.
        for level in 0..last {
            let index = self.index_at(virtual_address, level);
            let slot = self.slot_of(table, index)?;
            let existing = *self.arena.get(slot).ok_or(BuildError::OutOfTables)?;

            table = if existing & 0b11 == 0b11 {
                existing & self.address_mask()
            } else if existing == 0 {
                let fresh = self.allocate_table()?;
                let descriptor = fresh | 0b11;
                *self.arena.get_mut(slot).ok_or(BuildError::OutOfTables)? = descriptor;
                fresh
            } else {
                // A block covers this range at a higher level. See the note on
                // splitting in `map_pages`.
                return Err(BuildError::AlreadyMapped);
            };
        }

        let index = self.index_at(virtual_address, last);
        let slot = self.slot_of(table, index)?;
        let existing = *self.arena.get(slot).ok_or(BuildError::OutOfTables)?;
        if existing != 0 {
            return Err(BuildError::AlreadyMapped);
        }
        // 0b11 at the final level is a PAGE. The same bit pattern one level up
        // is a table descriptor, which is why this cannot be shared with
        // `map_one_block`: an identical encoding means two different things
        // depending on where it sits, and a page written at the block level is
        // a pointer the walker follows into the middle of nothing.
        *self.arena.get_mut(slot).ok_or(BuildError::OutOfTables)? =
            (physical_address & self.address_mask()) | attributes | 0b11;
        Ok(())
    }

    /// Output-address mask: granule-aligned, 48 bits wide.
    fn address_mask(&self) -> u64 {
        (1u64 << 48).wrapping_sub(1) & !(1u64 << self.granule_bits).wrapping_sub(1)
    }

    /// Table index for `virtual_address` at `level`.
    fn index_at(&self, virtual_address: u64, level: u32) -> u64 {
        let shift = self.shift_for(level);
        let bits = if level == 0 {
            self.input_bits.saturating_sub(shift).min(self.stride())
        } else {
            self.stride()
        };
        (virtual_address >> shift) & (1u64 << bits).wrapping_sub(1)
    }
}
