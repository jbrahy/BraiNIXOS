#![no_std]
#![deny(unsafe_code)]

//! aarch64 stage-1 translation descriptors, in which W^X is unrepresentable
//! (AS-1b).
//!
//! `INV-MEM` is *"W^X holds for every page, always"*, and the roadmap is
//! specific about where that obligation went when the HAL was cancelled: it
//! **attaches to the aarch64 MMU at AS-1 and stays Full tier**. This is the
//! encoding half of it, which is host-testable — the format is ARM's
//! VMSAv8-64, documented in the architecture reference manual, so nothing here
//! is reverse-engineered and the clean-room procedure does not apply.
//!
//! # W^X is a type, not a check
//!
//! A descriptor built from raw permission bits can be writable and executable,
//! and then something must notice. [`Permission`] has **three variants and no
//! fourth**: read-only executable, read-write never-executable, read-only
//! never-executable. There is no constructor that takes "writable" and
//! "executable" separately, so the violating page is not rejected — it cannot
//! be spelled.
//!
//! That matters more here than in most places, because the failure is silent:
//! a page that is writable and executable looks exactly like a page that works,
//! right up until something writes code into it.
//!
//! # 16 KiB, and why the granule is a parameter
//!
//! Apple Silicon's base page is 16 KiB. `INV-MEM-009` makes a hardcoded page
//! size a defect *including a hardcoded 16 KiB*, since architecture-neutral code
//! must not assume either — so [`Granule`] is explicit and the descriptor
//! carries it. The frozen x86-64 reference's 4 KiB is not expressible here at
//! all, which is correct: this is the aarch64 MMU, and a 4 KiB granule on it
//! would be a different architecture's assumption arriving by copy-paste.

/// The translation granule, in bytes.
///
/// aarch64 defines three. Apple Silicon uses 16 KiB, and the others are here
/// because the field exists in the architecture and pretending otherwise would
/// be the same assumption in the other direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granule {
    /// 4 KiB pages.
    Small,
    /// 16 KiB pages — the Apple Silicon base page.
    Medium,
    /// 64 KiB pages.
    Large,
}

impl Granule {
    /// The granule's size in bytes.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        match self {
            Self::Small => 4096,
            Self::Medium => 16384,
            Self::Large => 65536,
        }
    }

    /// Whether an address is granule-aligned.
    #[must_use]
    pub const fn is_aligned(self, address: u64) -> bool {
        address % self.bytes() == 0
    }
}

/// What a mapping permits.
///
/// **Three variants, and the absence of a fourth is the invariant.** There is
/// no `ReadWriteExecute`, so `INV-MEM-003` is not enforced by this module — it
/// is enforced by the type, and this module simply cannot express the
/// violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Executable, and never writable: code.
    ReadOnlyExecute,
    /// Writable, and never executable: data, stacks, the KV cache.
    ReadWriteNoExecute,
    /// Neither writable nor executable: sealed weights, read-only tables.
    ReadOnlyNoExecute,
}

impl Permission {
    /// Whether a mapping with this permission may be written.
    #[must_use]
    pub const fn is_writable(self) -> bool {
        matches!(self, Self::ReadWriteNoExecute)
    }

    /// Whether a mapping with this permission may be executed.
    #[must_use]
    pub const fn is_executable(self) -> bool {
        matches!(self, Self::ReadOnlyExecute)
    }
}

/// Which exception level the mapping serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// EL1: the kernel.
    Kernel,
    /// EL0: userspace.
    User,
}

// VMSAv8-64 stage-1 page-descriptor bits, from the architecture reference
// manual. Named rather than inlined so a reader can check each against the
// manual without decoding a hexadecimal literal.

/// Bits [1:0] = 0b11: a page descriptor at the last level.
const DESCRIPTOR_PAGE: u64 = 0b11;
/// Bit 10, the access flag. A descriptor without it faults on first touch.
const ACCESS_FLAG: u64 = 1 << 10;
/// Bits [7:6] = 0b01: read/write at EL0 and EL1.
const AP_READ_WRITE_ALL: u64 = 0b01 << 6;
/// Bits [7:6] = 0b11: read-only at EL0 and EL1.
const AP_READ_ONLY_ALL: u64 = 0b11 << 6;
/// Bits [7:6] = 0b00: read/write at EL1, no access at EL0.
const AP_READ_WRITE_KERNEL: u64 = 0b00 << 6;
/// Bits [7:6] = 0b10: read-only at EL1, no access at EL0.
const AP_READ_ONLY_KERNEL: u64 = 0b10 << 6;
/// Bit 53: privileged execute-never.
const PXN: u64 = 1 << 53;
/// Bit 54: unprivileged execute-never.
const UXN: u64 = 1 << 54;
/// Bits [47:12] of the output address, for the 4 KiB granule's descriptor form.
const OUTPUT_ADDRESS_MASK: u64 = 0x0000_FFFF_FFFF_F000;

/// A stage-1 page descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Descriptor {
    bits: u64,
    permission: Permission,
    granule: Granule,
}

/// Why a descriptor could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorError {
    /// The output address is not granule-aligned.
    Misaligned,
    /// The output address has bits outside the encodable field.
    AddressTooLarge,
}

impl Descriptor {
    /// Builds a page descriptor.
    ///
    /// # Errors
    ///
    /// [`DescriptorError::Misaligned`] for an address that is not a multiple of
    /// the granule, and [`DescriptorError::AddressTooLarge`] for one that does
    /// not fit the output-address field. Both deny rather than truncating: a
    /// truncated address maps the wrong page, which is a mapping that works
    /// until it corrupts something.
    pub const fn page(
        output_address: u64,
        permission: Permission,
        level: Level,
        granule: Granule,
    ) -> Result<Self, DescriptorError> {
        if !granule.is_aligned(output_address) {
            return Err(DescriptorError::Misaligned);
        }
        if output_address & !OUTPUT_ADDRESS_MASK != 0 {
            return Err(DescriptorError::AddressTooLarge);
        }

        let access = match (permission, level) {
            (Permission::ReadWriteNoExecute, Level::User) => AP_READ_WRITE_ALL,
            (Permission::ReadWriteNoExecute, Level::Kernel) => AP_READ_WRITE_KERNEL,
            (_, Level::User) => AP_READ_ONLY_ALL,
            (_, Level::Kernel) => AP_READ_ONLY_KERNEL,
        };

        // The execute-never bits, and this is where W^X becomes bits. A
        // writable permission sets **both** XN bits: not merely the one for the
        // level being mapped, because a page writable at EL0 and executable at
        // EL1 is the same defect wearing a different hat.
        let execute_never = match permission {
            Permission::ReadOnlyExecute => match level {
                // Executable where it is mapped, never at the other level.
                Level::Kernel => UXN,
                Level::User => PXN,
            },
            Permission::ReadWriteNoExecute | Permission::ReadOnlyNoExecute => UXN | PXN,
        };

        Ok(Self {
            bits: output_address | access | execute_never | ACCESS_FLAG | DESCRIPTOR_PAGE,
            permission,
            granule,
        })
    }

    /// The raw descriptor, as written into a translation table.
    #[must_use]
    pub const fn bits(&self) -> u64 {
        self.bits
    }

    /// The permission this descriptor was built with.
    #[must_use]
    pub const fn permission(&self) -> Permission {
        self.permission
    }

    /// The granule this descriptor was built for.
    #[must_use]
    pub const fn granule(&self) -> Granule {
        self.granule
    }

    /// The output address the descriptor maps to.
    #[must_use]
    pub const fn output_address(&self) -> u64 {
        self.bits & OUTPUT_ADDRESS_MASK
    }

    /// Whether the encoded bits permit writing.
    ///
    /// Read back **from the bits** rather than from the permission field, so a
    /// disagreement between what was asked for and what was encoded is
    /// detectable — which is the only way an encoding bug shows up before
    /// hardware.
    #[must_use]
    pub const fn bits_permit_write(&self) -> bool {
        let access = self.bits & (0b11 << 6);
        access == AP_READ_WRITE_ALL || access == AP_READ_WRITE_KERNEL
    }

    /// Whether the encoded bits permit execution at either level.
    #[must_use]
    pub const fn bits_permit_execute(&self) -> bool {
        self.bits & UXN == 0 || self.bits & PXN == 0
    }

    /// Whether this descriptor violates W^X.
    ///
    /// Always false, and the tests and proofs are what make that a fact rather
    /// than a claim. It exists so the property can be *asked* — a page table
    /// walker can call it on descriptors it did not build.
    #[must_use]
    pub const fn violates_write_xor_execute(&self) -> bool {
        self.bits_permit_write() && self.bits_permit_execute()
    }
}
