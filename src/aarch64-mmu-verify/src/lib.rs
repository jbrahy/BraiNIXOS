//! `INV-MEM-003` on the aarch64 MMU: W^X, for every descriptor it can build.
//!
//! The roadmap moved this obligation explicitly. When the HAL was cancelled the
//! W^X and page-table proof did not go away — it "attaches to the aarch64 MMU
//! at AS-1 and stays **Full tier**". This is that proof, and it can be
//! discharged now because the encoding is arithmetic over bits: the hardware is
//! needed to know the bits *do* what the manual says, not to know that the
//! encoder never sets both.
//!
//! The property is quantified over **every** output address, permission, level
//! and granule the constructor accepts, which is the whole input space of the
//! only function that produces a descriptor. A test could walk a handful of
//! addresses; the defect this excludes is an address whose bits collide with a
//! permission field, and that is exactly the case a handful of addresses
//! misses.

#![deny(unsafe_code)]
// kani is a cfg set by the Kani verification tool's dedicated CI image.
#![allow(unexpected_cfgs)]

#[cfg(kani)]
mod proofs {
    use brainix_aarch64_mmu::{Descriptor, DescriptorError, Granule, Level, Permission};

    fn any_permission() -> Permission {
        match kani::any::<u8>() % 3 {
            0 => Permission::ReadOnlyExecute,
            1 => Permission::ReadWriteNoExecute,
            _ => Permission::ReadOnlyNoExecute,
        }
    }

    fn any_level() -> Level {
        if kani::any() {
            Level::Kernel
        } else {
            Level::User
        }
    }

    fn any_granule() -> Granule {
        match kani::any::<u8>() % 3 {
            0 => Granule::Small,
            1 => Granule::Medium,
            _ => Granule::Large,
        }
    }

    /// **No descriptor is both writable and executable — over every input.**
    ///
    /// `INV-MEM-003`, and the reason it is stated over the *encoded bits*
    /// rather than over the permission enum: the enum cannot express the
    /// violation by construction, so asserting on it would prove a tautology.
    /// Reading the bits back proves the encoder did not introduce what the type
    /// forbade.
    #[kani::proof]
    fn aarch64_mmu_memory_no_descriptor_is_writable_and_executable() {
        let address: u64 = kani::any();
        let permission = any_permission();
        let level = any_level();
        let granule = any_granule();

        let Ok(descriptor) = Descriptor::page(address, permission, level, granule) else {
            return;
        };

        kani::assert(
            !descriptor.violates_write_xor_execute(),
            "a descriptor was encoded both writable and executable",
        );
        kani::assert(
            !(descriptor.bits_permit_write() && descriptor.bits_permit_execute()),
            "the encoded access and execute-never bits disagree with W^X",
        );
    }

    /// **The encoded bits say what the permission asked for.**
    ///
    /// An encoder that silently downgraded every page to read-only would
    /// satisfy W^X and break the system. The property is agreement in both
    /// directions, not merely safety in one.
    #[kani::proof]
    fn aarch64_mmu_memory_encoding_agrees_with_the_permission_requested() {
        let address: u64 = kani::any();
        let permission = any_permission();
        let level = any_level();
        let granule = any_granule();

        let Ok(descriptor) = Descriptor::page(address, permission, level, granule) else {
            return;
        };

        kani::assert(
            descriptor.bits_permit_write() == permission.is_writable(),
            "the encoded write permission is not the one requested",
        );
        kani::assert(
            descriptor.bits_permit_execute() == permission.is_executable(),
            "the encoded execute permission is not the one requested",
        );
    }

    /// **The output address survives encoding, or the descriptor is refused.**
    ///
    /// A truncated address maps the wrong page — a mapping that works until it
    /// corrupts something — so the constructor must deny rather than mask.
    #[kani::proof]
    fn aarch64_mmu_memory_an_address_is_encoded_exactly_or_refused() {
        let address: u64 = kani::any();
        let granule = any_granule();

        match Descriptor::page(address, any_permission(), any_level(), granule) {
            Ok(descriptor) => {
                kani::assert(
                    descriptor.output_address() == address,
                    "an accepted address was not encoded exactly",
                );
                kani::assert(
                    granule.is_aligned(address),
                    "an unaligned address produced a descriptor",
                );
            }
            Err(error) => {
                kani::assert(
                    matches!(
                        error,
                        DescriptorError::Misaligned | DescriptorError::AddressTooLarge
                    ),
                    "a descriptor was refused for a reason the model does not name",
                );
            }
        }
    }
}
