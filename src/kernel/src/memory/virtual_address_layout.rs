//! Virtual address layout constants per CONTEXT.md D-10.
//! These values are locked for all future phases.
//!
//! No phase may allocate VA regions outside this map without updating
//! docs/architecture/MEMORY_MODEL.md.

/// Start of the user-space virtual address range (canonical lower half).
pub const USER_SPACE_START: u64 = 0x0000_0000_0000_0000;

/// End of the user-space virtual address range (inclusive).
pub const USER_SPACE_END: u64 = 0x0000_7FFF_FFFF_FFFF;

/// Start of the kernel stack region.
pub const KERNEL_STACK_REGION_START: u64 = 0xFFFF_8000_0000_0000;

/// End of the kernel stack region (inclusive).
pub const KERNEL_STACK_REGION_END: u64 = 0xFFFF_8000_FFFF_FFFF;

/// Start of the pool region for kernel object allocators.
pub const POOL_REGION_START: u64 = 0xFFFF_8001_0000_0000;

/// End of the pool region (inclusive).
pub const POOL_REGION_END: u64 = 0xFFFF_8001_FFFF_FFFF;

/// Start of the direct-map region (physical-to-virtual 1:1).
pub const DIRECT_MAP_REGION_START: u64 = 0xFFFF_8800_0000_0000;

/// End of the direct-map region (inclusive).
pub const DIRECT_MAP_REGION_END: u64 = 0xFFFF_8800_FFFF_FFFF;

/// Fixed virtual address of the kernel binary (must match linker.ld).
pub const KERNEL_BINARY_VIRTUAL_ADDRESS: u64 = 0xFFFF_FFFF_8010_0000;

/// The architecture's base page size, in bytes.
///
/// **Not a constant of the system — a constant of the architecture.** x86-64
/// pages are 4 KiB and Apple Silicon's are 16 KiB, and this value was a bare
/// `4096` against a project whose only platform is the latter. `INV-MEM-009`
/// names a page-size assumption leaking into supposedly architecture-neutral
/// memory code as a defect rather than a portability nit, and a literal here is
/// how that leak starts: every size derived from it inherits the assumption
/// silently.
///
/// The frozen x86-64 reference keeps 4 KiB because that is what its hardware
/// does. Anything sized from this constant must be expressed in **pages**, so
/// that it means the same thing on both — see
/// [`crate::memory::reserved_regions`], which does.
#[cfg(target_arch = "x86_64")]
pub const PAGE_SIZE_IN_BYTES: usize = 4096;

/// The architecture's base page size, in bytes — 16 KiB on Apple Silicon.
///
/// See the x86-64 arm above for why this is architecture-selected rather than a
/// literal. There is no aarch64 kernel yet (AS-1); this constant exists so that
/// the first one does not begin by inheriting 4 KiB.
#[cfg(target_arch = "aarch64")]
pub const PAGE_SIZE_IN_BYTES: usize = 16384;

/// Size of each pool sub-region in bytes (512 MB per object type).
pub const POOL_SUB_REGION_SIZE: u64 = 0x2000_0000;

/// Size of each kernel stack in bytes (32 KiB).
pub const KERNEL_STACK_SIZE_IN_BYTES: u64 = 0x8000;

/// Address of the guard page for the initial kernel stack.
/// The guard page is the first page of the stack region (never mapped).
pub const INITIAL_KERNEL_STACK_GUARD_PAGE_ADDRESS: u64 = KERNEL_STACK_REGION_START;

/// Bottom of the initial kernel stack (one page above the guard page).
pub const INITIAL_KERNEL_STACK_BOTTOM: u64 = KERNEL_STACK_REGION_START + PAGE_SIZE_IN_BYTES as u64;

/// Top of the initial kernel stack (stack grows downward from here).
pub const INITIAL_KERNEL_STACK_TOP: u64 = INITIAL_KERNEL_STACK_BOTTOM + KERNEL_STACK_SIZE_IN_BYTES;

/// Returns true if the given address is in the kernel virtual address range.
pub const fn is_kernel_virtual_address(address: u64) -> bool {
    address >= KERNEL_STACK_REGION_START
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_binary_virtual_address_matches_linker_script() {
        assert_eq!(KERNEL_BINARY_VIRTUAL_ADDRESS, 0xFFFF_FFFF_8010_0000);
    }

    #[test]
    fn test_user_space_is_lower_half() {
        assert_eq!(USER_SPACE_START, 0x0000_0000_0000_0000);
        assert_eq!(USER_SPACE_END, 0x0000_7FFF_FFFF_FFFF);
    }

    #[test]
    fn test_kernel_stack_region_constants() {
        assert_eq!(KERNEL_STACK_REGION_START, 0xFFFF_8000_0000_0000);
        assert_eq!(KERNEL_STACK_REGION_END, 0xFFFF_8000_FFFF_FFFF);
    }

    #[test]
    fn test_pool_region_constants() {
        assert_eq!(POOL_REGION_START, 0xFFFF_8001_0000_0000);
        assert_eq!(POOL_REGION_END, 0xFFFF_8001_FFFF_FFFF);
    }

    #[test]
    fn test_direct_map_region_constants() {
        assert_eq!(DIRECT_MAP_REGION_START, 0xFFFF_8800_0000_0000);
        assert_eq!(DIRECT_MAP_REGION_END, 0xFFFF_8800_FFFF_FFFF);
    }

    #[test]
    fn test_is_kernel_virtual_address() {
        assert!(is_kernel_virtual_address(KERNEL_STACK_REGION_START));
        assert!(is_kernel_virtual_address(KERNEL_BINARY_VIRTUAL_ADDRESS));
        assert!(!is_kernel_virtual_address(USER_SPACE_END));
        assert!(!is_kernel_virtual_address(0));
    }

    #[test]
    fn test_initial_stack_layout_ordering() {
        assert!(INITIAL_KERNEL_STACK_GUARD_PAGE_ADDRESS < INITIAL_KERNEL_STACK_BOTTOM);
        assert!(INITIAL_KERNEL_STACK_BOTTOM < INITIAL_KERNEL_STACK_TOP);
    }

    #[test]
    fn test_guard_page_is_one_page_below_stack_bottom() {
        let expected_gap = PAGE_SIZE_IN_BYTES as u64;
        assert_eq!(
            INITIAL_KERNEL_STACK_BOTTOM - INITIAL_KERNEL_STACK_GUARD_PAGE_ADDRESS,
            expected_gap
        );
    }
}
