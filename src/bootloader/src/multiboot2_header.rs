#![allow(unsafe_code)]

// Multiboot2 header per the Multiboot2 Specification 2.0.
// Placed in the .multiboot2_header section so the linker script positions
// it within the first 32768 bytes of the binary (required by Multiboot2 §3.1
// for GRUB2 to recognize the binary).
//
// This header uses the ADDRESS TAG and ENTRY-ADDRESS TAG forms (§3.1.5,
// §3.1.6) rather than relying on ELF PT_LOAD segments. GRUB 2.06's
// multiboot2 runtime loader silently fails to register an ELF64 binary
// as a loaded kernel without explicit address tags, even though
// `grub-file --is-x86-multiboot2` validates the header. This was
// confirmed by booting a minimal ELF32 reference kernel successfully
// while the ELF64 bootloader without address tags failed with
// "error: you need to load the kernel first" from subsequent module/boot
// commands.
//
// Invariant enforced: INV-BOOT-001 (bootloader binary is GRUB2-loadable).

const MULTIBOOT2_MAGIC: u32 = 0xE85250D6;
const MULTIBOOT2_ARCHITECTURE_I386: u32 = 0;

// Physical address constants — must match bootloader linker.ld.
// Bootloader loads at 0x800000 (8 MiB), well above the kernel's physical
// footprint (kernel .bss ends at 0x3CBAFE) and the shell load region
// (0x400000), so the bootloader can copy the kernel module to its target
// physical address (0x100000) without overlapping itself.
const BOOTLOADER_HEADER_PHYSICAL_ADDRESS: u32 = 0x0080_0000;
const BOOTLOADER_LOAD_BEGIN_PHYSICAL_ADDRESS: u32 = 0x0080_0000;
// End of loadable data: .data section ends before 0x803000 (aligned).
// Using an explicit value rather than the 0 sentinel because GRUB 2.06's
// multiboot2 loader has been observed to refuse ELF64 binaries when
// load_end_addr = 0 (sentinel "use end of file").
const BOOTLOADER_LOAD_END_ADDRESS: u32 = 0x0080_3000;
// Physical end of .bss per bootloader linker.ld (.data+.bss
// segment MemSiz ends at 0x809004). Rounded up to 0x80A000 for safety.
const BOOTLOADER_BSS_END_PHYSICAL_ADDRESS: u32 = 0x0080_A000;
// Entry point physical address — matches bootloader ELF header Entry field
// and the _start label resolved by the linker.
const BOOTLOADER_ENTRY_PHYSICAL_ADDRESS: u32 = 0x0080_1000;

// Header layout (all little-endian):
//   16 bytes prologue (magic, architecture, length, checksum)
//    8 bytes info-request tag (type=1, flags=0, size=8)
//   24 bytes address tag (type=2, flags=0, size=24, 4 * u32 addresses)
//   12 bytes entry-address tag (type=3, flags=0, size=12, entry u32)
//    4 bytes padding to reach the next 8-byte boundary
//    8 bytes end tag (type=0, flags=0, size=8)
//  --
//   72 bytes total
const MULTIBOOT2_HEADER_LENGTH: u32 = 72;

// Checksum: the four prologue u32 fields must sum to zero (mod 2^32).
const MULTIBOOT2_CHECKSUM: u32 = (0u32)
    .wrapping_sub(MULTIBOOT2_MAGIC)
    .wrapping_sub(MULTIBOOT2_ARCHITECTURE_I386)
    .wrapping_sub(MULTIBOOT2_HEADER_LENGTH);

/// Constructs the 72-byte multiboot2 header as a byte array.
const fn build_multiboot2_header() -> [u8; 72] {
    let prologue_bytes = build_header_prologue_bytes();
    let info_request_tag_bytes = build_information_request_tag_bytes();
    let address_tag_bytes = build_address_tag_bytes();
    let entry_address_tag_bytes = build_entry_address_tag_bytes();
    let end_tag_bytes = build_end_tag_bytes();
    concatenate_header_sections(
        prologue_bytes,
        info_request_tag_bytes,
        address_tag_bytes,
        entry_address_tag_bytes,
        end_tag_bytes,
    )
}

const fn build_header_prologue_bytes() -> [u8; 16] {
    let magic_bytes = MULTIBOOT2_MAGIC.to_le_bytes();
    let architecture_bytes = MULTIBOOT2_ARCHITECTURE_I386.to_le_bytes();
    let length_bytes = MULTIBOOT2_HEADER_LENGTH.to_le_bytes();
    let checksum_bytes = MULTIBOOT2_CHECKSUM.to_le_bytes();
    pack_four_u32_little_endian_into_sixteen_bytes(
        magic_bytes,
        architecture_bytes,
        length_bytes,
        checksum_bytes,
    )
}

const fn pack_four_u32_little_endian_into_sixteen_bytes(
    first: [u8; 4],
    second: [u8; 4],
    third: [u8; 4],
    fourth: [u8; 4],
) -> [u8; 16] {
    [
        first[0], first[1], first[2], first[3], second[0], second[1], second[2], second[3],
        third[0], third[1], third[2], third[3], fourth[0], fourth[1], fourth[2], fourth[3],
    ]
}

const fn build_information_request_tag_bytes() -> [u8; 8] {
    [1, 0, 0, 0, 8, 0, 0, 0]
}

const fn build_address_tag_bytes() -> [u8; 24] {
    let header_address_bytes = BOOTLOADER_HEADER_PHYSICAL_ADDRESS.to_le_bytes();
    let load_begin_address_bytes = BOOTLOADER_LOAD_BEGIN_PHYSICAL_ADDRESS.to_le_bytes();
    let load_end_address_bytes = BOOTLOADER_LOAD_END_ADDRESS.to_le_bytes();
    let bss_end_address_bytes = BOOTLOADER_BSS_END_PHYSICAL_ADDRESS.to_le_bytes();
    [
        2, 0, 0, 0, 24, 0, 0, 0, header_address_bytes[0], header_address_bytes[1],
        header_address_bytes[2], header_address_bytes[3], load_begin_address_bytes[0],
        load_begin_address_bytes[1], load_begin_address_bytes[2], load_begin_address_bytes[3],
        load_end_address_bytes[0], load_end_address_bytes[1], load_end_address_bytes[2],
        load_end_address_bytes[3], bss_end_address_bytes[0], bss_end_address_bytes[1],
        bss_end_address_bytes[2], bss_end_address_bytes[3],
    ]
}

const fn build_entry_address_tag_bytes() -> [u8; 16] {
    // 12-byte tag (type=3, flags=0, size=12, entry_addr) + 4 bytes padding to 8-byte boundary.
    let entry_address_bytes = BOOTLOADER_ENTRY_PHYSICAL_ADDRESS.to_le_bytes();
    [
        3, 0, 0, 0, 12, 0, 0, 0, entry_address_bytes[0], entry_address_bytes[1],
        entry_address_bytes[2], entry_address_bytes[3], 0, 0, 0, 0,
    ]
}

const fn build_end_tag_bytes() -> [u8; 8] {
    [0, 0, 0, 0, 8, 0, 0, 0]
}

const fn concatenate_header_sections(
    prologue: [u8; 16],
    info_request_tag: [u8; 8],
    address_tag: [u8; 24],
    entry_address_tag: [u8; 16],
    end_tag: [u8; 8],
) -> [u8; 72] {
    [
        prologue[0], prologue[1], prologue[2], prologue[3], prologue[4], prologue[5], prologue[6],
        prologue[7], prologue[8], prologue[9], prologue[10], prologue[11], prologue[12],
        prologue[13], prologue[14], prologue[15], info_request_tag[0], info_request_tag[1],
        info_request_tag[2], info_request_tag[3], info_request_tag[4], info_request_tag[5],
        info_request_tag[6], info_request_tag[7], address_tag[0], address_tag[1], address_tag[2],
        address_tag[3], address_tag[4], address_tag[5], address_tag[6], address_tag[7],
        address_tag[8], address_tag[9], address_tag[10], address_tag[11], address_tag[12],
        address_tag[13], address_tag[14], address_tag[15], address_tag[16], address_tag[17],
        address_tag[18], address_tag[19], address_tag[20], address_tag[21], address_tag[22],
        address_tag[23], entry_address_tag[0], entry_address_tag[1], entry_address_tag[2],
        entry_address_tag[3], entry_address_tag[4], entry_address_tag[5], entry_address_tag[6],
        entry_address_tag[7], entry_address_tag[8], entry_address_tag[9], entry_address_tag[10],
        entry_address_tag[11], entry_address_tag[12], entry_address_tag[13],
        entry_address_tag[14], entry_address_tag[15], end_tag[0], end_tag[1], end_tag[2],
        end_tag[3], end_tag[4], end_tag[5], end_tag[6], end_tag[7],
    ]
}

// SAFETY: Read-only static. The #[used] attribute prevents dead-strip.
// The linker script places .multiboot2_header before .text at physical
// address 0x100000 so GRUB2 finds the magic within the first 32768 bytes.
// - Precondition: bootloader linker.ld places .multiboot2_header first.
// - Invariant: INV-BOOT-001 — bootloader binary is GRUB2-loadable.
#[used]
#[link_section = ".multiboot2_header"]
static MULTIBOOT2_HEADER: [u8; 72] = build_multiboot2_header();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multiboot2_header_magic_is_correct() {
        let header = build_multiboot2_header();
        let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        assert_eq!(magic, 0xE85250D6);
    }

    #[test]
    fn test_multiboot2_header_checksum_is_valid() {
        let header = build_multiboot2_header();
        let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let architecture = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        let length = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
        let checksum = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);
        assert_eq!(
            magic
                .wrapping_add(architecture)
                .wrapping_add(length)
                .wrapping_add(checksum),
            0
        );
    }

    #[test]
    fn test_multiboot2_header_end_tag_is_correct() {
        let header = build_multiboot2_header();
        // End tag starts at offset 64 (after 16 prologue + 8 info-request + 24 address + 16 entry-address-with-padding).
        let end_tag_type = u16::from_le_bytes([header[64], header[65]]);
        let end_tag_flags = u16::from_le_bytes([header[66], header[67]]);
        let end_tag_size = u32::from_le_bytes([header[68], header[69], header[70], header[71]]);
        assert_eq!(end_tag_type, 0);
        assert_eq!(end_tag_flags, 0);
        assert_eq!(end_tag_size, 8);
    }

    #[test]
    fn test_multiboot2_header_address_tag_contains_expected_load_addresses() {
        let header = build_multiboot2_header();
        // Address tag starts at offset 24 (after 16 prologue + 8 info-request).
        let address_tag_type = u16::from_le_bytes([header[24], header[25]]);
        let header_address = u32::from_le_bytes([header[32], header[33], header[34], header[35]]);
        let load_begin_address =
            u32::from_le_bytes([header[36], header[37], header[38], header[39]]);
        assert_eq!(address_tag_type, 2);
        assert_eq!(header_address, BOOTLOADER_HEADER_PHYSICAL_ADDRESS);
        assert_eq!(load_begin_address, BOOTLOADER_LOAD_BEGIN_PHYSICAL_ADDRESS);
    }

    #[test]
    fn test_multiboot2_header_entry_address_tag_contains_expected_entry() {
        let header = build_multiboot2_header();
        // Entry-address tag starts at offset 48 (after 16 + 8 + 24).
        let entry_tag_type = u16::from_le_bytes([header[48], header[49]]);
        let entry_address = u32::from_le_bytes([header[56], header[57], header[58], header[59]]);
        assert_eq!(entry_tag_type, 3);
        assert_eq!(entry_address, BOOTLOADER_ENTRY_PHYSICAL_ADDRESS);
    }
}
