#![allow(unsafe_code)]

// Multiboot2 header constants per the Multiboot2 Specification 2.0.
// Placing this header in the .multiboot2_header section ensures the linker
// script positions it within the first 32768 bytes of the binary, which is
// required by the Multiboot2 Specification for GRUB2 to recognize the binary.
//
// Invariant enforced: INV-BOOT-001 (bootloader binary is GRUB2-loadable via
// multiboot2 protocol).

const MULTIBOOT2_MAGIC: u32 = 0xE85250D6;
const MULTIBOOT2_ARCHITECTURE_I386: u32 = 0;
// Header layout: fixed 16-byte prologue + 8-byte info-request tag (type=1, flags=1, size=8)
// + 8-byte end tag = 32 bytes total.
const MULTIBOOT2_HEADER_LENGTH: u32 = 32;

// Checksum: the four header fields must sum to zero (mod 2^32).
// checksum = -(magic + architecture + length)
const MULTIBOOT2_CHECKSUM: u32 = (0u32)
    .wrapping_sub(MULTIBOOT2_MAGIC)
    .wrapping_sub(MULTIBOOT2_ARCHITECTURE_I386)
    .wrapping_sub(MULTIBOOT2_HEADER_LENGTH);

/// Constructs the 32-byte multiboot2 header as a byte array.
///
/// Layout (little-endian, per Multiboot2 Specification 2.0 §3.1):
///   bytes  0- 3: magic (0xE85250D6)
///   bytes  4- 7: architecture (0 = i386 protected mode)
///   bytes  8-11: header_length (32)
///   bytes 12-15: checksum
///   bytes 16-23: information-request tag (type=1, flags=0, size=8) — tells
///                GRUB the kernel wants module list and memory map information.
///                Tag has no `mbi_tag_types` entries because size is exactly 8;
///                this registers a kernel-loader-expects-info state in GRUB's
///                multiboot2 command (required in GRUB 2.06 to properly flag
///                the file as a loaded kernel).
///   bytes 24-31: end tag (type=0, flags=0, size=8)
const fn build_multiboot2_header() -> [u8; 32] {
    let magic_bytes = MULTIBOOT2_MAGIC.to_le_bytes();
    let architecture_bytes = MULTIBOOT2_ARCHITECTURE_I386.to_le_bytes();
    let length_bytes = MULTIBOOT2_HEADER_LENGTH.to_le_bytes();
    let checksum_bytes = MULTIBOOT2_CHECKSUM.to_le_bytes();
    [
        magic_bytes[0],
        magic_bytes[1],
        magic_bytes[2],
        magic_bytes[3],
        architecture_bytes[0],
        architecture_bytes[1],
        architecture_bytes[2],
        architecture_bytes[3],
        length_bytes[0],
        length_bytes[1],
        length_bytes[2],
        length_bytes[3],
        checksum_bytes[0],
        checksum_bytes[1],
        checksum_bytes[2],
        checksum_bytes[3],
        // information-request tag: type=1, flags=0, size=8
        1, // tag type low byte (1 = information request)
        0, // tag type high byte
        0, // tag flags low byte
        0, // tag flags high byte
        8, // tag size byte 0 (size = 8, no request entries)
        0, // tag size byte 1
        0, // tag size byte 2
        0, // tag size byte 3
        // end tag: type=0, flags=0, size=8
        0, // end tag type low byte
        0, // end tag type high byte
        0, // end tag flags low byte
        0, // end tag flags high byte
        8, // end tag size byte 0 (size = 8)
        0, // end tag size byte 1
        0, // end tag size byte 2
        0, // end tag size byte 3
    ]
}

// SAFETY: This static is read-only after initialization. The #[used] attribute
// prevents the compiler from dead-stripping it. The linker script places this
// section at the very start of the binary (before .text) so GRUB2 can find
// the multiboot2 magic within the first 32768 bytes.
// - Precondition: The bootloader linker script must include a .multiboot2_header
//   output section placed before .text.
// - Invariant: INV-BOOT-001 — bootloader binary is GRUB2-loadable.
// - Evidence: test_multiboot2_header_magic_is_correct in this module.
#[used]
#[link_section = ".multiboot2_header"]
static MULTIBOOT2_HEADER: [u8; 32] = build_multiboot2_header();

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
        // End tag: type=0 (u16), flags=0 (u16), size=8 (u32)
        let end_tag_type = u16::from_le_bytes([header[16], header[17]]);
        let end_tag_flags = u16::from_le_bytes([header[18], header[19]]);
        let end_tag_size = u32::from_le_bytes([header[20], header[21], header[22], header[23]]);
        assert_eq!(end_tag_type, 0);
        assert_eq!(end_tag_flags, 0);
        assert_eq!(end_tag_size, 8);
    }
}
