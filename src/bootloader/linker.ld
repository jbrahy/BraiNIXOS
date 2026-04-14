/* BraiNIX bootloader linker script
 *
 * Load address: 1 MiB (0x100000) — conventional multiboot2 load address.
 * The .multiboot2_header section is placed first so GRUB2 finds the
 * multiboot2 magic (0xE85250D6) within the first 32768 bytes of the binary.
 *
 * _kernel_start is defined as a fixed symbol at the kernel's higher-half
 * virtual load address. This address MUST match the ORIGIN defined in
 * src/kernel/linker.ld. The page table set up by start.s maps
 * 0xFFFFFFFF80000000 -> physical 0x0 so this virtual address is valid
 * after the long mode transition.
 */

ENTRY(_start)

SECTIONS
{
    . = 0x100000;

    /* Multiboot2 header must come before .text so it is within the first
     * 32768 bytes of the binary. ALIGN(8) satisfies the Multiboot2
     * Specification requirement that the header be 8-byte aligned. */
    .multiboot2_header : ALIGN(8)
    {
        *(.multiboot2_header)
    }

    .text : ALIGN(4096)
    {
        *(.text .text.*)
    }

    .rodata : ALIGN(4096)
    {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4096)
    {
        *(.data .data.*)
    }

    .bss : ALIGN(4096)
    {
        _bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        _bss_end = .;
    }

    /* Kernel virtual load address.
     * This symbol is referenced by start.s as the jump target after long mode
     * transition. It must match ORIGIN in src/kernel/linker.ld exactly. */
    _kernel_start = 0xFFFFFFFF80100000;
}
