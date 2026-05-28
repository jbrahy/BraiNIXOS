/* BraiNIX bootloader linker script
 *
 * Load address: 8 MiB (0x800000). Chosen to be safely above:
 *   - the kernel ELF's physical extent (.bss ends at 0x3CBAFE),
 *   - the shell binary's load region (Phase 14-02 puts shell at 0x400000),
 * which lets the bootloader copy the kernel module into its expected
 * physical destination (0x100000) without overlapping its own image.
 *
 * The .multiboot2_header section is placed first so GRUB2 finds the
 * multiboot2 magic (0xE85250D6) within the first 32768 bytes of the binary.
 *
 * _kernel_start is defined as a fixed symbol at the kernel's higher-half
 * virtual load address. This address MUST match the ORIGIN defined in
 * src/kernel/linker.ld. The bootloader's page tables map
 * 0xFFFFFFFF80000000 -> physical 0x0 (covering 6 MiB) so the kernel is
 * reachable at this virtual address after long mode is active.
 */

ENTRY(_start)

SECTIONS
{
    . = 0x800000;

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
