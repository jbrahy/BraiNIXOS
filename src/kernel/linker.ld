/* Brainix kernel linker script
 *
 * IMPORTANT: This address must match _kernel_start in src/bootloader/linker.ld.
 * The bootloader's start.s sets up a higher-half page table mapping
 * 0xFFFFFFFF80000000 -> physical 0x0, so the kernel is accessible at this
 * virtual address once long mode is active with paging enabled.
 *
 * Physical address: 0x100000 (1 MiB)
 * Virtual address:  0xFFFFFFFF80100000 (higher-half)
 */

ENTRY(_start)

KERNEL_VIRTUAL_BASE = 0xFFFFFFFF80100000;

SECTIONS
{
    . = KERNEL_VIRTUAL_BASE;

    _text_start = .;
    .text : AT(0x100000)
    {
        *(.text .text.*)
    }
    _text_end = .;

    .rodata : ALIGN(4096)
    {
        _rodata_start = .;
        *(.rodata .rodata.*)
        _rodata_end = .;
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

    /* Stack guard page placeholder for Phase 2 (memory management phase).
     * The guard page sits immediately below the kernel stack bottom.
     * Phase 2 will unmap this page to catch stack overflows.
     *
     * PROVIDE is used so these symbols do not collide if redefined in Phase 2. */
    PROVIDE(_kernel_stack_guard_page = KERNEL_VIRTUAL_BASE - 0x1000);
    PROVIDE(_kernel_stack_bottom = KERNEL_VIRTUAL_BASE - 0x1000 + 0x1000);
}
