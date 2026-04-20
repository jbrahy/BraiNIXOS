/*
 * BraiNIX shell binary linker script.
 *
 * Places code at SERVER_CODE_BASE_VIRTUAL_ADDRESS (0x400000) per the layout
 * constant in `brainix-libsyscall`. The kernel's ELF loader reads PT_LOAD
 * segments at their VirtAddr and sets the new thread's RIP to the ELF
 * e_entry field, which resolves to `_start`.
 *
 * Must match SERVER_CODE_BASE_VIRTUAL_ADDRESS in
 * src/servers/libsyscall/src/lib.rs.
 */

ENTRY(_start)

SECTIONS {
    . = 0x0000000000400000;

    .text : ALIGN(4K) {
        *(.text .text.*)
    }

    .rodata : ALIGN(4K) {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4K) {
        *(.data .data.*)
    }

    .bss : ALIGN(4K) {
        _bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        _bss_end = .;
    }

    /DISCARD/ : {
        *(.eh_frame)
        *(.note .note.*)
        *(.comment)
    }
}
