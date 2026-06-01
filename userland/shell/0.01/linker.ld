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
 *
 * The explicit PHDRS block emits exactly three PT_LOAD program headers and
 * nothing else. The kernel's ELF loader runs a strict whitelist pre-flight
 * (`validate_program_header_types_are_load_only`) that rejects ANY non
 * PT_LOAD program header, including the PT_GNU_STACK and PT_GNU_RELRO
 * segments rust-lld emits by default. Declaring PHDRS suppresses those.
 *
 * Each segment is page-aligned (ALIGN(4K)) and carries a single permission
 * class so no two segments share a 4 KiB page. The loader maps one fresh
 * physical page per virtual page; overlapping segments would map a page
 * twice with conflicting flags. Flags: text = R+X (5), rodata = R (4),
 * data = R+W (6) -- the three combinations the loader's W^X translator
 * accepts.
 */

ENTRY(_start)

PHDRS {
    text   PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data   PT_LOAD FLAGS(6);
}

SECTIONS {
    . = 0x0000000000400000;

    .text : ALIGN(4K) {
        *(.text .text.*)
    } :text

    .rodata : ALIGN(4K) {
        *(.rodata .rodata.*)
    } :rodata

    .data : ALIGN(4K) {
        *(.data.rel.ro .data.rel.ro.*)
        *(.got .got.plt)
        *(.data .data.*)
    } :data

    .bss : ALIGN(4K) {
        _bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        _bss_end = .;
    } :data

    /DISCARD/ : {
        *(.eh_frame)
        *(.note .note.*)
        *(.comment)
    }
}
