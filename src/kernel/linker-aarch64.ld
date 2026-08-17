/* BraiNIX kernel, Apple Silicon.
 *
 * Deliberately NOT modelled on linker.ld, whose higher-half virtual base only
 * exists once the x86-64 bootloader's page tables are live. A custom boot
 * object on Apple Silicon is entered with the **MMU off**, so a link at an
 * unmapped virtual address produces an image that cannot be entered at all.
 *
 * Linked at 0 and entered at offset 0, matching src/boot-stub-apple/linker.ld
 * and the entry point recorded for our payloads in bin/payloads.tsv. m1n1 is
 * entry 2048; ours is 0, and the two must never be copied from one another.
 */

ENTRY(_start)

PHDRS
{
    payload PT_LOAD FLAGS(7);   /* RWX: one loadable segment, as iBoot expects */
}

SECTIONS
{
    . = 0;

    .text : ALIGN(16) {
        KEEP(*(.text.boot))
        *(.text .text.*)
    } :payload

    .rodata : ALIGN(16) { *(.rodata .rodata.*) } :payload
    .data   : ALIGN(16) { *(.data .data.*) }     :payload

    /* The stack is emitted, not reserved.
     *
     * src/boot-stub-apple/linker.ld carries the scar: a `.stack (NOLOAD)`
     * section is not written by `objcopy -O binary`, so the image ended before
     * __stack_top and sp pointed 73 KB past the end of everything loaded. That
     * was the genuine AS-1a fault and it cost days, because it dies before any
     * output path. BYTE(0) forces PROGBITS so the bytes actually exist.
     */
    .stack : ALIGN(16) {
        __stack_bottom = .;
        . += 0x10000;
        . = ALIGN(16);
        __stack_top = .;
        BYTE(0)
    } :payload

    .bss : ALIGN(16) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } :payload

    /DISCARD/ : { *(.comment) *(.note.*) *(.eh_frame) *(.eh_frame_hdr) }
}
