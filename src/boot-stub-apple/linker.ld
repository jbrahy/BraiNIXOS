/* AS-1a first-light payload layout.
 *
 * Delivered as a raw binary via m1n1's `chainload.py -r` (fact table §5), so
 * this script's job is to produce exactly one loadable segment with `_start`
 * at offset 0 of the image.
 *
 * The load base is deliberately 0. No consulted source establishes the address
 * m1n1 loads a raw payload to (fact table §3), and `start.S` uses only
 * PC-relative addressing, so the payload runs correctly wherever it lands.
 * Linking at 0 keeps that property visible: if an absolute relocation ever
 * creeps in, it points at a null-ish address and faults loudly instead of
 * silently working on one machine.
 *
 * Page size is NOT baked in anywhere here. INV-MEM-009 forbids hardcoding
 * 4 KiB or 16 KiB outside arch code; this stub does not manage memory, so it
 * simply never states a page size. The 16-byte alignments below are the
 * AArch64 stack ABI requirement, not a page assumption.
 */

ENTRY(_start)

/* One loadable segment, explicitly.
 *
 * Left to itself lld emits three PT_LOADs, split by permission (RX, R, RW).
 * That is right for a system with an MMU and wrong here: the MMU is off at
 * entry (fact table §4), so page permissions do not exist yet and the split
 * buys nothing while making the flat image harder to reason about.
 *
 * W^X is NOT being waived. This stub never maps a page, never enables the
 * MMU, and is superseded by the real kernel image the moment AS-1c lands its
 * page tables. INV-MEM applies to mapped pages; there are none here.
 */
PHDRS
{
    payload PT_LOAD FLAGS(7); /* R + W + X */
}

SECTIONS
{
    . = 0;

    .text : {
        KEEP(*(.text.boot))
        *(.text .text.*)
    } :payload

    .rodata : ALIGN(8) {
        *(.rodata .rodata.*)
    } :payload

    .data : ALIGN(8) {
        *(.data .data.*)
    } :payload

    .bss : ALIGN(16) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    } :payload

    /* Boot stack.
     *
     * MUST be inside the loaded image, and the reason is the whole of AS-1a's
     * first failure on hardware. This was `(NOLOAD)` with 64 KiB, which
     * `objcopy -O binary` does not emit -- so the file ended at 0x2133 while
     * `__stack_top` sat at 0x12140, and `start.S` pointed `sp` 73 KB past the
     * last byte iBoot loaded. The first call into Rust wrote there. With the
     * MMU off that is not a fault into a guard page, it is a write into
     * whatever physical memory follows the payload: iBoot's own structures,
     * the boot_args, or the ADT this stub then tries to parse. It died before
     * reaching any output path, which presents as a powered machine with a
     * dark screen and a silent console -- indistinguishable, from outside,
     * from never having run at all.
     *
     * Emitting a byte after `__stack_top` forces this section to PROGBITS, so
     * the whole reservation lands in the flat binary and the memory is
     * unambiguously ours. 16 KiB is far more than first light needs; the cost
     * is 16 KiB of image, which is the correct price for not scribbling on
     * the firmware.
     */
    .stack : ALIGN(16) {
        __stack_bottom = .;
        . += 0x4000;
        . = ALIGN(16);
        __stack_top = .;
        BYTE(0)
    } :payload

    /DISCARD/ : {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame_hdr)
        *(.ARM.exidx .ARM.exidx.*)
    }
}
