// AS-1a entry.
//
// Entry state, from docs/platform-specs/apple-s5l-uart.md §4 (itself from the
// published Asahi MachO Boot Protocol):
//
//   MMU              off
//   Exception level  EL2
//   x0               pointer to the boot_args structure
//   Interrupts       masked
//   RVBAR            locked by iBoot to the top of the entrypoint's page
//
// Nothing is inherited and nothing is assumed beyond that.
//
// EVERY ADDRESS HERE IS PC-RELATIVE. The raw chainload load address is not
// established by any consulted source (fact table §3), so the link base may be
// wrong. Using only `adrp`/`adr` means the payload reaches its first output
// regardless of where it was loaded, which removes the largest unknown from
// the critical path. See fact table §7.

.section .text.boot, "ax"
.global _start
.type _start, @function

_start:
    // Preserve the boot_args pointer across the .bss clear below. x19 is
    // callee-saved and nothing has run yet to clobber it.
    mov     x19, x0

    // Stack: PC-relative, top of the reserved region. The AArch64 ABI requires
    // SP to be 16-byte aligned; the linker script aligns __stack_top to 16.
    adrp    x1, __stack_top
    add     x1, x1, :lo12:__stack_top
    mov     sp, x1

    // Zero .bss. The loader delivers a raw image with no zeroed tail, so
    // anything relying on zero-initialised statics needs this done here.
    adrp    x2, __bss_start
    add     x2, x2, :lo12:__bss_start
    adrp    x3, __bss_end
    add     x3, x3, :lo12:__bss_end

.Lbss_clear:
    cmp     x2, x3
    b.hs    .Lbss_done
    str     xzr, [x2], #8
    b       .Lbss_clear
.Lbss_done:

    // Hand the boot_args pointer to Rust.
    mov     x0, x19
    bl      boot_stub_main

    // boot_stub_main is declared `-> !`, so reaching here means it returned
    // anyway. Spin rather than fall through into whatever bytes follow.
.Lhang:
    wfe
    b       .Lhang

.size _start, . - _start
