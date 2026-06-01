# BraiNIX bootloader entry stub — GNU AT&T syntax, assembled with 'as'
#
# Entry: 32-bit protected mode (GRUB2 multiboot2 handoff)
#   EAX = 0x36D76289 (multiboot2 bootloader magic)
#   EBX = physical address of multiboot2 info structure
#
# Exit: 64-bit long mode, paging enabled, SMEP+SMAP set in CR4,
#       jump to _kernel_start (0xFFFFFFFF80100000)
#
# Security invariants enforced:
#   INV-BOOT-002: SMEP and SMAP are enabled before kernel entry
#   INV-BOOT-003: CPU is in 64-bit long mode before kernel entry
#
# Allowlist: src/bootloader/src/ per UNSAFE_CODE_POLICY.md

    .code32
    .section .text
    .global _start
    .type _start, @function

_start:
    # Disable interrupts immediately. GRUB may have left them enabled.
    cli

    # Preserve the multiboot2 info pointer (EBX) to a known memory
    # location. It survives the long mode transition there.
    movl %ebx, multiboot2_info_pointer_storage

    # Set up a temporary 32-bit stack for the transition sequence.
    movl $temporary_stack_top, %esp

    # -------------------------------------------------------------------
    # Step 1: Enable Physical Address Extension (PAE) in CR4 bit 5.
    # PAE is required before entering IA-32e (long) mode.
    # -------------------------------------------------------------------
    movl %cr4, %eax
    orl $0x20, %eax
    movl %eax, %cr4

    # -------------------------------------------------------------------
    # Step 2: Build page tables.
    #
    # Identity map: virtual 0x0..0x200000 -> physical 0x0..0x200000
    #   PML4[0] -> pdpt_identity[0] -> pd_low[0] (2MB page)
    #
    # Higher-half map: virtual 0xFFFFFFFF80000000 -> physical 0x0
    #   PML4[511] -> pdpt_high[510] -> pd_low[0] (reuses pd_low)
    #   Covers kernel at 0xFFFFFFFF80100000 -> physical 0x100000.
    #   (Both are within the same first 2MB physical region.)
    #
    # All 2MB pages: PS bit = bit 7 in PD. Present=1, Writable=1.
    # -------------------------------------------------------------------

    # PML4[0] = &pdpt_identity | 0x3 (present + writable)
    movl $pdpt_identity, %eax
    orl $0x3, %eax
    movl %eax, pml4_table

    # PML4[511] = &pdpt_high | 0x3
    # PML4 is 4096 bytes; index 511 is at offset 511*8 = 4088 = 0xFF8.
    movl $pdpt_high, %eax
    orl $0x3, %eax
    movl %eax, pml4_table + 0xFF8

    # pdpt_identity[0] = &pd_low | 0x3
    movl $pd_low, %eax
    orl $0x3, %eax
    movl %eax, pdpt_identity

    # pdpt_high[510] = &pd_low | 0x3
    # 0xFFFFFFFF80000000: PDPT index = 510; offset = 510 * 8 = 4080 = 0xFF0.
    movl $pd_low, %eax
    orl $0x3, %eax
    movl %eax, pdpt_high + 0xFF0

    # pd_low[0] = 0x83 (present=1, writable=1, PS=1 for 2MB page at phys 0)
    movl $0x83, %eax
    movl %eax, pd_low

    # Load PML4 physical address into CR3.
    movl $pml4_table, %eax
    movl %eax, %cr3

    # -------------------------------------------------------------------
    # Step 3: Set LME (bit 8) in EFER MSR (0xC0000080) to enable IA-32e.
    # -------------------------------------------------------------------
    movl $0xC0000080, %ecx
    rdmsr
    orl $0x100, %eax
    wrmsr

    # -------------------------------------------------------------------
    # Step 4: Enable paging (CR0 bit 31). Protected mode (bit 0) is
    # already set by GRUB2; we set it explicitly for correctness.
    # -------------------------------------------------------------------
    movl %cr0, %eax
    orl $0x80000001, %eax
    movl %eax, %cr0

    # -------------------------------------------------------------------
    # Step 5: Load 64-bit GDT and far-jump to 64-bit code segment.
    # -------------------------------------------------------------------
    lgdt gdt_pointer
    ljmp $0x08, $long_mode_entry

    # ===================================================================
    # 64-bit long mode entry point
    # ===================================================================

    .code64
    .global long_mode_entry
    .type long_mode_entry, @function

long_mode_entry:
    # Load null data segment selectors (flat 64-bit model).
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    # -------------------------------------------------------------------
    # Step 6: Enable SMEP (CR4 bit 20) and SMAP (CR4 bit 21).
    # Must be done in 64-bit mode. Invariant: INV-BOOT-002.
    # SMEP bit 20 = 0x100000, SMAP bit 21 = 0x200000; combined = 0x300000.
    # -------------------------------------------------------------------
    movq %cr4, %rax
    orq $0x300000, %rax
    movq %rax, %cr4

    # -------------------------------------------------------------------
    # Step 7: Set up 64-bit stack (bootloader stack in .bss).
    # -------------------------------------------------------------------
    movabsq $bootloader_stack_top, %rsp

    # -------------------------------------------------------------------
    # Step 8: Jump to kernel entry point at _kernel_start.
    # _kernel_start = 0xFFFFFFFF80100000 (defined in bootloader linker.ld).
    # The higher-half page table ensures this virtual address is mapped.
    # -------------------------------------------------------------------
    movabsq $_kernel_start, %rax
    jmpq *%rax

    # Halt loop: if kernel entry returns (should never happen), halt.
halt_loop:
    cli
    hlt
    jmp halt_loop

    # ===================================================================
    # Data: minimal 64-bit GDT
    #
    # [0x00] null descriptor
    # [0x08] 64-bit kernel code: P=1, DPL=0, L=1 (64-bit), D=0
    # [0x10] 64-bit kernel data: P=1, DPL=0
    # ===================================================================

    .section .data
    .align 8

gdt_table:
    .quad 0x0000000000000000    # [0x00] null
    .quad 0x00AF9A000000FFFF    # [0x08] 64-bit code: L=1, P=1, DPL=0, G=1
    .quad 0x00CF92000000FFFF    # [0x10] 64-bit data: P=1, DPL=0, G=1
gdt_table_end:

    .align 4
gdt_pointer:
    .word gdt_table_end - gdt_table - 1   # limit (size - 1)
    .long gdt_table                        # base (32-bit physical address)

    # ===================================================================
    # BSS: page tables, stacks, multiboot2 pointer storage
    #
    # Page tables must be 4096-byte aligned.
    # ===================================================================

    .section .bss
    .align 4096

pml4_table:
    .space 4096

pdpt_identity:
    .space 4096

pdpt_high:
    .space 4096

pd_low:
    .space 4096

    # Temporary 32-bit stack used only during the long mode transition.
    .align 16
temporary_stack_bottom:
    .space 4096
temporary_stack_top:

    # 64-bit bootloader stack used from long_mode_entry until kernel entry.
    .align 16
bootloader_stack_bottom:
    .space 4096
bootloader_stack_top:

    # Storage for the multiboot2 info struct pointer (EBX on entry).
    .align 4
multiboot2_info_pointer_storage:
    .space 4
