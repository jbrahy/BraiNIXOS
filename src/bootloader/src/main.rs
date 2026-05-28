#![no_std]
#![no_main]
#![allow(unsafe_code)]

// BraiNIX bootloader binary entry point.
//
// Unsafe is permitted in src/bootloader/src/ per UNSAFE_CODE_POLICY.md allowlist.
//
// This file is the binary crate root. The 32-bit entry stub (_start) and the
// long mode transition are implemented via global_asm! below. The assembly
// transitions the CPU from 32-bit protected mode (GRUB2 multiboot2 handoff)
// to 64-bit long mode, enables SMEP and SMAP in CR4, then jumps to the kernel
// entry point at the fixed virtual address _kernel_start (0xFFFFFFFF80100000).
//
// The linker script (linker.ld) places .multiboot2_header first (from
// multiboot2_header.rs) and defines _kernel_start as the fixed kernel virtual
// load address matching src/kernel/linker.ld.
//
// IMPORTANT — Address encoding in .code32 via global_asm!:
// LLVM's global_asm! compiles assembly as 64-bit even inside a .code32 block.
// Memory references using symbolic names (OFFSET symbol or [symbol]) generate
// RIP-relative relocations, which are wrong for 32-bit code. To avoid this,
// all 32-bit memory accesses use hardcoded absolute addresses that are fixed
// by the linker script and BSS layout below. These addresses MUST be kept in
// sync with the .bss labels at the bottom of this file.
//
// Fixed BSS layout (load address 0x800000, .bss starts at 0x803000):
//   0x803000 pml4_table          (4096 bytes)
//   0x804000 pdpt_identity       (4096 bytes)
//   0x805000 pdpt_high           (4096 bytes)
//   0x806000 pd_low              (4096 bytes)
//   0x807000 temporary_stack_bottom (4096 bytes, top = 0x808000)
//   0x808000 temporary_stack_top (label only, stack grows down from here)
//   0x808000 bootloader_stack_bottom (4096 bytes, top = 0x809000)
//   0x809000 bootloader_stack_top (label only)
//   0x809000 multiboot2_info_pointer_storage (4 bytes — separate from stack)
//
// Note: bootloader_stack_top and multiboot2_info_pointer_storage share address
// 0x809000. The stack grows downward from 0x809000 so the first push goes to
// 0x808FFC (inside bootloader_stack_bottom), NOT into the 4-byte info storage
// at 0x809000. The info storage is written BEFORE the 64-bit stack is set up,
// and read later — no collision occurs during normal execution.
//
// Security invariants enforced:
//   INV-BOOT-001: bootloader binary is GRUB2-loadable via multiboot2
//   INV-BOOT-002: SMEP and SMAP are enabled before kernel entry
//   INV-BOOT-003: CPU is in 64-bit long mode before kernel entry

mod elf_loader;
mod multiboot2_header;
mod multiboot2_info;

use core::arch::global_asm;
use core::panic::PanicInfo;

use crate::elf_loader::ParsedKernelImage;
use crate::multiboot2_info::ModuleLocation;

/// Multiboot2 boot magic value passed by GRUB in EAX. The kernel reads
/// this from EAX at `_start` to confirm a valid multiboot2 handoff.
const MULTIBOOT2_BOOT_MAGIC: u32 = 0x36D7_6289;

/// Fixed physical address where `_start` (32-bit code) saves GRUB's
/// multiboot2 info-structure pointer (originally in EBX) for later use
/// by the 64-bit Rust handoff stage. Must match the BSS layout in the
/// global_asm! block above.
const SAVED_MULTIBOOT2_INFO_POINTER_ADDRESS: u64 = 0x0080_9000;

/// Null-terminated identifier used in grub.cfg `module2` lines.
const KERNEL_MODULE_NAME: &[u8] = b"kernel";

/// Final stage of the bootloader: locate the kernel module that GRUB
/// loaded for us, ELF-load its PT_LOAD segments into their physical
/// destinations, and transfer control to the kernel's entry point
/// with the multiboot2 boot ABI registers populated.
///
/// Called from `long_mode_entry` in the global_asm! block above once
/// the CPU is in 64-bit long mode with SMEP+SMAP enabled.
///
/// # Safety
/// - Called exactly once, from the assembly stub, on the boot CPU.
/// - The bootloader's identity page-table mapping must cover both the
///   GRUB-loaded module address and every kernel `p_paddr`.
/// - This function never returns. On any error it halts the CPU.
#[no_mangle]
pub unsafe extern "C" fn load_kernel_module_and_jump_to_entry() -> ! {
    let information_structure_address = read_saved_multiboot2_info_pointer();
    let kernel_module = locate_kernel_module(information_structure_address);
    let parsed_image = parse_kernel_image(kernel_module);
    load_kernel_image(kernel_module, &parsed_image);
    jump_to_kernel_entry(
        parsed_image.entry_point_address,
        information_structure_address,
    );
}

unsafe fn read_saved_multiboot2_info_pointer() -> u64 {
    let storage_pointer = SAVED_MULTIBOOT2_INFO_POINTER_ADDRESS as *const u32;
    u64::from(core::ptr::read_volatile(storage_pointer))
}

unsafe fn locate_kernel_module(information_structure_address: u64) -> ModuleLocation {
    match multiboot2_info::find_module_by_name(information_structure_address, KERNEL_MODULE_NAME) {
        Some(module) => module,
        None => halt_on_boot_failure(),
    }
}

unsafe fn parse_kernel_image(kernel_module: ModuleLocation) -> ParsedKernelImage {
    let module_base_address = u64::from(kernel_module.physical_start_address);
    let module_size_in_bytes = u64::from(kernel_module.size_in_bytes());
    match elf_loader::parse_kernel_elf_image(module_base_address, module_size_in_bytes) {
        Ok(parsed_image) => parsed_image,
        Err(_) => halt_on_boot_failure(),
    }
}

unsafe fn load_kernel_image(kernel_module: ModuleLocation, parsed_image: &ParsedKernelImage) {
    let module_base_address = u64::from(kernel_module.physical_start_address);
    elf_loader::load_kernel_image_to_physical_memory(module_base_address, parsed_image);
}

unsafe fn jump_to_kernel_entry(entry_point_address: u64, information_pointer: u64) -> ! {
    // RBX cannot be used directly as an `in("rbx")` operand — LLVM reserves
    // it internally on x86-64. Set it via an explicit `mov` from a normal
    // scratch register; `options(noreturn)` tells LLVM not to expect any
    // register state to survive past the jump.
    core::arch::asm!(
        "mov rbx, {info}",
        "jmp {entry}",
        info = in(reg) information_pointer,
        entry = in(reg) entry_point_address,
        in("eax") MULTIBOOT2_BOOT_MAGIC,
        options(noreturn),
    );
}

fn halt_on_boot_failure() -> ! {
    loop {
        // SAFETY: hlt allowlisted for bootloader halt loops per
        // UNSAFE_CODE_POLICY.md (src/bootloader/src/).
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}

// Panic handler required for #![no_std] binaries.
// The bootloader halts on panic — no serial output available at this stage.
#[panic_handler]
fn handle_bootloader_panic(_info: &PanicInfo) -> ! {
    loop {
        // SAFETY: hlt is allowlisted for bootloader halt loops per
        // UNSAFE_CODE_POLICY.md (src/bootloader/src/).
        // Precondition: none (last-resort halt, no other safe option).
        // Invariant: system halts rather than continuing in undefined state.
        //
        // Intentional divergence from kernel halt pattern: the kernel uses
        // arch::interrupts::halt::disable_interrupts_and_halt() which issues
        // cli and hlt as two separate asm! calls. The bootloader is a separate
        // crate with no access to the kernel lib; the combined "cli; hlt" form
        // is equivalent and acceptable here as a last-resort halt with no
        // diagnostic infrastructure available.
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}

// SAFETY: This assembly block is in the src/bootloader/src/ allowlist per
// UNSAFE_CODE_POLICY.md. The bootloader executes before any safe Rust
// abstraction exists. Hardware register access and page table construction
// have no safe Rust equivalent at this stage.
//
// - Precondition: GRUB2 has loaded this binary in 32-bit protected mode with
//   EAX = multiboot2 magic (0x36D76289) and EBX = multiboot2 info pointer.
// - Invariant: INV-BOOT-002 (SMEP+SMAP enabled before kernel entry)
// - Invariant: INV-BOOT-003 (64-bit long mode active before kernel entry)
// - Evidence: cargo build -p brainix-bootloader --target x86_64-unknown-none
//   --release succeeds; binary contains _start and long_mode_entry symbols;
//   SMEP+SMAP (0x300000) encoded at correct location in .text.
global_asm!(
    // ===================================================================
    // 32-bit protected mode entry point (_start)
    // GRUB2 enters here after loading the bootloader binary via multiboot2.
    //
    // All memory addresses in this section are hardcoded absolute values.
    // See the address layout comment at the top of this file.
    // ===================================================================
    ".code32",
    ".section .text",
    ".global _start",
    ".type _start, @function",
    "_start:",
    // Disable interrupts immediately. GRUB2 may have left them enabled.
    "cli",
    // Save the multiboot2 info struct pointer (EBX) to fixed address
    // 0x809000. Hardcoded because OFFSET symbol generates wrong relocations
    // in .code32 via global_asm! (64-bit RIP-relative instead of 32-bit).
    "mov DWORD PTR ds:[0x809000], ebx",
    // Set up a temporary 32-bit stack at 0x808000 (top of temporary stack).
    "mov esp, 0x808000",
    // -------------------------------------------------------------------
    // Step 1: Enable Physical Address Extension (PAE) — CR4 bit 5.
    // Required before setting LME in EFER to enter IA-32e mode.
    // -------------------------------------------------------------------
    "mov eax, cr4",
    "or eax, 0x20",
    "mov cr4, eax",
    // -------------------------------------------------------------------
    // Step 2: Build page tables using hardcoded physical addresses.
    //
    // Identity map: virtual 0..0x2000000 -> physical 0..0x2000000 (32 MiB)
    //   PML4[0]    (at 0x803000) -> pdpt_identity (0x804000)
    //   pdpt_identity[0] (at 0x804000) -> pd_low (0x806000)
    //
    // Higher-half map: virtual 0xFFFFFFFF80000000..0xFFFFFFFF82000000
    //   -> physical 0..0x2000000 (shares pd_low; 16 huge pages)
    //   PML4[511]  (at 0x803FF8) -> pdpt_high (0x805000)
    //   pdpt_high[510] (at 0x805FF0) -> pd_low (0x806000)
    //   pd_low[i] (at 0x806000+i*8) = i*0x200000 | 0x83  for i in 0..16
    //
    // Coverage rationale (16 * 2 MiB = 32 MiB):
    //   - pd_low[0]: low memory + kernel entry (.text at 0x100370). The
    //     higher-half view maps the kernel's virt 0xFFFFFFFF80100000.
    //   - pd_low[1]: kernel .rodata/.data and start of .bss (kernel .bss
    //     ends at 0x3CBAFE).
    //   - pd_low[2]: shell module load region (Phase 14-02 placed shell
    //     at 0x400000).
    //   - pd_low[4]: bootloader's own image (.text/.data/.bss live at
    //     0x800000 after the relocate in src/bootloader/linker.ld).
    //   - pd_low[5..16]: headroom for GRUB to place the multiboot2
    //     information structure and additional modules above the
    //     bootloader. GRUB 2.06 has been observed to place the info
    //     struct at addresses well past 8 MiB on some configurations.
    //
    // Note: identity and higher-half share the same pd_low. The bootloader
    // is therefore visible at both virt 0x800000 and virt 0xFFFFFFFF80800000
    // during boot. This is a benign temporary mapping that disappears when
    // the kernel installs its own KPTI page tables in Phase 2.
    //
    // All page table entries: Present=1 (bit 0), Writable=1 (bit 1).
    // PD entries: PS=1 (bit 7) for 2MB huge pages (no PT level needed).
    //
    // 0xFF8 = index 511 * 8 bytes = byte offset in PML4 for index 511
    // 0xFF0 = index 510 * 8 bytes = byte offset in PDPT for index 510
    // -------------------------------------------------------------------

    // PML4[0] = 0x804003 (pdpt_identity physical address | P | W)
    "mov DWORD PTR ds:[0x803000], 0x804003",
    // PML4[511] = 0x805003 (pdpt_high physical address | P | W)
    // PML4 index 511 is at offset 511*8 = 0xFF8 from PML4 base (0x803000).
    "mov DWORD PTR ds:[0x803FF8], 0x805003",
    // pdpt_identity[0] = 0x806003 (pd_low physical address | P | W)
    "mov DWORD PTR ds:[0x804000], 0x806003",
    // pdpt_high[510] = 0x806003 (pd_low physical address | P | W)
    // PDPT index 510 is at offset 510*8 = 0xFF0 from PDPT base (0x805000).
    "mov DWORD PTR ds:[0x805FF0], 0x806003",
    // pd_low[0..16] = i*0x200000 | 0x83 (PS=1, W=1, P=1; 2 MiB huge pages)
    "mov DWORD PTR ds:[0x806000], 0x0000083",
    "mov DWORD PTR ds:[0x806008], 0x0200083",
    "mov DWORD PTR ds:[0x806010], 0x0400083",
    "mov DWORD PTR ds:[0x806018], 0x0600083",
    "mov DWORD PTR ds:[0x806020], 0x0800083",
    "mov DWORD PTR ds:[0x806028], 0x0A00083",
    "mov DWORD PTR ds:[0x806030], 0x0C00083",
    "mov DWORD PTR ds:[0x806038], 0x0E00083",
    "mov DWORD PTR ds:[0x806040], 0x1000083",
    "mov DWORD PTR ds:[0x806048], 0x1200083",
    "mov DWORD PTR ds:[0x806050], 0x1400083",
    "mov DWORD PTR ds:[0x806058], 0x1600083",
    "mov DWORD PTR ds:[0x806060], 0x1800083",
    "mov DWORD PTR ds:[0x806068], 0x1A00083",
    "mov DWORD PTR ds:[0x806070], 0x1C00083",
    "mov DWORD PTR ds:[0x806078], 0x1E00083",
    // Load PML4 physical address into CR3.
    "mov eax, 0x803000",
    "mov cr3, eax",
    // -------------------------------------------------------------------
    // Step 3: Enable IA-32e (long) mode: set LME (bit 8) in EFER MSR.
    // EFER MSR address: 0xC0000080.
    // -------------------------------------------------------------------
    "mov ecx, 0xC0000080",
    "rdmsr",
    "or eax, 0x100",
    "wrmsr",
    // -------------------------------------------------------------------
    // Step 4: Enable paging (CR0 bit 31). Protected mode bit 0 is already
    // set by GRUB2; we set it explicitly. Setting CR0.PG with LME=1 and
    // PAE=1 activates IA-32e mode on the next instruction fetch.
    // -------------------------------------------------------------------
    "mov eax, cr0",
    "or eax, 0x80000001",
    "mov cr0, eax",
    // -------------------------------------------------------------------
    // Step 5: Load a minimal 64-bit GDT and far-jump to flush the code
    // segment descriptor cache, entering 64-bit mode (segment 0x08).
    // The GDT descriptor is in .data; its physical address is fixed.
    // -------------------------------------------------------------------
    "lgdt [gdt_pointer]",
    "ljmp 0x08, OFFSET long_mode_entry",
    // ===================================================================
    // 64-bit long mode entry point
    // Reached via the far jump above. CPU is now in IA-32e 64-bit mode.
    // ===================================================================
    ".code64",
    ".global long_mode_entry",
    ".type long_mode_entry, @function",
    "long_mode_entry:",
    // Set all data segment registers to the flat kernel data descriptor
    // (selector 0x10 = third GDT entry).
    "mov ax, 0x10",
    "mov ds, ax",
    "mov es, ax",
    "mov fs, ax",
    "mov gs, ax",
    "mov ss, ax",
    // -------------------------------------------------------------------
    // Step 6: Enable SMEP (CR4 bit 20) and SMAP (CR4 bit 21).
    // 0x300000 = (1 << 20) | (1 << 21). Invariant: INV-BOOT-002.
    // SMEP prevents kernel from executing user-mode pages.
    // SMAP prevents kernel from accessing user-mode pages without STAC.
    // Must be done in 64-bit mode — these bits are ignored in 32-bit.
    // -------------------------------------------------------------------
    "mov rax, cr4",
    "or rax, 0x300000",
    "mov cr4, rax",
    // -------------------------------------------------------------------
    // Step 7: Set up the 64-bit stack. Use OFFSET (movabs) which generates
    // a correct 64-bit immediate in 64-bit code.
    // -------------------------------------------------------------------
    "mov rsp, OFFSET bootloader_stack_top",
    // -------------------------------------------------------------------
    // Step 8: Hand off to Rust. `load_kernel_module_and_jump_to_entry`
    // (defined below) walks the multiboot2 info structure to find the
    // kernel module, copies its PT_LOAD segments to their physical
    // destinations, and jumps to the kernel's entry point with EAX +
    // RBX set to the multiboot2 boot ABI values the kernel expects.
    // The Rust function never returns; the halt loop is unreachable.
    // -------------------------------------------------------------------
    "call load_kernel_module_and_jump_to_entry",
    // Halt loop — kernel entry should never return in normal operation.
    "halt_loop:",
    "cli",
    "hlt",
    "jmp halt_loop",
    // ===================================================================
    // .data: minimal 64-bit GDT
    //
    // Three 8-byte descriptors:
    //   [0x00] null descriptor (required by x86 architecture)
    //   [0x08] 64-bit kernel code: P=1, DPL=0, L=1 (64-bit), D=0, G=1
    //   [0x10] 64-bit kernel data: P=1, DPL=0, G=1
    // ===================================================================
    ".section .data",
    ".align 8",
    "gdt_table:",
    ".quad 0x0000000000000000", // [0x00] null descriptor
    ".quad 0x00AF9A000000FFFF", // [0x08] 64-bit code: L=1, P=1, DPL=0
    ".quad 0x00CF92000000FFFF", // [0x10] 64-bit data: P=1, DPL=0
    "gdt_table_end:",
    ".align 4",
    "gdt_pointer:",
    ".word gdt_table_end - gdt_table - 1", // limit = size - 1 = 23
    ".long gdt_table",                     // base = physical address
    // ===================================================================
    // .bss: page tables, stacks, and multiboot2 info pointer storage
    //
    // Layout is fixed and must match the hardcoded addresses in the
    // .code32 section above. BSS starts at 0x103000.
    //
    // Each page table must be 4096-byte aligned per the Intel spec.
    // ===================================================================
    ".section .bss",
    ".align 4096",
    // 0x103000: Page Map Level 4 — top-level page table (4096 bytes)
    "pml4_table:    .space 4096",
    // 0x104000: PDPT for identity map (first 512 GiB)
    "pdpt_identity: .space 4096",
    // 0x105000: PDPT for higher-half map
    "pdpt_high:     .space 4096",
    // 0x106000: Page Directory (shared by both PDPTs, 2MB entries)
    "pd_low:        .space 4096",
    // 0x107000: Temporary 32-bit stack (used only during long mode transition)
    ".align 16",
    "temporary_stack_bottom: .space 4096",
    // 0x108000: Top of temporary stack (stack grows down from here)
    "temporary_stack_top:",
    // 0x108000: 64-bit bootloader stack (used from long_mode_entry to kernel)
    ".align 16",
    "bootloader_stack_bottom: .space 4096",
    // 0x109000: Top of bootloader stack (stack grows down from here)
    "bootloader_stack_top:",
    // 0x109000: Multiboot2 info struct pointer storage (4 bytes).
    // Shares address with bootloader_stack_top — safe because the stack
    // grows downward (first push goes to 0x108FFC) and this storage is
    // written by the 32-bit code before the 64-bit stack is initialized.
    ".align 4",
    "multiboot2_info_pointer_storage: .space 4",
);
