# BraiNIX Unsafe Code Policy

## Purpose

Unsafe Rust is **prohibited by default** in BraiNIX. This is not "allowed with documentation" or "permitted when justified." Unsafe is prohibited. The policy mirrors the capability model: no ambient authority means no ambient unsafe.

Every crate in the BraiNIX workspace applies `#![deny(unsafe_code)]` at the crate root. Only files explicitly listed in the allowlist below may use `#![allow(unsafe_code)]` at the file level to override this denial.

This document is the authoritative specification for all unsafe code governance in BraiNIX. It defines the default policy, the complete allowlist, the exception process, the enforcement mechanism, and the audit trail requirements.

---

## Default Policy

The default policy is total prohibition:

1. **Every BraiNIX crate** includes `#![deny(unsafe_code)]` at the crate root.
2. **Every `unsafe` block** outside the allowlist is a CI merge blocker. Not a warning, not an advisory, not a suggestion. A blocker.
3. **No `unsafe` block** may exist without an accompanying `// SAFETY:` comment that explains the invariant being upheld.
4. **No `unsafe` function** may be declared without a documented safety contract in its doc comment specifying assumptions, ownership rules, aliasing constraints, preconditions, postconditions, and what would make it unsound.

The burden of proof is on the author of the unsafe code, not on the reviewer. Unsafe code is guilty until proven sound.

---

## Allowlisted Locations

The following table is the exhaustive list of source locations where `unsafe` is permitted. Each location uses `#![allow(unsafe_code)]` at the file level. Any `unsafe` code outside these locations is a CI merge blocker.

| Module/File Path | Justification | Specific Operations Permitted |
|---|---|---|
| `src/kernel/src/arch/paging/` | Page table construction requires raw pointer writes to page table entries. There is no safe Rust abstraction for writing to hardware-defined page table structures at physical addresses. | `write_volatile` to page table entries, raw pointer arithmetic for page table walks, casting physical addresses to page table entry pointers |
| `src/kernel/src/arch/interrupts/` | Interrupt Stack Table (IST) setup and Interrupt Descriptor Table (IDT) loading require direct manipulation of CPU control structures that have no safe Rust interface. | `lidt` instruction via inline assembly, stack pointer manipulation for IST entries, writing to the Task State Segment (TSS) |
| `src/kernel/src/memory/` | Capability slot zeroing on revocation requires `write_volatile` to prevent the compiler from eliding the zero-write as a dead store. This upholds invariant INV-AUTH-004 (revocation is final) and the CAP-04 requirement that revoked slots must not contain stale data. | `core::ptr::write_volatile` for capability slot zeroing, `core::ptr::write_bytes` for page zeroing before reuse |
| `src/bootloader/src/` | The bootloader executes before the kernel's safe abstractions are available. Hardware register access, memory mapping, multiboot2 info-structure traversal, and ELF64 kernel-module loading at this stage have no safe alternative. | Port I/O (`in`/`out` instructions), MSR reads and writes (`rdmsr`/`wrmsr`), memory-mapped I/O for early hardware initialization, raw address manipulation for initial memory mapping, `core::ptr::read_volatile`/`write_volatile` over GRUB-provided multiboot2 information-structure memory and over kernel-module ELF bytes during PT_LOAD segment copy, inline assembly for the 32→64-bit transition stub and for the kernel-entry trampoline (`mov rbx, …`/`jmp …` with multiboot2 boot ABI register state) |
| `src/kernel/src/arch/` (assembly stubs) | Interrupt handler entry and exit, syscall entry and exit, and context switching require inline assembly that manipulates registers and stack frames directly. These operations are inherently outside Rust's safety model. | Inline assembly (`core::arch::asm!`) for interrupt entry/exit trampolines, `syscall`/`sysret` instruction sequences, register save/restore sequences, `cli`/`sti` for interrupt flag manipulation |
| `src/kernel/src/boot/` | Identity mapping during early boot occurs before the kernel's page table abstractions are initialized. Raw address manipulation is required to establish the initial address space. Serial console output during early boot requires direct port I/O to the UART before any safe abstraction layer exists. | Raw address manipulation for identity mapping, writing to CR3 to load the initial page table, reading/writing control registers (CR0, CR4) for enabling paging and protection features, port I/O (`in`/`out` instructions) for COM1 UART serial console initialization and output (registers 0x3F8–0x3FD) |
| `src/kernel/src/main.rs` | The kernel binary entry point (`_start`) and panic handler must use `unsafe extern "C"` and inline assembly (`hlt`) to establish the initial Rust execution environment and halt the processor cleanly. No safe alternative exists for the kernel entry ABI or the halt instruction. | `unsafe extern "C" fn _start()` kernel entry point, `core::arch::asm!("hlt")` in panic handler halt loop and boot completion loop |
| `src/kernel/src/arch/hardware_registers.rs` | CPUID, MSR read/write, CR4 write, RDRAND/RDSEED instructions, and TPM TIS MMIO register access have no safe Rust wrappers on bare-metal. These are the raw hardware interface functions called by safe wrappers in `hardware_security/`. | `cpuid` instruction, `rdmsr`/`wrmsr` for IA32_SPEC_CTRL (0x48), IA32_PRED_CMD (0x49), IA32_ARCH_CAPABILITIES (0x10A), IA32_TME_ACTIVATE (0x982), MSR_AMD64_SYSCFG (0xC0010010); `mov cr4` for CET enable (bit 23); `rdrand`/`rdseed` instructions; `read_volatile`/`write_volatile` to TPM TIS registers at base 0xFED40000 |
| `src/kernel/src/hardware_security/csprng.rs` | The ChaCha20 CSPRNG state is a BSS-backed `static mut` (no dynamic allocation per kernel constraint). Access via `addr_of_mut!`/`addr_of!` is required to avoid mutable-static-reference UB (established Phase 1 pattern). Key zeroing on Phase B reseed requires `write_volatile` to prevent the compiler from eliding the zero-write as a dead store, upholding INV-AUTH-004. No safe abstraction exists for these two operations in a `no_std` bare-metal context. | `core::ptr::addr_of_mut!`/`addr_of!` for accessing BSS-backed `static mut GLOBAL_CSPRNG`; `core::ptr::write_volatile` for zeroing the old key before Phase B reseed replacement |
| `src/kernel/src/hardware_security/kernel_config_blob.rs` | `KernelSecurityConfigBlob` is `#[repr(C)]` with integer fields only and no padding-sensitive layout. Casting the struct reference to a byte slice for SHA-256 hashing requires an unsafe pointer cast. This is a single-site read-only cast used solely for PCR[1] measurement. No safe alternative exists for struct-to-bytes conversion in `no_std`. A `bytemuck` dependency is rejected: the project favors explicit allowlist entries over additional vendored dependencies for single-site operations. | `core::slice::from_raw_parts(ptr as *const u8, core::mem::size_of::<KernelSecurityConfigBlob>())` for read-only SHA-256 hashing of the config blob only |
| `src/kernel/src/hardware_security/pcr_measurement.rs` | PCR[0] measurement requires reading the kernel `.text` and `.rodata` section contents via linker-exported boundary symbols (`_text_start`, `_text_end`, `_rodata_start`, `_rodata_end`). Computing the section length from start/end pointers via `offset_from` requires unsafe pointer arithmetic. No safe abstraction exists for dereferencing linker symbols in a `no_std` bare-metal context. | `unsafe { &_text_start as *const u8 }` and equivalent for linker symbol address extraction; `unsafe { end_pointer.offset_from(start_pointer) }` for section length computation |
| `src/kernel/src/process/elf_loader.rs` | Module memory is bootloader-provided; reading ELF headers from raw bytes requires pointer arithmetic. Offsets validated defensively before dereference. | Raw pointer arithmetic over module memory, reading ELF64 header and program header fields from byte slices via offset-checked casts |
| `src/kernel/src/process/elf_load_into_address_space.rs` | Userspace ELF loading. The loader maps newly-allocated physical pages into a per-process user page table and copies segment bytes into them through the kernel's direct-map view. Page-table writes and `write_volatile` for the byte copy have no safe Rust abstraction at this layer. | `core::ptr::write_volatile` for segment byte copies; user-page-table PTE writes via `kernel_page_table::map_single_page_in_root`; PTE reads via `kernel_page_table::resolve_mapped_physical_address`; unsafe calls into `global_physical_allocator_pointer` for user-page allocation |
| `src/kernel/src/process/elf_load_failure.rs` | Pure-data hash builder for the attested-failure path. Has no unsafe blocks; the `#![allow(unsafe_code)]` is not asserted. | None — no unsafe operations performed |
| `src/kernel/src/process/address_space.rs` | Per-process page table setup requires direct PTE manipulation and CR3 write for new process address space. | CR3 write for new process, PTE manipulation for user page mappings, page allocation and mapping |
| `src/servers/libsyscall/src/lib.rs` | Userspace syscall wrappers require inline assembly for the SYSCALL instruction. No safe Rust abstraction exists for the userspace side of the SYSCALL ABI. | Inline assembly (`core::arch::asm!`) for SYSCALL instruction wrappers with register constraints |
| `src/kernel/src/capability/audit_log_protection.rs` | Write-protecting audit log pages requires modifying PTE write bits and issuing INVLPG. Already stubbed in Phase 3 with TODO(Phase 7). | PTE write-bit clear/set via page table entry manipulation, `invlpg` instruction for TLB invalidation |
| `src/kernel/src/boot/server_measurement.rs` | PCR[3] measurement reads raw server binary bytes from multiboot2 module physical addresses for SHA-256 hashing. | Reading server binary bytes from physical addresses provided by multiboot2 module tags |
| `src/kernel/src/syscall/device_map_mmio.rs` | Mapping device MMIO into a process address space requires writing to page table entries with device-specific physical addresses. This is inherently unsafe and has no safe Rust abstraction on bare metal. | PTE manipulation for MMIO mapping, raw physical address to page table entry conversion |
| `src/kernel/src/hardware_security/iommu_detection.rs` | Reading the ACPI DMAR table requires dereferencing a firmware-provided physical address. The table location comes from the ACPI RSDP/RSDT chain. No safe abstraction exists for reading firmware tables on bare metal. | Raw pointer dereference over ACPI RSDP/RSDT/DMAR table memory, reading DMAR signature bytes |
| `src/kernel/src/process/process_table.rs` | ProcessTable holds 32 Option<CapabilitySpace> entries (~320 KiB total). Placing this on the test stack causes SIGABRT. Test-only heap allocation via alloc + Box::from_raw is required; this follows the established physical_allocator.rs pattern. The unsafe is confined to cfg(test) helper functions and does not exist in production code paths. | `alloc::alloc::alloc` + `Box::from_raw` in #[cfg(test)] helpers for ProcessTable heap allocation; `core::ptr::addr_of_mut!` + `core::ptr::write` for per-entry None initialization |
| `src/kernel/src/boot/phases.rs` | Boot sequence calls unsafe initializer and accessor functions for kernel IPC state singletons (EndpointPool, ProcessTable). These calls occur at boot before any IPC dispatch is possible, following the established boot/ allowlist pattern. | Calling unsafe init/accessor functions from `kernel_ipc_state`; calling unsafe `kernel_process_table_mut` to insert CSpaces at boot |
| `src/kernel/src/process/server_launch.rs` | Storing the built Thread into `KERNEL_THREAD_POOL` requires calling the unsafe `kernel_thread_at_mut` accessor from `kernel_ipc_state`. The unsafe block is minimal (single dereference) and called only from the single-core boot path (D-03). | Calling `unsafe fn kernel_thread_at_mut` to store a Thread in the kernel thread pool at boot |
| `src/kernel/src/syscall/kernel_syscall_registers.rs` | `#[no_mangle]` on AtomicU64 statics is required for assembly RIP-relative addressing. No `unsafe` blocks exist in this file; the lint override covers only the `#[no_mangle]` attribute. | `#[no_mangle]` attribute on static items for assembly symbol visibility |
| `src/kernel/src/syscall/kernel_ipc_state.rs` | Global kernel IPC state (`EndpointPool`, `WaitForGraph`, `Thread` pool, `ProcessTable`) as `static mut` singletons with `addr_of_mut!` accessors. Required because the IPC dispatch path must access these from the SYSCALL handler without passing them through the assembly ABI. | `static mut` declarations for kernel IPC singletons; `core::ptr::addr_of_mut!` for safe `static mut` access; `MaybeUninit` for non-const-constructible types initialized at boot |
| `src/kernel/src/syscall/ipc_dispatch_handlers.rs` | IPC dispatch handler functions call `unsafe` accessor functions from `kernel_ipc_state.rs` to obtain `&mut` references to kernel IPC state. The unsafe blocks are minimal wrappers around the established `addr_of_mut!` accessor pattern. | Calling `unsafe fn` accessors from `kernel_ipc_state.rs` to obtain `&'static mut` references to kernel IPC state singletons |
| `src/kernel/src/syscall/irq_bind.rs` | sys_irq_bind handler reads syscall argument register atomics, looks up the caller's CapabilitySpace via the kernel process table (`unsafe fn` accessor), dereferences the validated `object_pointer` of a CapDevice slot as a `&'static DeviceCapabilityData`, and obtains `&mut` to the kernel IRQ binding table. | Calling `unsafe fn` accessors from `kernel_ipc_state.rs`; `*const DeviceCapabilityData::as_ref()` to dereference a validated CapDevice object_pointer; atomic load of `KERNEL_SYSCALL_*` register globals |
| `src/kernel/src/syscall/frame_map.rs` | sys_frame_map handler reads the CAP_SLOT syscall register, looks up caller CapabilitySpace via `unsafe fn kernel_process_table_mut`, and dereferences a validated `object_pointer` from a CapFrame slot as `&'static FrameCapabilityData`. Actual page-table mapping is deferred to follow-up work; this file performs validation only and fails closed. | Calling `unsafe fn` accessors from `kernel_ipc_state.rs`; `*const FrameCapabilityData::as_ref()` to dereference a validated CapFrame object_pointer; atomic load of `KERNEL_SYSCALL_CAP_SLOT_VALUE` |
| `src/kernel/src/syscall/serial_write.rs` | sys_serial_write_byte handler reads the byte-to-write from the MESSAGE_REGISTER_ZERO atomic and writes it to COM1 via SerialOutputPort. The SerialOutputPort methods themselves are allowlisted under `src/kernel/src/boot/`; this file's allowlist covers only the atomic load. | Atomic load of `KERNEL_SYSCALL_MESSAGE_REGISTER_ZERO_VALUE` from the syscall register global |
| `userland/shell/0.01/src/main.rs` | Shell binary entry stub. Contains only the `#[no_mangle] unsafe extern "C" fn _start` ELF entry (required attribute in Rust 2024+ for extern-C functions the linker references externally) plus a `#[panic_handler]`. No `unsafe` blocks, no unsafe operations — the `#![allow(unsafe_code)]` covers only the attribute requirement. | `#[no_mangle] unsafe extern "C"` attribute on `_start` for ELF entry symbol visibility |

### Allowlist Scope Rules

1. **File-level, not block-level.** The `#![allow(unsafe_code)]` attribute is applied at the file level for allowlisted modules. Individual blocks within those files still require `// SAFETY:` comments.
2. **No transitive expansion.** Being in an allowlisted module does not grant permission to use unsafe in helper modules that the allowlisted module depends on. Each file that contains unsafe must be independently allowlisted.
3. **Minimal scope within allowlisted files.** Even within an allowlisted file, unsafe blocks must be as small as possible. A function that performs one unsafe operation and ten safe operations must wrap only the unsafe operation in an `unsafe` block, not the entire function body.
4. **A path move is not a re-authorization.** The HAL extraction (P1-T2) relocates `src/kernel/src/arch/*` to `src/kernel/src/arch/x86_64/*`. Allowlist entries move with their files and their justifications carry over unchanged — but a move is the *only* thing that is automatic. If a file's unsafe operations change during the refactor, the entry is re-justified through the exception process below.
5. **Per-architecture entries are separate entries.** An allowlisted x86-64 file does not implicitly allowlist its aarch64 counterpart. `arch/x86_64/paging/` being allowlisted grants nothing to `arch/aarch64/paging/`; each requires its own row with its own justification, because the operations genuinely differ.

---

## Platform expansion (added 2026-08-02)

The Apple-primary decision will grow the unsafe surface. Recording the expected shape here **does not
pre-authorize any of it** — every file below still goes through the exception process, with its own row,
its own justification, and its own `// SAFETY:` comments. This section exists so the growth is anticipated
and reviewed rather than arriving as a surprise.

**Expected to require allowlisting** as Phase AS lands:

| Area | Why unsafe is expected | Task |
|---|---|---|
| aarch64 boot stub / entry | Entry ABI from iBoot, establishing our own MMU state, exception vectors, and stack before any abstraction exists. Nothing about the inherited state may be assumed. | AS-1 |
| s5l UART console | MMIO writes before any safe abstraction layer exists — the aarch64 analogue of the existing COM1 entry. | AS-1 |
| aarch64 page tables / MMU | Raw PTE writes, TLB maintenance. Distinct from x86-64: 16 KiB granule, different descriptor format. | P4-T2 |
| aarch64 exception vectors / context switch | Inline assembly for vector entry, register save/restore, FP/NEON state. | P4-T3, P4-T4 |
| AIC interrupt controller | MMIO register access, FIQ path, implementation-defined IPI system registers. | AS-2 |
| DART IOMMU | MMIO register access and page-table entry writes for **every discovered instance**. | AS-3 |
| RTKit / ANS2 / PCIe / NIC | Mailbox MMIO, DMA descriptor rings, device register access — in capability-bounded driver servers, **never in the kernel**. | AS-4 |

**Explicitly expected to need no unsafe:**

- **The Apple Device Tree parser** and the **boot-args parser**. These consume firmware-supplied bytes and
  are the highest-risk parsing in the system, so they are written in **entirely safe Rust** over byte
  slices with checked indexing. A request to allowlist unsafe in a hostile-input parser should be treated
  as a design failure and refused; see Rule 9.5 in [`../../PROJECT_RULES.md`](../../PROJECT_RULES.md) and
  `INV-PARSE-001`.

**A note on the trust asymmetry.** On Apple Silicon, SecureROM, iBoot1, iBoot2, and sepOS are in the TCB by
force (TCB-AS) and are not auditable by us at all. That makes the unsafe code we *can* audit — the boot
stub consuming firmware-supplied structures — disproportionately important. It is the first code we
control, and it runs on data we do not.

---

## Exception Process

Adding a new location to the allowlist requires all of the following:

1. **A pull request** that modifies this document to add the new entry to the allowlist table above.
2. **A written security exception** per PROJECT_RULES.md Rule 19, including:
   - The exact rule being deviated from (this policy's default prohibition)
   - Why the operation cannot be performed safely (with evidence, not assertion)
   - What risk the unsafe code introduces
   - Why safer alternatives were rejected (with specific alternatives named and their limitations described)
   - What compensating controls exist (tests, proofs, fuzzing, review requirements)
   - How long the exception remains active (permanent for hardware-interface code, time-bounded for workarounds)
   - What conditions would remove the need for the unsafe code
3. **At least one reviewer approval** with the reviewer confirming they have read and understood the safety contract.
4. **The new unsafe code must include:**
   - A `// SAFETY:` comment on every `unsafe` block
   - A doc-comment safety contract on every `unsafe` function
   - At least one test that exercises the unsafe code path
   - A reference to which allowlist entry the unsafe falls under

No exception is valid without documentation. Undocumented exceptions are prohibited per PROJECT_RULES.md Rule 17.5.

---

## Enforcement

Enforcement operates at three levels:

### Level 1: Compile-Time Denial

The workspace-level configuration in `Cargo.toml` includes:

```toml
[workspace.lints.clippy]
unsafe_code = "deny"
```

This causes `cargo clippy` to reject any `unsafe` block in any crate that does not explicitly override the denial. Allowlisted files use `#![allow(unsafe_code)]` at the file level to override.

### Level 2: CI Merge Gate

The CI pipeline runs `cargo clippy` with `-D warnings` as part of the `style` job. This job is the first job in the pipeline and must pass before any other job runs. Any `unsafe` block outside an allowlisted file fails the clippy check, which fails the style job, which blocks the merge.

This is enforced via GitHub branch protection rules that require all CI jobs to pass before merging to the main branch.

### Level 3: Code Review

Every pull request that introduces or modifies `unsafe` code requires:

1. The reviewer to verify the `// SAFETY:` comment is accurate and complete.
2. The reviewer to verify the code falls under an existing allowlist entry.
3. If the code requires a new allowlist entry, the reviewer to verify the exception process has been followed.
4. The reviewer to verify that tests exist for the unsafe code path.

A pull request that visibly violates this policy must not be approved, per PROJECT_RULES.md Rule 20.

### SAFETY Comment Format

Every `unsafe` block must be preceded by a comment in this format:

```rust
// SAFETY: [Explanation of why this operation is sound]
// - Precondition: [What must be true before this block executes]
// - Invariant: [Which security invariant this upholds, using IDs from SECURITY_INVARIANTS.md]
// - Evidence: [Test name or proof that validates this safety claim]
unsafe {
    // ... minimal unsafe operation ...
}
```

---

## Audit Trail

### Per-Commit Requirements

Every commit that adds or modifies `unsafe` code must include in its commit message:

1. Which allowlist entry the unsafe code falls under (by module path from the table above).
2. A one-sentence justification for why this specific change requires unsafe.
3. Confirmation that a `// SAFETY:` comment exists for every new or modified `unsafe` block.

### Tracking Metrics

The following metrics are tracked as part of the project's security posture:

1. **Total `unsafe` block count** across the workspace (measured by `cargo geiger` or equivalent).
2. **Unsafe blocks per allowlisted module** to detect scope creep within allowlisted files.
3. **New unsafe blocks per release** to track growth rate.

Any increase in the unsafe surface is reviewed as a security event per INV-UNSAFE-003 (unsafe growth is reviewed as a security event) from SECURITY_INVARIANTS.md.

### Periodic Review

The allowlist is reviewed at every phase transition to determine:

1. Whether any allowlisted location can be made safe due to new abstractions or library support.
2. Whether any allowlisted location has grown beyond its original scope.
3. Whether the `// SAFETY:` comments remain accurate after code changes.

---

## Relationship to Security Invariants

This policy directly enforces the following invariants from `docs/security/SECURITY_INVARIANTS.md`:

| Invariant ID | Invariant | How This Policy Enforces It |
|---|---|---|
| INV-UNSAFE-001 | Every unsafe block has a local soundness contract | Mandatory `// SAFETY:` comments with preconditions, invariants, and evidence |
| INV-UNSAFE-002 | Unsafe scope is minimized | Prohibited by default; hard allowlist limits where unsafe can exist |
| INV-UNSAFE-003 | Unsafe growth is reviewed as a security event | Exception process requires PR with security review; metrics tracked per release |
| INV-UNSAFE-004 | Assurance claims are traceable | Every `// SAFETY:` comment references the invariant ID and test name |
| INV-AUTH-004 | Revocation is final within defined scope | `write_volatile` for capability slot zeroing is allowlisted in `src/kernel/src/memory/` |
| INV-MEM-006 | Freed memory is sanitized before reuse | Page zeroing via `write_bytes` is allowlisted in `src/kernel/src/memory/` |

---

## Final Rule

Unsafe code in BraiNIX is not a convenience escape hatch. It is a managed hazard surface that exists only where hardware forces it. Every `unsafe` block is a place where Rust's safety guarantees do not apply, which means every `unsafe` block is a place where a bug can become a security vulnerability.

The default is prohibition. The exception is documented, reviewed, and tracked. There is no third option.
