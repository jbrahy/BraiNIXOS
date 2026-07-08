# BraiNIX Hardware Abstraction Layer (HAL)

Status: design (P1-T1). Implementation-ready specification for Phase-1 subagents. No
code is refactored by this document; it defines the trait boundary that x86-64 backends
will be coded against first, then aarch64 servers, then Apple Silicon.

Governing documents: `docs/NORTH_STAR.md`, `docs/THREAT_MODEL.md`,
`docs/architecture/MEMORY_MODEL.md`. Where this document and a governing document
disagree, the governing document wins and this document is the bug.

---

## 0. Purpose and non-goals

BraiNIX is today a single-architecture (x86-64) ring-0 microkernel. Its
architecture-specific code lives in two trees:

- `src/kernel/src/arch/**` — page tables, interrupts, syscall entry, context switch,
  timer, PCI/virtio, and the single raw-register unsafe boundary
  (`arch/hardware_registers.rs`).
- `src/kernel/src/hardware_security/**` — Spectre/IBT/entropy/TME/IOMMU/PCR logic that
  today reaches *directly into* `arch/hardware_registers.rs` for MSR/CPUID/CR4/RDRAND
  and *directly into* `arch/paging` for PTE flips.

The pivot to serve LLM inference to remote clients requires running the same confined,
capability-gated serving stack on aarch64 servers (Graviton/Ampere class) and, later,
Apple Silicon. This HAL makes every architecture-specific mechanism a **compile-time
selected backend** behind a **trait** so the kernel core, the serving path, the
inference engine, and `hardware_security/*` are written once against portable
interfaces.

**Hard constraints carried from NORTH_STAR (all preserved by this design):**

- **No new external crates.** The HAL is entirely in-tree. Backends may only use `core`
  and in-tree modules. (The x86-64 backend keeps calling the already-vendored `x86_64`
  crate *inside the backend* until that debt is paid down; the trait surface exposes
  none of it.)
- **`no_std`, no kernel heap.** No trait method allocates. Every buffer is a
  caller-owned fixed-size slice or a `Copy` value type. No `Box`, no `Vec`, no `dyn`.
- **W^X survives (INV-MEM).** The MMU trait cannot express a writable+executable
  mapping that reaches hardware without passing the W^X validator; the validator is
  promoted into the portable layer so *every* backend inherits it.
- **No `dyn` dispatch.** Backends are selected by `cfg(target_arch)` and bound to a
  single concrete zero-sized type per concern. Every call is static and inlinable;
  there are no vtables, no trait objects, no function pointers in the hot path.
- **The trait boundary must not create a way to violate INV-AUTH/INV-MEM.** Traits
  expose *mechanism*, never *policy*: a backend can program a page table but cannot
  decide who gets a capability; it can save FP state but cannot read another session's.

**Non-goals of the HAL:** it does not abstract the capability model, the IPC rendezvous,
the scheduler policy, the serving protocol, or the inference engine. Those are
architecture-independent already and stay in portable modules that *consume* the HAL.

---

## 1. Design shape: `cfg`-selected zero-cost backends, no `dyn`

Each concern is one trait. Each trait has **exactly one implementor per target arch**,
a zero-sized marker type, selected at compile time. The kernel refers to the active
backend through a single type alias per concern, resolved by `cfg`.

```
src/kernel/src/hal/
  mod.rs            // trait definitions + the cfg type-alias table (the ONLY cfg switch)
  mmu.rs            // trait Mmu
  interrupts.rs     // trait Interrupts
  timer.rs          // trait Timer
  context.rs        // trait Context      (+ portable RegisterFile value type)
  syscall.rs        // trait SyscallAbi
  entropy.rs        // trait Entropy
  mitigations.rs    // trait Mitigations
  iommu.rs          // trait Iommu
  measure.rs        // trait Measure
  fpu.rs            // trait Fpu          (NEW)
  bus.rs            // trait Bus + trait DmaRegion
  wx.rs             // portable W^X validator (arch-independent, shared by all MMU backends)

src/kernel/src/arch/
  x86_64/           // existing arch/** files move here; implement every hal trait
  aarch64/          // Phase-2+; server-class ARM (GICv3, SMMUv3, generic timer, PAC/BTI)
  apple/            // later; Apple Silicon (AIC, DART, PMU timer, PAC/BTI)
```

### 1.1 The single `cfg` switch

All conditional compilation for backend selection lives in **one place**, `hal/mod.rs`.
No other module contains a `cfg(target_arch)` for backend selection (existing
`cfg`s inside `hardware_security/*` that return host-test stubs are replaced by calls
through the HAL, so `#[cfg(not(target_arch="x86_64"))]` shims disappear from those files).

```rust
// hal/mod.rs — the ONLY backend cfg switch in the kernel.
#[cfg(target_arch = "x86_64")]
mod active {
    pub use crate::arch::x86_64::mmu::X86Mmu           as ActiveMmu;
    pub use crate::arch::x86_64::interrupts::X86Ints   as ActiveInterrupts;
    pub use crate::arch::x86_64::timer::X86Timer        as ActiveTimer;
    pub use crate::arch::x86_64::context::X86Context     as ActiveContext;
    pub use crate::arch::x86_64::syscall::X86Syscall      as ActiveSyscall;
    pub use crate::arch::x86_64::entropy::X86Entropy        as ActiveEntropy;
    pub use crate::arch::x86_64::mitigations::X86Mitigations as ActiveMitigations;
    pub use crate::arch::x86_64::iommu::VtdIommu              as ActiveIommu;
    pub use crate::arch::x86_64::measure::TpmMeasure           as ActiveMeasure;
    pub use crate::arch::x86_64::fpu::XsaveFpu                  as ActiveFpu;
    pub use crate::arch::x86_64::bus::PciBus                     as ActiveBus;
}
#[cfg(target_arch = "aarch64")]
mod active { /* Gicv3Ints, SmmuV3Iommu, PacBtiMitigations, NeonFpu, ... */ }

pub use active::*;
```

Portable kernel code never names a concrete backend; it calls
`<ActiveMmu as Mmu>::map_page(...)` (or through thin free-function facades that do the
same). Because each alias resolves to a concrete zero-sized type, monomorphization emits
a direct call — identical codegen to today's free functions, zero indirection.

### 1.2 Why traits at all (vs. plain `cfg`ed free functions)

A trait pins a **checked contract**: the compiler refuses to build a target whose
backend is missing a method, so a half-ported arch fails at compile time rather than
silently linking a stub. The trait is also the natural home for the safety contract and
the invariant mapping (below), and it lets the portable W^X validator and the portable
`RegisterFile`/`Digest` value types be shared verbatim across backends. `dyn` is never
needed because there is exactly one implementor per build.

### 1.3 Host-test story

`hardware_security/*` today carries `#[cfg(not(target_arch="x86_64"))]` stubs so pure
logic is unit-testable on the dev host. Those move behind the HAL: a `#[cfg(test)]`-only
`HostMock*` implementor per trait lives under `hal/` and is selected when building the
host test binary. Pure logic (mode selection, policy decisions, digest math) stays in
portable functions that take backend *outputs* as arguments and need no backend at all —
exactly as `determine_mode_from_capabilities` / `should_halt_due_to_absent_rdrand` /
`compute_boot_may_continue` already do. This keeps machine-checked coverage growing
without a live CPU.

---

## 2. The traits

Notation: every method's `# Safety` note is the **contract the caller must uphold**;
every trait's **Invariants** line names the NORTH_STAR invariant(s) the backend must
preserve and that a security audit checks the backend against. "Abstracts" names the
existing x86 file the trait subsumes.

### 2.1 `Mmu` — page tables and W^X

Abstracts: `arch/paging/kernel_page_table.rs`, `arch/paging/user_page_table.rs`,
`arch/paging/direct_map.rs`, `arch/paging/page_table_walk_helpers.rs`,
`arch/paging/stack_guard.rs`, and the flag computations in
`arch/paging/page_table_flags_validator.rs`.

The portable W^X validator (`hal/wx.rs`) and the portable permission vocabulary are
lifted **out** of the backend so no backend can define them away.

```rust
/// Architecture-neutral leaf permission. There is deliberately no
/// `WriteExecute` variant — W^X is unrepresentable, not merely rejected.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Perm {
    KernelCodeRX,     // present, executable, read-only        (kernel .text)
    KernelDataRW,     // present, writable, no-execute         (kernel data/stack/pool)
    KernelRoData,     // present, read-only, no-execute        (kernel .rodata)
    UserCodeRX,       // present, user, executable, read-only
    UserDataRW,       // present, user, writable, no-execute
    DeviceMmioRW,     // present, writable, no-execute, strong-uncacheable
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum MapError { WouldViolateWxInvariant, Unmapped, RangeOverlap, PoolExhausted }

pub trait Mmu {
    /// Opaque handle to a top-level translation root (x86: PML4 phys; arm: TTBR0/1).
    type Root: Copy;

    /// Build the kernel address space (code RX, data RW, rodata RO, direct map,
    /// guard page UNMAPPED, MMIO windows). Returns the kernel root.
    /// # Safety: single-threaded boot, called once before paging is active.
    unsafe fn build_kernel_root() -> Self::Root;

    /// Allocate an empty user root from the BSS bootstrap pool (no kernel VA entries).
    /// # Safety: single-threaded construction; caller owns the returned root.
    unsafe fn new_user_root() -> Self::Root;

    /// Map one page. `perm` is a closed enum, so a W^X mapping cannot be requested;
    /// the impl still calls the portable validator on the flags it derives, so a
    /// backend bug that widens flags fails closed with `WouldViolateWxInvariant`.
    /// # Safety: caller holds exclusive access to `root`; `phys` is a real frame.
    unsafe fn map_page(root: Self::Root, virt: u64, phys: u64, perm: Perm) -> Result<(), MapError>;

    /// Read-only walk: VA -> PA in `root`, or Unmapped.
    /// # Safety: caller holds exclusive access to `root`.
    unsafe fn translate(root: Self::Root, virt: u64) -> Result<u64, MapError>;

    /// Flip a live kernel leaf to read-only (post-init .text/.rodata lockdown) and
    /// flush translation caches for `virt`. Idempotent.
    /// # Safety: `virt` is a mapped kernel leaf; caller sequences the TLB flush.
    unsafe fn write_protect_page(virt: u64) -> Result<(), MapError>;

    /// Physical address of `root`, to load into the translation-base register.
    fn root_phys(root: Self::Root) -> u64;

    /// Install `root` as the active address space (x86: CR3 load; arm: TTBR + ISB).
    /// # Safety: `root` maps the current instruction pointer and stack, or the
    /// machine faults. This is the KPTI CR3-swap primitive.
    unsafe fn activate(root: Self::Root);
}
```

**Invariants preserved:** INV-MEM (W^X: `Perm` has no W+X variant and the portable
validator gates every backend write; no-heap: roots and intermediate tables come only
from the fixed BSS bootstrap pool, `map_page` returns `PoolExhausted` rather than
growing; KPTI: `new_user_root` yields an empty root, kernel is never mapped user-visible).
INV-SERVE indirectly: per-process roots are the substrate that keeps client sessions in
disjoint address spaces.

**Notes for backends.** The x86 backend keeps its existing bootstrap-pool allocator and
the guard-page-skipping stack mapping verbatim; it just implements them under
`X86Mmu`. The KPTI trampoline's supervisor-only two-page mapping (below, §2.5) is the
single named exception to "kernel not in user root" and is expressed through `map_page`
with a backend-private supervisor perm that is **not** in the public `Perm` enum — it is
constructed only inside the syscall backend, never reachable from portable code.

### 2.2 `Interrupts` — trap/exception vectors

Abstracts: `arch/interrupts/mod.rs`, `interrupt_descriptor_table.rs`,
`global_descriptor_table.rs`, `task_state_segment.rs`, `halt.rs`.

```rust
/// Portable classification of a synchronous fault, decoded by the backend from
/// its native vector + error code. Portable fault policy (halt vs. deliver)
/// keys off this, not off x86 vector numbers.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FaultClass {
    PageFault { addr: u64, write: bool, user: bool, instr_fetch: bool },
    ProtectionFault, IllegalInstruction, DivideError, DoubleFault,
    ControlFlowViolation,  // x86 #CP / arm BTI failure
    MachineCheck, Other,
}

pub trait Interrupts {
    /// Build and install the trap vectors + the separate fault stack
    /// (x86: GDT/TSS/IST + IDT; arm: VBAR_EL1 + SPSel stack).
    /// # Safety: single-threaded boot, before any interrupt can fire.
    unsafe fn install_traps();

    /// Mask / unmask asynchronous interrupts (x86: CLI/STI; arm: DAIF).
    /// # Safety: toggling delivery around a critical section; caller re-enables.
    unsafe fn set_interrupts_enabled(enabled: bool);

    /// Disable interrupts and halt forever. The fail-closed sink for any
    /// unrecoverable fault. Never returns.
    fn halt() -> !;

    /// The portable fault dispatcher the backend's raw trap stubs call after
    /// decoding native vector+error into a `FaultClass`. Returns whether the
    /// kernel handled it; `false` means the backend halts.
    fn on_fault(class: FaultClass, ip: u64, sp: u64) -> bool;
}
```

**Invariants preserved:** INV-MEM (fault delivery is the enforcement arm of W^X and the
stack guard page: a write to protected `.text`/guard page arrives as `PageFault` and the
portable handler halts — the `is_kernel_text_page` check moves into `on_fault`).
Fail-closed (`halt` is the universal sink). The backend owns *decoding*; policy stays
portable so no arch can silently drop a fault class.

### 2.3 `Timer` — scheduler tick

Abstracts: `arch/timer.rs` (LAPIC timer).

```rust
pub trait Timer {
    /// Program a periodic tick at the fixed scheduler rate and start it.
    /// # Safety: timer MMIO/registers are mapped; called once at boot.
    unsafe fn start_periodic();

    /// Acknowledge the current tick so the next one can fire (x86: LAPIC EOI;
    /// arm: write CNTV_TVAL + GIC EOI). Called at the end of every tick handler.
    /// # Safety: called only from within the tick interrupt handler.
    unsafe fn acknowledge_tick();

    /// Monotonic tick counter for IPC timeouts (portable scheduler reads this).
    fn now_ticks() -> u64;
}
```

**Invariants preserved:** INV-SERVE / partitioned scheduling (the tick is what preempts
one client session so another runs; a backend that failed to re-arm would starve the
partition — `acknowledge_tick` makes re-arming mandatory and testable). No new authority
is exposed.

### 2.4 `Context` — register save/restore for context switch

Abstracts: `arch/context_switch_assembly.rs`; owns the shape of
`thread::RegisterSaveArea`.

```rust
/// Portable, fixed-size, `Copy` integer register file. The x86 backend maps
/// this onto today's RegisterSaveArea fields; arm maps x0..x30,sp,pc,pstate.
/// Large enough for every target's GP set; unused slots are zero. No heap.
#[derive(Copy, Clone, Debug, Default)]
pub struct RegisterFile { /* backend-defined fixed array, portable accessors */ }

pub trait Context {
    /// Snapshot the current thread's integer registers into `out`.
    /// # Safety: `out` is exclusively owned; caller pairs save with a later restore.
    unsafe fn save(out: &mut RegisterFile);

    /// Restore integer registers from `in_` (stack pointer handled by the
    /// switch frame, not here, matching current x86 behavior).
    /// # Safety: `in_` is a valid prior snapshot of a resumable thread.
    unsafe fn restore(in_: &RegisterFile);

    /// Full switch: save outgoing, (FPU handled by `Fpu` at the call site,) restore
    /// incoming. The scheduler calls this; it never touches raw registers itself.
    /// # Safety: both areas are valid and exclusively owned for the switch.
    unsafe fn switch(from: &mut RegisterFile, to: &RegisterFile);
}
```

**Invariants preserved:** INV-SERVE / cross-session isolation (a switch that leaked a
register from client A into client B's resumed context is a cross-tenant leak; the trait
makes save/restore total over the register file). Note the switch does **not** save FP
state — that is the FPU trait's job, sequenced by the scheduler so the two concerns stay
independently testable and independently auditable.

### 2.5 `SyscallAbi` — kernel entry/exit (the trap gate + KPTI trampoline)

Abstracts: `arch/syscall_entry.rs`, `arch/syscall_trampoline.rs`.

This is the most security-critical trait: it is the ring-3→ring-0 gate and the KPTI
CR3-swap. Its contract is deliberately narrow.

```rust
pub trait SyscallAbi {
    /// Install the syscall entry vector (x86: LSTAR/STAR/SFMASK + EFER.SCE;
    /// arm: nothing beyond the SVC path in VBAR, so a near-noop).
    /// # Safety: ring 0, after traps/segments are installed.
    unsafe fn install_entry();

    /// Record the kernel translation root + ring-0 stack the entry trampoline
    /// swaps to (x86: fills SYSCALL_TRAMPOLINE_SCRATCH[0,1]).
    /// # Safety: called once after the kernel root is active.
    unsafe fn record_kernel_entry_state();

    /// Record the active user root for the return path / copy_from_user.
    /// # Safety: single-core, non-preemptible; `root_phys` is a valid user root.
    unsafe fn set_active_user_root(root_phys: u64);

    /// Read back the active user root (portable copy_from_user translates
    /// user pointers against it).
    fn active_user_root() -> u64;

    /// Map the entry trampoline code page(s) + scratch page into a user root as
    /// SUPERVISOR-ONLY (U/S=0) entries. This is the one named KPTI exception to
    /// "kernel not in user root"; it exposes no general kernel memory and is
    /// unreachable from ring 3.
    /// # Safety: caller holds exclusive access to `root`; single-threaded build.
    unsafe fn map_trampoline_into_user_root(root: Mmu::Root);

    /// First entry to ring 3 for a thread: set current thread id, record its
    /// root, and jump to `entry` on `user_sp` under `user_root`. Never returns.
    /// # Safety: `user_root` maps `entry`, `user_sp`, and the trampoline pages.
    unsafe fn enter_userspace(thread_id: u32, entry: u64, user_sp: u64, user_root: u64) -> !;
}
```

The register ABI (which registers carry endpoint/cap/message args) is defined by
`docs/architecture/IPC_SPEC.md` and is **portable**: the backend's asm stub marshals the
native registers into the same `KERNEL_SYSCALL_*` values the portable dispatcher reads,
so the IPC dispatch code is arch-independent. The canonical-RIP check
(`is_canonical_virtual_address`) is an x86 SYSRET erratum guard and stays private to the
x86 backend; the trait does not expose it.

**Invariants preserved:** INV-AUTH (this gate is the *only* way to enter the kernel and
name a capability; the backend may not add a second entry path — the trait is the whole
surface, audited as such). INV-MEM/KPTI (the trampoline mapping is supervisor-only and
the exit swaps back to the user root; a backend cannot leave the kernel root active in
ring 3). INV-SERVE (`set_active_user_root` + `active_user_root` are what bind
`copy_from_user` to the *calling* client's address space, so one client cannot make the
kernel read another's memory).

### 2.6 `Entropy` — hardware RNG source

Abstracts: the RDRAND/RDSEED wrappers in `arch/hardware_registers.rs` consumed by
`hardware_security/entropy_source.rs`; feeds `hardware_security/csprng.rs`.

```rust
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum EntropyError { HardwareEntropyUnavailable }

pub trait Entropy {
    /// True if a hardware RNG is present (x86: CPUID RDRAND bit; arm: RNDR/TRNG).
    fn hardware_available() -> bool;

    /// Fill `out` with hardware entropy, retrying transient failures internally.
    /// Fails closed if the source is absent/exhausted — the caller (boot) halts,
    /// per the locked "no entropy => no boot" policy.
    /// # Safety: none beyond ring 0; instruction is non-destructive.
    fn fill(out: &mut [u64]) -> Result<(), EntropyError>;

    /// Best-effort high-quality seed samples (x86: RDSEED; arm: RNDRRS).
    /// `None` per slot is non-fatal; the CSPRNG folds what it gets.
    fn seed_samples(out: &mut [Option<u64>]);
}
```

**Invariants preserved:** INV-BOOT / INV-MODEL weight-integrity anchor (the CSPRNG that
seeds session keys, nonces, and measurement salts depends on this; fail-closed absence
keeps the "explicit, conservative entropy" boot policy). No authority exposed — pure
source of bytes.

### 2.7 `Mitigations` — speculation and control-flow hardening

Abstracts: `hardware_security/spectre_mitigation.rs` (its MSR reach-through) and
`hardware_security/indirect_branch_tracking.rs` (its CR4 reach-through). On aarch64 the
same concerns map to **PAC** (pointer authentication) and **BTI** (branch target
identification) plus CSDB/SB speculation barriers.

```rust
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum BranchSpecPolicy { SoftwareSequences = 0, HardwareEnforced = 1 }

pub trait Mitigations {
    /// Detect and return the strongest available branch-speculation policy
    /// (x86: eIBRS via IA32_ARCH_CAPABILITIES; arm: BTI/CSV2 feature regs).
    fn detect_branch_spec_policy() -> BranchSpecPolicy;

    /// Enable it (x86: IBRS MSR write when eIBRS absent; enable CET/IBT CR4.23;
    /// arm: enable BTI enforcement / PAC keys). No-op where hardware-always-on.
    /// # Safety: ring 0; called once at boot before untrusted code runs.
    unsafe fn enable(policy: BranchSpecPolicy);

    /// Flush indirect-branch predictor state across a domain switch
    /// (x86: IBPB; arm: appropriate barrier). Called on every context switch
    /// between mutually distrusting domains (e.g. client sessions).
    /// # Safety: ring 0; non-destructive to architectural state.
    unsafe fn barrier_on_domain_switch();

    /// Speculative-load fence after a bounds check (x86: LFENCE; arm: CSDB/SB).
    /// Inlined; compile-time Spectre-v1 mitigation on identified paths.
    #[inline(always)]
    fn speculation_barrier();

    /// Serialize the selected policy into one byte for the PCR[1] config blob,
    /// so the active mitigation posture is measured into the boot chain.
    fn policy_tag() -> u8;
}
```

Pure decision logic (`determine_mode_from_capabilities`,
`is_enhanced_ibrs_supported`) stays as portable functions taking the detected
capability word; only the *reads/writes* are behind the trait. This keeps the existing
host tests intact.

**Invariants preserved:** INV-MODEL / INV-SERVE (predictor barriers on session switches
are part of what stops one hostile prompt's session from leaking another's via
speculation; W^X + IBT/BTI keep injected gadgets from executing). INV-BOOT (`policy_tag`
feeds the measured config blob). The trait exposes no way to *disable* a mitigation from
portable code — `enable` only strengthens.

### 2.8 `Iommu` — DMA confinement

Abstracts: `hardware_security/iommu_detection.rs`. Backends: **VT-d** (x86, ACPI DMAR),
**SMMUv3** (aarch64 server, IORT), **DART** (Apple Silicon).

```rust
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum IommuPresence { Present, Absent }

pub trait Iommu {
    /// Detect an IOMMU (x86: ACPI DMAR; arm: ACPI IORT / DT).
    fn detect() -> IommuPresence;

    /// Program a bounded DMA translation window for a device so it can reach
    /// ONLY `iova..iova+len` -> `phys..`. Returns the IOVA base the device must use.
    /// The device cannot widen this window (INV-GPU control).
    /// # Safety: ring 0; `phys..phys+len` is a real, device-grantable region;
    /// caller holds the device's grant.
    unsafe fn map_dma_window(phys: u64, len: u64, writable: bool) -> Result<u64, IommuError>;

    /// Tear the window down on device-capability revocation.
    /// # Safety: `iova` was returned by `map_dma_window` and is no longer in use.
    unsafe fn unmap_dma_window(iova: u64, len: u64) -> Result<(), IommuError>;
}
```

Policy (`enforce_iommu_policy`: production halts on absent, dev warns) stays a portable
function taking `IommuPresence` and the enforcement mode — unchanged, still host-tested.

**Invariants preserved:** INV-GPU / INV-SERVE (bounded windows are the control that keeps
a device or its driver from DMAing into kernel or another client's memory; the trait can
only *narrow* device reach, never grant blanket memory access). Fail-closed: the current
x86 backend returns `Absent` until ACPI DMAR traversal lands, so production keeps halting
rather than pretending isolation exists.

### 2.9 `Measure` — measured boot / attestation

Abstracts: `hardware_registers.rs` TPM TIS MMIO wrappers, `hardware_security/tpm/**`,
`pcr_measurement.rs`, `server_measurement.rs`. Backends: **TPM 2.0** (x86 TIS at
0xFED40000), **software-fallback** (in-tree measurement log when no TPM — matches the
THREAT_MODEL "honest software-only fallback" until the vTPM gap closes), **none** (arch
with neither, still keeps the measurement log for reproducibility).

```rust
/// Fixed-size digest; no heap. SHA-256 today (already vendored), 32 bytes.
pub type Digest = [u8; 32];

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum MeasureBackendKind { Tpm2, SoftwareFallback, None }

pub trait Measure {
    /// Which backend is live — measured into the config blob so verifiers know
    /// whether attestation is hardware-anchored or software-only.
    fn kind() -> MeasureBackendKind;

    /// Extend PCR `index` with `digest` (TPM: TIS extend; software: fold into the
    /// in-memory measurement log). Ordering is the caller's (portable) concern.
    /// # Safety: ring 0; `index` is a valid PCR slot; called during boot measure.
    unsafe fn extend_pcr(index: u8, digest: &Digest) -> Result<(), MeasureError>;

    /// Read back a PCR / log slot for the attestation gate and PCR prediction check.
    /// # Safety: ring 0; `index` valid.
    unsafe fn read_pcr(index: u8) -> Result<Digest, MeasureError>;
}
```

SHA-256 computation and the config-blob layout stay portable (they already are, in
`pcr_measurement.rs` / `kernel_config_blob.rs`); only the PCR extend/read hit the
backend.

**Invariants preserved:** INV-BOOT (measured boot; `kind()` is measured so a
software-fallback boot cannot masquerade as TPM-anchored — the fallback is *honest*, per
THREAT_MODEL §0/§Deployment). INV-MODEL (weight-integrity is anchored to a measured
digest through the same extend path). Fail-closed: a `MeasureError` on extend must abort
the gate, never open it.

### 2.10 `Fpu` — userspace FP/SIMD state (NEW; required by the inference engine)

No FP/SIMD save-restore exists in the tree today (confirmed: no `xsave`/`fxsave`/`fpu`
references). The CPU-only inference engine runs in a confined userspace tenant and will
use SIMD (x86: SSE/AVX/AVX-512; arm: NEON/SVE) heavily. When the scheduler switches
between the inference tenant and any other domain — crucially, between two client
sessions time-sharing the engine — FP/SIMD register state **must** be saved and restored,
or one client's partial activations/KV math leak into another's registers. This is a
first-order INV-SERVE cross-tenant concern, which is exactly why it earns its own trait
rather than being folded into `Context`.

```rust
/// Opaque, fixed-size, alignment-correct FP/SIMD save area. Lives in the
/// per-thread control block (fixed pool, no heap). Sized at build time for the
/// widest state the target enables (x86: XSAVE area for enabled features;
/// arm: NEON/SVE registers). `#[repr(C, align(64))]`, backend-defined length.
pub struct FpuState { /* backend-defined fixed byte array */ }

pub trait Fpu {
    /// Enable userspace FP/SIMD at boot (x86: CR0.MP/EM, CR4.OSFXSR/OSXSAVE, XCR0
    /// feature mask; arm: CPACR_EL1 FPEN). Chooses the enabled feature set.
    /// # Safety: ring 0, once at boot.
    unsafe fn enable();

    /// Zero-initialize a fresh save area for a new thread so it starts with no
    /// inherited SIMD state (INV-SERVE: no leakage into a new session).
    fn init_state(state: &mut FpuState);

    /// Save live FP/SIMD state into `out` (x86: XSAVE/FXSAVE; arm: NEON/SVE store).
    /// # Safety: `out` is exclusively owned; paired with a later restore.
    unsafe fn save(out: &mut FpuState);

    /// Restore FP/SIMD state from `in_` (x86: XRSTOR/FXRSTOR; arm: load).
    /// # Safety: `in_` is a valid prior snapshot for the resuming thread.
    unsafe fn restore(in_: &FpuState);

    /// Scrub live FP/SIMD registers to zero on a switch between mutually
    /// distrusting domains, before the incoming domain's restore. Defense in
    /// depth against SIMD-register residue across a client-session boundary.
    /// # Safety: ring 0; destroys live FP state, so call between save and restore.
    unsafe fn scrub_on_domain_switch();
}
```

The scheduler sequences `Fpu::save(outgoing)` →
`Mitigations::barrier_on_domain_switch()` → `Fpu::scrub_on_domain_switch()` →
`Fpu::restore(incoming)` around `Context::switch`. Lazy FP switching (x86
`#NM`/device-not-available trap) is a **backend-internal optimization** only, and only if
it can be proven not to leak state across a session boundary; the default is eager
save/restore because correctness and non-leakage dominate throughput per NORTH_STAR.

**Invariants preserved:** INV-SERVE (no client's SIMD state leaks to another —
`init_state` and `scrub_on_domain_switch` make non-leakage structural). INV-MEM (the save
area is a fixed-size field in the pool-allocated thread block, never a heap allocation;
its size is a build-time constant). INV-MODEL (the inference tenant gets full SIMD compute
but no new authority — `Fpu` exposes registers, never memory or capabilities).

### 2.11 `Bus` — PCI/PCIe enumeration + virtio transport + DMA regions

Abstracts: `arch/pci.rs`, `arch/virtio_blk.rs` (and the future virtio-net path;
`arch/e1000.rs` is a concrete device driver that consumes this, not part of the trait).
Backends: **PCIe ECAM + legacy 0xCF8/0xCFC** (x86), **PCIe ECAM + MMIO virtio** (arm
servers), **Apple-specific** (later).

```rust
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct BusDeviceLocation { /* segment/bus/device/function + vendor/device ids */ }

/// A page-aligned, fixed-size DMA-capable region (BSS-backed, no heap). Its
/// device-visible address goes through `Iommu::map_dma_window` when an IOMMU is
/// present; otherwise it is the direct-mapped physical address.
pub struct DmaRegion { /* backend fixed buffer + phys/iova accessors */ }

pub trait Bus {
    /// Enumerate present functions, invoking `visit` per device (no heap; caller
    /// keeps its own fixed table). Used at boot to discover virtio devices and
    /// validate the hardcoded MMIO bases before granting a CapDevice.
    fn for_each_device(visit: impl FnMut(BusDeviceLocation));

    /// Find the first function matching (vendor, device).
    fn find_device(vendor: u16, device: u16) -> Option<BusDeviceLocation>;

    /// Read/write a config-space dword.
    /// # Safety: ring 0; `loc` is a real function; config space is not RAM.
    unsafe fn config_read(loc: BusDeviceLocation, offset: u16) -> u32;
    unsafe fn config_write(loc: BusDeviceLocation, offset: u16, value: u32);

    /// Enable memory-space decode + bus-master DMA for a device the kernel or a
    /// device server will drive.
    /// # Safety: ring 0; enabling DMA — the region the device reaches MUST be
    /// IOMMU-confined first when an IOMMU is present (INV-GPU/INV-SERVE).
    unsafe fn enable_bus_master(loc: BusDeviceLocation);

    /// Read a device BAR (MMIO base) so it can be validated against the device
    /// table and mapped as `Perm::DeviceMmioRW`.
    /// # Safety: ring 0; `loc` is a real function.
    unsafe fn read_bar(loc: BusDeviceLocation, bar_index: u8) -> u64;
}
```

**Invariants preserved:** INV-SERVE / INV-GPU (the doc-comment and safety contract on
`enable_bus_master` bind DMA enablement to prior IOMMU confinement; the kernel
enumerates to *validate* device topology before a `CapDevice` grant, never to hand out
ambient device authority — drivers stay userspace servers). INV-MEM (`DmaRegion` is a
fixed BSS buffer; the trait never grows one from device-supplied sizes — the virtio
decoder's fail-closed length checks stay in the portable driver above the trait).
INV-AUTH (enumeration yields *data* — a `BusDeviceLocation` — not a capability; grants are
minted by the portable capability layer from that data).

---

## 3. `hardware_security/*` becomes a consumer, not an owner

Today `hardware_security/*` modules reach directly into `arch/hardware_registers.rs`
(MSR/CPUID/CR4/RDRAND/TPM MMIO) and into `arch/paging` (PTE flips), and each carries its
own `#[cfg(target_arch = "x86_64")]` / `#[cfg(not(...))]` split. Under the HAL they
**own no intrinsics and no `cfg`** — they call traits:

| `hardware_security` module | Was (owned x86 intrinsic) | Becomes (consumes HAL trait) |
|---|---|---|
| `entropy_source.rs` | `execute_rdrand/rdseed_instruction`, CPUID | `Entropy::fill / seed_samples / hardware_available` |
| `csprng.rs` | seeds from entropy_source | unchanged logic; seeded via `Entropy` |
| `spectre_mitigation.rs` | RDMSR/WRMSR 0x48/0x49/0x10A, LFENCE | `Mitigations::{detect_branch_spec_policy, enable, barrier_on_domain_switch, speculation_barrier, policy_tag}` |
| `indirect_branch_tracking.rs` | RD/WR CR4 bit 23, CPUID leaf 7 | folded into `Mitigations::{detect,enable}` |
| `memory_encryption.rs` | RDMSR/WRMSR TME/SME MSRs, CPUID | `Mitigations` (or a small `MemEncrypt` sub-method) — see open question Q3 |
| `iommu_detection.rs` | ACPI DMAR pointer walk | `Iommu::detect`; policy stays portable |
| `pcr_measurement.rs` | TPM TIS MMIO + linker-symbol section reads | `Measure::extend_pcr/read_pcr`; SHA-256 stays portable |
| `server_measurement.rs` | TPM extend | `Measure::extend_pcr` |
| `kernel_write_protection.rs` | PTE writable-bit clear via `arch/paging` | `Mmu::write_protect_page`; `is_kernel_text_page` moves into `Interrupts::on_fault` |
| `cpu_feature_detection.rs` | pure CPUID *decoding* | stays portable; receives raw feature words from the backend |
| `tpm/**` | TIS command/response over MMIO | becomes the **x86 `Measure` backend body** under `arch/x86_64/measure.rs` |

The rule: **pure logic stays in `hardware_security/` and stays host-testable; every raw
instruction/MMIO access moves into `arch/<arch>/*` behind a trait.** The
`hardware_security` layer keeps the *security decisions* (halt-on-absent-entropy,
prod-vs-dev IOMMU policy, mitigation selection, measurement ordering, attestation-gate
opening) — those are portable and are the falsifiable checks NORTH_STAR requires. The
backend keeps only the *mechanism*. This shrinks each `hardware_security` file's unsafe
surface to zero (it already aspires to that: "Callers in `hardware_security/` have zero
unsafe code") and makes the whole subsystem port for free to any arch that supplies the
backends.

---

## 4. Backend selection and directory layout (recap)

- **Selection:** one `cfg(target_arch)` block in `hal/mod.rs` maps each trait to its
  concrete zero-sized backend type (§1.1). Nowhere else selects a backend.
- **Layout:** existing `arch/*.rs` and `arch/paging|interrupts/**` files move under
  `arch/x86_64/` and each implements the relevant trait(s). `arch/aarch64/` and
  `arch/apple/` are added when those milestones land; until then they do not exist and
  the kernel only builds for x86-64, exactly as today.
- **Build:** the kernel target triple selects the arch; a target with a missing backend
  method fails to compile (the trait is the checklist). No runtime probing, no `dyn`.
- **Migration is mechanical and staged per trait:** wrap the existing free functions in
  a backend `impl`, introduce the trait + alias, flip callers to the alias, delete the
  now-dead `cfg(not(x86_64))` stubs from `hardware_security/*`. Each trait can land as
  its own atomic commit behind a security-audit gate.

---

## 5. Invariant → trait obligation matrix

Each cell is what the security audit verifies for that trait/invariant pair.

| Invariant | Mmu | Interrupts | Timer | Context | SyscallAbi | Entropy | Mitigations | Iommu | Measure | Fpu | Bus |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **INV-MEM (W^X)** | `Perm` has no W+X; portable validator gates every write | delivers W^X fault → `halt` | — | — | trampoline map is supervisor-only, RX code / RW-NX scratch | — | IBT/BTI + W^X stop injected exec | — | — | save area is fixed pool field | `DmaRegion` fixed-size, never grown from device |
| **INV-MEM (no heap)** | roots/tables from BSS pool; `PoolExhausted` not grow | fixed IST/trap stacks | — | fixed `RegisterFile` | fixed scratch | fixed `[u64]` out | — | fixed window tables | fixed `Digest` | fixed `FpuState` | fixed `DmaRegion` |
| **INV-AUTH** | maps mechanism, grants nothing | — | — | — | **sole** kernel-entry gate; no 2nd path | — | can only strengthen, never disable | — | — | — | yields data, not caps |
| **INV-SERVE (cross-tenant)** | per-session disjoint roots | — | tick preempts one session for another | total save/restore, no reg leak | binds copy_from_user to caller root | — | predictor barrier on session switch | bounded DMA window per device | — | init+scrub → no SIMD leak | per-device confinement |
| **INV-BOOT** | — | — | — | — | — | fail-closed seed for measure salts | `policy_tag` measured | — | `extend/read_pcr`; `kind()` measured | — | — |
| **INV-MODEL** | confines weight region mapping | — | — | — | model tenant enters via same gate, no extra authority | seeds integrity checks | barriers cap speculative cross-read | (GPU milestone) DMA confinement | weight digest anchored to PCR | full SIMD, zero authority | — |
| **INV-GPU (deferred)** | — | — | — | — | — | — | — | **the** control: unwidenable window | — | — | DMA only after IOMMU confine |
| **Fail-closed** | `MapError` denies | `halt` sink | — | — | non-canonical → halt (x86) | absent → boot halt | — | absent → prod halt | error → gate stays shut | — | malformed handled in portable driver |

---

## 6. Risks and open questions for the owner

1. **`SyscallAbi::map_trampoline_into_user_root` references `Mmu::Root`.** The two traits
   are coupled (the KPTI trampoline is inherently an MMU+syscall concern). Options:
   (a) make `SyscallAbi` generic over `M: Mmu`; (b) keep a per-arch `Root` associated
   type re-exported at the HAL top. Recommend (b) — one `pub type Root = <ActiveMmu as
   Mmu>::Root;` in `hal/mod.rs` — to avoid generic bounds proliferating through portable
   code. Needs owner sign-off because it slightly widens the MMU/syscall trait coupling.

2. **The x86 syscall backend uses `#[no_mangle]` statics + `global_asm!` with hardcoded
   stack offsets** (`SYSCALL_TRAMPOLINE_SCRATCH`, `KERNEL_SYSCALL_*`). The trait wraps
   the *entry points*, but the asm itself stays arch-private and is NOT made portable.
   Risk: the portable IPC dispatcher and the asm share the `KERNEL_SYSCALL_*` ABI by
   convention; that convention (IPC_SPEC.md §8) must be re-stated per backend and audited
   per backend. This is inherent to a syscall ABI and is called out, not hidden.

3. **Where does memory encryption (TME/SME ↔ arm MTE/CCA) live?** It is neither purely a
   mitigation nor a measurement. Proposal: keep it a method group inside `Mitigations`
   (`detect_mem_encrypt` / `enable_mem_encrypt`) since it is boot-time CPU hardening like
   IBRS/IBT, rather than mint an 11th trait. Flagged for owner: it could equally be its
   own `MemEncrypt` trait. The task's named trait list did not include it, so it is folded
   in by default.

4. **`FpuState` / `RegisterFile` sizing across arches.** Making these fixed-size means the
   per-thread block (fixed pool) is sized for the *widest* enabled state (AVX-512 XSAVE
   ≈ 2.5 KiB; SVE can be larger). Since the pool is fixed at build time and the build
   targets one arch, size to *that arch's* enabled feature set — not the union. Confirm
   the inference engine's required SIMD width so `Fpu::enable`'s XCR0/CPACR feature mask
   and the save-area size are set correctly at build time. Over-provisioning wastes fixed
   pool RAM; under-provisioning silently truncates state (a leak/corruption bug).

5. **Lazy vs. eager FP switch.** Default eager (§2.10) for provable non-leakage. If the
   inference throughput target later forces lazy FP, it must ship with a proof/test that
   the `#NM`-driven path cannot resume a session with another session's live SIMD
   registers. Recommend deferring lazy FP entirely until after the serving path is
   confinement-proven.

6. **`Iommu` window granularity.** `map_dma_window` as specified is page-granular and
   device-scoped; a shared-queue virtio model may want sub-page or multi-region windows.
   The current x86 virtio-blk path uses direct-mapped BSS buffers with *no* IOMMU (dev
   config), so this trait is unexercised until DMAR/SMMU traversal lands. Kept minimal
   deliberately; expect a follow-up once a real IOMMU backend is coded.

7. **`Measure` software-fallback honesty.** The fallback backend must make `kind() ==
   SoftwareFallback` impossible to spoof as `Tpm2` — the value is measured into the config
   blob, but a verifier needs the predicted-PCR set to encode which backend was expected.
   This ties into the still-open vTPM/swtpm gap (THREAT_MODEL §0); the trait is ready but
   the honest-fallback semantics need the attestation-gate owner's confirmation.

---

## 7. Trait list (summary)

`Mmu`, `Interrupts`, `Timer`, `Context`, `SyscallAbi`, `Entropy`, `Mitigations`,
`Iommu`, `Measure`, `Fpu` (new), `Bus`. Eleven traits, one implementor per target arch,
selected by a single `cfg(target_arch)` table in `hal/mod.rs`, zero `dyn`, zero new
crates, zero heap, W^X and INV-AUTH structurally preserved at the boundary.
