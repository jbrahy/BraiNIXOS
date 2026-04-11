# CODE_STANDARDS.md — Brainix Coding Standards

**Status:** Mandatory
**Applies to:** All Brainix-authored Rust source code in this repository
**Does not apply to:** Names exported by external crates consumed as dependencies

These standards exist to make every line of Brainix code readable, auditable, and independently testable. Security code that cannot be read cannot be reviewed. Code that cannot be reviewed cannot be trusted.

---

## Rule 1: Full-Word Names Only

Every variable, function, method, type, field, constant, module, and lifetime name must use complete English words. No abbreviations, contractions, acronym-based names, or truncations are permitted in Brainix-authored code.

### Required

```rust
// Variables
let capability_slot_index = 0;
let physical_memory_page = allocate_page();
let interrupt_descriptor_table = build_interrupt_descriptor_table();

// Functions
fn allocate_capability_slot() -> CapabilitySlot { ... }
fn revoke_derived_capabilities(parent: &ParentCapability) { ... }
fn build_interrupt_descriptor_table() -> InterruptDescriptorTable { ... }

// Types
struct CapabilitySlot { ... }
struct PhysicalMemoryPage { ... }
struct InterruptDescriptorTable { ... }
struct GlobalDescriptorTable { ... }
struct TaskStateSegment { ... }

// Fields
struct ProcessControlBlock {
    capability_space: CapabilitySpace,
    page_table_root: PhysicalAddress,
    interrupt_stack_table_entry: InterruptStackTableEntry,
}

// Constants
const MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS: usize = 256;
const KERNEL_STACK_SIZE_IN_BYTES: usize = 8192;
```

### Prohibited

```rust
// Do NOT use these forms:
let cap_slot = ...;         // "cap" abbreviates "capability"
let mem_pg = ...;           // double abbreviation
let idt = ...;              // acronym-as-name
let gdt = ...;              // acronym-as-name
let tss = ...;              // acronym-as-name
let ist = ...;              // acronym-as-name
let pma = ...;              // acronym-as-name
let addr = ...;             // truncation
let buf = ...;              // truncation
let ptr = ...;              // truncation (use "pointer")
let idx = ...;              // truncation (use "index")
let len = ...;              // truncation (use "length" or "count")
let num = ...;              // truncation (use "count" or "number")
let err = ...;              // truncation (use "error")
let res = ...;              // truncation (use "result")
let tmp = ...;              // truncation (use a descriptive name)
let i = ...;                // single-letter (use "index" or describe what is being indexed)
let n = ...;                // single-letter (use "count")
```

### External Crate Exception

Names that originate in external crates are used exactly as the crate defines them. You may bind an external crate's type to a Brainix-authored variable with a full-word name:

```rust
// Allowed: external crate type used as-is
use x86_64::structures::idt::InterruptDescriptorTable;

// Allowed: binding the type to a full-word variable
let interrupt_descriptor_table = InterruptDescriptorTable::new();

// Prohibited: binding the type to an abbreviated variable
let idt = InterruptDescriptorTable::new();   // "idt" is not a full word
```

---

## Rule 2: Maximum Six Lines Per Function Body

No function or method body may contain more than six lines of executable code. The six-line limit is counted as lines of executable statements, excluding:
- The function signature line
- Opening and closing braces on their own line
- Blank lines used for readability within the body
- Doc comment lines (`///`)

If a function exceeds six lines, it must be decomposed into named helper functions. Every named helper is an opportunity to name a concept and make it independently testable.

### Required Pattern

```rust
/// Initializes the capability space for a new process.
/// Enforces invariant CAP-01: no capability slot is readable before explicit grant.
/// Verified by: tests::capability_space::test_new_space_all_slots_are_null
pub fn initialize_capability_space() -> CapabilitySpace {
    let slot_array = build_empty_slot_array();
    let derivation_tree = build_empty_derivation_tree();
    CapabilitySpace { slots: slot_array, derivation_tree }
}

fn build_empty_slot_array() -> [CapabilitySlot; MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS] {
    [CapabilitySlot::null(); MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS]
}

fn build_empty_derivation_tree() -> CapabilityDerivationTree {
    CapabilityDerivationTree::new_empty()
}
```

### Prohibited Pattern

```rust
// Prohibited: body exceeds six lines
pub fn initialize_capability_space() -> CapabilitySpace {
    let mut slot_array = [CapabilitySlot::null(); MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS];
    for index in 0..MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS {
        slot_array[index] = CapabilitySlot::null();
    }
    let derivation_tree = CapabilityDerivationTree::new_empty();
    derivation_tree.set_root(None);
    derivation_tree.set_generation_counter(0);
    CapabilitySpace { slots: slot_array, derivation_tree }
}
```

---

## Rule 3: Maximum Refactoring — No Duplication

Any logic pattern that appears two or more times in the codebase must be extracted into a named helper function. Inline duplication is treated as a code defect equivalent to a failing test.

This applies regardless of how short the duplicated pattern is. Two lines of identical logic in two different places must become one named function.

The name of the extracted helper must describe what the pattern does, not where it came from.

```rust
// If this pattern appears twice:
serial_port.write_byte(b'\r');
serial_port.write_byte(b'\n');

// Extract it:
fn write_newline_to_serial_port(serial_port: &mut SerialPort) {
    serial_port.write_byte(b'\r');
    serial_port.write_byte(b'\n');
}
```

---

## Rule 4: Explicit Sequential Code Over Compact Abstractions

When there is a trade-off between a compact one-liner and an explicit multi-step sequence, choose the explicit sequence. Readability and auditability outrank brevity.

A reviewer reading the code for a security audit must be able to understand each step without mentally expanding abstractions or tracing through iterator combinators.

### Required

```rust
fn check_capability_rights_allow_read(capability: &Capability) -> bool {
    let rights_bitmask = capability.extract_rights_bitmask();
    let read_right_is_set = rights_bitmask.contains(CapabilityRight::Read);
    read_right_is_set
}
```

### Discouraged (even if it compiles and is correct)

```rust
fn check_capability_rights_allow_read(capability: &Capability) -> bool {
    capability.extract_rights_bitmask().contains(CapabilityRight::Read)
}
```

The explicit form names every intermediate value. Each named value is a place a reviewer can attach a mental model. Each is also a place a test can inject a value.

---

## Rule 5: Every Function Must Be Independently Testable

Function bodies must not mix levels of abstraction. Pure logic (computation, decision-making, state transitions) must be separable from impure operations (I/O, hardware register access, memory-mapped writes, interrupts).

A function that computes a value and also writes to a hardware register in the same body cannot be unit-tested. Split it into a pure computation function and a separate effect-applying function.

```rust
// Pure: independently testable
fn compute_page_table_flags_for_kernel_code() -> PageTableFlags {
    let base_flags = PageTableFlags::PRESENT;
    let executable_flags = base_flags | PageTableFlags::NO_EXECUTE.complement();
    let read_only_flags = executable_flags & !PageTableFlags::WRITABLE;
    read_only_flags
}

// Impure: applies the computed value — tested through integration
fn apply_kernel_code_page_table_flags(entry: &mut PageTableEntry) {
    let flags = compute_page_table_flags_for_kernel_code();
    entry.set_flags(flags);
}
```

---

## Rule 6: Security-Critical Functions Must Document Their Invariant

Every function that directly enforces a security invariant must have a doc comment that:
1. Names the invariant it enforces (using the ID from `docs/security/SECURITY_INVARIANTS.md`)
2. Names the test that verifies correct behavior

```rust
/// Zeroes a capability slot on revocation.
///
/// Enforces invariant CAP-04: a revoked capability slot must not be readable with
/// its prior contents. Uses `write_volatile` to prevent the compiler from eliding the
/// write as a dead store.
///
/// Verified by: tests::capability_revocation::test_revoked_slot_reads_as_null
pub fn zero_capability_slot_on_revocation(slot_pointer: *mut CapabilitySlot) {
    // SAFETY: slot_pointer is non-null and exclusively owned by the caller.
    // write_volatile prevents the compiler from treating this as a dead store.
    unsafe { core::ptr::write_volatile(slot_pointer, CapabilitySlot::null()) }
}
```

---

## Enforcement

These rules are enforced at three points:

1. **Code review** — every pull request is reviewed against these rules before merge approval
2. **CI clippy lints** — where mechanical detection is possible (e.g., function length via a custom lint or `clippy::cognitive_complexity`)
3. **Merge gate** — a pull request that visibly violates these rules must not be approved

Violations are treated as defects, not style preferences. A function with abbreviated names or more than six lines is as broken as a function with a failing test.

---

*Last updated: 2026-04-11*
*These rules apply to all Brainix code from this date forward.*
