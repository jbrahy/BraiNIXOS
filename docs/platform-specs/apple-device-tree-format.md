# Apple Device Tree (ADT) binary format — platform fact table

**Sources consulted:**

*Prose documentation (preferred; facts from here are marked **P**):*

- Asahi Linux Documentation, "Apple Device Tree (ADT)", <https://asahilinux.org/docs/fw/adt/>, fetched
  2026-08-03. Establishes only: the ADT is a hierarchy of nodes holding untyped byte-array properties;
  it is *not* the Open Firmware / FDT format Linux expects; the principal difference from a Linux DT is
  **byte order**; properties are untyped so byte order cannot be corrected automatically. It contains
  **no binary layout**.
- Asahi Linux Wiki, "FW:ADT", <https://leo3418.github.io/asahi-wiki-build/fwadt/>, fetched 2026-08-03.
  Same content; no binary layout.
- Asahi Linux Documentation, "Symmetric Multiprocessing (SMP)", <https://asahilinux.org/docs/hw/cpu/smp/>,
  fetched 2026-08-03. CPU spin-up sequence, the ADT property names it consumes, and the per-SoC CPU-start
  register offset table (including the M2 Pro/Max value).
- Asahi Linux Documentation, "MachO Boot Protocol",
  <https://asahilinux.org/docs/fw/macho-boot-protocol/>, fetched 2026-08-03. Establishes that `x0` holds a
  pointer to the XNU `boot_args` structure at entry, and the virtual→physical rule
  `phys = virt - virt_base + phys_base`. It does **not** give field offsets.

*Source code (facts from here are marked **S** — weaker footing, see §12):*

- Apple, XNU, `pexpert/pexpert/device_tree.h`, `apple-oss-distributions/xnu` branch `main`, fetched
  2026-08-03. Apple's own declaration of the on-disk node and property structures. **This is a
  first-party source**, not reverse-engineering.
- Apple, XNU, `pexpert/gen/device_tree.c`, same repo/branch, fetched 2026-08-03. Traversal arithmetic,
  padding rule, and Apple's own bounds-checking discipline.
- Apple, XNU, `pexpert/pexpert/arm64/boot.h`, same repo/branch, fetched 2026-08-03. `boot_args` field
  order.
- AsahiLinux/m1n1, branch `main`, fetched 2026-08-03: `src/adt.h`, `src/adt.c`, `src/xnuboot.h`,
  `rust/src/adt.rs`, `src/uart.c`, `src/aic.c`, `src/aic.h`, `src/smp.c`, `src/soc.h`, `src/main.c`,
  `src/startup.c`, `src/kboot.c`, `src/firmware.c`, `src/chickens.c`, `proxyclient/m1n1/adt.py`.
- bazad/devicetree-parse, `devicetree-parse.c`, branch `master`, fetched 2026-08-03. Independent
  (non-Asahi) parser; its comment is the only *written* statement found of the length-word flag's meaning.

*Direct hardware observation (marked **O**):*

- `ioreg -p IODeviceTree -l -w 0` captured 2026-08-03 on the machine described below. This is XNU's
  **live, mutated** `IODeviceTree` plane, not the raw ADT blob — see §11.3 for what that invalidates.

**Firmware / OS version:**

| | Observation host (**O** facts) | Deployment target (AS-1) |
|---|---|---|
| Machine | MacBook Pro `Mac15,6`, board `J514s` | Mac mini `Mac14,12`, board `J474s` |
| SoC | Apple M3 Pro, `T6030` (chip-id `0x6030`) | Apple M2 Pro, `T6020` (chip-id `0x6020`) |
| macOS | 26.5.2, build `25F84` | **not recorded — see OQ-7** |
| Kernel | `xnu-12377.121.10~1/RELEASE_ARM64_T6030` | not recorded |
| System Firmware / OS Loader | `18000.121.3` | **not recorded — see OQ-7** |
| ADT build stamp (root `device-tree-tag`) | `EmbeddedDeviceTrees-11156.120.31` | **not recorded — see OQ-7** |

> **The observation host is not the target machine.** Every **O** fact in this document was measured on a
> `T6030` MacBook Pro, not on the `T6020` Mac mini AS-1 will boot. Structural facts (§3–§7) are
> SoC-independent and are corroborated by **S** sources. Per-SoC *values* (§8) are marked with whether they
> were observed on `T6030` or inferred for `T6020`. **Before AS-1 is declared working on the target, the
> table above must be completed from the target machine and this spec re-qualified.**

**Machine / SoC:** Mac mini M2 Pro, `Mac14,12`, SoC `T6020` (target). Facts derived on `Mac15,6` / `T6030`
(observation host) plus first-party and third-party source.

**Spec author:** Claude Opus 5, AS-0-T1 clean-room spec-author session, 2026-08-03.

**Derived:** 2026-08-03.

**Implementer restriction:** the implementer of this subsystem **may not read the sources named above**.
Work from this file only. If it is insufficient, return the question to the spec author.

**Source-code-only disclosure (required by [`README.md`](README.md) §*Confidence marking*).** The
following are established **only** from source code, never from prose documentation. They rest on the
weaker footing:

| Fact | Section | Sole basis |
|---|---|---|
| Node header: two `u32` counts, properties before children | §4.1 | **S** (XNU `device_tree.h`, m1n1, bazad — three agreeing) |
| Property header: 32-byte name, `u32` length word | §4.2 | **S** (same three) |
| 4-byte padding of the property value | §4.3 | **S** (XNU `device_tree.c`, m1n1, bazad — three agreeing) |
| Length word bit 31 = placeholder flag; bits 30..0 = length | §5 | **S**, plus one written comment in bazad's parser. **No Apple or Asahi prose states this.** |
| Little-endian for all integer fields | §4.4 | **S** for the *format*; **O** corroborates the values. Asahi prose says only "byte order differs from Linux DT", never "little-endian". |
| `boot_args` field order and derived offsets | §3 | **S** (XNU `arm64/boot.h`, m1n1 `xnuboot.h` — two agreeing) |
| CPU release sequence register offsets | §8.4 | **P** for the sequence, **S** for the `T6020` constant `0x28000` |
| CPU release **access widths** (64-bit `RVBAR`, 32-bit PMGR), **plain-store not read-modify-write**, and the **two different bit indices** (`4 × cluster + core` at `+0x04`, `core` at `+0x08 + 4 × cluster`) | §8.4 | **S** only. The prose says "the core's bit" for both registers and states no access width; only the implementation distinguishes them. |
| PMGR per-die stride `0x20_0000_0000` | §8.4 | **S** only |
| ADT node names carry no `@unit` suffix | §4.5 | **O** (decisive; see §4.5) |

---

## 1. Scope

This document specifies **how to parse the Apple Device Tree blob** that Apple firmware (iBoot) hands to
the booting kernel on Apple Silicon, and **which nodes and properties AS-1 must read from it**.

It covers:

- how a boot stub obtains the ADT base address and length (§3),
- the binary layout of nodes and properties (§4),
- the semantics of the property length word's flag bit (§5),
- traversal (§6),
- a worked, byte-exact example (§7),
- the specific data AS-1 needs (§8),
- the mandatory hostile-input checks (§9),
- open questions (§10) and honest limits (§11–§12).

It does **not** cover: the meaning of any device's registers, the AGX firmware ABI, DART/IOMMU, RTKit, or
the FDT that m1n1 synthesises for Linux. Where a Linux-facing name and an ADT name differ, this document
gives the **ADT** name and flags the difference.

**No code appears in this document.** Arithmetic is written as arithmetic, not as an expression in any
language.

---

## 2. What the ADT is, in one paragraph

The ADT is a flattened tree of **nodes**. Each node holds an ordered list of **properties** and an ordered
list of **child nodes**, both laid out contiguously and immediately after the node's 8-byte header. A
property is a fixed-width name field, a length word, and an untyped byte array. There is **no string
table**, **no magic number**, **no version field**, and **no header of any kind before the root node** —
the blob *begins* with the root node's header at byte 0. Nothing in the blob records the size of a node;
a node's extent is known only by walking it. All integers are **little-endian**, which is the single most
important difference from a Linux FDT (big-endian). Property values are **untyped**: nothing in the format
says whether a 4-byte value is an integer or a 4-character string. `[P: untyped + byte-order difference;
S: everything else]`

---

## 3. Obtaining the ADT: the `boot_args` subset

At the firmware entry point, register `x0` holds the **physical** address of an XNU `boot_args`
structure. `[P]` The ADT pointer inside it is a **virtual** address in iBoot's mapping and must be
converted. `[P for the conversion rule, S for the field offsets]`

`boot_args` is a naturally-aligned (not packed) AArch64 LP64 structure. Offsets below are derived from the
field order given by two agreeing sources, applying standard AArch64 alignment.

| Offset | Width | Field | Meaning |
|---|---|---|---|
| `0x00` | 2 | `revision` | Structure revision. Values 1, 2, 3 are known. See §10 OQ-1. |
| `0x02` | 2 | `version` | Structure version. |
| `0x04` | 4 | — | Implicit alignment padding. Not a field. Do not read. |
| `0x08` | 8 | `virt_base` | Virtual base of the firmware's memory mapping. |
| `0x10` | 8 | `phys_base` | Physical base of DRAM as the firmware sees it. |
| `0x18` | 8 | `mem_size` | Size of the memory window described by `virt_base`/`phys_base`. |
| `0x20` | 8 | `top_of_kernel_data` | Highest physical address used by the loaded kernel image. |
| `0x28` | 48 | `video` | Framebuffer descriptor: 6 consecutive `u64` — base, display, stride, width, height, depth. |
| `0x58` | 4 | `machine_type` | Machine type code. |
| `0x5C` | 4 | — | Implicit alignment padding. Not a field. Do not read. |
| `0x60` | 8 | `devtree` | **Virtual** address of the ADT blob. |
| `0x68` | 4 | `devtree_size` | **Total length of the ADT blob in bytes.** |
| `0x6C` | ... | `cmdline` | Boot command line. **Offset disputed — see OQ-1.** Not needed by AS-1. |

**Deriving the ADT window.** With `BA` = the physical address in `x0`, and writing `u64le@X` for "the
little-endian 64-bit integer stored at address `X`" (a value, not a function call):

```
adt_phys  = (u64le@(BA + 0x60)) - (u64le@(BA + 0x08)) + (u64le@(BA + 0x10))
adt_len   =  u32le@(BA + 0x68)
```

The ADT occupies
`[adt_phys, adt_phys + adt_len)`. **Every pointer the parser ever forms must be proved to lie inside that
half-open interval before it is dereferenced** (§9).

`adt_len` is a **claim made by firmware**, not a measurement. §9.1 states what must be checked about it.

### 3.1 The offset basis — normative

**The parser works entirely in buffer-relative byte offsets.** This is a requirement of this spec, not an
implementation preference, because every bound in §6 and §9 is stated against it.

| Rule | Statement |
|---|---|
| Basis | The parser is handed **one contiguous byte buffer** of exactly `adt_len` bytes, starting at `adt_phys`, and works only in offsets measured from **byte 0 of that buffer**. Offset 0 is the root node header. |
| Physical addresses | `adt_phys` is used **once**, to locate and bound the buffer. It never appears in the parser's arithmetic afterwards. No offset in this document is ever a physical address. |
| "Start of the buffer" | Offset `0`. |
| "End of the buffer" | Offset `adt_len`. All intervals are half-open: valid *read* offsets are `[0, adt_len)`. |
| Buffer alignment | **`adt_phys` must be 4-byte aligned; reject the ADT if it is not.** This is what makes the §9.7 alignment check well-defined: with a 4-byte-aligned base, "offset is a multiple of 4" and "address is a multiple of 4" are the same statement. Without it they are not, and the check silently means neither. |
| `adt_len` alignment | **`adt_len` must be a multiple of 4; reject the ADT if it is not.** Every record is a multiple of 4 bytes (§4.3), so a well-formed tree can never end on a non-multiple-of-4 offset. A buffer length that is not a multiple of 4 is either a truncated blob or a mis-read `boot_args`. |

An implementation that takes the buffer as a bounds-checked byte slice gets the "is this offset inside the
buffer" half of §9 from the slice itself and must still perform every other check in §9 explicitly. A
slice bound is not a substitute for the overflow, count, length, alignment, or depth checks.

---

## 4. Binary layout

### 4.1 Node

A node header is 8 bytes. It is immediately followed by the node's properties, then by the node's
children. There is nothing else. `[S — three agreeing sources]`

| Offset | Width | Field | Notes |
|---|---|---|---|
| `+0x00` | 4 | `property_count` | Unsigned. Number of property records that follow the header. |
| `+0x04` | 4 | `child_count` | Unsigned. Number of child node records that follow the last property. |

- **Total header size: 8 bytes.**
- **A node's total extent cannot be computed from the header.** It is
  `8 + (sum of the sizes of all property_count properties) + (sum of the sizes of all child_count child
  subtrees)`, and each of those sums requires a full walk. There is no length field anywhere in the
  format that short-circuits this. This is the structural reason §9 is long.
- **`property_count = 0` is not a valid node.** Apple's own reader treats a zero property count as "end of
  the list of nodes" and refuses the node; m1n1 rejects it outright. Every well-formed node carries at
  least the `name` property. A parser must reject `property_count = 0`. `[S]`
- **Node alignment: 4 bytes.** A node header always begins on a 4-byte boundary, because the header is
  8 bytes and every property record is padded to a multiple of 4 (§4.3). `[S]`

### 4.2 Property

A property record is a 36-byte header followed by a variable-length value. `[S — three agreeing sources]`

| Offset | Width | Field | Notes |
|---|---|---|---|
| `+0x00` | 32 | `name` | ASCII, **NUL-terminated and NUL-padded** to 32 bytes. Maximum useful name length is **31 characters** plus the terminator. |
| `+0x20` | 4 | `length_word` | Unsigned. Carries both a length and a flag — see §5. |
| `+0x24` | *see §5* | `value` | Untyped bytes. Length is `length_word AND 0x7FFFFFFF`. |

- **Total header size: 36 bytes (`0x24`).**
- **Name termination is not guaranteed by the format, only by convention.** A conforming producer NUL-pads
  the field; a hostile producer need not. Apple's own reader compares the name with an unbounded string
  comparison in at least one code path, which over-reads if byte 31 is non-zero. A correct parser
  **rejects any property whose name field's byte at `+0x1F` is not `0x00`** before doing anything else
  with the name. `[S]`

### 4.3 Alignment and padding

- The **value** is padded with zero bytes to the next multiple of **4**. The padding is *not* counted in
  `length_word`. `[S — XNU, m1n1 and bazad all compute the same thing]`
- Therefore the size of a whole property record is:

```
padded_len   = value_len rounded UP to the next multiple of 4      i.e. ((value_len + 3) AND NOT 3)
record_size  = 32 + 4 + padded_len = 36 + padded_len
```

Note the parentheses in `((value_len + 3) AND NOT 3)`: the addition binds first. `AND NOT 3` clears the
low two bits of the *sum*. Written without the inner parentheses the expression would be read as
`value_len + (3 AND NOT 3)` = `value_len + 0`, i.e. no padding at all — a walk that desynchronises on the
first property whose length is not already a multiple of 4. Every restatement of this rule in this
document (§6.2, §9.3) is parenthesised the same way.

- **`record_size` is always a multiple of 4** (36 is, `padded_len` is).
- The last property of a node may, in the wild, be found un-padded at the very end of the buffer. bazad's
  parser tolerates exactly this case. **BraiNIX must not tolerate it** — it is indistinguishable from a
  truncation attack. Fail closed (§9.4).
- There is **no** 8-byte alignment anywhere in the format, even for 64-bit property values. A `u64`
  inside a property value is only guaranteed 4-byte aligned. On AArch64 an unaligned `u64` load is
  permitted for normal memory but the implementer must not assume 8-byte alignment when constructing
  references.

### 4.4 Endianness and integer widths

**Every integer field in the ADT container format is little-endian.** `[S for the format; O corroborating]`

| Field | Width | Endianness |
|---|---|---|
| `property_count` | 4 bytes | little-endian |
| `child_count` | 4 bytes | little-endian |
| `length_word` | 4 bytes | little-endian |

Property **values** are untyped bytes; the format assigns them no endianness. In practice every integer
Apple stores in an ADT value is also little-endian. Two independent confirmations from the observation
host `[O]`:

- `/chosen` `chip-id` reads as bytes `30 60 00 00`. Interpreted little-endian that is `0x00006030`, which
  is exactly the SoC code `T6030` of the observation host. Interpreted big-endian it is `0x30600000`,
  which is nothing.
- root `#address-cells` reads as bytes `02 00 00 00` = 2 little-endian, and a `#address-cells` of
  `0x02000000` is absurd.

> **This is the most likely single source of a silent, total parse failure.** A Linux FDT is big-endian.
> Any habit or helper carried over from FDT parsing will read every number in this format byte-reversed.

### 4.5 Node names

A node has **no name field in its header**. A node's name is the value of its property named `name`,
which is a NUL-terminated ASCII string inside that property's value. `[S, O]`

- The `name` property is **not guaranteed to be first**. It must be found by search. `[S]`
- A node with no `name` property is malformed. `[S — m1n1 refuses to construct such a node]`
- **ADT node names carry no `@unit-address` suffix.** Decisive evidence `[O]`: on the observation host,
  the UART node is displayed by `ioreg` as `uart0@79200000`, while that same node's `name` property value
  is exactly the 6 bytes `u`,`a`,`r`,`t`,`0`,`NUL`. The `@79200000` is synthesised by XNU for its own
  registry and does not exist in the ADT. A parser must therefore compare path components against the
  `name` value **exactly**, and must **never** attempt to parse an address out of a node name.
- Corollary, and a real trap: the synthesised suffix is not even reliable as a hint. The AIC node is
  displayed as `aic@41000000` while its `reg` property's address cell is `0x141000000` — the suffix has
  silently lost the top nibble. `[O]`
- Maximum name length: Apple's declaration allows an entry name of up to **63** characters plus
  terminator (older revisions said 31). Since the name lives in a property *value*, not a fixed field, the
  format imposes no bound at all — the only limit is the property length, which can be up to 2 GiB. A
  parser must therefore impose its own bound; **§9.5 states the required check.** `[S]`

---

## 5. The length word — flag semantics

**This is the single most implementation-critical detail in the format.**

| Bits | Meaning | Confidence |
|---|---|---|
| 30..0 | **Value length in bytes**, not including padding. Mask: `length_word AND 0x7FFFFFFF`. | **Established.** All three independent parsers apply exactly this 31-bit mask. `[S ×3]` |
| 31 | **Placeholder flag.** Set by the ADT *template* shipped in firmware to mark a property whose value iBoot is expected to substitute at boot time — from `syscfg` or a similar source — before handing the tree to the OS. | **Established as to which bit; the semantics rest on a single written statement.** See below. `[S, one prose-in-source comment]` |

### 5.1 What is firmly established

- Bit 31 is **not** part of the length. Three independent implementations mask it off before using the
  value: Apple-adjacent tooling, the Asahi bootloader (both its Rust and its Python parsers), and an
  unrelated third-party parser. They all use exactly `AND 0x7FFFFFFF` / `AND NOT 0x80000000`. `[S ×3]`
- The **maximum representable value length is therefore `0x7FFFFFFF` (2 GiB − 1)**, which is far larger
  than any real ADT. See §9.3.
- **Bits 30..20 are, in practice, always zero.** The Asahi bootloader's Rust parser treats any property
  whose length word has any of bits 30..20 set as malformed, i.e. it enforces an effective value-length
  ceiling of **1 MiB − 1**. This is a heuristic, not a format rule, but it is a heuristic shipped against
  real firmware on real machines. `[S]`

### 5.2 What the flag means, and the exact citation

The only *written* statement of bit 31's meaning found anywhere — in prose or in a source comment — is a
comment in bazad's `devicetree-parse.c` (`github.com/bazad/devicetree-parse`, branch `master`,
`devicetree-parse.c`, in the property-iteration loop). Paraphrased, not quoted, per the clean-room rule:
*properties are padded to a multiple of 4 bytes; there also appears to be a flag field at bit 31, set if
iBoot should replace the value of the field with a syscfg property or another value; this flag is not seen
in device trees dumped from kernel memory.*

Two corroborating facts, both `[S]`:

- The Asahi Python parser calls a property with bit 31 set a **template** property and parses its value as
  a NUL-terminated string — i.e. as a placeholder name rather than as data. It re-emits the bit when
  rebuilding a tree, so the bit round-trips.
- **Apple's own kernel reader never masks bit 31.** It uses the length word directly as a length in every
  path. This is only sound if bit 31 is guaranteed clear by the time the tree reaches the kernel — which
  matches bazad's observation that the flag is absent from kernel-memory dumps.

### 5.3 The rule BraiNIX must implement

1. Always mask: `value_len = length_word AND 0x7FFFFFFF`. Never use the raw word as a length.
2. On the live boot path, a set bit 31 means the firmware handed over an **unresolved template**. That is
   not a tree the OS was meant to see. **Treat bit 31 set as a hard parse failure**, not as a property to
   skip and not as a value to use. Rationale: Apple's kernel would mis-parse such a tree (it would read a
   length of at least 2 GiB and panic on the overflow check), so no correct boot path produces one.
3. Record the reason distinctly from other parse failures, so that if a future firmware legitimately
   starts shipping the bit, the failure is diagnosable rather than mysterious.
4. Do **not** reject on bits 30..20 as a *format* rule. Apply the 1 MiB ceiling as a **policy** bound
   (§9.3) with its own distinct failure reason, so the two can be told apart in a log.

### 5.4 What could not be established

- Whether bit 31 is the *only* flag bit, or whether bits 30..20 are reserved-for-future-flags rather than
  merely always-zero length bits. See OQ-2.
- What the placeholder's value *contains* when the bit is set (the Asahi parser's "NUL-terminated string"
  reading is an inference from observed data, not a documented rule). See OQ-3.

---

## 6. Traversal

### 6.1 Layout order

Within a node, the order is fixed and total: `[S ×3]`

```
node header (8 bytes)
  property[0], property[1], ... property[property_count - 1]      (contiguous, each 4-byte aligned)
  child[0], child[1], ... child[child_count - 1]                  (contiguous, each a full subtree)
```

Properties **always** precede children. There is no interleaving and no terminator record between the two
regions — the boundary is known only by having counted exactly `property_count` properties.

The whole blob is therefore a **depth-first pre-order serialisation**: a node, then all its properties,
then its first child's entire subtree, then its second child's entire subtree, and so on. Reading the blob
front to back visits nodes in depth-first pre-order.

### 6.2 The four navigation primitives

All offsets below are buffer-relative per §3.1. Let `N` be the offset of a node header, and let `P` be the
offset of a property record. Notation: `u32le@X` means "the little-endian 32-bit integer stored at buffer
offset `X`". It denotes a value, not a function call.

| Operation | Arithmetic |
|---|---|
| First property of `N` | `N + 8` |
| `value_len` of the property at `P` | `(u32le@(P + 32)) AND 0x7FFFFFFF` |
| `padded_len` of the property at `P` | `((value_len + 3) AND NOT 3)` — parenthesised exactly as in §4.3; the `+ 3` binds before the `AND NOT 3` |
| Next property after `P` | `P + 36 + padded_len` |
| **First child** of `N` | Start at `N + 8`; advance by "next property" exactly `property_count(N)` times. The offset you land on is the first child. |
| **End of node `N`** (= its next sibling, if it has one) | `end_of(N)` = start at "first child of `N`", then apply `end_of` recursively `child_count(N)` times. |
| Next sibling of `N` | `end_of(N)` — valid **only if** the caller knows from the parent's `child_count` that another sibling exists. |

**"First child" and "end of properties" are the same offset.** When `child_count(N) = 0`, that offset is
the end of node `N` itself.

**Two of these are *extent* offsets, not *read* offsets.** "End of node `N`" and — when
`child_count(N) = 0` — "first child of `N`" are one-past-the-end positions. They are legitimately allowed
to **equal** `adt_len`, and for the last node in the blob they always do. They must not be dereferenced
while they hold that value. §9.7 states the two different bounds tests this requires; conflating them
rejects every well-formed ADT.

### 6.3 How to know a node's children are exhausted

**By counting, and only by counting.** There is no sentinel, no terminator, and no end-of-list marker
anywhere in the format.

- Iterating children: read `child_count` from the node header **once, before the loop**, then take exactly
  that many siblings starting from "first child". Never test the bytes at the landing offset to decide
  whether to continue.
- Iterating properties: identically, read `property_count` once and take exactly that many.
- The recursion terminates because `end_of` on a node with `child_count = 0` reduces to the property walk.

> A parser that tries to detect the end of a child list by inspecting the next 8 bytes — for example by
> treating `property_count = 0` as a terminator, which is how Apple's own reader signals "end of list"
> internally — will walk off the end of a node into its parent's next sibling on any tree where the
> counts and the bytes disagree. Trust the counts, bound the counts (§9.2), and check every landing
> offset against the buffer (§9.7).

### 6.4 Path resolution

A path such as `/arm-io/uart0` is resolved by starting at the root node (offset 0) and, for each
component, scanning that node's children for one whose `name` property value equals the component exactly
(§4.5). There is no index, no phandle table, and no hash — resolution is a linear scan at every level.

The root node has no name of its own for path purposes; the leading `/` denotes offset 0. Properties of
the root itself are read from offset 0 directly. `[S, O]`

---

## 7. Worked byte-level example

The following 288-byte blob is a well-formed ADT fragment with the same shape and the same real property
values observed on the host `[O]`, laid out by the rules of §4. It is included so the implementer has a
fixture with known-correct offsets.

Tree: a node named `arm-io` with three properties and one child; the child is named `uart0` and has three
properties.

```
0000  03 00 00 00 01 00 00 00  6e 61 6d 65 00 00 00 00  |........name....|
0010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0020  00 00 00 00 00 00 00 00  07 00 00 00 61 72 6d 2d  |............arm-|
0030  69 6f 00 00 23 61 64 64  72 65 73 73 2d 63 65 6c  |io..#address-cel|
0040  6c 73 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |ls..............|
0050  00 00 00 00 04 00 00 00  02 00 00 00 23 73 69 7a  |............#siz|
0060  65 2d 63 65 6c 6c 73 00  00 00 00 00 00 00 00 00  |e-cells.........|
0070  00 00 00 00 00 00 00 00  00 00 00 00 04 00 00 00  |................|
0080  02 00 00 00 03 00 00 00  00 00 00 00 6e 61 6d 65  |............name|
0090  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00a0  00 00 00 00 00 00 00 00  00 00 00 00 06 00 00 00  |................|
00b0  75 61 72 74 30 00 00 00  63 6f 6d 70 61 74 69 62  |uart0...compatib|
00c0  6c 65 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |le..............|
00d0  00 00 00 00 00 00 00 00  0f 00 00 00 75 61 72 74  |............uart|
00e0  2d 31 2c 73 61 6d 73 75  6e 67 00 00 72 65 67 00  |-1,samsung..reg.|
00f0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0100  00 00 00 00 00 00 00 00  00 00 00 00 10 00 00 00  |................|
0110  00 00 20 79 00 00 00 00  00 40 00 00 00 00 00 00  |.. y.....@......|
```

Walk-through. All offsets are buffer-relative (§3.1) and absolute within the blob — none are
record-relative. **Every row below was re-derived mechanically by walking the bytes above with the rules
of §4 and §6.2, not written by hand.**

**Root node, at offset `0x0000`.**

| Offset | Field | Bytes | Reading |
|---|---|---|---|
| `0x0000` | `property_count` | `03 00 00 00` | 3 |
| `0x0004` | `child_count` | `01 00 00 00` | 1 |
| `0x0008` | property 0 begins | — | first property = `0x0000 + 8` |

*Root property 0:*

| Offset | Field | Reading |
|---|---|---|
| `0x0008` | name field, 32 bytes (`0x0008`–`0x0027`) | `name`, i.e. 4 ASCII bytes then 28 NULs. Terminator at `0x000C`. Byte at `0x0027` is `0x00` — passes the §4.2 check. |
| `0x0028` | `length_word` | `07 00 00 00` = 7. Bit 31 clear. `value_len` = 7. |
| `0x002C` | value, 7 bytes (`0x002C`–`0x0032`) | `arm-io` + NUL |
| `0x0033` | padding, 1 byte | `padded_len` = `((7 + 3) AND NOT 3)` = 8 |
| → `0x0034` | next property | `0x0008 + 36 + 8` = `0x0034` |

*Root property 1:*

| Offset | Field | Reading |
|---|---|---|
| `0x0034` | name field (`0x0034`–`0x0053`) | `#address-cells`; byte at `0x0053` is `0x00` |
| `0x0054` | `length_word` | `04 00 00 00` = 4 |
| `0x0058` | value, 4 bytes | `02 00 00 00` = **2**, little-endian. `padded_len` = 4, no padding bytes. |
| → `0x005C` | next property | `0x0034 + 36 + 4` = `0x005C` |

*Root property 2:*

| Offset | Field | Reading |
|---|---|---|
| `0x005C` | name field (`0x005C`–`0x007B`) | `#size-cells`; byte at `0x007B` is `0x00` |
| `0x007C` | `length_word` | `04 00 00 00` = 4 |
| `0x0080` | value, 4 bytes | `02 00 00 00` = **2**. `padded_len` = 4. |
| → `0x0084` | next property | `0x005C + 36 + 4` = `0x0084` |

**After exactly `property_count` = 3 properties the walk lands on `0x0084`. That offset is both the root's
end-of-properties and — since `child_count` = 1 — its first child.**

**Child node, at offset `0x0084`.**

| Offset | Field | Bytes | Reading |
|---|---|---|---|
| `0x0084` | `property_count` | `03 00 00 00` | 3 |
| `0x0088` | `child_count` | `00 00 00 00` | 0 |
| `0x008C` | property 0 begins | — | first property = `0x0084 + 8` |

*Child property 0:*

| Offset | Field | Reading |
|---|---|---|
| `0x008C` | name field (`0x008C`–`0x00AB`) | `name`; byte at `0x00AB` is `0x00` |
| `0x00AC` | `length_word` | `06 00 00 00` = 6 |
| `0x00B0` | value, 6 bytes (`0x00B0`–`0x00B5`) | `uart0` + NUL |
| `0x00B6` | padding, 2 bytes | `padded_len` = 8 |
| → `0x00B8` | next property | `0x008C + 36 + 8` = `0x00B8` |

*Child property 1:*

| Offset | Field | Reading |
|---|---|---|
| `0x00B8` | name field (`0x00B8`–`0x00D7`) | `compatible`; byte at `0x00D7` is `0x00` |
| `0x00D8` | `length_word` | `0F 00 00 00` = 15 |
| `0x00DC` | value, 15 bytes (`0x00DC`–`0x00EA`) | `uart-1,samsung` + NUL |
| `0x00EB` | padding, 1 byte | `padded_len` = `((15 + 3) AND NOT 3)` = 16 |
| → `0x00EC` | next property | `0x00B8 + 36 + 16` = **`0x00EC`** |

*Child property 2:*

| Offset | Field | Reading |
|---|---|---|
| `0x00EC` | name field (`0x00EC`–`0x010B`) | `reg`; byte at `0x010B` is `0x00` |
| `0x010C` | `length_word` | `10 00 00 00` = 16 |
| `0x0110` | value, 16 bytes (`0x0110`–`0x011F`) | two little-endian `u64`: address `0x79200000`, size `0x4000`. `padded_len` = 16, no padding bytes. |
| → `0x0120` | next property | `0x00EC + 36 + 16` = `0x0120` |

**Terminal offsets.** After exactly 3 child properties the walk lands on `0x0120`. Because the child's
`child_count` is 0, that offset is simultaneously the child's end-of-properties, its first-child position,
and `end_of(child)`. Since the child is the root's only child, it is also `end_of(root)`, and it equals
the blob length `0x0120` = 288.

**This is the case §6.2 and §9.7 warn about**: `0x0120` is a legitimate *extent* offset that equals
`adt_len`. A bounds check that requires every computed offset to be strictly less than the buffer end
rejects this fixture — and every real ADT. `0x0120` must never be dereferenced; it must also never be
rejected.

Total = `0x0120` = 288 bytes. Here that happens to equal `adt_len` exactly. **On a real ADT it usually
will not** — trailing slack after the tree is normal. See §9.1 for what a mismatch does and does not
mean.

---

## 8. The data AS-1 needs

Legend: **O(T6030)** = observed on the observation host; **T6020?** = expected on the target but
**unverified**; **S** = source-derived.

> A general rule for everything in this section: property *presence* is optional in the format. Firmware
> revisions add and remove properties. **Every read in this section must have a defined behaviour when the
> node or property is absent**, and that behaviour must never be "use an uninitialised value".

### 8.1 SoC identification

All of the following are properties of the **root node** (offset 0) unless stated.

| Property | Node | Type | Observed value on `T6030` | Expected on `T6020` |
|---|---|---|---|---|
| `compatible` | `/` | NUL-separated list of NUL-terminated ASCII strings | `J514sAP`, `Mac15,6`, `AppleARM` | `J474sAP`, `Mac14,12`, `AppleARM` — **T6020?** |
| `model` | `/` | NUL-terminated ASCII | `Mac15,6` | `Mac14,12` — **T6020?** |
| `target-type` | `/` | NUL-terminated ASCII | `J514s` | `J474s` — **T6020?** |
| `platform-name` | `/` | ASCII, NUL-padded to 32 bytes | `t6030` | `t6020` — **T6020?** |
| `device-tree-tag` | `/` | NUL-terminated ASCII | `EmbeddedDeviceTrees-11156.120.31` | — (use it to stamp the version table at the top of this file) |
| `#address-cells` | `/` | `u32` LE | 2 | 2 — **T6020?** |
| `#size-cells` | `/` | `u32` LE | 2 | 2 — **T6020?** |
| `chip-id` | `/chosen` | `u32` LE | `0x6030` | **`0x6020`** |
| `board-id` | `/chosen` | `u32` LE | `0x04` | unknown |

**`compatible` string-list semantics.** The value is a sequence of NUL-terminated strings packed
back-to-back. To test compatibility, iterate strings from the start of the value and compare each in full.
Iteration stops at the end of the value **or** at the first byte range with no NUL in it. Because the
value is padded to a multiple of 4 with zero bytes (§4.3), the tail of the value will usually produce one
or more empty strings — these are padding, not entries, and must be ignored, not matched. `[S, O]`

**Recommended identification order for AS-1:** read `/chosen` `chip-id` and require it to equal `0x6020`.
It is a single 4-byte integer and is the least fragile of the identifiers. Treat root `compatible` as a
secondary, human-facing confirmation. Do **not** identify the SoC by matching CPU `compatible` strings —
see §8.3.

### 8.2 Physical memory ranges

**There are four sources and they do not agree in scope. AS-1 must know which is authoritative.**

| Source | Meaning | Notes |
|---|---|---|
| `boot_args.phys_base` and `boot_args.mem_size` (§3) | The **usable** physical DRAM window as the firmware set it up. | **This is the authoritative one for AS-1.** The Asahi bootloader uses exactly this pair as the memory range it declares to the OS, precisely because the full DRAM range is not all usable. `[S]` |
| `/chosen` `dram-base`, `dram-size` | Base and size of **all** installed DRAM, including regions the OS must not touch. | Both `u64` LE. Observed `[O]`: `dram-base` = `0x100_0000_0000` (bytes `00 00 00 00 00 01 00 00`), `dram-size` = `0x4_8000_0000` (18 GiB, matching the host's installed RAM). **`dram-base` may be absent** — the Asahi bootloader has a fallback path for firmware that omits it. `[S]` |
| `/chosen/memory-map` | Firmware carve-outs, one property per named region. | Property **name** is the region name (e.g. `SEPFW`, `TrustCache`, `DeviceTree-ro`); property **value** is exactly **16 bytes: two little-endian `u64`, physical address then length**. `[S — Apple declares this record type explicitly; O — node present with the expected names]` |
| `/chosen/carveout-memory-map` | Additional carve-outs, same 16-byte record shape. | `[S, O]` |

**A trap, observed directly `[O]`:** there is a node named `memory` at the top level with
`device_type` = `memory`, and on the observation host its `reg` property is **8 bytes of zero** — while
the root declares `#address-cells` = 2 and `#size-cells` = 2, which would require a 32-byte `reg`.
**This node does not describe usable memory and must not be parsed as if it did.** If AS-1 reads it, it
must reject it on the cell-count/length mismatch (§9.8) rather than silently deriving a zero-length
region at address zero.

**A second trap `[O]`:** on the observation host, every value under `/chosen/memory-map` reads back as
**empty** in the live tree. That is an artefact of the observation method (§11.3), not of the format —
but it means the *values* of that node are, in this document, `[S]`-only. Their 16-byte shape is
first-party-declared; their contents at boot were not observed.

### 8.3 CPU nodes

| Path | Notes |
|---|---|
| `/cpus` | Container. Observed `#address-cells` = 1, `#size-cells` = 0 `[O]`. |
| `/cpus/cpu0` … `/cpus/cpuN` | One child per core. **Enumerate by walking `/cpus`' children; do not construct names.** |

Per-CPU properties `[O on T6030; the set is stable across the SoC generations the Asahi bootloader
supports, S]`:

| Property | Type | Meaning | Observed on `T6030` cpu0 |
|---|---|---|---|
| `name` | NUL-terminated ASCII | Node name | `cpu0` |
| `device_type` | NUL-terminated ASCII | Always `cpu` for a real core | `cpu` |
| `compatible` | string list | Core microarchitecture | `apple,sawtooth`, `ARM,v8` |
| `reg` | `u32` LE | **Packed core address.** bits 7..0 = core within cluster; bits 10..8 = cluster; bits 14..11 = die. `[S]` | `0x00000000` |
| `cpu-id` | `u32` LE | Logical CPU index. The Asahi bootloader prefers this over `reg` when present. `[S]` | 0 |
| `cluster-id` | `u32` LE | Cluster index | 0 |
| `cluster-type` | NUL-terminated ASCII | `E` (efficiency) or `P` (performance) | `E` |
| `state` | NUL-terminated ASCII | `running` for the boot CPU, `waiting` for every other core. **This is how the boot CPU identifies itself** — the Asahi bootloader notes this is also how Apple's kernel does it. `[S]` | `waiting` (host had already booted; see §11.3) |
| `cpu-impl-reg` | 2 × `u64` LE = 16 bytes | **(physical base, size) of this core's implementation register block.** Not translated through any `ranges` — it is already absolute. | base `0x2_1005_0000`, size `0x9010` |
| `cpu-uttdbg-reg` | 2 × `u64` LE = 16 bytes | Debug register block, (base, size). Not needed by AS-1. | base `0x2_1004_0000`, size `0xC8` |

**Do not identify the SoC from CPU `compatible`.** On `T6030` the E-core string is `apple,sawtooth`. On
the `T6020` target the analogous strings are expected to be `apple,blizzard` (E) and `apple,avalanche`
(P) — this is **inferred by analogy from the Asahi bootloader's per-SoC core naming, and is unverified on
the target** (OQ-5). Match on `device_type` = `cpu` instead, which is stable.

### 8.4 CPU release — there is no spin table

**The ADT contains no spin table and no release address.** "Spin table" is a Linux/devicetree boot method;
Apple firmware does not use it. Secondary cores are held in reset and are released by **writing hardware
registers**, whose addresses come from the ADT. Any implementation that searches the ADT for a
spin-table release address will find nothing and must not fall back to a guess. `[P — the Asahi SMP
documentation describes the register sequence; S — the per-SoC constant]`

Inputs needed:

| Input | Where from |
|---|---|
| `RVBAR` for core *n* | `cpu-impl-reg` container 0's **address** field (the first of the two `u64`) of that core's node, at offset `+0x00` within that block. `[P]` |
| PMGR register base | `/arm-io/pmgr` property `reg`, container 0, **translated through `/arm-io` `ranges`** (§8.5). Observed untranslated `[O]`: address `0x1_4070_0000`, size `0xCC000`. |
| CPU-start block offset within PMGR | Per-SoC constant. **`T6020` / `T6021` / `T6022` (M2 Pro / Max / Ultra): `0x28000`.** The Asahi prose table ("M2 Pro/Max: 0x28000") and the bootloader's constant agree exactly. `[P + S]` For reference only: `T8103`/`T600x` (M1 family) `0x54000`; `T8112` (M2) `0x34000`; `T6031` (M3 Max) `0x88000`. **Do not generalise from this table** — for `T6030` (M3 Pro) the prose says `0x88000` while the bootloader uses `0x34000`, a direct conflict (OQ-8). The target value is unaffected. |

**The three index values, and which register uses which.** This is the part the prose leaves ambiguous —
"the core's bit" is written twice and means a different index each time. Resolved from the bootloader's
implementation `[S]`. Three distinct values are in play, all obtained from §8.3:

| Symbol | Where from | Meaning |
|---|---|---|
| `core` | `reg` bits 7..0 | Index of the core **within its cluster** |
| `cluster` | `reg` bits 10..8 | Index of the cluster |
| `die` | `reg` bits 14..11 | Index of the die (0 on all single-die parts, including `T6020`) |

`cpu-id` (or the whole `reg` word) identifies the core to *software* and indexes per-CPU arrays. It is
**not** used as a hardware bit index in either register below.

**Sequence**, with access widths — the prose gives the sequence `[P]`, the widths and bit indices are
`[S]`:

| # | Access | Address | Value | Notes |
|---|---|---|---|---|
| 0 | — | — | — | Establish the die-adjusted base first: `cpu_start_base` = `pmgr_base + cpu_start_off + die × 0x20_0000_0000`. The die stride is `0x20_0000_0000`. On `T6020` `die` is 0 and the term vanishes. `[S]` |
| 1 | **64-bit read** | `cpu_impl_reg_base + 0x00` | — | Read `RVBAR`. If bit 0 (lock) is set, the address cannot be changed; verify that bits 47..12 already equal the intended entry point and **fail loudly if they do not**. This is the expected state for the boot CPU, which iBoot locks. |
| 2 | **64-bit write** | `cpu_impl_reg_base + 0x00` | entry point address | Plain write of the whole 64-bit word, **not** read-modify-write. Writing the address also clears the lock bit, since a 4 KiB-aligned address has bit 0 clear. Only possible when the lock is not already set. |
| 3 | barrier | — | — | A full system data barrier between the `RVBAR` write and the PMGR writes. |
| 4 | **32-bit write** | `cpu_start_base + 0x04` | `1 << (4 × cluster + core)` | System-level activation. **Plain write of a single set bit, not read-modify-write.** The bit index is the composite `4 × cluster + core` — **not** `cpu-id`, and **not** `core` alone. Without this write the core starts but its interrupts do not work. `[S]` |
| 5 | **32-bit write** | `cpu_start_base + 0x08 + 4 × cluster` | `1 << core` | Actually releases the core. **Plain write of a single set bit, not read-modify-write.** Here the bit index is `core` alone — the core's index *within its cluster* — because the register is already selected per-cluster by the `+ 4 × cluster` term. `[S]` |

The core then begins executing at `RVBAR`.

> **The two writes use different bit indices, and this is the single easiest thing to get wrong here.**
> Step 4 uses `4 × cluster + core`; step 5 uses `core`. They coincide only for cluster 0. An
> implementation that uses one index for both will appear to work on the first (efficiency) cluster and
> fail on every performance core.

**Both PMGR writes are plain stores of a single set bit**, not read-modify-writes. These are
write-1-to-act registers; reading them and OR-ing does not preserve meaningful state and is not what the
reference implementation does.

`RVBAR` field layout `[S]`: bit 0 = **lock**; address bits occupy 47..12, so the entry point must be
**4 KiB aligned**. Read back and verify rather than assuming the write took.

**Caveat on the `4 × cluster + core` composite (OQ-9).** That formula embeds an assumption of **at most 4
cores per cluster** — with 5 it would alias onto the next cluster's bits. It holds for the `T6020` target
(4 E-cores in one cluster, 8 P-cores in two clusters of 4), which is why it is stated here without
qualification for that part. It is **not** safe to carry to other SoCs unchecked.

### 8.5 `reg` and address translation

A `reg` property is an array of `(address, size)` containers. `[S]`

- The number of 4-byte cells in each half comes from the **parent** node's `#address-cells` and
  `#size-cells`. Not the node's own.
- **Cells are ordered least-significant first.** For `#address-cells` = 2, the first `u32` is the low half
  of the address and the second is the high half. Each `u32` is itself little-endian. This is the opposite
  of FDT's convention. `[S]`
- Container *i* begins at cell index `i × (address_cells + size_cells)`.
- Sane bounds the Asahi bootloader enforces, which BraiNIX should match: `1 ≤ address_cells ≤ 2` and
  `size_cells ≤ 2`. Anything else is malformed. `[S]`

**Translation through `ranges` is mandatory for anything under `/arm-io`.** A child's `reg` address is in
the parent's child address space and must be walked up to the root:

- The parent node's `ranges` property is an array of entries, each
  `(child_address, parent_address, child_size)`, with cell counts `address_cells` (the child's),
  `parent_address_cells` (the grandparent's `#address-cells`), and `size_cells` respectively — so each
  entry is `4 × (parent_address_cells + address_cells + size_cells)` bytes. `[S]`
- Find the entry where `child_address ≤ addr` **and** `addr + size ≤ child_address + child_size`, then
  substitute `addr := addr − child_address + parent_address`. Repeat up the path until a node has no
  `ranges` or the root is reached.
- **Absence of `ranges` on an intermediate node terminates translation** — it does not mean "identity"
  and it does not mean "error". `[S]`

**Worked check, verified against the live system `[O]`.** `/arm-io` `ranges` entry 0 is child `0x0`,
parent `0x2_1000_0000`, size `0x1_9000_0000`. The AIC node's `reg` container 0 is address `0x1_4100_0000`,
size `0x18_4000`. Translating: `0x1_4100_0000 − 0x0 + 0x2_1000_0000` = **`0x3_5100_0000`**, size
`0x18_4000` = 1 589 248. The kernel's own device-memory entry for that node reports address
`14 243 856 384` = `0x3_5100_0000` and length `1 589 248`. Exact match — the translation rule as stated is
correct.

### 8.6 The serial console UART

**Naming, stated precisely because it is easy to get wrong:** in the **ADT** the debug UART's `compatible`
is **`uart-1,samsung`** `[O]`. The string `apple,s5l-uart` is the **Linux FDT binding** name that the
Asahi bootloader writes into the *synthesised* FDT; it does **not** appear in the ADT. The hardware is a
Samsung S5L-lineage UART, which is where the "s5l" naming comes from. **Match on `uart-1,samsung`.**

| Item | Value |
|---|---|
| Node selection | If `/arm-io/uart6/debug-console` exists, use `/arm-io/uart6`. Otherwise use `/arm-io/uart0`. If neither exists, fail — there is no third candidate and no default address. `[S]` |
| `compatible` | `uart-1,samsung` `[O]` |
| `device_type` | `uart` `[O]` |
| `reg` | One container, address + size. Observed on `T6030` `[O]`: address `0x7920_0000`, size `0x4000`. **Must be translated through `/arm-io` `ranges`** (§8.5) — untranslated it points nowhere. On the observation host the translated base is `0x2_8920_0000`. The `T6020` value will differ. |
| `uart-version` | `u32` LE, observed 1 `[O]` |
| `clock-ids`, `clock-gates` | `u32` arrays; power/clock management, not needed to *read* an already-running console. `[O]` |
| Reference clock | **24 000 000 Hz.** This is a constant in the Asahi bootloader, **not a value read from the ADT**. `[S]` — see OQ-6. |

`/arm-io/uart6/debug-console` is a **child node**, not a property. Its mere existence is the signal; its
contents are not read. `[S]`

### 8.7 The AIC interrupt controller

| Item | Value |
|---|---|
| Path | `/arm-io/aic` `[S, O]` |
| `compatible` | One of `aic,1`, `aic,2`, `aic,3`. Observed `aic,3` on `T6030` `[O]`. **Expected `aic,2` on the `T6020` target — unverified (OQ-4).** Match all three and dispatch; never assume. |
| `device_type` | `interrupt-controller` `[O]` |
| `interrupt-controller` | NUL-terminated ASCII, observed `master` `[O]` |
| `#interrupt-cells` | `u32` LE, observed 1 `[O]` |
| `reg` | One container. Observed `[O]` address `0x1_4100_0000`, size `0x18_4000`; translated `0x3_5100_0000` (§8.5). |
| `aic-iack-offset` | **`u64` LE, 8 bytes.** Observed `0x40000` `[O]`. Register offset of the interrupt-acknowledge register, relative to the AIC base. Required for AIC v2 and v3. `[S, O]` |
| `#main-cpus` | `u32` LE, observed 12 `[O]` |
| `aic-ext-intr-cfg` | Byte array, **3 bytes per entry**: byte 0 = IRQ low 8 bits; byte 1 = IRQ high 4 bits in its low nibble, die in its high nibble; byte 2 = target CPU. Optional. `[S]` |
| `cap0-offset`, `maxnumirq-offset` | `u32` LE. Fixed constants for AIC v2; **read from the ADT for AIC v3**. Observed on `T6030` `[O]`: `cap0-offset` = 4, `maxnumirq-offset` = `0x0C`. `[S, O]` |
| `extintrcfg-stride`, `intmaskset-stride`, `intmaskclear-stride` | `u32` LE, per-die register strides. Observed 0 on the single-die host `[O]`. |

AS-1's requirement is only to **locate** the node, confirm its version, and resolve its translated base
address. Programming the controller is out of scope for this document.

---

## 9. Hostile input

**The ADT is firmware-supplied data. BraiNIX's threat model
([`../THREAT_MODEL.md`](../THREAT_MODEL.md)) treats it as hostile input on the same footing as network
bytes.** It is not signed to BraiNIX, BraiNIX cannot verify it, and a compromised or simply
different-version firmware can supply anything at all. Every rule below is mandatory.

**The three global rules.**

- **Fail closed, always.** On any violation, the parse ends. Do not skip the offending record and continue;
  do not truncate a length to what fits; do not clamp a count to a maximum and proceed. A saturating
  clamp turns "this tree is malformed" into "this tree is now silently different from what the firmware
  described", which is a worse state than not booting.
- **Every arithmetic operation on an attacker-controlled value is checked for overflow, and an overflow is
  a failure, not a wrap.** Apple's own reader panics on overflow in exactly these spots rather than
  wrapping — the danger is real and known. A wrapped offset lands *inside* the buffer and passes every
  subsequent bounds check.
- **Bounds are checked immediately before each dereference, not once after forming a pointer.** Because a
  node's extent is unknowable without walking it (§4.1), there is no up-front validation pass that can
  make later reads safe. Apple's reader adopts precisely this discipline and documents why.

### 9.0 Format rules versus BraiNIX policy

Some checks below follow from the format; others are **numeric limits BraiNIX chooses**. They are listed
together because a parser must apply both, but they are not the same kind of statement and must not be
recorded as if they were.

| Limit | Value | Status | Provenance |
|---|---|---|---|
| Property/child count ceiling | 2048 | **BraiNIX policy** | Adopted from the Asahi bootloader, which ships this ceiling against real firmware. Not a format rule; no source states a maximum. |
| Value length ceiling | 1 MiB − 1 | **BraiNIX policy** | Same. The format permits up to `0x7FFFFFFF` (§5). |
| Maximum nesting depth | 8 | **BraiNIX policy** | Same. The format imposes no depth limit. |
| Maximum node-name length | 63 bytes + NUL | **BraiNIX policy**, anchored on a format hint | Apple's declaration names 63 as the maximum entry-name length, but the name lives in a property value that the format does not bound (§4.5). |
| Rejecting a non-NUL byte at name offset 31 | — | **BraiNIX policy** | Adopted from a third-party parser. The format does not *require* termination (§4.2); this makes it required. |
| Everything else in §9 | — | **Format-derived** | Follows from §3–§6: overflow, truncation, alignment, and the counts-are-authoritative rule. |

Each policy limit must carry a **distinct failure reason** in the implementation, so that a tree rejected
by BraiNIX policy can be told apart from a tree that is genuinely malformed. If real firmware ever trips
one of these, the log must say which, and the limit is a decision to revisit — not evidence that the ADT
is corrupt.

### 9.1 `devtree_size` — the total-size claim

| Attacker-controlled value | Required check |
|---|---|
| `boot_args.devtree_size` | Reject 0. Reject any value less than 8 (a blob cannot hold even a root header). **Reject any value that is not a multiple of 4** (§3.1). Reject if `adt_phys + devtree_size` overflows a 64-bit address. Reject if the resulting interval is not entirely inside the physical DRAM window derived from `boot_args.phys_base`/`mem_size`. |
| `adt_phys` (derived) | **Reject unless 4-byte aligned** (§3.1). This is what gives the §9.7 alignment check a well-defined meaning; without it, offset alignment and address alignment are different properties and the check silently guarantees neither. |
| `boot_args.devtree` (virtual) | The subtraction `devtree − virt_base` must not underflow, and the addition of `phys_base` must not overflow. Both are attacker-controlled 64-bit values. |
| Relationship to the parse | `devtree_size` is a **claim**, and the tree inside it is a second, independent claim. **They need not agree, and a mismatch is not automatically fatal**: a well-formed tree may end before `devtree_size` (trailing slack is normal). What is fatal is the converse — the tree extending *beyond* `devtree_size`. Never use "the tree ended exactly at the buffer end" as a validity signal, and never extend the buffer to fit the tree. |

### 9.2 Property and child counts

Both are 32-bit unsigned values read directly from the blob. Both are used as loop bounds.

| Value | Required check |
|---|---|
| `property_count` | Reject `0` — structurally invalid (§4.1). **Minimum-space test, applied at the node header:** the node's properties alone need at least `property_count × 36` bytes, so reject if `8 + property_count × 36` exceeds `adt_len − node_offset`. Overflow-check the multiplication. Then apply the **2048** ceiling (§9.0 — BraiNIX policy). |
| `child_count` | **Minimum-space test, applied after the property walk, not at the node header.** Each child needs at least an 8-byte header, so once the first-child offset `F` is known (§6.2), reject if `child_count × 8` exceeds `adt_len − F`. Measuring against `adt_len − node_offset` instead is wrong: it counts the node's own properties as space available to its children, so it accepts a `child_count` that cannot possibly fit. A cheap pre-check against `adt_len − node_offset` at the header is permitted as an *early* reject, but it does not discharge the real test. Overflow-check the multiplication. Then apply the **2048** ceiling (§9.0 — BraiNIX policy). |
| Both | A count of `0xFFFFFFFF` must be rejected by the space test, not merely by the ceiling — the space test is the one that stays correct for small buffers, and it is the one that is a format rule rather than a policy. |

### 9.3 The length word

| Value | Required check |
|---|---|
| Bit 31 set | **Reject the tree** (§5.3). Distinct failure reason. |
| `value_len = length_word AND 0x7FFFFFFF` | Reject if `property_offset + 36 + value_len` overflows, **or** exceeds the buffer end. |
| Padding | Reject if `property_offset + 36 + padded_len` overflows or exceeds the buffer end — note this is a **strictly stronger** test than the one on `value_len`, and it is the one that matters, because the padded size is what the next-property arithmetic uses. Checking only the unpadded length lets a property whose value ends exactly at the buffer end produce a next-property offset past the end. |
| `padded_len = ((value_len + 3) AND NOT 3)` | Note the inner parentheses (§4.3). `value_len` can be as large as `0x7FFFFFFF`, so `value_len + 3` must be computed in a width where it cannot wrap — do the addition in 64 bits, or reject `value_len > 0x7FFFFFFC` first. A wrapped `padded_len` is small and passes every subsequent bounds test. |
| Policy ceiling | Reject `value_len` greater than **1 MiB − 1** (equivalently: any of bits 30..20 set). **BraiNIX policy, not a format rule** (§9.0). Distinct failure reason (§5.3 rule 4). |

### 9.4 Truncation

A blob may end in the middle of any record.

| Situation | Required behaviour |
|---|---|
| Fewer than 8 bytes remain where a node header is expected | Reject. |
| Fewer than 36 bytes remain where a property header is expected | Reject. |
| The value or its padding runs past the buffer end | Reject. **Do not adopt the "last property may be unpadded at the very end" leniency** that exists in third-party parsers (§4.3). Under a threat model, that leniency is a hole: it lets a crafted blob end 1–3 bytes early and still parse. |
| Any child of a node lies wholly or partly outside the buffer | Reject. |

### 9.5 Name field termination

| Value | Required check |
|---|---|
| Property `name` field | Reject the property unless the byte at `name + 31` is `0x00`. This is checked **before** any string operation on the name. **BraiNIX policy** (§9.0) — the format does not require termination. Rationale: Apple's own reader compares property names with an unbounded string comparison, which over-reads past the 36-byte header on a non-terminated name. |
| Name comparison | Compare bounded to 32 bytes regardless, even after the termination check — defence in depth. |
| `name` property *value* (the node's name) | The value is not guaranteed to contain a NUL. Search for a NUL only within `value_len` bytes. If there is none, the node name is malformed — reject the node; do not treat the whole value as the name. |
| **Node-name length bound** (the check §4.5 requires) | The node name is a string inside a property value, and the format bounds that value only by `0x7FFFFFFF` (§4.5). **Reject any node whose `name` property has `value_len` greater than 64** — 63 name characters plus the terminator, the maximum entry-name length Apple's own declaration names. **BraiNIX policy** (§9.0). Without it, a single crafted `name` property can present a 2 GiB "node name" to every path comparison at every level of the walk. |
| Any string value (`compatible`, `state`, `cluster-type`, `device_type`, `model`, …) | Same rule. Every string read is bounded by `value_len`. Never hand a property value to anything that scans for a terminator without a length bound. |

### 9.6 Nesting depth

The tree is walked recursively (`end_of` in §6.2 is recursive by construction). A blob of `N` bytes can
encode a chain of roughly `N / 8` nested nodes — a 1 MiB ADT permits over 130 000 levels. Unbounded
recursion in a kernel boot stub with a fixed, small stack is a **guaranteed** stack overflow into whatever
lies below the stack.

| Required check |
|---|
| Enforce a hard maximum depth and reject any tree that exceeds it. **BraiNIX policy** (§9.0), adopted from the Asahi bootloader, which uses **8**. Real Apple ADTs are shallow; a limit in the range 8–16 is generous. |
| The depth counter is incremented before descending and checked before the recursive step, so that the limit is enforced even on the first descent. |
| Prefer an explicit bounded stack over language-level recursion, so that the limit is a data-structure property rather than a discipline. |

### 9.7 Every computed offset

**This is the general rule that subsumes the specific ones.** These are the values in the format that are
attacker-controlled *and* used to compute an offset:

| Field | Used to compute | Must be validated before use |
|---|---|---|
| `property_count` | The offset of the first child (by iterating that many times) | §9.2 |
| `child_count` | How many sibling walks to perform | §9.2 |
| `length_word` (bits 30..0) | The offset of the next property, and of the first child | §9.3 |
| `devtree_size` | The single bound every other check is measured against | §9.1 |
| `#address-cells`, `#size-cells` | The cell offset of a `reg` container | §9.8 |
| `ranges` entry cell counts | The stride between `ranges` entries | §9.8 |
| `reg` container index | The byte offset within the `reg` value | §9.8 |

**Two kinds of offset, two different bounds.** Conflating them is a real defect in either direction: the
strict test rejects every well-formed ADT, the loose test permits a read past the end.

| Kind | What it is | Required bound |
|---|---|---|
| **Read offset** | An offset the parser is about to dereference: a node header, a property header, a property value, a cell within a value. | `0 ≤ offset` **and** `offset < adt_len` **and** the *entire* record starting there fits, i.e. `offset + record_size ≤ adt_len`, computed without overflow. |
| **Extent offset** | A one-past-the-end position: `end_of(N)`, and the first-child offset of a node whose `child_count` is 0. It marks where something *stopped*, and is never dereferenced while it holds that value. | `0 ≤ offset` **and** `offset ≤ adt_len`. **Equality with `adt_len` is legal and normal** — for the last node in the blob it is guaranteed. |

The transition between the two is the only place this matters: an extent offset **becomes** a read offset
the moment the parser decides to read a node or property there — which happens only when a count says
another record exists. At that moment the read-offset test applies in full, and an extent offset equal to
`adt_len` fails it, correctly. So the rule is: **bound extent offsets with `≤`, then re-test with `<` and
the record-fits test before any dereference.** Never carry the `<` test back onto the extent computation.

The §7 fixture exercises exactly this: `0x0120` is simultaneously `end_of(child)`, `end_of(root)`, the
child's first-child position, and `adt_len`. A parser that requires every computed offset to be strictly
less than the buffer end rejects it, and rejects every real ADT for the same reason.

Additionally: every offset a node or property is **found at** must be **4-byte aligned** (§4.3), which is
well-defined because §3.1 requires the buffer base to be 4-byte aligned. A misaligned landing offset means
the walk has desynchronised and must fail closed. The Asahi bootloader checks exactly this.

### 9.8 Derived-value checks specific to `reg` and `ranges`

| Value | Required check |
|---|---|
| `#address-cells` | Read as a `u32` from a property whose `value_len` must be exactly 4. Reject unless `1 ≤ value ≤ 2`. |
| `#size-cells` | Same; reject unless `value ≤ 2`. |
| Missing `#address-cells` / `#size-cells` on the parent | Reject. **Do not default to 1, 2, or anything else.** A wrong default silently produces a wrong address, which is worse than not booting. |
| `reg` container index *i* | Reject unless `reg_value_len ≥ (i + 1) × (address_cells + size_cells) × 4`. Overflow-check that multiplication. |
| `reg` value length | It need not be an exact multiple of the container size — but a partial trailing container must never be read. |
| `ranges` entry size | `4 × (parent_address_cells + address_cells + size_cells)`. Reject if it is 0 or if it exceeds the `ranges` value length. Iterate only over whole entries; ignore any trailing partial entry rather than reading it. |
| Translation arithmetic | `addr − child_address + parent_address` must be checked for both underflow and overflow. The containment test `child_address ≤ addr` **and** `addr + size ≤ child_address + child_size` must itself be evaluated without overflow — both right-hand sums are attacker-controlled 64-bit values. |
| No matching `ranges` entry | The address is untranslatable. **Fail** — do not pass the untranslated address through. An untranslated `/arm-io` address is a valid-looking physical address pointing at the wrong place, which is precisely the input an attacker wants a driver to MMIO-map. |

### 9.9 Values that are plausible but must still be rejected

| Value | Why it must be rejected |
|---|---|
| A `reg` address+size that is not inside a region BraiNIX is willing to map as device memory | The ADT can name any address, including DRAM holding the kernel. Range-check every MMIO base against the platform's device-memory windows before mapping. |
| A `cpu-impl-reg` block whose `value_len` is not exactly 16 | Reading 16 bytes from a shorter value over-reads. Every fixed-shape property (`cpu-impl-reg`, memory-map entries, `reg` containers) must have its length checked for **exact** or **at-least** conformance before the fields are extracted. |
| A memory-map entry whose `value_len` is not exactly 16 | Same. |
| `dram-size` = 0, or `dram-base + dram-size` overflowing | Both are 64-bit attacker-controlled values feeding an address computation. |
| A `/cpus` child count larger than BraiNIX's compiled-in maximum CPU count | Bound the enumeration by the compiled maximum and reject (not truncate) a tree that exceeds it. |
| Two `/cpus` children with the same `cpu-id` | Would alias entries in any per-CPU array. Detect and reject. |
| `cpu-id` greater than or equal to the compiled maximum CPU count | Reject before using it as an array index. |
| A duplicate property name within one node | The format does not forbid it, and a parser returning "first match" and one returning "last match" then disagree about the same tree. **Two rules, and they apply at different times.** (a) *Lookup semantics, always:* a name lookup returns the **first** matching property in node order, and stops there. This is normative so that two conforming implementations agree. (b) *Duplicate rejection, at the point of use:* when the parser reads one of the properties AS-1 actually depends on — `name`, `compatible`, `reg`, `ranges`, `#address-cells`, `#size-cells`, `cpu-impl-reg`, `chip-id`, `device_type`, `state` — it must scan that node's full property list and **reject the node if the name appears more than once**. Rule (a) makes behaviour deterministic; rule (b) makes the ambiguity non-exploitable where it would matter. A duplicate of a property AS-1 never reads is ignored. |

---

## 10. Open questions

Each names what is unknown and what evidence would settle it. **None of OQ-1 through OQ-6, OQ-8 and OQ-9
blocks AS-1** — each is either outside what AS-1 reads, or mitigated in the body by a rule that is correct
under every candidate answer. **OQ-7 does not block implementation, but must be closed before this spec is
trusted on the target.**

**OQ-1 — `boot_args.cmdline` offset: `0x6C` or `0x70`?**
Apple's own structure places the command line immediately after `devtree_size` at `0x6C`. The Asahi
bootloader's equivalent declaration wraps the tail in a union whose alignment pushes it to `0x70`. One of
the two is wrong, or Apple's compiles differently than read. *Not needed by AS-1* — everything AS-1 reads
lives at `0x68` or below, where the two sources agree exactly.
*Would settle it:* dumping the first 256 bytes at `x0` on the target and locating the ASCII command line.

**OQ-2 — Are bits 30..20 of the length word reserved flags, or just always-zero length bits?**
The Asahi bootloader rejects any property with those bits set, which is consistent with either reading.
No source states which. This spec treats them as length bits with a policy ceiling (§5.3 rule 4), which is
safe under both readings.
*Would settle it:* an Apple firmware image whose ADT template sets one of them, or Apple documentation.

**OQ-3 — What does a placeholder property's value contain when bit 31 is set?**
The Asahi Python parser reads it as a NUL-terminated string, which is an inference from observed data.
*Not needed by AS-1*, which rejects such trees outright (§5.3).
*Would settle it:* extracting a raw `DeviceTree` image from a firmware bundle (before iBoot processes it)
and examining the flagged properties. Note this is the one case where the *pre-boot* ADT differs from the
one the OS receives.

**OQ-4 — Is `/arm-io/aic` `compatible` equal to `aic,2` on `T6020`?**
`aic,3` was observed on `T6030`. `aic,2` on M2 Pro is the expectation from the Asahi bootloader's version
dispatch, but was not verified. Mitigated in §8.7 by requiring the implementation to dispatch on all three
rather than assume.
*Would settle it:* `ioreg -p IODeviceTree -l` on the target Mac mini, or an m1n1 ADT dump from it.

**OQ-5 — What are the CPU `compatible` strings on `T6020`?**
`apple,blizzard` / `apple,avalanche` are inferred by analogy. Mitigated in §8.3 by matching on
`device_type` = `cpu` instead.
*Would settle it:* same dump as OQ-4.

**OQ-6 — Is the UART reference clock discoverable from the ADT?**
The Asahi bootloader hard-codes 24 MHz rather than reading it, which suggests either that it is not in the
ADT or that it was not worth reading. No property named for a UART clock frequency was found on the
observation host. If the console only needs to *read* an already-configured UART, the clock is not needed;
if AS-1 sets the baud divisor it is.
*Would settle it:* a full property dump of `/arm-io/uart0` and of any node its `clock-ids` refer to, on
the target.

**OQ-7 — The target machine's firmware version is unrecorded.**
The version table at the top of this file is complete for the observation host and empty for the target.
Per [`README.md`](README.md), *"a fact table with no version recorded is a fact table about an unknown
machine."*
*Would settle it:* on the target Mac mini, capture `sw_vers`, `system_profiler SPHardwareDataType`
(System Firmware Version / OS Loader Version), and the root node's `device-tree-tag`; fill in the table;
re-qualify this spec.

**OQ-8 — Prose and source disagree on the `T6030` CPU-start offset.**
The Asahi SMP page's table gives "M3 Pro/Max: 0x88000"; the bootloader's dispatch sends `T6030` to
`0x34000` and only `T6031` and later to `0x88000`. One of them is wrong. **This does not affect the
`T6020` target**, where both sources give `0x28000` — but it is direct evidence that the prose tables and
the shipped constants are not always in sync, so per-SoC constants in §8.4 must not be extrapolated.
*Would settle it:* attempting a secondary-core start on an M3 Pro with each value.

**OQ-9 — The `4 × cluster + core` activation bit index assumes at most 4 cores per cluster.**
§8.4 step 4 uses that composite as a bit index in the register at `cpu_start_base + 0x04`. With 5 or more
cores in a cluster it would alias onto the next cluster's bits. **It holds for the `T6020` target** (one
E-cluster of 4, two P-clusters of 4), so AS-1 is unaffected, and the reference implementation uses it
unconditionally across every SoC it supports. What is not established is whether the register's true
layout is 4-bits-per-cluster or something that merely coincides with it on the parts tested.
*Would settle it:* a part with more than 4 cores in one cluster, or Apple documentation of the register.

---

## 11. What this document is not

### 11.1 Not a stable contract

Apple can change the ADT's contents in any firmware update, and does. **The layout itself** (§4–§6) has
been stable across every Apple Silicon generation for which evidence exists and is anchored by Apple's own
first-party declaration, so it is the least likely part to move. **The contents** (§8) — which nodes
exist, which properties they carry, and what those properties mean — carry no compatibility promise
whatsoever. Treat §8 as a snapshot, and write the parser so that a missing node or property is a clean,
diagnosable failure rather than a crash or a wrong answer.

### 11.2 Not derived from the target machine

Restated because it matters: §8's observed values come from a `T6030` MacBook Pro. See OQ-7.

### 11.3 The observation method's limits

The `[O]` facts were read from XNU's live `IODeviceTree` registry plane, not from the raw ADT blob. That
plane is the ADT **after** the kernel has parsed and mutated it. Specifically:

- XNU **adds** properties that are not in the ADT (`AAPL,phandle`, `IODeviceMemory`, `IOInterrupt*`,
  `IOPlatform*`, and others). Any property name beginning with `IO` or `AAPL,` in an `ioreg` dump should be
  assumed synthetic.
- XNU **synthesises** the `@unit-address` suffix on node labels (§4.5).
- XNU (or iBoot) **zeroes or removes** sensitive and consumed values. Every `/chosen/memory-map` value read
  back empty, and `dram-base` appeared in only some of the places the Asahi bootloader reads it. Absence in
  an `ioreg` dump is therefore **not** evidence of absence in the ADT.
- `state` on the boot CPU read `waiting`, not `running`, because the machine had long since finished
  booting.
- Nothing about the **binary encoding** — field widths, padding, endianness of the container fields, the
  flag bit — can be observed this way at all. Those facts are `[S]` and are marked as such.

---

## 12. The honest limit

Per [`README.md`](README.md) §*The honest limit* and [`../NORTH_STAR.md`](../NORTH_STAR.md): **this
procedure protects code provenance, not knowledge provenance.** No line of any source named above was
copied into this document, and every fact here is traceable to a named artefact. That is the claim. It is
*not* claimed that an implementer working from this file arrives at an understanding independent of the
sources that produced it — the fact tables in §4–§6 are, necessarily, a description of the same structures
those sources describe.

A second limit, specific to this file: **the most implementation-critical fact in it (§5, bit 31) is
established only from source code and one source comment.** No Apple prose and no Asahi prose states it.
Three independent implementations agreeing is strong evidence about *what the bit is*, and one comment is
weak evidence about *what it means*. §5.3 is written so that BraiNIX's behaviour is correct under any
reading of the semantics: it masks the bit, and it refuses any tree in which the bit is set.

A third: **Apple's first-party sources are the strongest evidence here, and they are still source code.**
`device_tree.h` and `arm64/boot.h` are Apple's own declarations of these structures — not reverse
engineering, and not subject to the Asahi clean-room concern at all. They are nonetheless marked `[S]`
throughout, because the confidence-marking rule is about *prose versus source*, not about who wrote the
source.
