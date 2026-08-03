# BXW1 — BraiNIX weight-blob format (model weights at rest and in the reserved region)

**Task:** P3-T1 — weight format specification. Design only, no implementation.
**Authoritative parents:** [`../NORTH_STAR.md`](../NORTH_STAR.md),
[`../THREAT_MODEL.md`](../THREAT_MODEL.md),
[`../security/SECURITY_INVARIANTS.md`](../security/SECURITY_INVARIANTS.md).
**Governs:** the byte layout of the served model's weights on disk and in the
build-time-reserved `WEIGHTS_REGION`, and the validation every consumer of those
bytes performs before any of them reaches a tensor kernel.
**Consumed by:** P3-T3 (the fail-closed loader), P3-T4 (the tensor kernels, which
are written against §4's dequantization formula), P3-T5 (the tokenizer, bound to
the model by §5.4), P3-T6 (the transformer forward pass, which reads every
hyperparameter from §5 and resolves every tensor by the names in §6).
**Related:** [`MEMORY_MODEL.md`](MEMORY_MODEL.md) §13 (`WEIGHTS_REGION`,
`KV_REGION` — P3-T2 owns region lifecycle),
[`BSP-v2-serving-protocol.md`](BSP-v2-serving-protocol.md) §10.4 (the
`LoadWeights` admin verb, which names a digest this document defines).
**Status:** design spec. Precise enough to drive Kani harnesses and libFuzzer/AFL
targets against every field and every rejection path. **Nothing here is
implemented** — see §11, which states exactly what does not exist.

This spec is normative. "MUST", "MUST NOT", and "DENY" are hard requirements.
"DENY" always means the fail-closed action defined in §7.1. Absence of an
explicit accept path is denial (NORTH_STAR "Fail closed").

Proof tier, per [`../security/SECURITY_INVARIANTS.md`](../security/SECURITY_INVARIANTS.md)
§16: the **BXW1 weight loader is Full tier** — invariant mapping, fuzz target,
Kani harness, Prusti contracts, audit report, and no-regression bars. It is
listed there as "hostile input from disk, and the integrity gate for the weights
themselves (`INV-MODEL-002`)." This document is the invariant-mapping artifact.
The parser `inferd` embeds to resolve tensors (§10.3) is Full tier in its own
right and does not inherit `inferd`'s Reduced tier — §16's first corollary.

---

## 0. Non-negotiables inherited

- **The weights region is fixed and reserved at build time.** `INV-MEM` admits no
  growing allocator for weights, and `MEMORY_MODEL.md` §13 sizes `WEIGHTS_REGION`
  in **pages**, at build time, from the model the image is built to serve. No
  quantity in a BXW1 blob ever sizes, extends, or selects a region. A blob whose
  declared sizes exceed the region denies **before any mapping** (§8).
- **The blob is hostile input.** It arrives from disk, which the project did not
  write and cannot audit, and it is parsed with more authority than anything from
  the network — the parse happens before `inferd` launches. `INV-PARSE-001`
  applies verbatim: `#![no_std]`, zero-allocation, every offset, length, and count
  bounds-checked against its containing region, malformed input denies rather than
  proceeding best-effort.
- **The model is a tenant, not an authority.** A blob that passes every check in
  this document is still a confined tenant (`INV-MODEL-001`). Integrity checking
  says nothing about whether the model is safe; it says the bytes are the bytes
  someone named. §9 states that boundary precisely, because it is the single
  claim most likely to be overstated.
- **No new external crate.** The only primitive BXW1 needs is **SHA-256**, which
  is in the in-tree set. Honest status: `sha2` is still vendored today and the
  in-tree reimplementation has not landed (NORTH_STAR §"What advancing the goal
  means"). There is no compression, no container library, and no third-party
  format parser.
- **Bytes moved is the metric.** Inference on the reference machine is
  memory-bandwidth-bound: single-stream decode reads essentially the whole weight
  set per token, so the ceiling is (model bytes ÷ memory bandwidth). Every layout
  decision below was made against that arithmetic first (§4.5), which is why
  Q8_0 is a first-class dtype and not an optimization bolted on later.
- **Structure over secrecy.** Every field, bound, and rejection path is public.
  Nothing here rests on an attacker not knowing the format.

---

## 1. Invariant mapping (what BXW1 exists to enforce)

| Invariant | How BXW1 enforces it |
|---|---|
| **INV-MODEL** / `INV-MODEL-002` (weights integrity-checked before use) | A per-tensor SHA-256 in the tensor table (§3) and a whole-blob SHA-256 (§9.1), both verified against region-resident bytes **before** the region is sealed and before `inferd` exists (§10). A corrupt or oversized blob denies with nothing activated. There is no partial activation and no best-effort load. |
| `INV-MODEL-001` (the model's capability set is exactly three things) | The format carries **no** path, filename, capability reference, endpoint, address, or executable content. A tensor name is an opaque label matched against a compile-time set (§6); it never names a file, a device, or an object. There is nothing in a blob that a loader could act on other than to place bytes. |
| `INV-MODEL-003` (model-adjacent bytes are untrusted everywhere) | Tensor names are blob-supplied strings. They are validated to a printable-ASCII, NUL-terminated form (§7.3) and are compared, never interpreted, never used as a path, and never emitted to a console or log as control. |
| **INV-MEM** / `INV-MEM-003` (W^X is global) | `WEIGHTS_REGION` is mapped non-executable at all times and read-only after seal (§10.2). Weights are data; there is no exception and no JIT path (NORTH_STAR "Out of bounds without written sign-off"). |
| `INV-MEM-005` (memory ownership is explicit) | The region is exclusively owned by the loader while writable and by the sealed read-only view afterwards. No two holders name it writable at once, which is what makes the single validation pass of §10.1 sound. |
| `INV-MEM-006` (freed memory sanitized before reuse) / `INV-OBJ-002` | Any denial after the copy zeroizes the whole region before returning (§7.1). A replaced weight generation zeroizes before the next load begins, so no residue of a previous model is observable. |
| `INV-MEM-009` (page size is a platform parameter) | `BXW1_ALIGN` is **128 bytes** — a property of the NEON/cache-line geometry, not of the page size — and it composes with the platform's 16 KiB page because 16384 is a multiple of 128 (§4.4). Region sizing stays in pages and stays P3-T2's; this document contributes no page-size literal. |
| `INV-SERVE-002` (no allocation driven by foreign sizes) — read here as its disk analogue | Every buffer the loader uses is a compile-time-sized `static`: a 256-byte header buffer, the ≤ 640 KiB table buffer, and the hash state. The copy length in §10.1 comes from the **storage layer's** reported object length checked against a `const`, never from the blob's own `total_size`. No file-supplied number sizes anything, ever. |
| `INV-SCHED-004` (exhaustion is explicit) | A blob larger than `WEIGHTS_REGION` returns an enumerated error before any copy (§8.2). There is no truncation, no partial residency, and no fallback to a smaller model. |
| `INV-PARSE-001` (fail-closed hostile-input parser) | §7's rule table is the enumeration of every attacker-controllable value and its required behaviour. All arithmetic is checked; nothing saturates or wraps; a value that does not fit denies. |
| `INV-PARSE-002` (fuzz target *and* Kani harness) | §12 names both, plus the Prusti and audit obligations Full tier requires. |
| `INV-PARSE-004` (disagreeing sources fail closed) | Three sources describe overlapping facts — the header's hyperparameters, the tensor table's shapes, and the tokenizer vocabulary blob. Disagreement is a DENY with no precedence rule (§7.5), for the reason `INV-PARSE-004` gives: picking a winner means trusting one unaudited source over another. |
| `INV-FAIL-001` (failure modes are defined) | §7.1 defines exactly one failure action for every rejection in this document. |
| `INV-FAIL-002` (recovery mints no hidden authority) | A failed load grants nothing, and leaves the previously sealed generation active when it is refused before §10.5's teardown. A successful load grants `inferd` a **read-only** view and no new capability (§10.2). `modeld`'s own capabilities are its three (§10.0) and it exits holding none of them. |
| `INV-FAIL-003` (secure degradation over silent insecurity) | There is no "load anyway and warn" path, no digest-check bypass, and no relaxed mode. A blob that cannot be fully verified is not served. |
| `INV-AUTH-009` (admin authority is a capability, not a shell) | Activation is the `LoadWeights` verb — one of exactly six — and it names a 32-byte digest, never a path and never a byte stream (BSP v2 §10.4). BXW1 defines no field that could widen that verb, and adds no seventh. |
| `INV-AUD-001` / `INV-SERVE-005` (security-relevant events observable) | Load attempt, outcome, blob digest, tensor count, and total size are emitted to `auditd` (§10.4). Weight bytes are never emitted. Observing a load grants no authority. |
| `INV-BOOT-AS-001` (attestation claims are forbidden) | No field, log line, or sentence in this document asserts that a verified digest attests anything to a remote party. §9.3 states the opposite explicitly. |
| `INV-BOOT-AS-002` (the measurement log is never evidence) | The load's measurement-log entry is **self-reported**, is a debugging and accidental-corruption aid, and is not evidence against an attacker who already controls the kernel. §9.3 says so in the same words `INV-MODEL-002` already uses. |

No new invariant identifier is introduced by this document, and none may be.

---

## 2. Byte-encoding primitives, and why they are little-endian

All multi-byte integers and all IEEE-754 values in a BXW1 blob — header, tensor
table, and tensor payload alike — are **little-endian**. There are exactly three
encoding forms:

1. **Fixed scalar** — `u8`, `u16`, `u32`, `u64`, little-endian, at a fixed offset
   in a fixed-size structure. A short buffer ⇒ DENY.
2. **Fixed array** — an exactly-N-byte field (a 32-byte digest, a 64-byte name).
   No length prefix anywhere in the format.
3. **Bulk payload** — a tensor extent, described entirely by the fixed fields of
   its table record.

**There is no variable-length field, no TLV, no self-describing recursion, no
length that governs a following length, no compression, and no string table.**
Structure is decided by fixed offsets and by `tensor_count`, which is bounded by
a `const` before it is used for anything. The consequence is the one that matters
for a Full-tier parser: the header decoder is **total from the first byte** — it
reads a constant number of bytes and every deviation is a single DENY.

**Readers are byte-wise.** Every field is assembled from a byte slice by an
explicit little-endian reader. No `#[repr(C)]` struct cast, no `transmute`, no
pointer cast over blob bytes. This is why the 160-byte tensor record (§3) need
not be a power of two: record alignment is irrelevant when nothing is read
through a typed pointer. `BXW1_ALIGN` (§4.4) governs **tensor data** only, where
alignment is a performance property the kernels actually rely on.

### Why this diverges from BSP

BSP v2 is big-endian; BXW1 is little-endian. The divergence is deliberate and
costed rather than accidental:

- The tensor payload **must** be little-endian, because it is consumed in place
  by NEON on a little-endian machine. Byte-swapping it would mean a second full
  pass over up to `BXW1_MAX_BLOB_BYTES`, which on a bandwidth-bound machine is
  the single most expensive thing the loader could do (§4.5 puts a number on it).
- Metadata in a different endianness from the payload it describes is a
  standing source of exactly one bug, repeated: the reader that gets it right for
  the header and wrong for the data. One rule per file is worth more than one
  rule per tree.

**The cost, stated plainly: the tree now has two byte-order conventions**, and a
reviewer must know which document governs the bytes in front of them. The
mitigation is that the two never meet — a weight blob never travels over BSP
(BSP v2 §10.4: "the blob is not carried over BSP"), and a BSP record never
reaches the weight loader.

---

## 3. Layout

A blob is exactly three regions, in this order, with no other bytes:

```
┌──────────────────────────────────────────────────────────────┐
│ header            256 bytes, fixed, no variable-length field │  §5
├──────────────────────────────────────────────────────────────┤
│ tensor table      tensor_count × 160 bytes, fixed records    │  §3.2
├──────────────────────────────────────────────────────────────┤
│ pad to BXW1_ALIGN (zero bytes)                               │
├──────────────────────────────────────────────────────────────┤
│ tensor data       extents, ascending, disjoint, 128-aligned, │  §4
│                   separated only by zero pad < BXW1_ALIGN    │
└──────────────────────────────────────────────────────────────┘
```

**Every byte of the blob is accounted for** by one of those categories. A byte
that belongs to none of them is a DENY (§7.4 rules D8–D10). That is not
tidiness: an unaccounted region inside a declared blob is a smuggling channel
that the whole-blob digest would faithfully cover and never object to.

### 3.1 Header — fixed size, 256 bytes

Offsets are absolute from the first byte of the blob. Every field is
little-endian. `BXW1_HEADER_BYTES = 256`.

**Bytes 0–63 — format identity and layout**

| Off | Len | Type | Field | Required value / meaning |
|--:|--:|---|---|---|
| 0 | 4 | `[u8;4]` | `magic` | MUST equal ASCII `"BXW1"` (`0x42 0x58 0x57 0x31`) |
| 4 | 2 | `u16` | `version_major` | MUST equal `1`. Exact match, not a negotiation |
| 6 | 2 | `u16` | `version_minor` | MUST equal `0`. Exact match |
| 8 | 4 | `u32` | `flags` | Bit 0 = `BXW1_FLAG_TIED_OUTPUT` (§6.3). Bits 1–31 MUST be zero |
| 12 | 4 | `u32` | `tensor_count` | `1 ≤ tensor_count ≤ BXW1_MAX_TENSORS` |
| 16 | 8 | `u64` | `total_size` | Total blob bytes, header inclusive. MUST equal the object length the storage layer reports (§7.2 rule H7) |
| 24 | 8 | `u64` | `tensor_table_off` | MUST equal `256`. A fixed constant, restated in the file so a decoder can assert it; it is **not** a pointer to follow |
| 32 | 8 | `u64` | `tensor_data_off` | Byte offset of the first tensor extent. MUST be `BXW1_ALIGN`-aligned |
| 40 | 8 | `u64` | `tensor_data_len` | Total bytes of the tensor-data region, pads included |
| 48 | 8 | `u64` | `reserved_0` | MUST be zero |
| 56 | 8 | `u64` | `reserved_1` | MUST be zero |

**Bytes 64–95 — table integrity**

| Off | Len | Type | Field | Meaning |
|--:|--:|---|---|---|
| 64 | 32 | `[u8;32]` | `tensor_table_digest` | SHA-256 over the `tensor_count × 160` table bytes at offset 256. Verified before any record's contents are used for anything beyond bounds checking (§10.1 stage S4) |

**Bytes 96–159 — model metadata** — see §5 for meaning, units, and bounds.

| Off | Len | Type | Field |
|--:|--:|---|---|
| 96 | 4 | `u32` | `arch_id` |
| 100 | 4 | `u32` | `n_layers` |
| 104 | 4 | `u32` | `d_model` |
| 108 | 4 | `u32` | `n_heads` |
| 112 | 4 | `u32` | `n_kv_heads` |
| 116 | 4 | `u32` | `d_head` |
| 120 | 4 | `u32` | `d_ffn` |
| 124 | 4 | `u32` | `vocab_size` |
| 128 | 4 | `u32` | `max_seq_len` |
| 132 | 4 | `u32` | `rope_theta_bits` (IEEE-754 binary32 bit pattern) |
| 136 | 4 | `u32` | `norm_eps_bits` (IEEE-754 binary32 bit pattern) |
| 140 | 4 | `u32` | `rope_dim` |
| 144 | 4 | `u32` | `bos_token_id` |
| 148 | 4 | `u32` | `eos_token_id` |
| 152 | 4 | `u32` | `rope_pairing` — enumerated, §5.5. **No zero value and no default** |
| 156 | 4 | `u32` | `reserved_3` — MUST be zero |

**Bytes 160–199 — tokenizer binding** — see §5.4.

| Off | Len | Type | Field |
|--:|--:|---|---|
| 160 | 32 | `[u8;32]` | `vocab_digest` — SHA-256 of the tokenizer vocabulary blob |
| 192 | 8 | `u64` | `vocab_len` — that blob's exact byte length |

**Bytes 200–255 — `reserved_tail[56]`, every byte MUST be zero.**

The header is fixed-size with no variable-length field, so the decoder that reads
it is total: it requires exactly 256 bytes, reads exactly 256 bytes, and every
field is at a compile-time offset. `tensor_count` is the only field that governs
how much is read afterwards, and it is bounds-checked against a `const` before it
is used (§7.2 rule H5). 76 of the 256 bytes are reserved padding; against a
maximum blob that is a rounding error six orders of magnitude below anything
measurable, and it buys a decoder with no arithmetic in it.

**Reserved fields are not extension points.** A nonzero reserved field is a DENY,
not a forward-compatible unknown, and a nonzero undefined `flags` bit is a DENY
for the same reason. Like BSP v2 §5.5, BXW1 has no in-band evolution path: **a
v2 is a new magic and a new document.** The cost is stated: adding a dtype, a
rank, or a metadata field means a format version bump and a converter run over
every blob, not a flag.

**`rope_pairing` at offset 152 was `reserved_2` until 2026-08-03**, and the
change is recorded here rather than smoothed over. It is **not** an in-band
extension and does not weaken the paragraph above: v1.0 was unimplemented when
the field was defined (§11 — no loader, no converter, no blob has ever
existed), so this is an edit to the format *before* there is anything to be
compatible with, not a reserved byte being repurposed under a running system. A
reserved field is still never an extension point once a blob exists. The
consequence is deliberate and desirable: a hypothetical blob written against the
earlier draft carries `0x00000000` there, which §5.5 admits no meaning for, so
it **denies** rather than silently defaulting to one of the two conventions.
That is the correct outcome, and §5.5 explains why the alternative is worse than
a refused load.

### 3.2 Tensor table — one fixed record per tensor

`BXW1_TENSOR_RECORD_BYTES = 160`. Record `i` begins at
`256 + 160 × i`. All fields little-endian; offsets are relative to the record.

| Off | Len | Type | Field | Meaning and constraints |
|--:|--:|---|---|---|
| 0 | 64 | `[u8;64]` | `name` | NUL-terminated printable ASCII, NUL-padded to 64. `name[0] != 0`, `name[63] == 0`, all bytes after the first NUL are `0x00`, all bytes before it are in `0x21..=0x7E` (§7.3) |
| 64 | 2 | `u16` | `dtype` | `0x0000 = F32`, `0x0001 = Q8_0`. Any other value ⇒ DENY |
| 66 | 2 | `u16` | `rank` | `1 ≤ rank ≤ BXW1_MAX_RANK` |
| 68 | 4 | `u32` | `reserved_a` | MUST be zero |
| 72 | 32 | `[u64;4]` | `dims` | `dims[j]` for `j < rank` is the extent of axis `j`, **outermost first** (row-major). `dims[j]` for `j ≥ rank` MUST be zero |
| 104 | 8 | `u64` | `data_off` | Absolute byte offset of this tensor's payload. MUST be `BXW1_ALIGN`-aligned |
| 112 | 8 | `u64` | `data_len` | Payload byte length. MUST equal the length derived from `dtype` and `dims` (§4.3) — it is a cross-check, never a source of truth |
| 120 | 32 | `[u8;32]` | `digest` | SHA-256 over exactly `data_len` bytes at `data_off` |
| 152 | 8 | `u64` | `reserved_b` | MUST be zero |

Two properties of this record are load-bearing and are stated so they are not
optimized away:

- **`data_len` is redundant and is kept anyway.** It is fully derivable from
  `dtype` and `dims`. It is present so that the derived value and the declared
  value can be compared, which turns a shape/length disagreement into a
  detected DENY instead of a silent reinterpretation of the payload. The
  derived value is the one used; the declared value is only ever compared.
- **Records are validated in index order and the extents are required to be
  strictly ascending and disjoint** (§7.4). That requirement is what reduces
  overlap detection from a quadratic scan needing `BXW1_MAX_TENSORS` extents of
  scratch to a single forward pass carrying **one `u64`** of state. The cost is
  in §4.6.

`BXW1_MAX_TENSORS = 4096`, so the table is at most `4096 × 160 = 655,360` bytes
= **640 KiB**, which is the size of the loader's fixed table buffer. A
40-layer decoder-only model has 363 tensors (§6.2), so 4096 leaves room for
roughly 450 layers.

---

## 4. Data types

Exactly two: `F32` and `Q8_0`. **The cost of a two-dtype format is stated first,
because it is the largest cost in this document.** There is no `f16`, no `bf16`,
no `Q4`, `Q5`, or `Q6`. A model that would fit at 4-bit and does not fit at 8-bit
**cannot be served at all** — there is no fallback, and adding one is a format
version bump, a converter change, and new kernels in P3-T4. The bandwidth win
available to this format is the single 3.56× step from `F32` to `Q8_0` (§4.5),
and nothing beyond it. Open question 2 (§13) records the `bf16` case, which is
the most defensible third dtype and is deliberately not in v1.0.

### 4.1 `F32` (`dtype = 0x0000`)

IEEE-754 binary32, little-endian, one value per element, row-major over `dims`
with the last axis fastest-varying. `data_len = elements × 4`.

**Every element's bit pattern is validated** during the digest pass (§10.1 stage
S7): NaN, ±Inf, and subnormals DENY. See §4.7 for why subnormals are rejected.

### 4.2 `Q8_0` (`dtype = 0x0001`) — split-plane, 32-element blocks

`BXW1_Q8_0_BLOCK = 32` elements per block.

A `Q8_0` tensor's payload is **two contiguous planes**, not an interleaved
sequence of blocks:

```
data_off ─────────────► ┌───────────────────────────────┐
                        │ scale plane                   │  nblocks × 4 bytes
                        │   f32 scale[0..nblocks], LE   │
                        ├───────────────────────────────┤
                        │ zero pad to BXW1_ALIGN        │  0..127 bytes
quant_off ────────────► ├───────────────────────────────┤
                        │ quant plane                   │  nblocks × 32 bytes
                        │   i8 q[0..nblocks*32]         │
                        └───────────────────────────────┘
```

where

```
elements   = dims[0] × dims[1] × … × dims[rank-1]
nblocks    = elements / BXW1_Q8_0_BLOCK
scale_len  = nblocks × 4
quant_off  = data_off + round_up(scale_len, BXW1_ALIGN)
quant_len  = nblocks × 32
data_len   = round_up(scale_len, BXW1_ALIGN) + quant_len
```

**Blocks run along the last (fastest-varying) axis in row-major order.** Block
`b` covers linear element indices `b*32 .. b*32 + 32`. `dims[rank-1] MUST be a
multiple of 32` (§7.4 rule T9), so **no block ever straddles a row boundary**.
That is why the rule is on the last dimension rather than on the element count:
it is what lets a per-row dot product decompose into whole blocks, with no
partial-block branch anywhere in P3-T4's inner loop.

Given the storage convention of §6.1 — weight matrices are `[out_features,
in_features]`, row-major — this is exactly the requirement that
`in_features % 32 == 0`.

**Dequantization, normative:**

```
x[b*32 + j] = scale[b] × (f32) q[b*32 + j]        for j in 0..32
```

`q` is a two's-complement **signed** 8-bit integer, `scale[b]` is the
little-endian binary32 at `data_off + 4*b`. The multiply is a single f32
multiply; there is no zero point, no offset, no per-tensor scale, and no
asymmetry. A dequantized value is exactly representable as
`scale × q` with no rounding beyond the f32 multiply itself.

**Accumulation precision, normative.** A dot product over dequantized `Q8_0`
values **accumulates in f32**, and the block's scale is applied **once per
block, outside the 32 multiplies**:

```
acc = Σ_b  scale[b] × ( Σ_{j<32} (f32) q[b*32 + j] × x[b*32 + j] )
```

This is pinned rather than left to the kernel author because it is numerically
visible and because P3-T6's logits-parity reference has to make the same choice
or the parity test compares two different computations. f32 is specified — not a
wider accumulator — because it is what a NEON implementation does, so the scalar
and vector paths round identically and a vectorization pass cannot change
results. Factoring the scale out of the block is algebraically identical to
applying it per element and is *more* accurate, since the scale's rounding is
applied once per 32 terms instead of 32 times; it is also where a vector
implementation wants it. A wider block-level accumulator is permitted only if it
is used by every implementation including the parity reference.

**Quantization (the producer's side, not the loader's):** for each block,
`scale = max(|x_j|) / 127.0` and `q_j = clamp(round_ties_even(x_j / scale),
-127, 127)`. Using 127 rather than 128 keeps the quantized range symmetric, so
the reference producer never emits `-128`.

**The all-zero block, normative.** When `max(|x_j|) == 0` the formula above
divides by zero, so the producer's output is specified instead of derived: a
block whose every element is zero MUST be emitted as `scale = +0.0` (bit pattern
`0x0000_0000`) and 32 zero quants. That is the only assignment consistent with
§4.7, which explicitly admits exactly `+0.0` in the accepted scale set and would
otherwise admit a value no producer could ever legally emit. The consumer needs
no special case: `0.0 × q = 0.0` for every `q`, so the dequantization formula
above is already correct for such a block and no branch belongs in the inner
loop. A producer that emits a nonzero scale with all-zero quants is not
malformed — it dequantizes identically — but it is not the canonical encoding
and a converter MUST NOT produce it.

The loader nonetheless
performs **no validation on quant bytes at all**: all 256 bit patterns are valid
`i8`, and the dequantization above is well-defined for every one of them
including `-128`. This is the only field in the format that is unvalidated *by
construction* rather than by omission, and it is called out here so a reviewer
does not read its absence from §7 as a gap.

**Scale validation is mandatory** and is described in §4.7.

### 4.3 Derived length, exactly

Given a validated `dtype`, `rank`, and `dims`, the loader derives `data_len` and
compares it to the declared value. Every step is checked `u64` arithmetic (§7.6):

| dtype | `elements` | `data_len` |
|---|---|---|
| `F32` | `dims[0] × … × dims[rank-1]` | `elements × 4` |
| `Q8_0` | same | `round_up(elements/32 × 4, 128) + elements/32 × 32` |

A declared `data_len` that differs from the derived value in **either direction**
is a DENY. A shorter declaration would leave payload bytes unaccounted for; a
longer one would claim bytes belonging to the next tensor or past the blob.

### 4.4 Alignment

`BXW1_ALIGN = 128` bytes, and it applies to:

- `tensor_data_off` — the start of the tensor-data region;
- every tensor's `data_off`;
- the `Q8_0` quant plane's offset within its tensor, which is why the scale plane
  is padded up to a multiple of 128 rather than packed against it.

**Why 128 and not 16.** A NEON register is 128 **bits** = 16 bytes, so 16 would
be the minimum for aligned vector loads. 128 **bytes** is the reference machine's
cache-line size, and aligning to it means a tensor's first vector load does not
straddle a line and the whole payload tiles the cache hierarchy from a known
phase. The cost is at most 127 bytes of pad per tensor plus at most 127 per
`Q8_0` inter-plane gap: with `BXW1_MAX_TENSORS = 4096`, **at most 1,040,384
bytes ≈ 1 MiB of padding in the worst case**, which is 0.005% of
`BXW1_MAX_BLOB_BYTES`. Buying guaranteed alignment for 0.005% of the bandwidth
budget is not a close call.

**Alignment in the file must compose with alignment in memory, or it buys
nothing.** `WEIGHTS_REGION`'s base is page-aligned and the platform's base page
is 16 KiB; `16384 = 128 × 128`, so a 128-aligned blob offset yields a
128-aligned virtual address once the blob is placed at the region base. The
composition is stated because "aligned in the file" is not by itself a claim
about anything the kernels can use. This is the only place BXW1 depends on the
page size, and it depends on it as a **divisibility fact**, not as a literal —
the constant's home stays the aarch64 MMU module (`INV-MEM-009`).

**A declared offset that violates the alignment is a DENY of the whole blob,
before any mapping.** It is emphatically **not** rounded up. Rounding a
misaligned offset is the silent-corruption path: it would shift every subsequent
extent relative to the digests that were computed over the unshifted bytes, and
produce a model that loads, verifies, and computes wrong numbers.

### 4.5 The bandwidth arithmetic that chose Q8_0

The reference machine's published unified-memory bandwidth is **200 GB/s**
(Mac mini M2 Pro, `T6020`). That is a nameplate figure, not a measured one, and
the achievable fraction is lower and currently unmeasured; the ratios below are
therefore more trustworthy than the absolute rates.

Bytes per element: `F32` is exactly `4.000`; `Q8_0` is `(4 + 32)/32 = 1.125`
before pad and within 0.005% of that after it. **The ratio is 3.556×**, and on a
bandwidth-bound decode that ratio is the token-rate ratio directly.

| Model | dtype | Weight bytes | Fits in 22 GiB? | ms/token @ 200 GB/s | tok/s |
|---|---|--:|---|--:|--:|
| 7 B | `F32` | 28.0 GB | **no** | — | — |
| 7 B | `Q8_0` | 7.9 GB | yes | 39 | 25.4 |
| 13 B | `Q8_0` | 14.6 GB | yes | 73 | 13.7 |
| ~21 B | `Q8_0` | 23.6 GB | at the ceiling | 118 | 8.5 |

The first row is the whole argument: **a 7 B model does not fit on this machine
at `F32` and fits with 15 GB to spare at `Q8_0`.** Quantization here is not a
speed optimization layered onto a working system; it is the difference between
serving a mid-sized model and not serving one. That is why `Q8_0` is specified
with the same precision as the header rather than described loosely and left to
the kernel author — an ambiguity in §4.2 produces silently wrong numerics, not a
crash, and the parity test in P3-T6 is the only thing that would catch it.

### 4.6 What the split-plane layout costs

Stated because it is a real departure from the common practice of interleaving a
scale with its 32 quants:

- **A BXW1 blob is not a GGUF file and cannot be produced by renaming one.** A
  converter must de-interleave the planes. There is no zero-copy path from any
  existing quantized format, and no memory-mapping of a third-party file.
- **A dequant kernel carries two pointers instead of one.** In exchange it reads
  two purely sequential, 128-aligned streams that both hardware prefetchers and
  the load/store units handle well, instead of one stream with a 4-byte scalar
  every 36 bytes and no stable alignment phase. The scale plane also vectorizes
  on its own (`vld1q_f32` over four consecutive scales), which the interleaved
  layout forbids.
- **The last dimension must be a multiple of 32.** A model with, say,
  `d_model = 100` cannot store its projections as `Q8_0` at all; it must store
  them `F32`, at 3.556× the bytes, or not be served. In practice every dimension
  in the target model family is a multiple of 128, so this bites rarely and
  loudly rather than often and quietly.
- **Strictly ascending, disjoint extents forbid aliasing.** Two tensors can never
  share bytes. Where a model ties its output projection to its input embedding —
  the one common case where aliasing would be natural — the format expresses it
  with `BXW1_FLAG_TIED_OUTPUT` (§6.3) rather than with two records pointing at
  one extent. Any *other* form of weight sharing must be duplicated on disk; for
  a `[32000, 4096]` `Q8_0` matrix that is 147 MB per duplicate.

### 4.7 Float bit patterns are attacker-controlled, and are validated as integers

Four kinds of float reach the engine from the blob: `rope_theta`, `norm_eps`, the
`Q8_0` scales, and the `F32` elements. Every one of them is validated **as a
`u32` bit pattern, by integer comparison, before any of them is interpreted as a
float.** Comparing an unvalidated float is itself the bug: `NaN < x` and
`NaN > x` are both false, so a range check written with float comparisons accepts
NaN silently.

Let `s` be the little-endian `u32` bit pattern. The accepted set is:

```
s & 0x8000_0000 == 0                                   (sign bit clear)
AND ( s == 0x0000_0000                                 (exactly +0.0)
      OR (0x0080_0000 <= s && s <= 0x7F7F_FFFF) )      (positive normal, finite)
```

`0x0080_0000` is the smallest positive normal (2⁻¹²⁶); `0x7F7F_FFFF` is
`f32::MAX`; `0x7F80_0000` is `+Inf` and everything above it is `Inf` or `NaN`.
The rule therefore rejects **NaN, ±Inf, subnormals, negative values, and −0.0**
in a single pair of integer comparisons. `F32` **elements** use the same rule
except that the sign bit is unconstrained, since weights are legitimately
negative — for elements the accepted set is NaN-free, Inf-free, and
subnormal-free, sign ignored.

**Why subnormals are rejected, in a format that otherwise tolerates a lot.** On
aarch64 the flush-to-zero behaviour of subnormal operands is controlled by
`FPCR.FZ`, a register this specification does not fix and P3-T0 has not yet
settled. A format that admits subnormals therefore admits values whose meaning
depends on a control register — the same bytes give a different model depending
on how the FP context was configured. That is not a magnitude argument (a
subnormal scale multiplies quants of at most 127, so the block's values are
below 1.5 × 10⁻³⁶ either way and flushing them changes nothing anyone can
measure); it is a **determinism** argument, and determinism is what P3-T6's
logits-parity test against a host `F32` reference actually depends on. The cost:
a training checkpoint containing subnormals cannot be copied verbatim into a
BXW1 blob — the converter must flush them to zero, which is one line and must be
in the converter rather than discovered later as a parity failure.

**Validating every `F32` element is not free but is already paid for.** The
digest pass (§10.1 stage S7) reads every payload byte anyway; the bit-pattern
check rides on that read and adds arithmetic to a pass that is bandwidth-bound,
not compute-bound. For a `Q8_0`-dominated model the validated float volume is
just the scale planes — one ninth of the payload.

---

## 5. Model metadata

The transformer must run without any model constant compiled into it. Every
hyperparameter P3-T6 needs is a fixed-offset field of the header (§3.1, bytes
96–199) with the width given there. There is no separate metadata section, no
key-value store, and no string table — those would reintroduce variable-length
parsing into a header whose totality is the point.

### 5.1 Fields, meaning, and bounds

| Field | Width | Meaning | Accepted range |
|---|--:|---|---|
| `arch_id` | `u32` | Enumerated architecture family (§5.2) | MUST equal `1` |
| `n_layers` | `u32` | Number of transformer blocks | `1 ..= BXW1_MAX_LAYERS` |
| `d_model` | `u32` | Residual-stream width | `1 ..= BXW1_MAX_D_MODEL`, and `d_model == n_heads × d_head` |
| `n_heads` | `u32` | Query heads | `1 ..= BXW1_MAX_HEADS` |
| `n_kv_heads` | `u32` | Key/value heads (grouped-query attention) | `1 ..= n_heads`, and `n_heads % n_kv_heads == 0` |
| `d_head` | `u32` | Per-head width | `1 ..= BXW1_MAX_D_HEAD` |
| `d_ffn` | `u32` | Feed-forward inner width | `1 ..= BXW1_MAX_D_FFN` |
| `vocab_size` | `u32` | Token count | `1 ..= BXW1_MAX_VOCAB` |
| `max_seq_len` | `u32` | Maximum context length in tokens the weights support | `1 ..= BXW1_MAX_SEQ_LEN` |
| `rope_theta_bits` | `u32` | Binary32 bit pattern of the RoPE base θ | §4.7 rule, then `1.0e2 ≤ θ ≤ 1.0e8` |
| `norm_eps_bits` | `u32` | Binary32 bit pattern of the normalization ε | §4.7 rule, then `1.0e-8 ≤ ε ≤ 1.0e-1` |
| `rope_dim` | `u32` | Leading per-head dimensions RoPE rotates | `2 ..= d_head`, and `rope_dim % 2 == 0` |
| `rope_pairing` | `u32` | Which two components form a rotated pair (§5.5) | MUST be `1` or `2`. **No zero value, no default** |
| `bos_token_id` | `u32` | Beginning-of-sequence token | `< vocab_size` |
| `eos_token_id` | `u32` | End-of-sequence token | `< vocab_size` |

**`n_kv_heads` is the grouped-query attention parameter and is mandatory, not
optional.** `n_kv_heads == n_heads` expresses ordinary multi-head attention and
`n_kv_heads == 1` expresses multi-query attention, so there is one code path in
P3-T6 rather than three, and no "absent means equal to `n_heads`" default for a
decoder to get wrong. The group size `n_heads / n_kv_heads` is exact because
divisibility is enforced.

Three definitional points, stated only because leaving them implicit would make
the metadata ambiguous and P3-T4/P3-T6 would each guess:

- **`rope_theta` is the base**, in `θ_i = rope_theta^(−2i / rope_dim)` for
  `i` in `0 .. rope_dim/2`. It is not a precomputed frequency and not an inverse.
- **`norm_eps` is added to the mean square before the reciprocal square root**,
  i.e. inside the root, not to the root's result and not to the normalized
  output. The two conventions differ numerically and neither crashes.
- **`rope_dim < d_head` means the remaining dimensions pass through
  unrotated.** Components `rope_dim .. d_head` of every head are copied to the
  output unchanged. They are **not** zeroed and they are **not** rotated at a
  frequency extrapolated past `rope_dim`. This is what "leading per-head
  dimensions RoPE rotates" means, and it is stated because the alternative
  reading — zeroing the tail — also runs, also produces plausible output, and
  silently discards however much model capacity lives in those dimensions.
  `rope_dim == d_head` is the ordinary case and leaves no tail.

The operator semantics themselves — how RMSNorm, RoPE, softmax, SiLU, and the
SwiGLU composition are computed — belong to P3-T4 and P3-T6 and are **not**
defined here. This document defines only what the format's fields and shapes
mean, which is the minimum for those tasks to be unambiguous.

### 5.2 `arch_id`

| Value | Name | Meaning |
|--:|---|---|
| `1` | `BXW1_ARCH_DECODER_ROPE_GQA_SWIGLU` | Decoder-only transformer: pre-normalization RMSNorm, rotary position embedding, grouped-query attention, SwiGLU feed-forward, untied or tied output projection |
| any other | — | **DENY** |

`arch_id` selects the required tensor-name set of §6.2 and nothing else. The
cost is explicit: **the format describes one architecture family.** Encoder
stacks, mixture-of-experts routing, learned positional embeddings, and attention
biases cannot be expressed at all — not "are unsupported and ignored," but have
no field. A second family is a new `arch_id`, a new name set, and new kernels,
and it lands as an edit to this document.

### 5.3 Cross-checks against the tensor table

The header and the tensor table describe overlapping facts, so `INV-PARSE-004`
applies: **disagreement denies, with no precedence rule.** The loader does not
prefer the header over the shapes or the reverse; it refuses the blob.

| Header fact | Table fact that must agree |
|---|---|
| `vocab_size`, `d_model` | `tok_embeddings.weight` has `dims = [vocab_size, d_model]` |
| `vocab_size`, `d_model` | `output.weight`, when present, has `dims = [vocab_size, d_model]` |
| `n_heads × d_head`, `d_model` | `layers.{l}.attention.wq.weight` has `dims = [n_heads × d_head, d_model]` |
| `n_kv_heads × d_head`, `d_model` | `wk` and `wv` have `dims = [n_kv_heads × d_head, d_model]` |
| `d_model`, `n_heads × d_head` | `wo` has `dims = [d_model, n_heads × d_head]` |
| `d_ffn`, `d_model` | `w1` and `w3` have `dims = [d_ffn, d_model]`; `w2` has `dims = [d_model, d_ffn]` |
| `d_model` | every norm weight has `dims = [d_model]` |
| `n_layers` | exactly `n_layers` complete per-layer groups exist, indices `0 .. n_layers` with no gap and no extra |

### 5.4 Tokenizer binding — `vocab_digest` and `vocab_len`

**BXW1 does not carry the tokenizer vocabulary.** It carries a 32-byte SHA-256 of
it and its exact byte length. The vocabulary's own format is P3-T5's to define,
and its parser is separately Full tier
([`../security/SECURITY_INVARIANTS.md`](../security/SECURITY_INVARIANTS.md) §16,
"Tokenizer vocab parser").

The binding exists so that a model and its tokenizer **cannot be mismatched**.
Pairing model A's weights with model B's vocabulary is not a crash; it is a
system that runs and emits plausible nonsense, and it is the single most likely
operational mistake in provisioning a model. The loader:

- verifies the vocabulary blob's length equals `vocab_len` and its SHA-256 equals
  `vocab_digest`, before the tokenizer parses a byte of it;
- verifies the vocabulary's entry count equals `vocab_size` after P3-T5's parser
  reports it — a third source of the same fact, and a third `INV-PARSE-004`
  disagreement point;
- DENIES the whole load on any mismatch. A verified model with an unverified
  tokenizer is not served.

This is why P3-T5 depends on P3-T1: the binding, the digest, and the length live
here; the vocabulary's structure lives there.

### 5.5 `rope_pairing` — which two components form a rotated pair

*Added 2026-08-03 by owner decision, closing the ambiguity P3-T4 raised. Offset
152, formerly `reserved_2` — see §3.1 for why that is an edit to the format
rather than an in-band extension.*

`rope_dim` says how many leading per-head dimensions are rotated and `rope_theta`
says at what frequencies, but neither says **which two components form pair `i`**.
Two conventions are in wide use and they are not interchangeable:

| Value | Name | Pair `i` is | Used by |
|--:|---|---|---|
| `0` | — | **DENY.** There is no zero value and no default | — |
| `1` | `BXW1_ROPE_PAIR_INTERLEAVED` | `(x[2i], x[2i+1])` | Meta's reference LLaMA, which applies the rotation through a complex-number view of adjacent components |
| `2` | `BXW1_ROPE_PAIR_HALF_SPLIT` | `(x[i], x[i + rope_dim/2])` | The HuggingFace `rotate_half` formulation, which permutes Q and K at conversion time so the arithmetic comes out equivalent |
| any other | — | **DENY** | — |

In both cases the rotation itself is the same:

```
out[lo] = x[lo]·cos(a_i) − x[hi]·sin(a_i)
out[hi] = x[lo]·sin(a_i) + x[hi]·cos(a_i)
```

with `a_i = position × rope_theta^(−2i / rope_dim)`. Only the choice of
`(lo, hi)` differs, and `rope_pairing` is that choice.

**Why this is a format field and not an engine constant.** Which convention is
correct is a property of **the weight file** — it was fixed by whoever converted
the checkpoint, since the two differ by a permutation of the Q and K projection
rows — and not a property of the inference engine. A runtime that hardcodes
either one silently produces garbage on every model converted under the other.
Since BXW1 exists to let the transformer run with no model constant compiled
into it (§5's opening sentence), a hardcoded pairing would be exactly the kind
of constant the format is meant to eliminate.

**Why it is worth a whole `u32` in a header whose totality is the point.** The
failure mode is the worst class this format recognises: **it is silent, it
produces fluent and plausible output, and no unit test can detect it.** Position
0 is the identity rotation under both conventions; both are norm-preserving per
pair; both agree with any reference implementation that shares their assumption.
Every property a kernel test can check passes under either. The *only* thing
that distinguishes them is an end-to-end logits-parity comparison against a
known-correct implementation — which is P3-T6, arrives long after the model is
loaded, and is exactly the sort of late, expensive, whole-system check a
fail-closed header field is supposed to make unnecessary. Four bytes against a
22 GiB ceiling is not a close call; the cost is entirely in the paragraph above,
not in the blob.

**No default and no zero-value fallback, and this is the load-bearing clause.**
`rope_pairing == 0` is a DENY, not "assume interleaved". Absence of an explicit
grant is denial (NORTH_STAR "Fail closed"), and here the argument is unusually
concrete: a default would mean that the one case the field exists to
disambiguate — a converter that did not know about the field — is precisely the
case the field does not catch. An unrecognised value is a DENY for the same
reason (§7.2 rule H23), on the same footing as an unrecognised `arch_id`. There
is no relaxed mode, no "try both and pick the better perplexity", and no
operator override.

**The cost, stated plainly.** Every converter must now decide and record the
pairing, and it cannot be derived from the weights: the two conventions produce
byte-identical tensors and differ only in how the engine reads them. A converter
that guesses is exactly the failure this field exists to prevent, moved one
layer earlier — so the converter's obligation is to carry the value forward from
the source framework's own convention, never to infer it.

---

## 6. Tensor names and the required set

### 6.1 Storage convention

- **Row-major**, last axis fastest-varying, for every dtype.
- **Weight matrices are stored `[out_features, in_features]`.** A projection
  `y = W x` is then `out_features` dot products, each over a *contiguous* row of
  `in_features` values — the cache-friendly orientation, and the one in which a
  `Q8_0` row decomposes into whole 32-element blocks (§4.2). No tensor is stored
  transposed and there is no transpose flag; a producer that has the other
  orientation transposes at conversion time, once, rather than at every token.
- Vectors (norm weights) are `rank = 1`.

### 6.2 Required names for `arch_id = 1`

`{l}` is the layer index in **decimal with no leading zeros**, `0 .. n_layers`.
The canonical spelling is mandatory, which is what makes "duplicate name" (§7.3
rule T4) a complete check — two spellings of one layer are impossible.

**Global (3 tensors, or 2 when `BXW1_FLAG_TIED_OUTPUT` is set):**

| Name | Shape | Permitted dtypes |
|---|---|---|
| `tok_embeddings.weight` | `[vocab_size, d_model]` | `F32`, `Q8_0` |
| `norm.weight` | `[d_model]` | `F32` only |
| `output.weight` | `[vocab_size, d_model]` | `F32`, `Q8_0` — **absent iff** `BXW1_FLAG_TIED_OUTPUT` is set |

**Per layer (9 tensors × `n_layers`):**

| Name | Shape | Permitted dtypes |
|---|---|---|
| `layers.{l}.attention_norm.weight` | `[d_model]` | `F32` only |
| `layers.{l}.attention.wq.weight` | `[n_heads × d_head, d_model]` | `F32`, `Q8_0` |
| `layers.{l}.attention.wk.weight` | `[n_kv_heads × d_head, d_model]` | `F32`, `Q8_0` |
| `layers.{l}.attention.wv.weight` | `[n_kv_heads × d_head, d_model]` | `F32`, `Q8_0` |
| `layers.{l}.attention.wo.weight` | `[d_model, n_heads × d_head]` | `F32`, `Q8_0` |
| `layers.{l}.ffn_norm.weight` | `[d_model]` | `F32` only |
| `layers.{l}.feed_forward.w1.weight` | `[d_ffn, d_model]` | `F32`, `Q8_0` |
| `layers.{l}.feed_forward.w3.weight` | `[d_ffn, d_model]` | `F32`, `Q8_0` |
| `layers.{l}.feed_forward.w2.weight` | `[d_model, d_ffn]` | `F32`, `Q8_0` |

`w1` is the gate projection, `w3` the up projection, `w2` the down projection, in
the SwiGLU composition `w2( SiLU(w1 x) ⊙ (w3 x) )`. The names are fixed here so
P3-T6 resolves them from a compile-time table rather than from a naming
convention someone has to remember.

`tensor_count` MUST equal `3 + 9 × n_layers`, or `2 + 9 × n_layers` when the tied
flag is set. **The set is exact in both directions:** a missing tensor denies,
and an *extra* tensor — one whose name is not in the required set — also denies.
There is no "unknown tensor, ignore it" path, because a blob carrying tensors the
engine will not read is a blob whose bytes are unaccounted for at the semantic
level even though they are accounted for at the byte level (§3).

Longest required name: `layers.127.feed_forward.w2.weight`, 33 bytes, against a
64-byte field. The margin is deliberate and is not an extension point.

**Norm weights are `F32`-only.** They are `d_model` elements each — for a
40-layer, 5120-wide model that is 81 tensors × 20 KB = 1.6 MB, roughly 0.01% of
the blob — and they multiply an entire activation vector, so quantizing them
trades a rounding error across every element for a saving that does not appear
in the bandwidth arithmetic at all.

### 6.3 `BXW1_FLAG_TIED_OUTPUT`

Bit 0 of `flags`. When set, the output projection reuses `tok_embeddings.weight`
and `output.weight` MUST be absent; when clear, `output.weight` MUST be present.
Either violation denies.

This is how the format expresses weight tying **without aliasing**: one flag
rather than two records pointing at one extent. It preserves the strictly
ascending, disjoint-extent rule that makes overlap checking a single forward pass
(§3.2), and it is worth real bytes — for `[32000, 4096]` at `Q8_0` it saves
147 MB, which on a bandwidth-bound decode is 147 MB fewer read per token.

---

## 7. Hostile input — every attacker-controllable value and its required behaviour

This section is as important as the layout, and it is the section the fuzz and
Kani work of §12 is written against. Every value below arrives from disk and is
therefore attacker-controllable under the project's threat model. Every one is
bounds-checked **before use**, and every check's failure action is DENY.

### 7.1 What DENY means

DENY is a single, uniform action:

1. **Do not seal.** The weights region is not made read-only and not activated.
2. **Do not map.** No view of the region is handed to any other component, and
   nothing that would place a mapping runs after a denial.
3. **Zeroize.** If the copy of §10.1 stage S1 has already run, the whole region
   is zeroized before returning (`INV-MEM-006`, `INV-OBJ-002`). Residue of a
   rejected blob is not observable by the next load.
4. **Leave the previous generation alone.** A previously sealed, verified weight
   generation stays active and untouched — this is BSP v2 §12 row A5's "the
   previous weights stay active." **This holds for a load refused before the
   teardown of §10.5 begins.** Once a reload has torn the previous generation
   down there is nothing left to leave alone, and §10.5 states that cost rather
   than implying a rollback that the single fixed region cannot provide.
5. **Return an enumerated error** and emit exactly one audit event naming the
   rule that fired (§10.4). Never a partial success, never a warning, never a
   degraded mode (`INV-FAIL-003`).

There is exactly one failure action in this document. There is no
"Error-and-continue" class the way BSP has, because there is no session to keep:
a weight load either produces a fully verified generation or produces nothing.

### 7.2 Header rules

| # | Attacker-controlled value | Required behaviour |
|---|---|---|
| H1 | Object shorter than `BXW1_HEADER_BYTES` | DENY. The header decoder requires exactly 256 bytes and never reads a partial header |
| H2 | `magic` ≠ `"BXW1"` | DENY |
| H3 | `version_major` ≠ 1, or `version_minor` ≠ 0 | DENY. Exact match; not a negotiation and not a compatibility range |
| H4 | `flags` with any bit above bit 0 set | DENY. An undefined flag bit is an attack surface, not a forward-compatibility affordance |
| H5 | `tensor_count == 0`, or `> BXW1_MAX_TENSORS` | DENY **before** `tensor_count` is used in any arithmetic or to bound any read |
| H6 | `total_size < BXW1_HEADER_BYTES`, or `> BXW1_MAX_BLOB_BYTES`, or `> WEIGHTS_REGION` capacity | DENY (§8) |
| H7 | `total_size` ≠ the object length the storage layer reported | DENY, in **both** directions. A `total_size` smaller than the object leaves trailing bytes inside the digest-covered file that nothing accounts for; a `total_size` larger than the object is a read past the end. The storage-reported length is the authority; `total_size` is only ever compared to it |
| H8 | `tensor_table_off` ≠ 256 | DENY. It is asserted, never followed |
| H9 | `256 + tensor_count × 160` overflows, or exceeds `total_size` | DENY. Checked multiply and checked add; H5 makes the overflow unreachable and the check is still mandatory (§7.6) |
| H10 | `tensor_data_off` not `BXW1_ALIGN`-aligned, or less than the table end, or ≥ `total_size`, or more than `BXW1_ALIGN − 1` bytes past the table end | DENY. Never rounded (§4.4). The last clause bounds the pad between the table and the first extent to what alignment can justify; a larger gap is unaccounted space, exactly as D17 treats the gaps between extents |
| H11 | `tensor_data_off + tensor_data_len` overflows, or ≠ `total_size` | DENY. The tensor-data region must end exactly at the end of the blob |
| H12 | Any of `reserved_0`, `reserved_1`, `reserved_3`, `reserved_tail` nonzero | DENY |
| H13 | `arch_id` not in the enumerated set | DENY. No default and no "unknown architecture, try anyway" |
| H14 | Any hyperparameter zero, or above its `const` bound (§5.1) | DENY, each field independently, before any of them is multiplied by another |
| H15 | `n_heads % n_kv_heads ≠ 0`, or `n_kv_heads > n_heads` | DENY. GQA's group size must be exact |
| H16 | `n_heads × d_head` overflows, or ≠ `d_model` | DENY. Checked multiply |
| H17 | `rope_dim` odd, zero, or `> d_head` | DENY. RoPE rotates dimension pairs; an odd count has no meaning |
| H17a | `rope_pairing` not in `{1, 2}` | DENY (§5.5). **`0` is not a default and not "unspecified"** — it is the value a converter that never heard of the field writes, which is exactly the case the field exists to catch. No fallback, no operator override, and no "try both" |
| H18 | `rope_theta_bits` or `norm_eps_bits` failing the §4.7 bit-pattern rule, or outside its stated range | DENY. The bit-pattern class check runs **first**, as integer comparisons, so no float comparison is ever performed against a possible NaN |
| H19 | `bos_token_id` or `eos_token_id` `≥ vocab_size` | DENY |
| H20 | `vocab_len == 0`, or `> BXW1_MAX_VOCAB_BLOB_BYTES` | DENY |
| H21 | `BXW1_FLAG_TIED_OUTPUT` set and `output.weight` present, or clear and absent | DENY (§6.3) |
| H22 | `tensor_count` ≠ `3 + 9 × n_layers` (or `2 + 9 × n_layers` when tied) | DENY. Checked multiply |

### 7.3 Name rules (per record)

The 64-byte `name` field is the only string in the format, and a name is
**compared, never interpreted**. It is not a path, not a format string, not a
console-bound value, and not an index (`INV-MODEL-003`).

| # | Value | Required behaviour |
|---|---|---|
| T1 | `name[63] ≠ 0x00` | DENY. The terminator's presence is guaranteed by position, so no reader ever scans past the field looking for one |
| T2 | `name[0] == 0x00` (empty name) | DENY |
| T3 | Any byte after the first NUL is nonzero | DENY. Trailing bytes past the terminator are unreachable by any reader and are therefore a covert channel; requiring zero removes it |
| T4 | Any byte before the first NUL outside `0x21..=0x7E` | DENY. No control bytes, no space, no non-ASCII |
| T5 | A name equal to any earlier record's name | DENY. Duplicate names make resolution ambiguous, and a resolver that takes the first match silently ignores the second's bytes |
| T6 | A name not in the required set for `arch_id` (§6.2) | DENY. Unknown tensors are refused, not skipped |
| T7 | A required name absent from the table | DENY |

### 7.4 Shape, extent, and overlap rules (per record)

| # | Value | Required behaviour |
|---|---|---|
| D1 | `dtype` not in `{0x0000, 0x0001}` | DENY. No "unknown dtype, skip this tensor" |
| D2 | `dtype` not permitted for this name (§6.2) | DENY — norm weights are `F32`-only |
| D3 | `rank == 0`, or `> BXW1_MAX_RANK` | DENY |
| D4 | `dims[j] == 0` for any `j < rank` | DENY. A zero-extent tensor has no meaning and would make the element product zero, which would pass a naive length check |
| D5 | `dims[j] ≠ 0` for any `j ≥ rank` | DENY. Unused dimension slots carry no data |
| D6 | `dims[j] > BXW1_MAX_DIM` for any `j < rank` | DENY, per dimension, before the product is formed |
| D7 | The product `dims[0] × … × dims[rank-1]` | Folded left with **checked** multiplication; after **each** step the running product is checked against `BXW1_MAX_ELEMENTS`. Overflow ⇒ DENY. Running product above the cap ⇒ DENY. A per-dimension bound alone does **not** make the product safe: four dimensions each at `BXW1_MAX_DIM` is 2¹¹², which is not representable and would wrap (§7.6) |
| D8 | `dims[rank-1] % 32 ≠ 0` when `dtype == Q8_0` | DENY (§4.2) |
| D9 | Derived `data_len` (§4.3) overflowing at any step | DENY. Checked multiply and checked add throughout, including the `round_up` to `BXW1_ALIGN` |
| D10 | Declared `data_len` ≠ derived `data_len` | DENY, in both directions |
| D11 | `data_off % BXW1_ALIGN ≠ 0` | DENY, before any mapping. Never rounded (§4.4) |
| D12 | `data_off + data_len` overflowing | DENY. Checked add |
| D13 | `data_off < tensor_data_off`, or `data_off + data_len > total_size`, or `> tensor_data_off + tensor_data_len` | DENY. The extent is checked against the blob length **and** against the declared tensor-data region — both, because either alone leaves a way to point inside the header or the table |
| D14 | `data_off + data_len` exceeding the **reserved region** capacity | DENY (§8), checked in addition to D13, because the blob's own accounting agreeing with itself says nothing about whether it fits in memory |
| D15 | Record 0: `data_off ≠ tensor_data_off` | DENY. No unaccounted gap before the first extent |
| D16 | Record `i > 0`: `data_off[i] < data_off[i-1] + data_len[i-1]` | DENY. This is the overlap check, and because extents are required to be **strictly ascending**, it costs one `u64` of carried state and no scratch proportional to `tensor_count` |
| D17 | Record `i > 0`: `data_off[i] − (data_off[i-1] + data_len[i-1]) ≥ BXW1_ALIGN` | DENY. A gap larger than the maximum alignment pad is unaccounted space |
| D18 | The final extent's end, rounded up to `BXW1_ALIGN`, ≠ `total_size` | DENY. No unaccounted trailing region |
| D19 | Any pad byte — between the table and the first extent, between extents, or after the last — nonzero | DENY. Together with D15–D18 this is what makes "every byte of the blob is accounted for" (§3) a checked property rather than a description |
| D20 | `reserved_a` or `reserved_b` nonzero | DENY |

### 7.5 Content rules (checked during the digest pass)

| # | Value | Required behaviour |
|---|---|---|
| C1 | `tensor_table_digest` ≠ SHA-256 over the table bytes | DENY, **before** any record's contents are used beyond the bounds checks above |
| C2 | Any tensor's `digest` ≠ SHA-256 over its `data_len` bytes at `data_off` | DENY the **whole blob**, not the tensor. There is no partial activation |
| C3 | Any `Q8_0` scale failing the §4.7 rule | DENY |
| C4 | Any `F32` element that is NaN, ±Inf, or subnormal | DENY |
| C5 | Whole-blob SHA-256 ≠ the digest named by `LoadWeights` | DENY (§9.1) |
| C6 | Tokenizer blob length ≠ `vocab_len`, or its SHA-256 ≠ `vocab_digest` | DENY, before the tokenizer parses a byte |
| C7 | Vocabulary entry count (as reported by P3-T5's parser) ≠ `vocab_size` | DENY, with no precedence rule (`INV-PARSE-004`, §5.4) |
| C8 | Any §5.3 header/table shape disagreement | DENY, with no precedence rule |
| C9 | The detached Ed25519 signature over the whole-blob digest absent, malformed, or failing verification against the weights-signing public key | DENY (§9.2). Checked at S8 alongside C5, before the seal. A blob whose bytes are intact but whose signature does not verify is not served |

### 7.6 Arithmetic discipline

**All arithmetic over blob-supplied values is checked `u64` arithmetic. Nothing
saturates, nothing wraps, and a value that does not fit denies.**

- Every multiply is `checked_mul`, every add is `checked_add`, and every
  round-up-to-alignment is a checked add followed by a mask. `None` ⇒ DENY.
- Arithmetic is performed in `u64` and converted to `usize` **only after** the
  value has been proven `≤ WEIGHTS_REGION` capacity. The target's `usize` is 64
  bits; the specification does not rely on that, because a width assumption that
  happens to hold is still an unchecked assumption.
- The element-product fold (D7) checks the running value against
  `BXW1_MAX_ELEMENTS` after *each* multiply, not only at the end. That ordering
  is what bounds the next multiply: with the running product capped at 2³⁵ and
  each dimension capped at 2²⁸, the next product is at most 2⁶³, which is
  representable. **Overflow is therefore unreachable — and `checked_mul` is still
  mandatory**, because "unreachable" is an argument in a document and
  `checked_mul` is a property of the program. A Kani harness proves the former;
  only the latter survives a future edit to a bound.
- No signed arithmetic appears anywhere in the parse. There is no subtraction
  whose operands are not already ordered by a prior check (D16 orders them; D17
  and D18 subtract only after D16 has established the direction).

### 7.7 What a hostile blob cannot do

Stated as the positive form of the rules above, because it is the claim the
fuzz targets exist to falsify:

- It cannot cause an allocation. Every buffer is a compile-time-sized `static`.
- It cannot cause a read outside the region, because every extent is checked
  against both the blob length and the region capacity before it is read.
- It cannot cause a write outside the region, because the only write is the
  fixed-length copy of §10.1 stage S1, whose length comes from the storage layer
  and is checked against a `const` before the copy begins.
- It cannot cause the loader to loop unboundedly: the only loops are over
  `tensor_count` (≤ `BXW1_MAX_TENSORS`), over `rank` (≤ 4), and over payload
  bytes (≤ `BXW1_MAX_BLOB_BYTES`), and all three bounds are `const`.
- It cannot cause a panic, an arithmetic wrap, or an unchecked cast.
- It cannot activate partially. Verification completes for the entire blob before
  anything is sealed or mapped.

---

## 8. Bounds and `INV-MEM`

### 8.1 Constants

Every bound is a build-time `const`. The *values* are tunable against the final
boot memory budget; the *presence of a hard `const` bound on each* is not.

| Const | Value | Governs / rationale |
|---|--:|---|
| `BXW1_MAGIC` | `"BXW1"` | 4-byte format tag |
| `BXW1_VERSION` | `1.0` | major/minor, exact match |
| `BXW1_HEADER_BYTES` | `256` | fixed header; no variable-length field |
| `BXW1_TENSOR_RECORD_BYTES` | `160` | fixed tensor record |
| `BXW1_MAX_TENSORS` | `4096` | table bound; fixed table buffer is `4096 × 160` = **640 KiB** |
| `BXW1_MAX_RANK` | `4` | dimension slots per record |
| `BXW1_MAX_DIM` | `1 << 28` (268,435,456) | per-dimension bound, checked before the product |
| `BXW1_MAX_ELEMENTS` | `1 << 35` (34,359,738,368) | running-product bound; chosen so that even at `Q8_0`'s 1.125 bytes/element the derived length (38.7 GB) exceeds `BXW1_MAX_BLOB_BYTES` and is caught by the byte check — this cap bounds the multiply loop, it is not the operative limit |
| `BXW1_ALIGN` | `128` | tensor-data alignment; cache-line sized, divides the 16 KiB page (§4.4) |
| `BXW1_Q8_0_BLOCK` | `32` | elements per `Q8_0` block |
| `BXW1_MAX_BLOB_BYTES` | `22 GiB` = `23,622,320,128` | hard maximum blob size (§8.2) |
| `BXW1_MAX_LAYERS` | `128` | |
| `BXW1_MAX_D_MODEL` | `16384` | |
| `BXW1_MAX_HEADS` | `256` | bounds `n_heads` and `n_kv_heads` |
| `BXW1_MAX_D_HEAD` | `512` | |
| `BXW1_MAX_D_FFN` | `65536` | |
| `BXW1_MAX_VOCAB` | `1 << 20` (1,048,576) | |
| `BXW1_MAX_SEQ_LEN` | `1 << 17` (131,072) | weights-supported context; the *served* context is additionally bounded by the KV budget, which is P3-T2's |
| `BXW1_MAX_VOCAB_BLOB_BYTES` | `64 MiB` | tokenizer blob ceiling (§5.4) |
| `WEIGHTS_REGION` size | build-time, in **pages** | Owned by [`MEMORY_MODEL.md`](MEMORY_MODEL.md) §13 and P3-T2. BXW1 does not set it and does not contain a page-size literal |

### 8.2 Where 22 GiB comes from

The reference machine has **32 GiB** of unified memory
(34,359,738,368 bytes). The budget that produced the ceiling:

| Claimant | Size | Note |
|---|--:|---|
| `WEIGHTS_REGION` | **22 GiB** | `BXW1_MAX_BLOB_BYTES` |
| `KV_REGION` | 6 GiB | 8 sessions × 768 MiB, per BSP v2 §8's `MAX_SESSIONS = 8` |
| Kernel image, fixed pools, server images, stacks, direct map | 2 GiB | |
| Unallocated slack and firmware carve-outs | 2 GiB | |
| **Total** | **32 GiB** | |

At `Q8_0`'s 1.125 bytes per element, 22 GiB is **≈ 21.0 billion parameters**; at
`F32` it is ≈ 5.9 billion. The KV figure is illustrative and is P3-T2's to fix,
not this document's: 6 GiB across 8 sessions supports roughly a 4096-token
context for a 40-layer, 8-KV-head, 128-wide-head model at 16-bit KV
(160 KiB per token per session), and a change to `MAX_SESSIONS`, to KV
precision, or to the context length moves the weights ceiling in the opposite
direction. **The number in this table is therefore provisional and is open
question 3 (§13).**

The ceiling has a second meaning that is easy to miss: at 200 GB/s, a 22 GiB
model is ~118 ms per token, or ~8.5 tokens/second (§4.5). **`BXW1_MAX_BLOB_BYTES`
is a token-rate floor as much as a memory ceiling**, and a decision to raise it
is a decision to serve more slowly.

### 8.3 The region is reserved, never grown

Restating `INV-MEM` for this format, because it is the rule most likely to be
eroded by a plausible-sounding optimization:

- `WEIGHTS_REGION` is a **fixed reserved region sized at build time**, in pages,
  from the model the image is built to serve. It is not an arena, not a pool that
  can be extended, and not a mapping that can be grown on demand.
- **No quantity in a BXW1 blob ever sizes it.** `total_size`, `tensor_data_len`,
  and every `data_len` are compared against the region's capacity; none of them
  ever sets it, extends it, or selects a growth factor.
- A blob whose declared sizes exceed the region **denies before any mapping**
  (rules H6 and D14), and before the copy of §10.1 stage S1 begins. The
  storage-reported object length is checked against both `BXW1_MAX_BLOB_BYTES`
  and the region capacity at stage S0, so an oversized object is refused without
  a single byte being placed.
- Denial is an enumerated error, never a truncation, never a partial residency,
  and never a fallback to a smaller model (`INV-SCHED-004`, `INV-FAIL-003`).

**The cost, stated: there is no streaming, no paging, and no partial residency.**
A model larger than `WEIGHTS_REGION` cannot be served at any speed, and a blob
that fits on disk but not in memory is simply refused. On a bandwidth-bound
machine this is close to free — a model that had to be paged from storage per
token would be two orders of magnitude slower than the memory-bound ceiling, so
the capability being given up is one no one would use. It is given up for a
different reason: demand paging of weights would mean a fault path that maps
memory in response to model-driven addresses, which is an allocator wearing a
different hat.

---

## 9. Integrity, and what it does and does not prove

### 9.1 The three digests, and what each is for

| Digest | Covers | Where it lives | What it is for |
|---|---|---|---|
| Per-tensor `digest` | Exactly `data_len` bytes at `data_off` | Tensor table record (§3.2) | Failure **localization**, and the ability to re-verify one tensor later without re-reading the whole blob |
| `tensor_table_digest` | `tensor_count × 160` table bytes | Header (§3.1) | Prevents a corrupt table from silently relabelling correct data — a record whose name, shape, or extent has changed no longer matches |
| Whole-blob digest | Bytes `0 .. total_size`, header inclusive | **Not in the file** — named by `LoadWeights` (BSP v2 §10.4) | Selects *which* generation is being loaded, and covers every byte the two digests above cover plus the header and the table |
| Detached Ed25519 signature | The 32-byte whole-blob digest | **Not in the file** — a sidecar beside the blob on storage (§9.2) | The **integrity anchor**: it is what makes the whole-blob digest a value the project vouched for rather than a value the caller asserted |

**Be precise about what the per-tensor digests add.** They add no integrity
*strength* over the whole-blob digest, which already covers every byte they
cover plus the header and the table. What they add is: localization (which
tensor is wrong, not merely that something is), independent re-verification
without a 22 GiB re-read, and a self-describing table in which the shape and the
bytes are bound to each other. Overstating them — presenting `N` digests as `N`
independent integrity checks — would be exactly the kind of unfalsifiable claim
NORTH_STAR's "every claim is falsifiable" forbids.

**The header is the file's trust root and is covered by nothing inside the
file.** A digest of the header cannot be in the header. What covers it is the
whole-blob digest, which lives outside the file entirely — and what covers *that*
is the signature of §9.2.

### 9.2 The weights are a separately signed artifact

**Specified 2026-08-03 by owner decision, closing open question 1. No part of
this is implemented — see §11.**

The weights blob is to carry **its own Ed25519 signature**, over the 32-byte
whole-blob digest, produced by the same signing process and verified by the same
verify-only stack the release signature uses
([`../operations/RELEASE_AND_SIGNING_POLICY.md`](../operations/RELEASE_AND_SIGNING_POLICY.md)
§11). It is a **detached sidecar** stored beside the blob; nothing about it goes
inside the BXW1 file, which is why the format above gains no field for it and no
version bump. `modeld` verifies it at stage S8 (rule C9), before the seal and
before `inferd` exists.

So the chain is:

```
Ed25519 release signature ──► payload (kernel + servers)          [signed]
                                    │
                                    │  runs
                                    ▼
                              admin session, CapAdmin              [authenticated by PSK]
                                    │
                                    │  LoadWeights{weights_digest[32]}
                                    ▼
Ed25519 weights signature ──► modeld ──► whole-blob SHA-256        [verified, then compared]
                                    │
                                    ▼
                              per-tensor SHA-256, table SHA-256    [localization]
```

**The weights are deliberately *not* folded into the release signature**, which
was the alternative open question 1 posed. Signing the kernel image over the
model's digest would make the published image model-specific — one image per
model, a rebuild and a re-signature to swap models — and that weakens INV-BOOT's
**reproducible-build clause**, which is the one clause of INV-BOOT that still
holds in full on the only platform (NORTH_STAR, *INV-BOOT is the Apple boot
posture*). Trading the last undegraded clause of a headline invariant for
coverage that a second signature provides directly is not a trade worth making.

**The two signatures are independent.** They cover different artifacts and are
verified at different times by different components — the release signature at
build/verification time over the payload, the weights signature by `modeld` at
load time over the blob digest. Compromise of one key does not imply the other:
a forged weights signature yields a wrong model on a genuine kernel, and a
forged release signature yields a compromised kernel that can ignore weight
verification entirely. Neither substitutes for the other, and neither may be
described as covering the other.

**What this fixes, and what it does not.** It removes the anchor's dependence on
the admin credential *alone*: previously the whole-blob digest was a 32-byte
value asserted by an authenticated `CapAdmin` session and nothing else, so anyone
holding the disk held the admin credential — the credential store is **plaintext
at rest, permanently** (`INV-BOOT-006`, BSP v2 §2.4) — and could therefore name
any digest they liked over any blob they liked. With a signature required, naming
a digest selects among *signed* generations; it no longer confers the ability to
mint one. The plaintext-at-rest exposure itself is unchanged and is not BXW1's to
fix, and an attacker who already controls the kernel is out of reach of this or
any other in-kernel check (§9.3 item 3).

### 9.3 What integrity checking does **not** prove

Six things, stated because each of them is a claim someone will otherwise read
into a verified digest:

1. **It does not prove the weights are the intended model.** It proves they match
   a digest someone supplied, and — once §9.2 is built — that the digest was
   signed by the weights-signing key. Neither says the operator named the
   generation they meant to: any *signed* blob is a fully verified load, so a
   `LoadWeights` naming last quarter's model succeeds completely.
2. **It does not prove the model is safe.** A correctly digested model is still a
   confined tenant, still adversary-influenced by design, and still subject to
   `INV-MODEL-001`'s three-capability manifest and `INV-MODEL-004`'s adversarial
   confinement suite. Integrity and trustworthiness are unrelated properties;
   the served model's outputs remain hostile bytes (`INV-MODEL-003`).
3. **It does not detect an attacker who already controls the kernel.** The
   measurement-log entry recording the load is **self-reported**, is a debugging
   and accidental-corruption aid, and is never evidence
   (`INV-BOOT-AS-002`). This is the same limit `INV-MODEL-002` already states.
4. **It attests nothing to a remote party.** There is no quote, no sealing, and
   no hardware-anchored measurement on this platform, and none can be added
   (`INV-BOOT-AS-001`). A client cannot learn which weights are loaded, and no
   field in this format or in BSP may be added to imply otherwise.
5. **It does not survive a writable region.** The verification of §10.1 is sound
   only because the region is exclusively owned by the loader while writable and
   sealed read-only before anyone else sees it. If a weights page could become
   writable after the seal, every digest above would be a time-of-check value
   with a time-of-use gap behind it. That seal is P3-T2's Kani obligation
   ("weights-never-writable-post-seal"), and **BXW1's integrity claim is
   conditional on it** — if that proof is not discharged, this section's claims
   weaken accordingly, and saying so is the point.
6. **It does not bound numerical correctness.** A blob can pass every check here
   and still produce wrong logits if the dequantization in §4.2 is implemented
   against a different convention. That is what P3-T6's parity test against a
   host `F32` reference exists to catch, and it is why §4.2 is specified to the
   bit rather than described.

---

## 10. Load sequence (normative ordering)

### 10.0 The component that runs this sequence: `modeld`

**Specified 2026-08-03 by owner decision, closing open question 6. Nothing in
this subsection is implemented — see §11.**

The stages of §10.1 are to be executed by **`modeld`**, a one-shot server that
runs to completion and **exits before `inferd` launches**. It is named here
because a load sequence with no named executor is a sequence nobody owns, and
because `INV-MODEL-001` forbids `inferd` from being that executor: `inferd`'s
manifest is exactly `{Model, its serving endpoint, its own KV slice}`, and none
of the three can read a byte from storage.

`modeld`'s manifest is to be **exactly three capabilities**, and the
authoritative statement of it is
[`../security/SECURITY_INVARIANTS.md`](../security/SECURITY_INVARIANTS.md) §14.
Each is load-bearing for a specific stage below:

| Capability | The stage that cannot run without it |
|---|---|
| `CapEndpoint` to the storage server (`devd-ans2`) | **S0** obtains the object's byte length and **S1** reads its bytes; **S9** reads the tokenizer vocabulary blob. This is the capability `INV-MODEL-001` denies `inferd`, so some principal must hold it and it must not be `inferd` |
| `CapMemory` over `WEIGHTS_REGION` — writable, never executable | **S1** writes the region and **S10** requests the seal. Held **exclusively** while the region is writable (`INV-MEM-005`), which is what makes S7's single validation pass sound |
| `CapEndpoint` to `auditd`, send-only | **S11**'s audit event (§10.4, `INV-AUD-001`, `INV-SERVE-005`) |

No new `CapabilityType` discriminant is required: both are existing types
([`CAPABILITY_MODEL.md`](CAPABILITY_MODEL.md) §2) named over different objects.

**Lifetime is half of the confinement.** `modeld` exits at S11, so the storage
capability and the writable-weights capability exist in **no running process**
while the system is serving. It holds no `CapServe`, no `CapModel`, no
`CapAdmin`, no network capability, and no spawn authority: it cannot accept a
connection, is not reachable from any client session, and cannot release a seal
— unsealing is a kernel operation (§10.5).

**The rejected alternative, recorded because it is the one that will be
proposed again.** The other way to close this gap is to grant `inferd` a fourth
capability and let it read the blob itself. That is a degradation of
`INV-MODEL-001` — an invariant whose entire content is the number three — and
would need the written sign-off NORTH_STAR's exceptions ledger requires. It also
widens the wrong component: `inferd` is long-lived, reachable through `servd`,
and adversarially prompted by design, so a storage capability in its manifest is
reachable for the whole life of the system by exactly the party the confinement
exists to stop. A **separate principal, bounded in scope** (three capabilities,
none of them serving) **and in lifetime** (exits before the first request) is
the capability-native answer. It costs one more server image instead of one more
capability on the tenant.

`modeld` is **Full tier** — it parses a hostile blob. The tier and its reason
are recorded in
[`../security/SECURITY_INVARIANTS.md`](../security/SECURITY_INVARIANTS.md) §16,
which is the sole authoritative tier table; this document restates neither.

### 10.1 Stages

The order is normative. Two placements are load-bearing and are noted where they
occur.

| Stage | Action | On failure |
|---|---|---|
| **S0** | Obtain the object's byte length `L` from the storage layer. Check `L ≥ 256`, `L ≤ BXW1_MAX_BLOB_BYTES`, `L ≤ WEIGHTS_REGION` capacity. `L` is itself foreign data — the storage server's response is a hostile-input parser in its own right — so it is bounds-checked against `const`s before any use | DENY, **no copy** |
| **S1** | Copy exactly `L` bytes from storage into the region. **The copy length is `L`, from the storage layer — never `total_size`, which has not been read yet and is a blob-supplied number.** This is the placement that matters: the only write into the region is bounded by a quantity checked against a `const` in S0 | DENY, zeroize |
| **S2** | Parse and validate the header from **region bytes** (§7.2, rules H1–H22) | DENY, zeroize |
| **S3** | Derive the table extent; check overflow and containment (H9) | DENY, zeroize |
| **S4** | Compute SHA-256 over the table bytes and compare to `tensor_table_digest` (C1). **This precedes any use of record contents beyond bounds checking** | DENY, zeroize |
| **S5** | Validate every record in index order, carrying one `u64` of extent state (§7.3, §7.4) | DENY, zeroize |
| **S6** | Resolve the required name set for `arch_id`; check completeness, exactness, and every §5.3 shape cross-check (T6, T7, C8) | DENY, zeroize |
| **S7** | One pass over the payload: compute the whole-blob SHA-256 and every per-tensor SHA-256, validate every `Q8_0` scale and every `F32` element bit pattern, and verify every pad byte is zero (C2, C3, C4, D19) | DENY, zeroize |
| **S8** | Compare the whole-blob digest to the digest named by `LoadWeights` (C5), **and** verify the detached Ed25519 signature over that digest against the weights-signing public key (C9, §9.2) | DENY, zeroize |
| **S9** | Verify the tokenizer blob's length and digest, then its entry count against `vocab_size` (C6, C7) | DENY, zeroize |
| **S10** | **Seal** the region read-only and non-executable | — |
| **S11** | Emit the audit event (§10.4) and **exit**. The sealed read-only view is what `inferd` receives in its manifest when it launches afterwards (§10.2) | — |

**Everything is parsed from region-resident bytes, exactly once.** Parsing the
storage object first and copying afterwards would create a time-of-check/
time-of-use gap: nothing lets the loader assume the storage object is immutable
between the two reads. Copying first and validating the resident copy removes
the gap entirely and costs nothing, because the copy's length never depended on
the file's own claims.

**The seal at S10 is what makes S7's verification durable.** Before it, the
region is writable and exclusively `modeld`'s — no other component holds a
capability naming it (`INV-MEM-005`). After it, no path makes a weights page
writable again. The window in which verified bytes could change is therefore
empty by construction rather than by timing.

### 10.2 What `inferd` receives

`inferd` launches **after `modeld` has exited**. It receives a **read-only,
non-executable** view of the sealed region, plus its existing three capabilities
(`INV-MODEL-001`). The load grants nothing new (`INV-FAIL-002`). `inferd` never
holds a writable weights capability at any point in its life, and it never holds
a storage capability at all.

### 10.3 The second parser, and why it is not redundant

`inferd` must resolve tensor names to extents in order to run, so it re-parses
the header and the tensor table from the sealed region. This is a **second
Full-tier parser over the same bytes**, and §16's first corollary is why it does
not inherit `inferd`'s Reduced tier.

**It MUST re-run the structural validation of stages S2–S6 and MUST NOT assume
the loader ran.** The two parsers may be built from different code, may diverge
across versions, and the second one's correctness must not rest on an assumption
about the first. This is exactly the check that gets deleted as redundant during
a later cleanup, so it is written down as a requirement rather than left as good
practice.

It **may** skip the digest recomputation of S7, and the reason it may is precise
and conditional: the region is sealed read-only, so the bytes it reads are the
bytes the loader verified. **If the seal obligation is not discharged, the skip
is unsound** and S7 must be repeated. The soundness of the cheap path is
therefore a consequence of P3-T2's Kani proof and of nothing else.

### 10.4 Audit

One event per load attempt, to `auditd` (`INV-AUD-001`, `INV-SERVE-005`),
carrying: the outcome, the whole-blob digest, `total_size`, `tensor_count`,
`arch_id`, and — on failure — the identifier of the rule that fired. It carries
**no weight bytes, no tensor contents, and no scale values**. Observing a load
grants no authority (`INV-AUD-002`).

### 10.5 Replacing an active generation — a reboot-class operation

**Specified 2026-08-03 by owner decision, closing open question 5. The mechanism
is P3-T2's and P2-T14's, not this document's, and none of it is implemented
(§11).**

A second `LoadWeights` naming a different digest is **a new generation, not a
mutation of the current one**. No sealed page ever becomes writable again;
instead the whole serving stack is torn down and rebuilt:

1. All sessions end and `inferd` terminates. There is no live reader of the
   region left.
2. The region is zeroized (`INV-MEM-006`, `INV-OBJ-002`) and the seal is
   released as a **kernel** operation that neither `inferd` nor `modeld` can
   invoke. Releasing a seal is not a permission change on a mapping held by a
   running process; the generation the mapping belonged to no longer exists.
3. `modeld` runs again from S0 against the newly named digest, and exits.
4. `inferd` launches against the new sealed generation.

The sealed state is therefore per generation, not per boot, which is the only
reading consistent with both `MEMORY_MODEL.md` §13's "after sealing there is no
code path that can make a weights page writable again" and BSP v2's expectation
that `LoadWeights` is issuable more than once. **A generation is destroyed and
replaced; it is never edited.**

**Two costs, stated.** First, this is *not* a hot swap: every session in flight
is terminated, and BSP v2 §10.4 says so in the verb's own semantics so that no
client can read it as one. Second — and this supersedes §7.1 item 4 for the
reload case specifically — because `WEIGHTS_REGION` is single and fixed, the
previous generation is already gone by the time the new blob is verified. A
reload whose blob DENIES therefore leaves the machine with **no active
generation** and unable to serve until a `LoadWeights` naming a verifying digest
succeeds. §7.1 item 4's "the previous generation stays active" holds for a load
that is refused *before* teardown begins; it cannot hold across a teardown, and
claiming otherwise would require a second region the memory budget (§8.2) does
not have.

---

## 11. Implementation status — what does not exist

Recorded because NORTH_STAR requires that an unbuilt control never be described
in the present tense, and because a specification written in normative voice
otherwise reads like a description of a running system. **As of 2026-08-03, none
of BXW1 is implemented:**

- There is no BXW1 loader. P3-T3 is unstarted, and its dependencies P3-T1 (this
  document) and P3-T2 (the reserved regions) are respectively this document and
  unstarted.
- **There is no `modeld`.** §10.0 is a specification of a server that does not
  exist: no `src/servers/modeld/`, no manifest, no launch ordering, and nothing
  that runs before `inferd` because there is no `inferd` either. P3-T3a is
  unstarted.
- **The weights signature of §9.2 does not exist.** Nothing signs a weight blob,
  no sidecar format is produced by any tool, no weights-signing key exists, and
  no verification path calls the Ed25519 stack on anything but a release
  signature. Rule C9 and stage S8's signature clause describe required behaviour
  of unwritten code.
- **The reboot-class reload of §10.5 does not exist**, in either half: there is
  no teardown sequence, no kernel unseal operation, and no `LoadWeights`
  dispatch to invoke either (P2-T14 is unstarted).
- **`WEIGHTS_REGION` does not exist.** `memory/virtual_address_layout.rs` and
  `physical_allocator.rs` have no weights region and no KV region; P3-T2 adds
  them. Every sizing figure in §8.2 is therefore a proposal, not a measurement.
- **The seal does not exist.** "Read-only after load" and
  "weights-never-writable-post-seal" are P3-T2 Kani obligations that have not
  been written, and §9.3 item 5 states what BXW1's integrity claim loses if they
  are not discharged.
- **The tensor kernels exist** (P3-T4, `src/tensor`, 2026-08-03): the §4.2
  dequantization, the §5.1 hyperparameter meanings, and the §5.5 pairing are
  implemented and host-tested. What is still unbuilt around them: they are
  **scalar soft-float, not NEON** (P3-T0 has not landed and the context switch
  does not preserve vector state), nothing has ever fed them a real blob
  because there is no loader, and **the split-plane layout's claimed advantage
  over interleaving remains an argument rather than a measurement** — no
  BraiNIX code has run on the reference machine.
- There is no tokenizer and no vocabulary format. P3-T5 is unstarted, so
  `vocab_digest` binds to a format that is not yet specified.
- There is no `inferd`, no transformer forward pass, and no parity test. The
  numerical consequences of §4.2 and §5.1 are therefore unverified.
- **`LoadWeights` fails closed today and will until P3-T3 lands** — BSP v2 §10.4
  says so explicitly, and BSP v2 itself is unimplemented in full.
- `sha2` is still vendored; the in-tree SHA-256 this format depends on has not
  been written.
- No fuzz target, Kani harness, Prusti contract, or test vector from §12 exists.
- **The 200 GB/s bandwidth figure is Apple's published number, not a measurement
  taken on the reference machine.** Every tokens-per-second figure in §4.5 and
  §8.2 is derived from it and inherits its uncertainty. No BraiNIX code has ever
  run on the machine.

Nothing in §§1–10 may be cited as an implemented control until the corresponding
line above is struck.

---

## 12. Verification obligations (Full tier)

The BXW1 loader is **Full tier**
([`../security/SECURITY_INVARIANTS.md`](../security/SECURITY_INVARIANTS.md) §16),
which means all six artifacts: invariant mapping (§1), fuzz target, Kani
harness, Prusti contracts, security audit report, and no-regression bars. P3-T9b
requires the loader to be green under fuzz soak and Kani **independently**, with
no component permitted to pass on another's evidence.

**Fuzz targets** (libFuzzer/AFL, host, `#![no_std]`-compatible harness):

1. **Header decoder** — arbitrary bytes into stages S2–S3. Assert: never panics,
   never allocates, never reads past the 256-byte header buffer, and reaches S4
   only when every H-rule passes.
2. **Tensor-table decoder** — arbitrary table bytes with a valid header. Assert:
   total over all inputs, no out-of-bounds read, no arithmetic wrap, and no
   extent accepted that overlaps, misaligns, leaves a gap, or exceeds either the
   blob length or the region capacity.
3. **Whole-blob decoder** — arbitrary blobs end to end. Assert: exactly one of
   {sealed generation, DENY} results; no partial activation is reachable; every
   DENY path zeroizes the region.
4. **Metadata validator** — arbitrary 160-byte metadata blocks. Assert: no float
   is compared before its bit pattern is classified, and no NaN, Inf, subnormal,
   or out-of-range value reaches a consumer.

**Kani harnesses:**

1. Every §2 reader is total and bounds-checked for all inputs.
2. The element-product fold (D7) neither wraps nor exceeds `BXW1_MAX_ELEMENTS`
   for any `rank ≤ 4` and any `dims` — the property §7.6 argues informally.
3. The derived-length computation (§4.3) neither wraps nor disagrees with the
   layout of §4.2, for all valid `dtype`/`dims`.
4. No reachable path sizes, extends, or indexes a buffer from a blob-supplied
   length, offset, or count — the `INV-SERVE-002`-analogue proof obligation.
5. The extent walk (D15–D18) accepts a table **iff** its extents are ascending,
   disjoint, `BXW1_ALIGN`-aligned, gap-free beyond the pad bound, and exactly
   cover `tensor_data_off .. total_size`.
6. The load reaches "sealed" **iff** every rule in §7 passes, for all inputs; and
   every DENY path zeroizes the region and leaves any previous generation
   untouched.
7. No path makes a sealed weights page writable or executable — jointly owned
   with P3-T2, and the proof §9.3 item 5 depends on.

**Property tests:**

1. **Dequantization round-trip** — for random `F32` tensors, quantize with the
   §4.2 producer formula and dequantize with the §4.2 consumer formula; assert
   the error bound holds per block and that the split-plane and a reference
   interleaved implementation agree bit-for-bit.
2. **Alignment composition** — for every accepted blob, every tensor's virtual
   address in the region is `BXW1_ALIGN`-aligned, at both 16 KiB and 4 KiB base
   pages (`INV-MEM-009`; the frozen x86-64 reference is the only remaining
   second data point).
3. **Corruption localization** — flipping one bit anywhere in the blob causes a
   DENY, and when the bit is inside a tensor extent the reported rule is C2 and
   the reported tensor is the right one.
4. **No residue** — after a DENY at each of stages S2 through S9, the region
   reads as all zeros.

**Test vectors:** a fixed set of small blobs — one minimal valid `F32` model, one
minimal valid `Q8_0` model, one tied-output model, and one blob per rule in §7 —
checked into the tree, so the converter and the loader are checked against the
same bytes rather than against each other.

---

## 13. Open questions for the owner

1. ~~**Does the release signature cover the weights?**~~ — **RESOLVED
   2026-08-03: no, and it never will.** The weights are a **separately signed
   artifact** with their own Ed25519 signature over the whole-blob digest,
   verified by the existing verify-only stack (§9.2, rule C9, stage S8,
   [`../operations/RELEASE_AND_SIGNING_POLICY.md`](../operations/RELEASE_AND_SIGNING_POLICY.md)
   §11). Folding the weights into the release signature was rejected because it
   makes the published kernel image model-specific and weakens INV-BOOT's
   reproducible-build clause — the one clause that still holds in full on the
   only platform. The two signatures are independent; compromise of one does not
   imply the other.
2. **A third dtype for the embedding and output matrices?** `bf16` is the
   strongest candidate: it halves those two tensors relative to `F32` with no
   block structure, no scales, and an almost-free conversion on aarch64. For a
   `[32000, 5120]` pair that is roughly 655 MB saved against `F32`, which is
   ~4% of a 13 B model's bytes and therefore ~4% more tokens/second. **The cost
   is a third code path in every kernel that touches those tensors** and a
   format version bump. v1.0 deliberately does not have it.
3. **`BXW1_MAX_BLOB_BYTES = 22 GiB`.** This is derived from a KV budget (6 GiB
   across 8 sessions) that P3-T2 has not fixed and that depends on
   `MAX_SESSIONS`, KV precision, and the served context length — every one of
   which moves the weights ceiling in the opposite direction. Needs the real boot
   memory budget to finalize. Note the second consequence: raising the ceiling
   lowers the token rate (§8.2).
4. **Where does the vocabulary blob live?** §5.4 binds it by digest and leaves it
   beside the weights. The alternative is carrying it inside BXW1 as a third
   region, which would make the model and tokenizer one object and one digest —
   at the cost of putting a non-tensor, variable-structure payload inside a
   format whose totality comes from having none. Confirm the split, and confirm
   that the vocabulary arrives by the same out-of-band path as the weights (BSP
   v2 §15 question 4, still open there).
5. ~~**The weight-generation lifecycle.**~~ — **RESOLVED 2026-08-03:
   `load-weights` is a reboot-class operation.** A reload is a **new generation,
   not a mutation**: the serving stack is torn down, `modeld` re-runs, `inferd`
   restarts, and no sealed page ever becomes writable again (§10.5, BSP v2
   §10.4). The seal is per generation, not per boot. The transition mechanism is
   assigned to **P3-T2** (the kernel-side unseal-and-zeroize of a destroyed
   generation) and **P2-T14** (the server-side dispatch that orders the
   teardown). The `CapAdmin` verb set is unchanged at six — this changes what
   `load-weights` *means*, not the set.
6. ~~**Who runs the loader?**~~ — **RESOLVED 2026-08-03: `modeld`**, a one-shot
   server holding exactly `{CapEndpoint→devd-ans2, writable CapMemory over
   `WEIGHTS_REGION`, CapEndpoint→auditd}`, which populates and seals the region
   and **exits before `inferd` launches** (§10.0; manifest in
   [`../security/SECURITY_INVARIANTS.md`](../security/SECURITY_INVARIANTS.md)
   §14; tier in its §16). Granting `inferd` a fourth capability was **rejected**:
   it degrades `INV-MODEL-001` and widens the long-lived, remotely reachable,
   adversarially prompted component. A separate principal bounded in scope and
   lifetime is the capability-native answer.
7. **Is `BXW1_MAX_RANK = 4` enough?** It covers every tensor in §6.2, all of
   which are rank 1 or 2, with two ranks of headroom. A mixture-of-experts
   variant would want a rank-3 expert-stacked weight, which fits; anything
   needing rank 5 does not, and is a format version bump. Confirm 4 is the right
   place to draw it.
