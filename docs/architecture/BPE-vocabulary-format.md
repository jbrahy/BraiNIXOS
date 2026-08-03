# BXV1 — BraiNIX BPE vocabulary format (the tokenizer's blob, at rest and in memory)

**Task:** P3-T5 — in-tree byte-level BPE tokenizer. Specification and
implementation land together.
**Authoritative parents:** [`../NORTH_STAR.md`](../NORTH_STAR.md),
[`../THREAT_MODEL.md`](../THREAT_MODEL.md),
[`../security/SECURITY_INVARIANTS.md`](../security/SECURITY_INVARIANTS.md).
**Governs:** the byte layout of the tokenizer vocabulary on disk and in memory,
the validation every consumer performs before any of those bytes decides
anything, and the exact semantics of encode and decode.
**Consumed by:** P3-T6 (the transformer forward pass, which receives token
identifiers from here and returns them to here), BSP v2 §10.2 (`PromptChunk`
bytes in, `TokenChunk` bytes out).
**Related:** [`BXW1-weight-format.md`](BXW1-weight-format.md) §5.4 (the
`vocab_digest` / `vocab_len` binding and the `vocab_size` cross-check, which
this document does **not** restate authority over),
[`BSP-v2-serving-protocol.md`](BSP-v2-serving-protocol.md) §8
(`MAX_PROMPT_BYTES`, which is where this document's encode ceiling comes from).
**Implementation:** `src/tokenizer/` (`brainix-tokenizer`).
**Status:** specification and implementation. Every rule below is enforced by
`Vocabulary::parse` and named in `VocabularyError`; §7's tables give the variant
each rule denies with, so a rule with no variant is a rule that does not exist.

This spec is normative. "MUST", "MUST NOT", and "DENY" are hard requirements.
"DENY" always means the fail-closed action defined in §7.1. Absence of an
explicit accept path is denial (NORTH_STAR "Fail closed").

Proof tier, per
[`../security/SECURITY_INVARIANTS.md`](../security/SECURITY_INVARIANTS.md) §16:
the **tokenizer vocab parser is Full tier** — it is listed there as "hostile
input from disk, consumed before any request is served." It does not inherit
`inferd`'s Reduced tier, by §16's first corollary. The encoder is on the same
footing for a different reason: it is the first thing a remote client's prompt
bytes touch.

---

## 0. Non-negotiables inherited

- **The blob is hostile input.** It arrives from disk, which the project did not
  write and cannot audit, and it is parsed before a single request is served.
  `INV-PARSE-001` applies verbatim: `#![no_std]`, zero allocation, every offset,
  length, and count bounds-checked against its containing region, malformed
  input denies rather than proceeding best-effort.
- **The prompt is hostile input.** Encode runs on bytes a remote peer chose. The
  work it performs is bounded by a build-time `const` before the first byte is
  looked at (§5.3). A parser that is total but slow on a chosen input has not
  failed closed, it has failed slowly, and on a single-model serving box that is
  the same outage.
- **Zero allocation.** No heap, no arena, no growable buffer. Every working set
  is a caller-supplied slice or a fixed-size array (`INV-MEM`). Encoding writes
  into a caller-provided slice and returns a length; it never allocates and
  never truncates silently.
- **No new external crate.** BXV1 needs no primitive at all — not even SHA-256,
  which belongs to the loader that verifies the blob before this decoder sees it
  (§8). There is no compression, no container library, and no third-party format
  parser.
- **Structure over secrecy.** Every field, bound, and rejection path is public.
  Nothing here rests on an attacker not knowing the format.

---

## 1. Invariant mapping (what BXV1 exists to enforce)

| Invariant | How BXV1 enforces it |
|---|---|
| `INV-PARSE-001` (fail-closed hostile-input parser) | §7's rule tables enumerate every attacker-controllable value and its required behaviour. All arithmetic is checked; nothing saturates or wraps; a value that does not fit denies. The decoder is `#![no_std]`, `#![forbid(unsafe_code)]`, and allocation-free. |
| `INV-PARSE-002` (fuzz target *and* Kani harness) | §9 names both, plus the Prusti and audit obligations Full tier requires. |
| `INV-PARSE-004` (disagreeing sources fail closed) | Three sources describe the vocabulary's size: BXW1's `vocab_size`, the embedding matrix's row count, and this format's `token_count`. Disagreement is a DENY with no precedence rule — BXW1 §7.5 rule C7 owns that check, and `Vocabulary::token_count()` exists to feed it. Inside this format the same principle applies to every redundant field: `rank`, the byte-token table, and both sort indices are all derivable and all compared (§2). |
| **INV-MEM** (fixed pools, no heap) | Every buffer is caller-supplied or a compile-time-sized array. No quantity in a blob ever sizes, extends, or indexes a buffer: counts are compared against a `const` first and are then used only to bound loops. |
| `INV-SERVE-002` (no allocation driven by foreign sizes) | The encode path takes its output and scratch slices from the caller and refuses a call whose slices are too small. The prompt length is compared against `MAX_ENCODE_INPUT_BYTES`, never used to size anything. |
| `INV-SCHED-004` (exhaustion is explicit) | An input above the encode ceiling returns an enumerated error before any work. There is no truncation and no "encode as much as fits". |
| `INV-MODEL-003` (model-adjacent bytes are untrusted everywhere) | Token bytes are blob-supplied and are **compared, never interpreted**. They are not a path, not a format string, not console-bound, and are never validated as UTF-8 or rendered as control (§5.4). |
| `INV-FAIL-001` (failure modes are defined) | §7.1 defines exactly one failure action, and `VocabularyError` has one variant per rule. |
| `INV-FAIL-003` (secure degradation over silent insecurity) | There is no "parse anyway and warn", no partial vocabulary, and no relaxed mode. A blob that cannot be fully validated is not used. |
| `INV-MODEL-002` (weights integrity-checked before use) — as it reaches here | The blob's digest and length are checked by the BXW1 loader **before** this decoder is called (§8). This decoder does not verify integrity and does not claim to; it checks structure. |

No new invariant identifier is introduced by this document, and none may be.

---

## 2. Byte-encoding primitives

All multi-byte integers are **little-endian**, matching BXW1 and for the same
reason: the vocabulary is a memory image consumed in place on a little-endian
machine, not a wire format. BSP v2 is big-endian; the two never meet, because a
vocabulary blob never travels over BSP and a BSP record never reaches this
decoder.

There are exactly two encoding forms:

1. **Fixed scalar** — `u16` or `u32`, little-endian, at a fixed offset in a
   fixed-size structure. A short buffer ⇒ DENY.
2. **Bulk payload** — the token-bytes region, described entirely by the fixed
   fields of the token table.

**There is no variable-length field in any header or record, no TLV, no
self-describing recursion, no length that governs a following length, no
compression, and no string table.** Structure is decided by fixed offsets and by
`token_count` and `merge_count`, both bounded by a `const` before they are used
for anything. The header decoder is therefore **total from the first byte**: it
reads a constant number of bytes and every deviation is a single DENY.

**Readers are byte-wise.** Every field is assembled from a byte slice by an
explicit little-endian reader. No `#[repr(C)]` struct cast, no `transmute`, no
pointer cast over blob bytes. Record alignment is consequently irrelevant, and
the format specifies none.

**Four fields are redundant on purpose.** A merge's `rank`, the byte-token
table, the token sort index, and the merge sort index are all derivable from
other parts of the blob. They are present so the derived value and the declared
value can be compared, which turns a disagreement into a detected DENY instead
of a silent reinterpretation. The derived meaning is always the one used; the
declared value is only ever compared. This is BXW1 §3.2's discipline applied to
a different shape of data.

---

## 3. Layout

A blob is exactly seven regions, in this order, with no other bytes and **no
padding anywhere**:

```
┌──────────────────────────────────────────────────────────────┐
│ header             64 bytes, fixed, no variable-length field │  §3.1
├──────────────────────────────────────────────────────────────┤
│ byte-token table   1024 bytes = 256 × u32                    │  §3.3
├──────────────────────────────────────────────────────────────┤
│ token table        token_count × 8 bytes, fixed records      │  §3.2
├──────────────────────────────────────────────────────────────┤
│ token index        token_count × 4 bytes, sorted by bytes    │  §3.4
├──────────────────────────────────────────────────────────────┤
│ merge table        merge_count × 16 bytes, fixed records     │  §3.5
├──────────────────────────────────────────────────────────────┤
│ merge index        merge_count × 4 bytes, sorted by (l, r)   │  §3.6
├──────────────────────────────────────────────────────────────┤
│ token bytes        every token's bytes, ascending by id,     │  §3.7
│                    contiguous, ending at the end of the blob │
└──────────────────────────────────────────────────────────────┘
```

Every record in the format is a whole number of 4-byte words and the header is
64 bytes, so every section begins on a 4-byte boundary by construction. **No
alignment padding exists, and therefore no pad byte can carry anything.**

**Every byte of the blob is accounted for.** A byte that belongs to none of the
seven regions is unreachable, and rules K4–K7 make the token-bytes region tile
exactly. That is not tidiness: an unaccounted region inside a digest-covered
blob is a smuggling channel that the digest would faithfully cover and never
object to. BXW1 §3 pays for the same property with pad-byte rules; BXV1 pays for
it by having no pads.

### 3.1 Header — fixed size, 64 bytes

Offsets are absolute from the first byte of the blob. Every field is
little-endian. `BXV1_HEADER_BYTES = 64`.

| Off | Len | Type | Field | Required value / meaning |
|--:|--:|---|---|---|
| 0 | 4 | `[u8;4]` | `magic` | MUST equal ASCII `"BXV1"` (`0x42 0x58 0x56 0x31`) |
| 4 | 2 | `u16` | `version_major` | MUST equal `1`. Exact match, not a negotiation |
| 6 | 2 | `u16` | `version_minor` | MUST equal `0`. Exact match |
| 8 | 4 | `u32` | `flags` | MUST be zero. No flag is defined in v1.0 |
| 12 | 4 | `u32` | `token_count` | `BXV1_MIN_TOKENS ≤ token_count ≤ BXV1_MAX_TOKENS` |
| 16 | 4 | `u32` | `merge_count` | `merge_count ≤ BXV1_MAX_MERGES`. Zero is legal — a vocabulary with no merges encodes one token per byte |
| 20 | 4 | `u32` | `byte_token_table_offset` | MUST equal `64` |
| 24 | 4 | `u32` | `token_table_offset` | MUST equal `1088` |
| 28 | 4 | `u32` | `token_index_offset` | MUST equal `1088 + 8 × token_count` |
| 32 | 4 | `u32` | `merge_table_offset` | MUST equal `1088 + 12 × token_count` |
| 36 | 4 | `u32` | `merge_index_offset` | MUST equal `1088 + 12 × token_count + 16 × merge_count` |
| 40 | 4 | `u32` | `token_bytes_offset` | MUST equal `1088 + 12 × token_count + 20 × merge_count` |
| 44 | 4 | `u32` | `token_bytes_length` | MUST equal `total_size − token_bytes_offset` |
| 48 | 4 | `u32` | `total_size` | Total blob bytes, header inclusive. MUST equal the object length the caller supplied (§7.2 rule H13) |
| 52 | 12 | `[u8;12]` | `reserved_tail` | Every byte MUST be zero |

Every offset in the table is **asserted, never followed**. The decoder computes
each one from `token_count` and `merge_count` with checked arithmetic and
compares; a declared offset that disagrees is a DENY and is never used to reach
a byte. The fields exist so that a blob states its own shape and can be
cross-checked, not so a reader can chase a pointer.

**Reserved fields are not extension points.** A nonzero `flags` or a nonzero
`reserved_tail` byte is a DENY, not a forward-compatible unknown. Like BXW1 §3.1
and BSP v2 §5.5, BXV1 has no in-band evolution path: **a v2 is a new magic and a
new document.** The cost is stated: adding a special-token table, a
pre-tokenization rule, or a scoring field means a format version bump and a
converter run over every blob, not a flag.

### 3.2 Token table — one fixed record per token

`BXV1_TOKEN_RECORD_BYTES = 8`. Record `i` begins at `token_table_offset + 8 × i`
and describes token identifier `i`. Offsets are relative to the record.

| Off | Len | Type | Field | Meaning and constraints |
|--:|--:|---|---|---|
| 0 | 4 | `u32` | `byte_offset` | Absolute blob offset of the token's bytes. MUST equal the previous record's `byte_offset + byte_length`, and for record 0 MUST equal `token_bytes_offset` (§7.3) |
| 4 | 4 | `u32` | `byte_length` | `1 ≤ byte_length ≤ BXV1_MAX_TOKEN_BYTES` |

**A token identifier is its index in this table.** There is no identifier field,
so an identifier cannot disagree with a position, and the mapping from
identifier to embedding row (BXW1 §6.2's `token_embedding.weight`, indexed by
token identifier) is positional at both ends.

**`byte_offset` is redundant and is kept anyway.** It is fully derivable by
summing the preceding lengths. It is present so the derived value and the
declared value can be compared, which turns a tiling disagreement into a
detected DENY instead of a silently shifted vocabulary — exactly the argument
BXW1 §3.2 makes for `data_len`.

### 3.3 Byte-token table — 256 fixed entries

`BXV1_BYTE_TOKEN_TABLE_BYTES = 1024`. Entry `b` is the little-endian `u32` at
`byte_token_table_offset + 4 × b`, and is the token identifier that spells the
single byte `b`.

The table is redundant with the token bytes and is validated against them: entry
`b` MUST name a token whose `byte_length` is exactly 1 and whose single byte is
exactly `b` (§7.4). What the check buys is the property the whole codec rests
on: **after parsing, every one of the 256 byte values provably has a token**, so
no input can fail to encode and the invalid-UTF-8 rule of §5.4 is a fact about
the data rather than a hope about the converter.

The alternative — reserving identifiers `0..=255` for the byte tokens — was
rejected because it constrains the identifier space, and the identifier space is
shared with the embedding matrix. A converter that must renumber tokens must
also permute two large matrices, and a converter that permutes matrices is a
converter that can permute them wrongly. 1 KiB of table is cheaper than that
class of bug.

### 3.4 Token index — the sort permutation over token bytes

`token_count` little-endian `u32` entries. Entry `p` is a token identifier, and
the sequence of `token_bytes(entry[p])` MUST be **strictly ascending** in
byte-string order (`[]` < `[0x00]` < `[0x00, 0x01]` < `[0x01]`).

Strictness is doing two jobs:

- It detects **duplicate tokens** in a single forward pass carrying one borrowed
  slice of state. Two tokens with identical bytes make the mapping from bytes to
  identifiers ambiguous, and two readers that resolve it differently would
  disagree about the same vocabulary. Detecting duplicates any other way in a
  zero-allocation parser means either a quadratic scan or a scratch set
  proportional to `BXV1_MAX_TOKENS`.
- It makes the index a **permutation** of `0..token_count` without a visited
  set: entries with strictly ordered sort keys are pairwise distinct records, and
  there are exactly `token_count` of them, every one in range.

### 3.5 Merge table — one fixed record per merge rule

`BXV1_MERGE_RECORD_BYTES = 16`. Record `i` begins at
`merge_table_offset + 16 × i`. Offsets are relative to the record.

| Off | Len | Type | Field | Meaning and constraints |
|--:|--:|---|---|---|
| 0 | 4 | `u32` | `left` | Left operand token identifier. `< token_count` |
| 4 | 4 | `u32` | `right` | Right operand token identifier. `< token_count` |
| 8 | 4 | `u32` | `result` | Token identifier the pair collapses to. `< token_count` |
| 12 | 4 | `u32` | `rank` | Priority. **Lower binds first.** MUST equal `i` |

Two rules make a merge mean what BPE says it means:

- **`rank` MUST equal the record index.** Rank is therefore unique by
  construction, so "the lowest-ranked applicable rule" never needs a tie-break
  between two different rules, and the encoder's output does not depend on how
  ties would have been broken. The field is redundant and kept for the reason
  §2 gives.
- **`token_bytes(result)` MUST equal `token_bytes(left)` followed by
  `token_bytes(right)`.** This is the rule that makes the merge graph coherent,
  and it is also what makes **a cyclic merge graph unconstructible**: a result is
  strictly longer in bytes than either operand, so the "is built from" relation
  strictly increases a natural number and cannot close a cycle. No cycle
  detection code exists, because no cycle can be expressed.

`result == left` or `result == right` is a separate, earlier DENY with its own
reason, so a self-referential rule is diagnosable as such in a log rather than
appearing as a length disagreement.

### 3.6 Merge index — the sort permutation over merge operands

`merge_count` little-endian `u32` entries. Entry `p` is a merge record index, and
the sequence of keys `(left << 32) | right` MUST be **strictly ascending**.

This is what makes the encoder's pair lookup a binary search — at most 20 probes
against `BXV1_MAX_MERGES` — rather than a scan of the whole merge table for
every adjacent pair at every iteration, which would multiply the encoder's
already-quadratic bound by `merge_count` and turn a bounded computation into an
unusable one.

Strictness detects a **duplicate `(left, right)` pair** in the same pass, and by
the argument of §3.4 makes the index a permutation. A duplicate pair would mean
two rules apply to the same adjacency, and which one won would depend on the
reader.

### 3.7 Token-bytes region

Every token's bytes, concatenated in ascending identifier order, starting at
`token_bytes_offset` and ending exactly at the end of the blob. No gap, no
overlap, no pad, no shared span. Tokens are opaque byte strings: they are
compared, never interpreted, and are not required to be UTF-8, printable, or
non-empty-of-control-bytes.

Forbidding shared spans forbids the natural encoding of a token whose bytes are
a prefix of another's. That is a real cost — a vocabulary with 1M tokens
averaging 8 bytes stores 8 MB where an overlap-sharing encoding might store
less — and it is paid deliberately: sharing would make the tiling check
quadratic, would remove the one-`u32`-of-state property, and would make "every
byte accounted for" unprovable in a single pass.

---

## 4. What the format deliberately does not carry

Stated explicitly, because each absence is a decision rather than an oversight:

- **No special-token table, no BOS/EOS.** BXW1 §3.1 carries `bos_token_id` and
  `eos_token_id` at offsets 144 and 148, and §7.2 rule H19 bounds them against
  `vocab_size`. Two sources for one fact is an `INV-PARSE-004` disagreement
  point that buys nothing, so BXV1 has none.
- **No scores or probabilities.** A rank total order is all the encoder consumes.
  A score field would be a float from a hostile blob, which means a bit-pattern
  validation rule (BXW1 §4.7) for a value that changes nothing.
- **No pre-tokenization regex.** Real BPE tokenizers split on a regex before
  merging. BXV1 does not, and §10 states what that costs and what it buys.
- **No normalization, no case folding, no Unicode tables.** Bytes in, bytes out.
- **No digest and no signature.** Integrity belongs to the BXW1 loader (§8). A
  self-describing digest inside the artifact it covers proves nothing an
  attacker cannot restate.
- **No path, filename, capability reference, endpoint, or address.** There is
  nothing in a blob that a consumer could act on other than to compare bytes and
  emit identifiers (`INV-MODEL-001`, `INV-MODEL-003`).

---

## 5. Encoding and decoding semantics

### 5.1 Encode — the merge rule, stated exactly

1. Seed: the token sequence is one byte token per input byte, in order, taken
   from the byte-token table. An `N`-byte input seeds exactly `N` tokens.
2. Repeat: among all adjacent pairs of the current sequence that match a merge
   rule, apply **the rule with the lowest rank**. If that rule matches at more
   than one position, apply it at the **leftmost** of them. Applying a rule
   replaces the two tokens with its `result`, shortening the sequence by one.
3. Stop when no adjacent pair matches any rule, or when one token remains.

Because ranks are unique (§3.5), step 2 never needs a tie-break between two
different rules; the leftmost tie-break is between two occurrences of the *same*
rule. The procedure is therefore **deterministic**: the same blob and the same
input always yield the same token sequence, on every run and on every machine.

**Rank priority is not greedy left-to-right, and the difference is silent.** An
encoder that walks the sequence and collapses the first pair it can produces a
different, valid-looking token sequence that the model was never trained on, and
nothing crashes. `src/tokenizer/tests/merge_order.rs` builds vocabularies where
the two strategies provably differ, runs a reference greedy encoder alongside the
real one, asserts they disagree, and pins the rank-priority answer.

### 5.2 Decode

Each token identifier is replaced by its bytes, in order, concatenated. An
identifier at or above `token_count` is a DENY. Decode writes bytes, never a
`&str`: the vocabulary can spell any byte sequence, so a `&str` result would
have to either fail on a valid vocabulary or misreport what the model produced.

`decode(encode(x)) == x` for **every** byte string `x`, because encoding starts
from a complete cover of the byte alphabet and every merge preserves the
concatenation of the sequence's bytes (§3.5).

### 5.3 The work bound

Let `N` be the input length in bytes.

- The sequence starts at exactly `N` tokens and every iteration removes exactly
  one, and the loop stops at one token. Therefore **at most `N − 1` merge
  iterations**.
- Each iteration scans at most `N − 1` recorded ranks to find the minimum, and
  performs at most three merge lookups, each a binary search of at most
  `log2(BXV1_MAX_MERGES) = 20` probes.
- Seeding performs `N` byte-token lookups and `N − 1` merge lookups.

So the whole encode is **`≤ (N − 1)²` rank comparisons and `≤ 3N` binary
searches**. The quadratic term is why `N` MUST be bounded by a build-time
`const`: `MAX_ENCODE_INPUT_BYTES = 16384`, equal to BSP v2 §8's
`MAX_PROMPT_BYTES`, which is the size of the fixed per-session buffer a prompt is
reassembled into. An input above it is a DENY before any work is done.

At the ceiling the worst case is `16383² ≈ 2.7 × 10⁸` `u32` comparisons over a
compact array — around a tenth of a second on the reference machine, which is
under the ~118 ms BXW1 §8.2 budgets for a **single** decoded token at the maximum
model size. An attacker's best case is therefore to buy less than one token's
worth of compute with a maximum-size prompt, which is the bound this design was
chosen to reach.

**The bound is enforced, not merely argued.** The merge loop carries a budget of
`N` iterations and denies with `MergeBudgetExhausted` if it is ever exhausted.
That path is unreachable given the argument above, and it is checked anyway,
because "unreachable" is an argument in a document and the counter is a property
of the program — the same reasoning BXW1 §7.6 gives for keeping `checked_mul`
where overflow is provably impossible.

`Vocabulary::encode_measured` reports the iteration count, so the bound is
observable rather than inferred; `src/tokenizer/tests/bounded_work.rs` drives it
with a vocabulary built to maximize it and asserts the bound holds.

### 5.4 Invalid UTF-8 — the rule

**The tokenizer is byte-level and never inspects UTF-8 structure.** Encode takes
`&[u8]`, decode writes `&mut [u8]`, and neither validates, rejects, replaces, nor
normalizes anything. Invalid UTF-8 is not an error and is not special: a lone
continuation byte, a truncated sequence, an overlong form, a surrogate encoding,
and `0xFE`/`0xFF` all encode and decode back to themselves exactly.

This is guaranteed by structure, not by convention: §3.3's validation proves
every byte value has a token before the vocabulary handle exists.

The alternative — validating UTF-8 on the way in — is rejected for two reasons.
It makes the round trip lossy in exactly the case an attacker chooses: a
replacement character means the model sees bytes the client did not send, and the
client cannot tell. And it puts a second hostile-input parser on the prompt path
to do work the model does not need. A tokenizer that cannot represent a byte is
a tokenizer with a hole in it.

The cost is stated: BXV1 offers **no** protection against a prompt that is
deliberately malformed text. It is not a filter and was never meant to be one.
What renders bytes safely is the client, and BSP v2 §10.2 already says token
bytes are opaque model output rendered by the client and never interpreted as
control (`INV-MODEL-003`).

---

## 6. Bounds and constants

Every bound is a build-time `const`. The *values* are tunable against the served
model; the *presence of a hard `const` bound on each* is not.

| Const | Value | Governs / rationale |
|---|--:|---|
| `BXV1_MAGIC` | `"BXV1"` | 4-byte format tag |
| `BXV1_VERSION` | `1.0` | major/minor, exact match |
| `BXV1_HEADER_BYTES` | `64` | fixed header; no variable-length field |
| `BXV1_BYTE_TOKEN_TABLE_BYTES` | `1024` | 256 × `u32` |
| `BXV1_TOKEN_RECORD_BYTES` | `8` | fixed token record |
| `BXV1_MERGE_RECORD_BYTES` | `16` | fixed merge record |
| `BXV1_INDEX_ENTRY_BYTES` | `4` | one entry of either sort index |
| `BXV1_MIN_TOKENS` | `256` | a vocabulary that cannot name all 256 byte values cannot encode arbitrary input |
| `BXV1_MAX_TOKENS` | `1 << 20` (1,048,576) | matches `BXW1_MAX_VOCAB`, so the two cannot disagree about what is representable |
| `BXV1_MAX_MERGES` | `1 << 20` | a trained byte-level vocabulary has roughly `token_count − 256` merges |
| `BXV1_MAX_TOKEN_BYTES` | `256` | bounds the byte output one identifier can demand from decode, so a decode buffer is sized from a `const` and never from the blob |
| `BXV1_MAX_BLOB_BYTES` | `64 MiB` | the same value `BXW1_MAX_VOCAB_BLOB_BYTES` states (BXW1 §8.1) |
| `MAX_ENCODE_INPUT_BYTES` | `16384` | equal to BSP v2 §8's `MAX_PROMPT_BYTES`; §5.3 is why it must be a `const` |

**The fixed sections at maximum size.** At `token_count = merge_count = 2²⁰` the
six fixed sections occupy `64 + 1024 + 12 × 2²⁰ + 20 × 2²⁰ = 33,555,520` bytes ≈
32 MiB, leaving ≈ 31 MiB of the 64 MiB ceiling for token bytes — about 30 bytes
per token at the maximum token count. A vocabulary that wants both a million
tokens and long tokens does not fit, and the check that refuses it is the
`BXV1_MAX_BLOB_BYTES` comparison, not a per-token rule. Stated so the interaction
is not discovered later as a surprising rejection.

---

## 7. Hostile input — every attacker-controllable value and its required behaviour

This section is as important as the layout, and it is the section the fuzz and
Kani work of §9 is written against. Every value below arrives from disk or from
the network and is therefore attacker-controllable under the project's threat
model. Every one is bounds-checked **before use**, and every check's failure
action is DENY.

### 7.1 What DENY means

DENY is a single, uniform action:

1. **Produce nothing.** No `Vocabulary` handle is returned, no token is written,
   no byte is written. There is no partial vocabulary and no partial encode.
2. **Return an enumerated error** naming the rule that fired. Never a partial
   success, never a warning, never a degraded mode (`INV-FAIL-003`).
3. **Leave the caller's buffers alone as far as the returned length is
   concerned.** The returned length is the only thing that says how much of an
   output slice is meaningful, and no error path returns one.

There is exactly one failure action in this document. The decoder holds no
state, owns no memory, and has nothing to unwind: it borrows a slice and returns
a handle or an error.

### 7.2 Header rules

| # | Attacker-controlled value | Required behaviour | Variant |
|---|---|---|---|
| H1 | Zero-length object | DENY | `EmptyBlob` |
| H2 | Object shorter than 64 bytes | DENY. The header decoder requires 64 bytes and never reads a partial header | `BlobTooSmallForHeader` |
| H3 | Object larger than `BXV1_MAX_BLOB_BYTES` | DENY, before any field is read | `BlobExceedsCeiling` |
| H4 | `magic` ≠ `"BXV1"` | DENY | `BadMagic` |
| H5 | `version_major` ≠ 1, or `version_minor` ≠ 0 | DENY. Exact match; not a negotiation and not a compatibility range | `UnsupportedVersion` |
| H6 | `flags` ≠ 0 | DENY. An undefined flag bit is an attack surface, not a forward-compatibility affordance | `NonZeroReservedField` |
| H7 | Any `reserved_tail` byte ≠ 0 | DENY | `NonZeroReservedField` |
| H8 | `token_count < BXV1_MIN_TOKENS` | DENY | `TokenCountBelowMinimum` |
| H9 | `token_count > BXV1_MAX_TOKENS` | DENY **before** `token_count` is used in any arithmetic or to bound any read | `TokenCountExceedsCeiling` |
| H10 | `merge_count > BXV1_MAX_MERGES` | DENY, on the same ordering | `MergeCountExceedsCeiling` |
| H11 | Any section-offset derivation overflowing | DENY. Checked multiply and checked add throughout; H9 and H10 make the overflow unreachable and the check is mandatory anyway (§7.9) | `ArithmeticOverflow` |
| H12 | Any declared section offset ≠ its derived value | DENY. Offsets are asserted, never followed | `SectionOffsetMismatch` |
| H13 | `total_size` ≠ the object length | DENY, in **both** directions. A `total_size` below the object length leaves trailing bytes nothing accounts for; above it is a read past the end. The object length is the authority; `total_size` is only ever compared to it | `TotalSizeMismatch` |
| H14 | `token_bytes_length` ≠ `total_size − token_bytes_offset`, or `token_bytes_offset > total_size` | DENY | `TokenBytesRegionMismatch` |

### 7.3 Token-table rules (per record, in identifier order)

| # | Value | Required behaviour | Variant |
|---|---|---|---|
| K1 | A record read running past the end of the blob | DENY | `TruncatedTokenTable` |
| K2 | `byte_length == 0` | DENY. A token that spells nothing has no meaning and would make the merge concatenation rule vacuous | `TokenLengthZero` |
| K3 | `byte_length > BXV1_MAX_TOKEN_BYTES` | DENY | `TokenLengthExceedsCeiling` |
| K4 | Record 0: `byte_offset ≠ token_bytes_offset` | DENY. No unaccounted gap before the first token | `TokenBytesNotContiguous` |
| K5 | Record `i > 0`: `byte_offset ≠ byte_offset[i−1] + byte_length[i−1]` | DENY. This is the overlap *and* gap check at once, and because the tiling is required to be ascending and exact it costs one `usize` of carried state and no scratch proportional to `token_count` | `TokenBytesNotContiguous` |
| K6 | `byte_offset + byte_length` overflowing, or exceeding the end of the blob | DENY. Checked add | `TruncatedTokenBytes` |
| K7 | The last record's end ≠ the end of the blob | DENY. No unaccounted trailing region | `TokenBytesNotContiguous` |

### 7.4 Token-index and byte-token rules

| # | Value | Required behaviour | Variant |
|---|---|---|---|
| X1 | An index read running past the end of the blob | DENY | `TruncatedTokenIndex` |
| X2 | An index entry `≥ token_count` | DENY | `TokenIndexOutOfRange` |
| X3 | Entry `p`'s bytes sorting **before** entry `p−1`'s | DENY | `TokenIndexNotAscending` |
| X4 | Entry `p`'s bytes **equal** to entry `p−1`'s | DENY, with a distinct reason so a duplicate token is diagnosable as such rather than as a sort-order complaint | `DuplicateToken` |
| B1 | A byte-token read running past the end of the blob | DENY | `TruncatedByteTokenTable` |
| B2 | A byte-token entry `≥ token_count` | DENY | `ByteTokenIdOutOfRange` |
| B3 | Entry `b` naming a token whose bytes are not exactly `[b]` | DENY. This is the check that makes §5.4's byte-level claim a property of the data | `ByteTokenNotSingleByte` |

### 7.5 Merge-table rules (per record, in table order)

| # | Value | Required behaviour | Variant |
|---|---|---|---|
| M1 | A record read running past the end of the blob | DENY | `TruncatedMergeTable` |
| M2 | `rank ≠ i` | DENY. Rank uniqueness is what makes the encoder deterministic | `MergeRankMismatch` |
| M3 | Any of `left`, `right`, `result` `≥ token_count` | DENY | `MergeTokenIdOutOfRange` |
| M4 | `result == left`, or `result == right` | DENY, checked **before** M5 so a self-referential rule is diagnosable as such | `MergeSelfReferential` |
| M5 | `token_bytes(result) ≠ token_bytes(left) ++ token_bytes(right)`, in length or in content | DENY. §3.5 explains why this rule is also the cycle check | `MergeResultBytesMismatch` |

### 7.6 Merge-index rules

| # | Value | Required behaviour | Variant |
|---|---|---|---|
| I1 | An index read running past the end of the blob | DENY | `TruncatedMergeIndex` |
| I2 | An index entry `≥ merge_count` | DENY | `MergeIndexOutOfRange` |
| I3 | Entry `p`'s key sorting **before** entry `p−1`'s | DENY | `MergeIndexNotAscending` |
| I4 | Entry `p`'s key **equal** to entry `p−1`'s | DENY, with a distinct reason | `DuplicateMergePair` |

### 7.7 Codec rules (the client-controlled path)

| # | Value | Required behaviour | Variant |
|---|---|---|---|
| E1 | `input.len() > MAX_ENCODE_INPUT_BYTES` | DENY, before any work (§5.3) | `PromptTooLong` |
| E2 | `output.len() < input.len()` | DENY. Never a truncated encode | `TokenOutputTooSmall` |
| E3 | `scratch.len() < input.len()` | DENY | `ScratchTooSmall` |
| E4 | The merge loop exceeding `N` iterations | DENY. Unreachable; enforced anyway (§5.3) | `MergeBudgetExhausted` |
| E5 | A recorded rank whose pair no longer resolves | DENY. Unreachable for a validated vocabulary; enforced anyway | `MergeLookupInconsistent` |
| D1 | A token identifier `≥ token_count` passed to decode | DENY | `TokenIdOutOfRange` |
| D2 | Decoded bytes not fitting the caller's output slice | DENY. Never a truncated decode | `ByteOutputTooSmall` |

### 7.8 What a hostile blob or prompt cannot do

Stated as the positive form of the rules above, because it is the claim the fuzz
targets exist to falsify:

- It cannot cause an allocation. There is no allocator reachable from this crate.
- It cannot cause a read outside the blob: every read is a checked slice access
  and every offset is derived, compared, and bounds-tested before use.
- It cannot cause a write outside a caller's slice: every write goes through a
  checked `get_mut`.
- It cannot cause the decoder or the encoder to loop unboundedly: every loop is
  over a count bounded by a `const` (`token_count`, `merge_count`, the 256 byte
  values, `rank ≤ 20` binary-search probes) or by the enforced merge budget.
- It cannot cause a panic, an arithmetic wrap, or an unchecked cast.
- It cannot produce a partially valid vocabulary: `Vocabulary::parse` returns a
  handle only after every rule above has passed over the whole blob.
- It cannot make encode and decode disagree: §5.2's round-trip property holds for
  every accepted blob and every byte string.

### 7.9 Arithmetic discipline

**All arithmetic over blob-supplied and caller-supplied values is checked.
Nothing saturates, nothing wraps, and a value that does not fit denies.**

- Every multiply is `checked_mul`, every add is `checked_add`, every subtract is
  `checked_sub`, every divide is `checked_div`. `None` ⇒ DENY.
- Counts are compared against their `const` ceilings **before** they are
  multiplied by a record size. With `token_count ≤ 2²⁰` and `merge_count ≤ 2²⁰`,
  every section derivation is at most 2²⁵ and overflow is unreachable — **and the
  checked operation is still mandatory**, because "unreachable" is an argument in
  a document and `checked_mul` is a property of the program. A Kani harness
  proves the former; only the latter survives a future edit to a bound.
- No signed arithmetic appears anywhere. There is no subtraction whose operands
  are not already ordered by a prior check.

---

## 8. Binding to BXW1, and what this decoder does not check

[`BXW1-weight-format.md`](BXW1-weight-format.md) §5.4 binds a vocabulary to a
model by SHA-256 digest and exact length. That binding is the **loader's**, and
it runs **before** this decoder is called:

- the loader verifies `blob.len() == vocab_len` and `SHA-256(blob) ==
  vocab_digest` (BXW1 §7.5 rule C6) — before the tokenizer parses a byte;
- the loader compares `Vocabulary::token_count()` against `vocab_size`
  (BXW1 §7.5 rule C7) — a third source of the same fact, denied with no
  precedence rule (`INV-PARSE-004`);
- a mismatch anywhere denies the whole load. A verified model with an unverified
  tokenizer is not served.

**This decoder verifies no digest and claims no integrity property.** It checks
structure. Saying otherwise would be the single most overstatable claim in this
document, and BXW1 §9.3 already enumerates what a verified digest does and does
not prove. In particular: a structurally valid vocabulary is not evidence that it
is the *right* vocabulary for the served model, and pairing model A's weights
with model B's vocabulary is not a crash — it is a system that runs and emits
plausible nonsense. The digest binding is what catches that, and it is not here.

**The decoder does not assume the loader ran.** It re-checks the blob length
against `BXV1_MAX_BLOB_BYTES` and validates the whole structure from the first
byte, exactly as BXW1 §10.3 requires `inferd`'s second parser to re-run
structural validation without assuming the first one did.

---

## 9. Verification obligations (Full tier)

The tokenizer vocab parser is **Full tier**
([`../security/SECURITY_INVARIANTS.md`](../security/SECURITY_INVARIANTS.md) §16),
which means all six artifacts: invariant mapping (§1), fuzz target, Kani harness,
Prusti contracts, security audit report, and no-regression bars. P3-T9b requires
it to be green under fuzz soak and Kani **independently**, with no component
permitted to pass on another's evidence.

**Fuzz targets** (libFuzzer/AFL, host, `#![no_std]`-compatible harness):

1. **Whole-blob decoder** — arbitrary bytes into `Vocabulary::parse`. Assert:
   never panics, never allocates, never reads outside the slice, and returns a
   handle only when every §7 rule passes.
2. **Encoder against a valid vocabulary** — arbitrary prompt bytes. Assert:
   total, bounded by `(N − 1)` merge iterations, never writes past the caller's
   slices, and `decode(encode(x)) == x`.
3. **Encoder against an arbitrary accepted vocabulary** — arbitrary blob and
   arbitrary prompt, encoding only when the blob parses. Assert the same
   properties hold for *every* structurally valid vocabulary, not only for
   well-trained ones.
4. **Decoder** — arbitrary identifier sequences. Assert: total, and either a
   length that fits the output slice or `ByteOutputTooSmall`.

**Kani harnesses:**

1. Every §2 reader is total and bounds-checked for all inputs.
2. Section derivation neither wraps nor accepts a layout that overlaps or leaves
   a gap, for all `token_count ≤ BXV1_MAX_TOKENS` and `merge_count ≤
   BXV1_MAX_MERGES` — the property §7.9 argues informally.
3. The token tiling walk (K4–K7) accepts a table **iff** its extents are
   ascending, contiguous, and exactly cover `token_bytes_offset .. total_size`.
4. No reachable path sizes, extends, or indexes a buffer from a blob-supplied
   length, offset, or count.
5. The merge loop terminates for all inputs, in at most `N − 1` iterations.
6. `Vocabulary::parse` returns `Ok` **iff** every rule in §7 passes, for all
   inputs.

**Property tests** (present in `src/tokenizer/tests/`):

1. **Round trip** — `decode(encode(x)) == x` over ASCII, multi-byte UTF-8,
   emoji, every single byte value, and arbitrary non-UTF-8 byte sequences.
2. **Determinism** — the same input yields the same token sequence across
   repeated calls, across dirty scratch, and across independently parsed handles.
3. **Merge-order correctness** — vocabularies where greedy left-to-right and
   rank priority provably disagree, with the rank-priority answer pinned.
4. **Bounded work** — a vocabulary constructed to maximize merge iterations,
   asserted against the `N − 1` bound.
5. **Adversarial blobs** — one fixture per rule in §7, each asserting the
   **specific** variant rather than merely that an error occurred.

**Test vectors:** a fixed set of small blobs checked into the tree, so a
converter and this decoder are checked against the same bytes rather than
against each other. **Not yet present** — see §11.

---

## 10. Costs stated plainly

1. **No pre-tokenization.** Real BPE tokenizers split the input on a regex
   (whitespace, punctuation, digit runs) before merging, which both bounds the
   merge work per segment and changes which merges are reachable. BXV1 does not,
   which means (a) the work bound is quadratic in the whole prompt rather than
   linear in it with a small constant, and (b) **a vocabulary trained with a
   pre-tokenizer will not reproduce its trainer's tokenization here**, because
   merges that the regex forbade can now fire across a boundary. A model whose
   tokenizer depends on pre-tokenization must have that behaviour added, and
   adding it is a format version bump plus a second hostile-input parser on the
   prompt path. This is the largest cost in this document and the most likely
   reason for a v2.
2. **Quadratic encode.** §5.3's arithmetic is acceptable only because
   `MAX_ENCODE_INPUT_BYTES` is 16 KiB and a decoded token already costs ~118 ms.
   Raising the prompt ceiling raises the encode cost quadratically. A
   linked-list-plus-heap encoder would make it `O(N log N)` at the cost of ~4×
   the scratch and a lazily-deleted heap to audit; it was rejected for v1.0
   because the simpler loop is within budget and is far easier to prove. If the
   prompt ceiling ever rises materially, this decision must be revisited rather
   than assumed.
3. **The output slice must hold one entry per input byte.** The seeded sequence
   is one token per byte, so a caller cannot pass a slice sized to the *expected*
   token count. At the ceiling that is a 64 KiB fixed buffer per session, on top
   of BSP v2 §8's 16 KiB prompt buffer.
4. **No token span sharing.** §3.7. Token bytes are stored in full even when one
   token's bytes are a prefix of another's.
5. **Two sort indices in the file.** 8 bytes per token and 4 per merge of pure
   redundancy — ~12 MiB at the maximum counts. Bought to make duplicate
   detection and pair lookup possible with zero scratch.
6. **No in-band evolution.** Reserved fields and undefined flag bits DENY. A v2
   is a new magic and a new document.
7. **BXV1 is not a filter.** §5.4. It will faithfully encode any byte sequence,
   including one designed to be malformed text.
8. **A converter is required.** No existing tokenizer file can be renamed into a
   BXV1 blob: the sort indices, the byte-token table, and the exact tiling must
   be computed.

---

## 11. Open questions for the owner

1. **Does the served model's tokenizer depend on pre-tokenization?** If it does,
   cost 10.1 is not a cost but a blocker, and the regex — or a bounded
   hand-written splitter that reproduces it — becomes a v2 requirement and a new
   Full-tier hostile-input parser. *Settled by:* naming the model family and
   inspecting its tokenizer configuration. **This is the question that decides
   whether BXV1 v1.0 is sufficient.**
2. **The converter does not exist.** Nothing in the tree produces a BXV1 blob
   from an upstream tokenizer, so no real vocabulary has ever been parsed. The
   test fixtures are synthetic. *Settled by:* writing the converter, which also
   settles question 1.
3. **`BXV1_MAX_TOKEN_BYTES = 256`.** Chosen to bound decode output from a
   `const`. Real byte-level BPE tokens rarely exceed 32 bytes. *Settled by:*
   the converter reporting the true maximum for the served vocabulary.
4. **Where the vocabulary blob lives, and how it arrives.** BXW1 §13 question 4
   and BSP v2 §15 question 4 are both still open on this. BXV1 assumes only that
   it arrives as a byte slice whose digest and length the loader has already
   checked.
5. **Should `token_count` be permitted to exceed the embedding row count?** Some
   vocabularies reserve trailing identifiers with no embedding. BXW1 §7.5 rule
   C7 currently requires exact equality, which forbids it. *Settled by:* an owner
   ruling; the conservative reading (exact equality) is what is implemented, and
   relaxing it would be a `INV-PARSE-004` weakening that needs writing down.
