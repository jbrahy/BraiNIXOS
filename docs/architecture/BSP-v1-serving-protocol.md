> # ⛔ SUPERSEDED — do not use as guidance
>
> **Superseded by [`BSP-v2-serving-protocol.md`](BSP-v2-serving-protocol.md) on 2026-08-02.**
>
> Owner decision 7 of 2026-08-02 removed asymmetric cryptography from the serving transport
> entirely. The §5 handshake below — Ed25519 identities over an ephemeral X25519 exchange, with a
> compile-time `CLIENT_ALLOWLIST` — is obsolete on both counts: the transport is now pre-shared-key
> only (HKDF-SHA256 derivation, ChaCha20-Poly1305 records, mutual authentication by proof of PSK
> possession), and no credential may be compiled into a build artifact.
>
> What survived into v2, unchanged: the `chacha20-poly1305@openssh.com` record layer, the implicit
> per-direction sequence nonces, the fixed-pool sizing discipline, the message grammar, and the
> fail-closed rejection table.
>
> Retained unedited as a historical record — including three stale `THREAT_MODEL.md` dominant-threat
> **rank** citations (§0, §9), which v2 replaces with citations by name. See
> [`../DOCUMENTATION_MAP.md`](../DOCUMENTATION_MAP.md).

---

# BSP v1 — BraiNIX Serving Protocol (authenticated inbound wire protocol)

**Task:** P2-T1 (design only — no implementation, no git).
**Authoritative parents:** `docs/NORTH_STAR.md`, `docs/THREAT_MODEL.md`.
**Governs:** the single authenticated, capability-gated inbound socket a remote
client uses to reach the confined inference tenant.
**Status:** design spec. Precise enough to drive Kani harnesses and libFuzzer/AFL
targets against every parser and every state transition. Nothing here rests on
obscurity (NORTH_STAR "Structure over secrecy").

This spec is normative. "MUST", "MUST NOT", "REJECT" are hard requirements.
"REJECT" always means the fail-closed action defined in §10 (deny, do not
allocate, do not grow a pool, and — for framing/decoder faults — drop the whole
connection). Absence of an explicit accept path is denial (NORTH_STAR "Fail
closed").

---

## 0. Non-negotiables inherited

From NORTH_STAR hard lines and THREAT_MODEL §"Dominant threats" #1/#2:

- **No new external crate.** BSP reuses only the already-in-tree primitives in
  `src/kernel/src/ssh/`: Ed25519 (`crypto.rs` sign/verify pattern), X25519
  (`crypto::x25519_public_key` / `x25519_shared_secret`), SHA-256 (exchange-hash
  KDF), and the `chacha20-poly1305@openssh.com` AEAD record layer
  (`transport::derive_direction_keys` / `seal_packet` / `open_packet`,
  `poly1305::poly1305_mac`). No AES, no TLS, no new KEM.
- **`#![no_std]`, zero-allocation.** No `alloc`, no `#[global_allocator]`. Every
  buffer is a compile-time-sized `static`/stack array. No pool is ever sized,
  grown, or indexed from a client-supplied length, offset, or tag (INV-MEM,
  INV-SERVE).
- **Fail closed.** Any malformed length, offset, tag, signature, nonce, or state
  violation denies. The connection/auth/request decoder is the #1 attack surface
  (THREAT_MODEL); it is a hostile-input parser, fuzzed and Kani-checked before it
  faces real clients.
- **Structure over secrecy.** Every field, bound, and rejection path is public.
  Security is the capability/isolation structure and the crypto, never the
  attacker's ignorance of the format.

---

## 1. Invariant mapping (what BSP exists to enforce)

| Invariant | How BSP enforces it |
|---|---|
| **INV-SERVE** (mutual client isolation; fail-closed hostile-input decoder) | **No wire field names a session, KV slice, weights view, or peer.** A session *is* the authenticated AEAD channel; it is keyed by unique per-session material and addressed internally by the accept-time connection binding, never by a client-supplied handle (§7, §8). The decoder is fail-closed and zero-alloc (§4, §10). |
| **INV-MODEL** (served model is a confined tenant, not an authority) | BSP carries **only** prompt bytes in and token bytes out. It exposes **no** field that selects a model, loads weights, names another session, or requests any kernel/spawn/network action. Prompt content is opaque, length-bounded transport payload; the model reached through BSP holds no BSP-grantable capability (§8.4). |
| INV-AUTH (no ambient authority; frozen capability set) | A completed handshake grants exactly one capability: *this* session. The grant is frozen at accept (§7.3). BSP defines no message that widens it. |
| INV-MEM (W^X, fixed pools, no heap) | All sizes in §6 are `const`. Session pool, per-session prompt buffer, and record buffers are build-time sized BSS. No handshake or request ever allocates. |
| INV-BOOT | Out of scope for the wire protocol; the server host Ed25519 key is a TCB secret whose provenance is INV-BOOT's concern (§5.1 note). |

---

## 2. Roles, keys, and trust

- **Server (BraiNIX, ring 0 / serving front end).** Holds a static Ed25519
  **host key** (the `crypto.rs` host-key pattern — dev seed today, measured/sealed
  key once the vTPM gap in THREAT_MODEL §0 closes). Trusted per THREAT_MODEL
  trust boundary.
- **Client (remote, hostile until proven).** Holds a static Ed25519 **identity
  key**. The client is authenticated **and authorized**: its identity public key
  MUST appear in the server's compile-time **client allowlist**
  (`CLIENT_ALLOWLIST`, mirroring the strict, no-TOFU pinning in
  `client_identity.rs::PINNED_HOSTS`, but for inbound identities). Unknown
  identity ⇒ REJECT. There is no registration-on-first-use.
- **Forward secrecy.** Each connection uses fresh **ephemeral X25519** key pairs
  on both sides; the static Ed25519 keys authenticate the ephemeral exchange but
  are never used for key agreement. Compromise of a static key does not decrypt
  recorded past sessions.

Everything outside the server TCB — every inbound byte, the client, the prompt,
the emitted tokens — is hostile (THREAT_MODEL attacker model).

---

## 3. Byte-encoding primitives (the only encodings BSP uses)

All integers **big-endian**. There are exactly three encoding forms; the decoder
implements one reader each, and nothing else:

1. **Fixed scalar** — `u8`, `u16`, `u32`. Fixed width; a short buffer ⇒ REJECT.
2. **Fixed array** — an exactly-N-byte field (e.g. a 32-byte key). Reader
   requires ≥ N remaining bytes or REJECT. **No length prefix.**
3. **Bounded var-bytes** — `u16 len` (or `u32 len` where noted) followed by
   `len` bytes, where `len` MUST be `≤ MAX` for that specific field (the MAX is a
   `const`, §6). The reader checks, in order: (a) ≥ 2 (or 4) bytes remain for the
   length; (b) the decoded `len ≤ MAX_field`; (c) ≥ `len` bytes remain. Any check
   fails ⇒ REJECT. The `MAX` is **always** the compile-time cap, never the value
   just read — the destination buffer is pre-sized to `MAX_field`; `len` only
   bounds a copy into it (INV-MEM).

**Handshake messages carry no var-bytes at all** — every handshake field is a
fixed scalar or fixed array (§5). This makes the handshake decoder total and
trivially Kani-provable: message length is a constant, and any deviation from the
exact expected length is a single REJECT.

There is no self-describing/TLV recursion, no length that governs a following
length, no compression, and no in-band control bytes. (THREAT_MODEL §"trusted
path": structure is decided by the tagged type, never interpreted from the byte
stream.)

---

## 4. Framing (record layer)

BSP runs over a reliable ordered byte stream (one TCP connection). Bytes on the
wire are a sequence of **records**. There are two record classes, separated by
the handshake:

### 4.1 Handshake records (plaintext, pre-key)

Before session keys exist, the three handshake messages (§5) are sent as raw
fixed-length byte blocks — **no length prefix on the wire**, because each message
type has a single constant length known to both sides from the state machine
(§5.4). The receiver, in a given handshake state, expects **exactly** the byte
count for the message due in that state; it reads that many bytes and no reader
ever consults a client-supplied length. A byte count that cannot be reached
(peer sends fewer, then stalls past the handshake timeout) ⇒ REJECT + drop.

### 4.2 Data records (AEAD, post-key)

Every post-handshake record is an authenticated `chacha20-poly1305@openssh.com`
frame, produced/consumed **verbatim** by the in-tree
`transport::seal_packet` / `transport::open_packet`:

```
data_record := enc_length[4] || ciphertext[packet_length] || tag[16]
```

`open_packet` already enforces, fail-closed, exactly the properties BSP needs
(verified against the code in `transport.rs`):

- decrypts the 4-byte length with `K_1`, then **REJECTs if `packet_length < 2`
  or `packet_length > 35000`** — an absolute, client-independent bound, checked
  **before** any buffer is touched;
- REJECTs (returns `None`) on Poly1305 tag mismatch (constant-time compare) —
  this is the authentication check; a forged/replayed/corrupt record never
  reaches the message decoder;
- REJECTs if `padding_length + 1 > packet_length` or if the recovered payload
  would exceed the caller's fixed `payload_out` buffer.

BSP adds two record-layer rules on top:

- **BSP_MAX_RECORD_PLAINTEXT** (§6) is the BSP payload ceiling and MUST be `≤`
  the `open_packet`/`seal_packet` internal plaintext buffer (today `4096` in
  `transport.rs`). The `payload_out` BSP passes is a `BSP_MAX_RECORD_PLAINTEXT`
  BSS buffer; a larger inner packet ⇒ `open_packet` REJECT. If
  `BSP_MAX_RECORD_PLAINTEXT` is set above 4096, that internal buffer MUST be
  raised to a named `const` in the same change (tracked as an implementation
  note, not a wire change).
- **Sequence numbers** are the per-direction AEAD nonces. Each direction starts
  at `0` at the first data record and increments by exactly `1` per record. The
  receiver derives the expected sequence locally; it is **never on the wire**. A
  record that fails to authenticate at the expected sequence ⇒ REJECT + drop
  (this closes replay and reorder: `open_packet` at the wrong sequence fails the
  Poly1305 check, as its own `test_wrong_sequence_fails_auth` shows). Sequence
  MUST NOT wrap; on reaching `u32::MAX` the session is torn down (§7.4).

The decoded record payload is a **BSP message** (§8): `type[1] || body`.

---

## 5. Handshake state machine (mutual authentication)

Goal: mutual authentication (both static Ed25519 identities proven) bound to a
fresh ephemeral X25519 ECDH, yielding forward-secret per-session ChaCha20-Poly1305
keys. Design is a fixed 1.5-RTT exchange, Noise-IK-like in spirit but built only
from the in-tree primitives.

### 5.1 Messages (all fixed-length; big-endian; no var-bytes)

**`ClientHello`** (client → server), length **`= 86`**:

| Off | Len | Field | Notes |
|--:|--:|---|---|
| 0 | 4 | `magic` | MUST equal ASCII `"BSP1"` (`0x42 0x53 0x50 0x31`) |
| 4 | 1 | `version_major` | MUST equal `1` |
| 5 | 1 | `version_minor` | MUST equal `0`; a higher minor from a v1 server is accepted only if it does not change these fields (forward rule: unknown minor ⇒ treat as `0`) |
| 6 | 32 | `client_eph_pub` | client ephemeral X25519 public key |
| 38 | 32 | `client_id_pub` | client static Ed25519 identity public key |
| 70 | 16 | `client_nonce` | 16 random bytes (anti-replay / transcript salt) |

**`ServerHello`** (server → client), length **`= 144`**:

| Off | Len | Field | Notes |
|--:|--:|---|---|
| 0 | 32 | `server_eph_pub` | server ephemeral X25519 public key |
| 32 | 16 | `server_nonce` | 16 random bytes |
| 48 | 32 | `server_host_pub` | server static Ed25519 host public key (client pins it, §5.3) |
| 80 | 64 | `server_sig` | Ed25519 signature by the host key over `LABEL_SERVER \|\| TH_1` (§5.2) |

**`ClientAuth`** (client → server), **AEAD-sealed** as the very first data record
(sequence 0, direction C→S), inner plaintext length **`= 64`**:

| Off | Len | Field | Notes |
|--:|--:|---|---|
| 0 | 64 | `client_sig` | Ed25519 signature by the client identity key over `LABEL_CLIENT \|\| TH_2` (§5.2) |

Sealing `ClientAuth` under the derived keys proves the client actually holds the
ECDH shared secret (key confirmation) *and* its identity key, in one message.

> §5.1 note: `server_host_pub` provenance and the client `CLIENT_ALLOWLIST` are
> TCB inputs. Their integrity is INV-BOOT/measured-boot's job; BSP consumes them
> as trusted constants.

### 5.2 Transcript hashes and signature inputs (SHA-256)

```
TH_1 = SHA256( ClientHello[0..86] || ServerHello[0..80] )      # ServerHello minus its signature
TH_2 = SHA256( ClientHello[0..86] || ServerHello[0..144] )     # full ServerHello incl. server_sig

LABEL_SERVER = "BSP1 server-auth\0"     # 16 bytes, domain separation
LABEL_CLIENT = "BSP1 client-auth\0"     # 16 bytes

server_sig = Ed25519_sign(host_key,   LABEL_SERVER || TH_1)
client_sig = Ed25519_sign(client_key, LABEL_CLIENT || TH_2)
```

Signing over the transcript (which includes both nonces and both ephemeral keys)
binds each identity to *this* ECDH, defeating MITM, key-compromise-impersonation,
and handshake replay: a replayed `ClientHello` produces a different `server_nonce`
⇒ different `TH_2` ⇒ the replayed `client_sig` fails verification.

### 5.3 Shared secret and session keys

```
ss          = X25519(server_eph_priv, client_eph_pub)      # server side
            = X25519(client_eph_priv, server_eph_pub)      # client side  (crypto::x25519_shared_secret)
session_id  = TH_2                                          # 32 bytes, unique per connection
K_c2s       = derive_direction_keys(ss, TH_2, session_id, b'C')   # transport.rs, verbatim
K_s2c       = derive_direction_keys(ss, TH_2, session_id, b'D')
```

Reusing `derive_direction_keys` unchanged gives two independent 512-bit
directional keys (K_1 length-key + K_2 payload-key) exactly as the AEAD record
layer expects. `ss` MUST be rejected if it is all-zero (low-order-point / contributory
check) ⇒ REJECT (defends against a peer forcing a known shared secret).

### 5.4 State machine

Server side (the hostile-input side — this is the fuzz/Kani target):

```
        ┌────────────┐  recv 86 bytes
 START ─┤ WAIT_HELLO ├───────────────► validate ClientHello (§10 rows H1–H5)
        └────────────┘                    │ fail → REJECT+drop
                                          ▼
                                 compute ss (§5.3), reject all-zero ss
                                          │
                                          ▼
                                 acquire session slot from fixed pool
                                   (pool full → REJECT+drop, §10 row S1)
                                          │
                                          ▼
                                 send ServerHello ; derive K_c2s/K_s2c
                                          │
                                          ▼
                               ┌────────────────┐  recv data record @ seq0
                               │ WAIT_CLIENTAUTH ├──► open_packet (auth) 
                               └────────────────┘      │ fail → REJECT+drop
                                          │             (release slot)
                                          ▼
                              inner len == 64 ? verify client_sig over
                              LABEL_CLIENT||TH_2 with client_id_pub
                                   │ fail → REJECT+drop (release slot)
                                          ▼
                                  ┌─────────────┐
                                  │ ESTABLISHED │  session live (§7, §8)
                                  └─────────────┘
```

Client side is the mirror: send `ClientHello`; on `ServerHello`, verify
`server_host_pub` equals the pinned key for this server (`constant_time_equals`)
and verify `server_sig` over `LABEL_SERVER||TH_1`; on success derive keys and send
sealed `ClientAuth`; else abort.

**One shot, no negotiation, no retries.** BSP offers a single crypto suite
(X25519 / Ed25519 / ChaCha20-Poly1305 / SHA-256) — there is no algorithm
negotiation to downgrade. Any handshake fault drops the connection; the client
must open a fresh connection to retry. A **handshake timeout** (`HS_TIMEOUT`,
§6) bounds every pre-`ESTABLISHED` state so a peer cannot pin a session slot by
stalling.

---

## 6. Explicit maximum sizes (build-time pool sizing)

Every variable-length element and every pool is a compile-time `const`. Proposed
starting values (tune to the boot memory budget in the Stage PR; the *values* are
tunable, the *presence of a hard const bound on each* is not):

| Const | Value | Governs / rationale |
|---|--:|---|
| `BSP_MAGIC` | `"BSP1"` | 4-byte protocol tag |
| `BSP_VERSION` | `1.0` | major/minor |
| `LEN_CLIENT_HELLO` | `86` | fixed handshake msg 1 |
| `LEN_SERVER_HELLO` | `144` | fixed handshake msg 2 |
| `LEN_CLIENT_AUTH` | `64` | fixed handshake msg 3 (inner) |
| `BSP_MAX_RECORD_PLAINTEXT` | `4096` | max BSP message bytes per data record; `≤` AEAD internal buffer (§4.2) |
| `MAX_PROMPT_BYTES` | `16384` | total prompt per request; fixed **per-session** BSS buffer. Reassembled across `PromptChunk` records |
| `MAX_PROMPT_CHUNK` | `4032` | one `PromptChunk` payload; `≤ BSP_MAX_RECORD_PLAINTEXT − header` |
| `MAX_TOKEN_CHUNK` | `512` | one outbound `TokenChunk` payload |
| `MAX_TOKENS_REQUESTED` | `4096` | ceiling on `max_tokens` a request may ask for |
| `MAX_SESSIONS` | `8` | fixed session-slot pool (whole server). New handshake when full ⇒ REJECT |
| `MAX_INFLIGHT_PER_SESSION` | `1` | at most one active inference per session; a second `InferBegin` before `StreamEnd` ⇒ REJECT |
| `HS_TIMEOUT` | `5 s` | wall-clock bound on each pre-`ESTABLISHED` state |
| `IDLE_TIMEOUT` | `120 s` | max idle in `ESTABLISHED` before server teardown |
| `MAX_RECORD_SEQ` | `u32::MAX` | per-direction; reaching it forces teardown (§7.4) |

**Total inbound serving memory is therefore fixed at build time:**
`MAX_SESSIONS × (session control block + MAX_PROMPT_BYTES + 2 × BSP_MAX_RECORD_PLAINTEXT + K_c2s + K_s2c + KV region)`.
No client input changes this figure (INV-MEM).

---

## 7. Session lifecycle

### 7.1 Session slot (fixed pool)

A `static` array `SESSIONS: [SessionSlot; MAX_SESSIONS]` (BSS). Each slot holds:
directional keys `K_c2s`/`K_s2c`, the two sequence counters, `session_id` (=`TH_2`,
for logging/audit only — never wire-addressable), the reassembly state, the
per-session `prompt_buf: [u8; MAX_PROMPT_BYTES]`, the reserved KV region handle,
and a state enum. Slots are acquired at §5.4 "acquire session slot" and released
on teardown. **The slot index is server-internal and never appears on the wire.**

### 7.2 Establish

On reaching `ESTABLISHED` (§5.4), the slot is bound 1:1 to this connection.
Per-session key material is unique (fresh ephemeral ECDH → unique `ss` → unique
`TH_2` → unique `K_c2s`/`K_s2c`), so no two live sessions share keystream, and a
record sealed for one session **cannot** authenticate under another's keys
(cross-session confusion is cryptographically foreclosed, not merely
access-checked — INV-SERVE).

### 7.3 Capability grant (frozen)

Establishing grants exactly one capability: *serve inference within this slot*.
It authorizes reading this slot's `prompt_buf`, running the single served model
against it, and writing tokens back on this connection. It authorizes **nothing
else** — no other slot, no weights mutation, no spawn, no kernel call, no network
egress. The grant is frozen at accept and BSP defines no message to widen it
(INV-AUTH, INV-MODEL). The served model runtime that consumes `prompt_buf` runs
under its own frozen capability manifest (INV-MODEL) and cannot name any other
slot regardless of prompt content.

### 7.4 Teardown

Session ends on: client `Close` (§8.2), server `Close` (idle/limits), any record
that fails to authenticate or decode (§10 fail-closed), `IDLE_TIMEOUT`, or
sequence exhaustion. Teardown **zeroizes** `K_c2s`, `K_s2c`, `prompt_buf`, and the
KV region, resets the sequence counters, and returns the slot to the free pool.
No teardown path leaks a slot (else `MAX_SESSIONS` degrades — a DoS). Teardown is
idempotent and reachable from every non-`FREE` state.

---

## 8. Message types (data phase)

Inner payload of an AEAD data record: `type[1] || body`. Unknown/again `type` in
the current session state ⇒ REJECT (§10). Client→server tags are `0x0X`;
server→client tags are `0x8X`. **No message carries a session/KV/weights
selector** (INV-SERVE, INV-MODEL): the only correlation field is `request_id`,
defined below and structurally inert.

### 8.1 `request_id` — scoped, inert correlation token

`request_id: u32` is a client-chosen opaque tag echoed by the server on that
request's responses so the client can correlate streams **within its own
session**. It is **NOT** an index, handle, offset, or key into any server-side
structure. The server validates it only as: "equals the `request_id` of the
in-flight request in *this* slot." It never selects a session, a KV entry, a
weights view, or a buffer. A duplicate/garbage `request_id` cannot reach another
session because it is only ever compared within the one slot bound to this
connection. (This is the concrete realization of "no field lets one client name
another's session".)

### 8.2 Client → server

| Tag | Name | Body | Rules |
|--:|---|---|---|
| `0x01` | `InferBegin` | `request_id[4]`, `max_tokens[4]`, `temperature[2]` (u16 fixed-point /1000), `top_p[2]` (u16 /1000), `prompt_total_len[4]` | `max_tokens ≤ MAX_TOKENS_REQUESTED`; `prompt_total_len ≤ MAX_PROMPT_BYTES`; slot MUST be `ESTABLISHED`/idle (no in-flight request) — else REJECT. Opens a request; server zeroes reassembly, records declared length |
| `0x02` | `PromptChunk` | `request_id[4]`, `chunk[u16 len ≤ MAX_PROMPT_CHUNK]` | `request_id` MUST match the open request; running total `+ len` MUST be `≤ prompt_total_len` **and** `≤ MAX_PROMPT_BYTES` — else REJECT. Appends into fixed `prompt_buf`; the cap is the buffer size, never `len` |
| `0x03` | `InferCommit` | `request_id[4]` | accumulated bytes MUST equal `prompt_total_len` — else REJECT. Hands `prompt_buf[..total]` to the confined model; server enters streaming |
| `0x04` | `Cancel` | `request_id[4]` | cancels the in-flight request; server stops streaming, emits `StreamEnd{finish=CANCELLED}`, returns to idle |
| `0x05` | `Close` | (empty) | graceful teardown (§7.4); server replies `Bye` then closes |

Splitting the prompt into `InferBegin`/`PromptChunk`/`InferCommit` keeps every
record `≤ BSP_MAX_RECORD_PLAINTEXT` while allowing prompts up to
`MAX_PROMPT_BYTES`, with reassembly bounded by a fixed per-session buffer — no
client length ever sizes memory.

### 8.3 Server → client

| Tag | Name | Body | Rules |
|--:|---|---|---|
| `0x81` | `Accepted` | `request_id[4]` | acks a valid `InferCommit`; streaming begins |
| `0x82` | `TokenChunk` | `request_id[4]`, `tokens[u16 len ≤ MAX_TOKEN_CHUNK]` | one or more emitted; `tokens` are opaque model output bytes, rendered by the client (never interpreted as control by BSP) |
| `0x83` | `StreamEnd` | `request_id[4]`, `finish_reason[1]` | `finish_reason ∈ {0 OK, 1 LENGTH (hit max_tokens), 2 CANCELLED, 3 MODEL_ERROR}`; returns slot to idle |
| `0x8E` | `Error` | `request_id[4]` (or `0` if none), `error_code[2]` | non-fatal protocol error at message level; see §10 for which faults are `Error`-then-continue vs. drop |
| `0x8F` | `Bye` | (empty) | teardown ack; connection closes after |

### 8.4 What is deliberately absent (INV-MODEL / INV-SERVE)

There is **no** message to: select or name a model or weights file; load, patch,
or measure weights; name a session id, KV slot, or another client; request a
kernel operation, spawn, file, or network action; set arbitrary server config; or
carry in-band terminal/control sequences. The served model is reachable **only**
as "run the one confined model over this slot's prompt bytes." A poisoned or
hijacked model (trusted-but-uncomfortable, THREAT_MODEL §trust boundary) therefore
cannot use BSP to escape its session: BSP grants it no nameable target beyond its
own slot's output stream.

---

## 9. Defence of the top-ranked threats

**Threat #1 — hostile remote clients and the inbound protocol (THREAT_MODEL).**
The entire pre-`ESTABLISHED` path (§5) and message decoder (§8) is a `#![no_std]`,
zero-alloc, fail-closed parser. Handshake messages are fixed-length ⇒ the
decoder is total and Kani-provable (no length arithmetic on client input at all).
Data records are authenticated by `open_packet` **before** the message decoder
runs, so an unauthenticated attacker cannot even reach §8 parsing — only the
handshake decoder faces fully-unauthenticated bytes, and it does no allocation
and no client-sized copy. Every malformed length/offset/tag denies and drops
(§10). No pool is ever grown from client input (INV-MEM). Downgrade is
impossible (single suite). Replay/reorder is closed by transcript-bound
signatures + monotonic AEAD sequence nonces.

**Threat #2 — hostile prompts against the served model (THREAT_MODEL).** BSP caps
the blast radius to the attacker's own slot: the prompt is opaque bytes copied
into *this session's* fixed buffer and handed to a model confined by its own
frozen capability manifest (INV-MODEL). BSP exposes the model no field to name
another session, the weights, the kernel, or the network. Cross-session reads are
cryptographically foreclosed (§7.2): even a model that "wanted" to answer for
another client has no BSP channel to another slot's keys or KV. Prompt-injection
thus stays within the confined tenant; INV-SERVE + INV-MODEL hold under any
prompt.

---

## 10. Threat / rejection table (fail-closed behavior)

"Drop" = terminate the connection, release any acquired slot, zeroize its key
material (§7.4). "Error+keep" = emit `Error{code}` and remain `ESTABLISHED`,
consuming the offending record. Handshake faults are **always Drop** (no
authenticated session to keep, and no partial-trust state). Every row is a
Kani/fuzz assertion target.

| # | Malformed-input class | Detected by | Fail-closed action |
|---|---|---|---|
| H1 | `ClientHello` length ≠ 86 | handshake reader (fixed len) | Drop |
| H2 | `magic` ≠ `"BSP1"` / bad version | §5.1 field checks | Drop |
| H3 | `client_id_pub` not in `CLIENT_ALLOWLIST` | allowlist lookup | Drop (no oracle; same path/timing as H4 via constant-time compare) |
| H4 | malformed/invalid `client_eph_pub` (not a valid point) or all-zero `ss` | X25519 + §5.3 check | Drop |
| H5 | client fails to send `ClientAuth` / stalls | `HS_TIMEOUT` | Drop |
| H6 | `ClientAuth` record fails AEAD auth (`open_packet` → None) | `transport::open_packet` | Drop |
| H7 | `ClientAuth` inner length ≠ 64, or `client_sig` invalid over `LABEL_CLIENT‖TH_2` | Ed25519 verify | Drop |
| H8 | (client side) `server_host_pub` ≠ pinned, or `server_sig` invalid | client verify | Drop (client aborts) |
| S1 | no free session slot at handshake | pool acquire | Drop (server at capacity; existing sessions unaffected — INV-SERVE) |
| R1 | AEAD `enc_length` decodes `< 2` or `> 35000` | `open_packet` bound | Drop |
| R2 | AEAD tag mismatch (forged/corrupt/replayed record) | `open_packet` Poly1305 | Drop |
| R3 | record at unexpected sequence (replay/reorder/gap) | seq mismatch ⇒ auth fail | Drop |
| R4 | inner payload > `BSP_MAX_RECORD_PLAINTEXT` | `payload_out` bound | Drop |
| R5 | sequence would exceed `MAX_RECORD_SEQ` | counter guard | Drop (teardown) |
| M1 | unknown `type` tag | message decoder | Error+keep (`ERR_BAD_TYPE`) or Drop if policy-strict |
| M2 | message body shorter than its fixed fields | fixed reader | Drop (framing-level corruption inside an authenticated record ⇒ treat as attack) |
| M3 | var-bytes `len` > field MAX (`MAX_PROMPT_CHUNK` / `MAX_TOKEN_CHUNK`) | §3 reader | Drop |
| M4 | `InferBegin` with `max_tokens > MAX_TOKENS_REQUESTED` or `prompt_total_len > MAX_PROMPT_BYTES` | §8.2 check | Error+keep (`ERR_LIMIT`) |
| M5 | second `InferBegin` while a request is in-flight (> `MAX_INFLIGHT_PER_SESSION`) | slot state | Error+keep (`ERR_BUSY`) |
| M6 | `PromptChunk`/`InferCommit`/`Cancel` `request_id` ≠ open request | slot state | Error+keep (`ERR_NO_REQUEST`) |
| M7 | `PromptChunk` running total > declared `prompt_total_len` or > `MAX_PROMPT_BYTES` | reassembly guard | Drop (declared-length lie ⇒ attack) |
| M8 | `InferCommit` accumulated ≠ declared `prompt_total_len` | commit check | Error+keep (`ERR_INCOMPLETE`) |
| M9 | message of a type invalid in the current state (e.g. `PromptChunk` before `InferBegin`) | state guard | Error+keep (`ERR_STATE`) |
| T1 | idle past `IDLE_TIMEOUT` | timer | Drop (server `Bye` then close) |

**Design rule for the M-rows:** anything that could only arise from a
*non-conforming or hostile* client after authentication and that indicates
*framing/state corruption* (M2, M3, M7) is **Drop**, because inside an
authenticated channel such corruption implies a broken/hostile peer, not a
recoverable hiccup. Faults that a benign client could plausibly hit (over-limit
request, busy, incomplete) are **Error+keep** to be usable without weakening
isolation. Both branches are fail-closed: neither ever allocates or advances
state on bad input. (The Drop-vs-Error boundary for M1 and the M-rows is the one
policy knob flagged for the owner — see §12.)

---

## 11. Verification obligations (Kani + fuzz)

BSP MUST ship with these before facing real clients (THREAT_MODEL INV-SERVE
"how we know"):

- **Fuzz targets** (libFuzzer/AFL, host, `#![no_std]`-compatible harness):
  1. handshake decoder — arbitrary bytes into `WAIT_HELLO` / `WAIT_CLIENTAUTH`;
     assert never panics, never allocates, only ever `ESTABLISHED` on a
     well-formed authenticated transcript;
  2. message decoder — arbitrary authenticated-plaintext bytes into every slot
     state; assert total, no panic, no out-of-bounds, no state advance on REJECT;
  3. reassembly — arbitrary `InferBegin`/`PromptChunk`/`InferCommit` sequences;
     assert `prompt_buf` writes never exceed `MAX_PROMPT_BYTES` and totals are
     exact.
- **Kani harnesses:**
  1. every §3 reader is total and bounds-checked for all inputs (no OOB, no
     panic);
  2. the handshake state machine reaches `ESTABLISHED` **iff** all H-row checks
     pass, for all inputs;
  3. no reachable path sizes/indexes a buffer from a client-supplied length or
     offset (INV-MEM proof obligation);
  4. teardown from every non-`FREE` state returns the slot and zeroizes keys (no
     slot leak).
- **Isolation property test:** two concurrent sessions with distinct ephemeral
  keys — a record sealed for session A never authenticates for session B; no
  `request_id` value routes across slots (INV-SERVE).

---

## 12. Open questions for the owner

1. **M1 / M-row Drop-vs-Error policy.** Should an unknown message `type` or a
   post-auth framing fault (M2/M3) drop the connection (strict, treat any
   deviation inside an authenticated channel as hostile) or emit `Error` and
   continue (lenient, more usable)? Spec defaults strict for
   framing/state-corruption rows and lenient for limit/busy rows; confirm the
   boundary.
2. **`MAX_SESSIONS` = 8 and `MAX_PROMPT_BYTES` = 16 KiB.** These set the fixed
   inbound memory budget. Need the real boot memory budget to finalize; also
   whether concurrency should be higher than 8 for the CPU-inference MVP given
   `MAX_INFLIGHT_PER_SESSION = 1`.
3. **Prompt fragmentation vs. single-record.** Spec chose 3-message prompt
   assembly to keep records `≤ 4 KiB` and prompts `≤ 16 KiB`. If prompts are to be
   capped at one record instead, `MAX_PROMPT_BYTES` drops to ~`4 KiB` and
   `PromptChunk`/`InferCommit` disappear. Confirm the larger-prompt need.
4. **Client authorization model.** Spec pins client identities in a compile-time
   `CLIENT_ALLOWLIST` (strict, no-TOFU, mirrors `client_identity.rs`). If clients
   must be provisioned at runtime, that needs a separate signed-manifest
   mechanism (still no TOFU) — out of scope for v1 but flagged.
5. **Host-key provenance.** `server_host_pub` is a dev seed today; wiring it to
   the measured/sealed key depends on the unmet vTPM/swtpm dependency
   (THREAT_MODEL §0). Until then BSP's server authentication degrades to the
   honest software-only fallback, same as INV-BOOT.
6. **Rekeying.** v1 tears down at `MAX_RECORD_SEQ` rather than rekeying. For the
   expected session volume this is ample; confirm no long-lived session needs
   in-session rekey (would add a `Rekey` handshake sub-exchange).
7. **Transport buffer const.** `BSP_MAX_RECORD_PLAINTEXT = 4096` matches the
   current hardcoded `transport.rs` plaintext buffer. If raised, that buffer must
   become a shared named `const`; confirm 4 KiB records are acceptable.
