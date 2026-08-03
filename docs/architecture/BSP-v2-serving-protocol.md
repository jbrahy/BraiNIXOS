# BSP v2 — BraiNIX Serving Protocol (pre-shared-key inbound wire protocol)

**Task:** Wave 2 BSP v2 protocol spec — design only, no implementation, no git.
**Supersedes:** `docs/architecture/BSP-v1-serving-protocol.md` (P2-T1). v1's
signature-over-ephemeral-key-agreement handshake is obsolete; its record layer,
its sizing discipline, and its message grammar are retained here.
**Authoritative parents:** `docs/NORTH_STAR.md`, `docs/THREAT_MODEL.md`,
`docs/security/SECURITY_INVARIANTS.md`.
**Governs:** the single authenticated, capability-gated inbound socket a remote
client uses to reach the confined inference tenant, and the second session type
on that same socket by which the machine is administered.
**Status:** design spec. Precise enough to drive Kani harnesses and libFuzzer/AFL
targets against every parser and every state transition. Nothing here rests on
obscurity (NORTH_STAR "Structure over secrecy"). **Nothing here is implemented** —
see §14, which states exactly what does not exist yet.

This spec is normative. "MUST", "MUST NOT", "REJECT" are hard requirements.
"REJECT" always means the fail-closed action defined in §12 (deny, do not
allocate, do not grow a pool, do not advance persisted state, and — for
framing/decoder faults — drop the whole connection). Absence of an explicit
accept path is denial (NORTH_STAR "Fail closed").

**Why v2 exists.** Owner decision 7 of 2026-08-02 removed asymmetric cryptography
from the serving transport entirely. BSP v1 §5 authenticated static signature
identities over an ephemeral elliptic-curve key agreement; v2 authenticates by
proof of possession of a pre-shared key and derives session keys with HKDF-SHA256.
The two costs of that decision are stated once here and again where they bite:

- **There is no forward secrecy until the ratchet of §6 ships.** A disclosed
  pre-shared key retroactively decrypts every recorded session for the entire
  lifetime of that key. This is the current state of the system, not a
  hypothetical future risk (`INV-BOOT-007`, THREAT_MODEL §"The serving
  transport").
- **Wire compatibility with stock OpenSSH clients is forfeited.** OpenSSH has no
  pre-shared-key mode, and the one key exchange that avoids curve arithmetic —
  `diffie-hellman-group14-sha256` — requires constant-time bignum modular
  exponentiation, a harder assurance problem than curve25519. Clients speak BSP
  or they do not connect (NORTH_STAR §"Named crypto exception").

---

## 0. Non-negotiables inherited

From NORTH_STAR hard lines and THREAT_MODEL §"Dominant threats" — *No remote
attestation, anywhere* (renamed there on 2026-08-03 when x86-64 was dropped; it
was *No remote attestation on the primary platform*) and *Hostile remote clients
and the inbound protocol*. **This spec cites dominant threats by name, never by
rank.** That list is explicitly a re-ranking for the shipping deployment, so a
rank is a moving target and a rank citation rots silently; BSP v1 carried three
such citations and all three went stale. A *name* can still change — as one just
did — but it changes visibly and is repaired in one place.

- **No new external crate.** BSP uses exactly four primitives: **SHA-256, HKDF,
  ChaCha20, Poly1305**. All four are constant-time by construction (fixed
  schedule / ARX, no data-dependent branches, no table lookups) and are specified
  to be in-tree. Honest status: `sha2` and `chacha20` are **still vendored today**
  and the in-tree reimplementation has not landed (NORTH_STAR §"What advancing the
  goal means"). No AES, no TLS, no KEM, and **no asymmetric cryptography of any
  kind** — the Ed25519 verification stack that stays vendored under the named
  crypto exception serves INV-BOOT's release signature and is reachable from no
  network path.
- **Authentication proves key possession, not machine integrity.** On the primary
  platform there is no attestation and none can be added (INV-BOOT/AS). A client
  that completes a BSP handshake has learned that its peer holds the credential;
  it has **not** learned that the peer is running an unmodified BraiNIX. Nothing
  in this protocol can supply that, and no wording in it may imply otherwise.
- **`#![no_std]`, zero-allocation.** No `alloc`, no `#[global_allocator]`. Every
  buffer is a compile-time-sized `static`/stack array. No pool is ever sized,
  grown, or indexed from a client-supplied length, offset, or tag (`INV-MEM`,
  `INV-SERVE-002`).
- **Fail closed.** Any malformed length, offset, tag, confirmation value, counter,
  or state violation denies. The connection/auth/request decoder is the largest
  attack surface the project controls (THREAT_MODEL); it is a hostile-input parser
  (`INV-PARSE-001`), fuzzed and Kani-checked before it faces real clients
  (`INV-PARSE-002`).
- **No secret ever enters a build artifact.** Every credential is enrolled at
  runtime and persisted by the kernel's credential store (`INV-BOOT-006`,
  `INV-BUILD-004`). There is no compile-time allowlist of client keys in v2 —
  v1's `CLIENT_ALLOWLIST` is gone, because a compiled-in credential is
  structurally incompatible with INV-BOOT's reproducible-build clause.
- **Structure over secrecy.** Every field, bound, derivation, and rejection path
  is public. Security is the capability/isolation structure and the key schedule,
  never the attacker's ignorance of the format.

---

## 1. Invariant mapping (what BSP exists to enforce)

| Invariant | How BSP enforces it |
|---|---|
| **INV-SERVE** / `INV-SERVE-001` (mutual client isolation) | **No wire field names a session, KV slice, weights view, or peer.** A session *is* the authenticated AEAD channel; it is keyed by per-session material and addressed internally by the accept-time connection binding, never by a client-supplied handle (§9, §10). |
| `INV-SERVE-002` (no client-sized allocation) | Every bound in §8 is a `const`. A client length is only ever compared against a `const`; it never sizes, grows, or indexes a pool (§3). |
| `INV-SERVE-003` (bounded admission) | `MAX_SESSIONS`, `MAX_ADMIN_SESSIONS`, and `MAX_SESSIONS_PER_CREDENTIAL` are `const`, and the per-credential limit counts **half-open** handshakes as well as established sessions (§9.1). |
| `INV-SERVE-004` (complete teardown) | Teardown zeroizes both directional key sets, the session chain key, `prompt_buf`, and the KV region, and returns the slot (§9.4). |
| `INV-SERVE-005` (observable to the auditor) | Connection, selector-match, authentication, capability-grant, admin-verb, and denial events are emitted to `auditd` (§9.5). Visibility grants no authority. |
| **INV-MODEL** (served model is a confined tenant) | BSP carries **only** prompt bytes in and token bytes out on a client session. It exposes **no** field that selects a model, loads weights, names another session, or requests any kernel/spawn/network action (§10.6). Weight activation exists only as an admin verb on a *different* capability (§10.4). |
| **INV-AUTH** / `INV-AUTH-009` (no ambient authority; admin is a capability, not a shell) | A completed handshake grants exactly one capability — `CapServe` for *this* session, or `CapAdmin` — determined by the credential record and **never by a wire field** (§7). Frozen at accept. BSP defines no message that widens it, and the admin verb set is exactly six (§10.4). |
| `INV-AUTH-008` (auditable authority flow) | Enrollment, revocation, and every admin verb and denial are distinct attributable events (§10.4). |
| `INV-BOOT-006` (runtime enrollment) | Credentials arrive over the admin channel (§10.4) or the serial console, and nowhere else. No credential is compiled in. |
| `INV-BOOT-007` (ratchet) | Session key *n* derives from chain key *n*; the chain advances and chain key *n* is zeroized, as one operation, at the transition to `ESTABLISHED` (§6). |
| `INV-BOOT-008` (break-glass) | The break-glass credential **never authenticates on this transport** — the network listener refuses it at selector match (§2.5, §12 row K5) — and `enroll-key` and `revoke-key` both refuse its handle, unconditionally and non-configurably (§7.3, §10.4). |
| `INV-BUILD-004` (no secret in a build artifact) | v1's compile-time `CLIENT_ALLOWLIST` is deleted. The wire protocol has no compile-time secret of any kind. |
| `INV-MEM` (W^X, fixed pools, no heap) | All sizes in §8 are `const`. Session pool, credential table, per-session prompt buffer, and record buffers are build-time-sized BSS. No handshake, request, or admin verb ever allocates. |
| `INV-FAIL-003` (secure degradation) | Ratchet desynchronization denies the session and is recoverable only by re-enrollment or the serial console (§6.4). It never falls back to an un-ratcheted key. |
| `INV-PARSE-001`, `INV-PARSE-002` | The handshake decoder, the record layer, and the message decoder are `no_std`, zero-allocation, fail-closed, and each ships a fuzz target *and* a Kani harness (§13). |
| **INV-BOOT** | Out of scope for the wire protocol. The credential store's at-rest protection is INV-BOOT's concern and is **not implemented** on either platform today (§2.4, §14). |

Proof tier, per `docs/security/SECURITY_INVARIANTS.md` §16: the BSP request
parser, the transport crypto, and the credential store are all **Full** tier —
invariant mapping, fuzz, Kani, Prusti, audit report, and no-regression bars. None
of the three is a Reduced-tier component, and this document is the invariant
mapping artifact for the first two.

---

## 2. Roles, credentials, and trust

### 2.1 The two parties

- **Server (BraiNIX).** Terminates the transport in `servd`, which is **outside
  the TCB** and stays there (THREAT_MODEL §"Trust boundary"). It reads credential
  material from the kernel's credential store, which **is** in the TCB.
- **Client (remote, hostile until proven).** Holds one credential. It is
  authenticated **and** authorized by that credential alone: there is no
  registration-on-first-use, no fallback, and no anonymous mode.

Everything outside the server TCB — every inbound byte, the client, the prompt,
the emitted tokens — is hostile (THREAT_MODEL attacker model).

### 2.2 A credential

A credential is enrolled from **32 bytes of uniformly random key material** and
is expanded once, at enrollment, into the four values the system actually keeps
(§5.2). After that expansion the enrolled bytes are zeroized and never stored.
Each credential record holds:

| Field | Size | Purpose |
|---|--:|---|
| `handle` | 16 | Non-secret administrative handle. Used by `revoke-key`. **Never appears pre-key on the wire.** |
| `K_id` | 32 | Stable identification secret. Never advances. Used only to compute and match the per-connection selector (§5.3). |
| `CK_n` | 32 | Chain key at position *n*. Advances (§6). |
| `counter` | 8 | Chain position *n*, big-endian `u64`. |
| `role` | 1 | `0x01` = client (`CapServe`), `0x02` = admin (`CapAdmin`). |
| `flags` | 1 | Bit 0: break-glass. No other bit is defined; a set undefined bit fails the record closed. |

`K_id` and the chain are separated deliberately: identification MUST survive a
ratchet advance, and a desynchronized client MUST still be identifiable so the
failure can be reported and audited rather than presenting as an unknown peer.
Making the selector a function of the chain would have coupled the two and turned
every desync into an indistinguishable "unknown credential".

### 2.3 What a stolen credential yields

A client credential is the whole of that client's identity. An attacker holding
one opens sessions as that client and decrypts and forges that client's records.
It does **not** yield another client's sessions: every credential is distinct and
`INV-SERVE-001` is enforced after authentication regardless of which credential
authenticated. A stolen *admin* credential yields the six verbs of §10.4 and
nothing outside them (THREAT_MODEL §"The admin channel's blast radius").

### 2.4 The credential store at rest — not protected today

Stated because the transport's entire security rests on it, and because asserting
an unbuilt control would violate NORTH_STAR's "every claim is falsifiable":

The credential store is **plaintext at rest, permanently** (owner ruling
2026-08-02, made unconditional 2026-08-03). Anyone who obtains the disk obtains
every client and admin credential. Sealing means binding a secret to a measured
boot state, and the only platform has neither the measurement nor the hardware.
`src/kernel/src/boot/credential_store.rs` persists to disk and seals nothing, and
that is the end state, not a pending task.

~~*x86-64 (attested):* the credential store is specified to be TPM-sealed…~~ —
**deleted 2026-08-03 with the platform.** There is no target on which sealing
could ship, so there is no route out and no better-configured deployment to
point at.

Combined with the absent forward secrecy, this is THREAT_MODEL's dominant threat
*Credential-store disclosure, retroactively*: physical possession of the machine,
a decommissioned drive, or a backup is a total, retroactive loss of serving
confidentiality. BSP cannot mitigate it. BSP can only avoid making it worse, and
§6 is the mechanism that will.

### 2.5 The break-glass credential — serial only, never on this transport

One admin credential carries the break-glass flag. **Owner ruling, 2026-08-02: it
authenticates over the serial transport and nowhere else.** The network listener
this document governs MUST refuse it outright, before any other check that could
depend on it (§12 row K5). It is provisioned over the serial console and only
over the serial console (`INV-BOOT-008`), and neither `enroll-key` nor
`revoke-key` will touch it, so it cannot be revoked or replaced by a compromised
admin session. That is why it exists: physical presence wins, and the owner cannot
be permanently locked out of the owner's own machine.

This is what `docs/NORTH_STAR.md` already says — "the serial console is the
break-glass path when the network path is unusable or untrusted" — and what
`INV-AUTH-009` already says: "the serial console — **not a network path** — is the
break-glass channel." A protocol spec may not resolve a north-star silence by
widening, and the earlier draft of this section did exactly that.

The security reason, beyond the authority argument: under the at-rest ruling of
§2.4 the credential store is plaintext on disk, on the only platform there is. A
network-capable break-glass credential would therefore be a **permanent,
by-definition-unrevocable remote administrative credential recoverable by disk
theft** — the one credential an attacker most wants and the one the design
deliberately refuses to make remotely usable. Its cost stays what it always was
and is not softened: it is long-lived by construction, and its disclosure is
repairable only by physical presence.

---

## 3. Byte-encoding primitives (the only encodings BSP uses)

All integers **big-endian**. There are exactly three encoding forms; the decoder
implements one reader each, and nothing else:

1. **Fixed scalar** — `u8`, `u16`, `u32`, `u64`. Fixed width; a short buffer ⇒
   REJECT.
2. **Fixed array** — an exactly-N-byte field (e.g. a 32-byte nonce). Reader
   requires ≥ N remaining bytes or REJECT. **No length prefix.**
3. **Bounded var-bytes** — `u16 len` followed by `len` bytes, where `len` MUST be
   `≤ MAX` for that specific field (the MAX is a `const`, §8). The reader checks,
   in order: (a) ≥ 2 bytes remain for the length; (b) the decoded
   `len ≤ MAX_field`; (c) ≥ `len` bytes remain. Any check fails ⇒ REJECT. The
   `MAX` is **always** the compile-time cap, never the value just read — the
   destination buffer is pre-sized to `MAX_field`; `len` only bounds a copy into
   it (`INV-SERVE-002`).

**Handshake messages carry no var-bytes at all** — every handshake field is a
fixed scalar or fixed array (§5.1). This makes the handshake decoder total and
trivially Kani-provable: message length is a constant, and any deviation from the
exact expected length is a single REJECT. It also matters cryptographically: the
transcript hashes of §5.4 are taken over inputs whose length is a compile-time
constant, so there is no canonicalization ambiguity and no length-extension
question to argue about.

There is no self-describing/TLV recursion, no length that governs a following
length, no compression, and no in-band control bytes. Structure is decided by the
tagged type, never interpreted from the byte stream.

---

## 4. Framing (record layer) — retained unchanged from v1

BSP runs over a reliable ordered byte stream (one TCP connection). Bytes on the
wire are a sequence of **records**. There are two record classes, separated by the
handshake.

### 4.1 Handshake records (plaintext, pre-key)

The three handshake messages (§5.1) are sent as raw fixed-length byte blocks —
**no length prefix on the wire**, because each message type has a single constant
length known to both sides from the state machine (§5.5). The receiver, in a
given handshake state, expects **exactly** the byte count for the message due in
that state; it reads that many bytes and no reader ever consults a client-supplied
length. A byte count that cannot be reached (peer sends fewer, then stalls past
`HS_TIMEOUT`) ⇒ REJECT + drop.

### 4.2 Data records (AEAD, post-key)

Every post-handshake record is an authenticated `chacha20-poly1305@openssh.com`
frame. The construction is retained verbatim from v1, which took it verbatim from
the in-tree `transport::seal_packet` / `transport::open_packet`:

```
data_record := enc_length[4] || ciphertext[packet_length] || tag[16]
```

The construction is kept for its properties, **not** for interoperability — there
is none, and §0 says so. The properties are: the length field is encrypted under a
separate key `K_1`, so a passive observer learns record boundaries only by
inference; the Poly1305 tag covers the encrypted length *and* the ciphertext, so
length forgery is an authentication failure rather than a parsing problem; and the
tag comparison is constant-time.

`open_packet` enforces, fail-closed:

- decrypts the 4-byte length with `K_1`, then **REJECTs if `packet_length < 2` or
  `packet_length > 35000`** — an absolute, client-independent bound, checked
  **before** any buffer is touched;
- REJECTs on Poly1305 tag mismatch (constant-time compare) — this is the
  authentication check; a forged/replayed/corrupt record never reaches the message
  decoder;
- REJECTs if `padding_length + 1 > packet_length` or if the recovered payload
  would exceed the caller's fixed `payload_out` buffer.

Plaintext inside the frame is `padding_length[1] || payload || padding`, padded so
`1 + payload + padding` is a multiple of 8 with at least 4 padding bytes.

BSP adds two record-layer rules on top:

- **`BSP_MAX_RECORD_PLAINTEXT`** (§8) is the BSP payload ceiling and MUST be `≤`
  the `seal_packet`/`open_packet` internal plaintext buffer (today `4096`). The
  `payload_out` BSP passes is a `BSP_MAX_RECORD_PLAINTEXT` BSS buffer; a larger
  inner packet ⇒ REJECT. If `BSP_MAX_RECORD_PLAINTEXT` is raised above 4096, that
  internal buffer MUST become a shared named `const` in the same change.
- **Sequence numbers** are the per-direction AEAD nonces: a 64-bit big-endian
  nonce whose low 32 bits are the sequence. Each direction starts at `0` at its
  first data record and increments by exactly `1` per record. The receiver derives
  the expected sequence locally; it is **never on the wire**. A record that fails
  to authenticate at the expected sequence ⇒ REJECT + drop, which closes replay
  and reorder. Sequence MUST NOT wrap; on reaching `MAX_RECORD_SEQ` the session is
  torn down (§9.4).

**Code provenance note.** These functions live in `src/kernel/src/ssh/transport.rs`
today. P2-T2 factors them into `src/brainix-transport-crypto/` and P2-T6 deletes
the SSH bridge; the construction survives that move, the SSH protocol around it
does not. One function does **not** survive: `derive_direction_keys` is the SSH
exchange-hash KDF and there is no SSH exchange hash in v2. Directional keys come
from HKDF-Expand (§5.4).

The decoded record payload is a **BSP message** (§10): `type[1] || body`.

---

## 5. Handshake (mutual authentication by proof of PSK possession)

Goal: both parties prove possession of the same credential, bound to a transcript
containing two fresh nonces, yielding independent directional
ChaCha20-Poly1305 keys — using only SHA-256, HKDF, ChaCha20, and Poly1305. Design
is a fixed 1.5-RTT exchange of **160 bytes total**, with no negotiation, no
retries, and no variable-length field anywhere before the keys exist.

### 5.1 Messages (all fixed-length; big-endian; no var-bytes)

**`ClientHello`** (client → server), length **`= 64`**:

| Off | Len | Field | Notes |
|--:|--:|---|---|
| 0 | 4 | `magic` | MUST equal ASCII `"BSP2"` (`0x42 0x53 0x50 0x32`) |
| 4 | 1 | `version_major` | MUST equal `2` |
| 5 | 1 | `version_minor` | MUST equal `0` |
| 6 | 2 | `reserved` | MUST equal `0x0000`. Not a negotiation field; a nonzero value is a REJECT, not an extension point |
| 8 | 8 | `chain_counter` | `u64`, the chain position the client derived from (§6.3) |
| 16 | 32 | `client_nonce` | 32 fresh random bytes; the selector salt and the client's freshness contribution |
| 48 | 16 | `key_selector` | per-connection blinded credential selector, computed over `chain_counter` and `client_nonce` (§5.3) |

**`ServerHello`** (server → client), length **`= 64`**:

| Off | Len | Field | Notes |
|--:|--:|---|---|
| 0 | 32 | `server_nonce` | 32 fresh random bytes from the kernel CSPRNG (`INV-BOOT-005`) |
| 32 | 32 | `server_confirm` | server's proof of possession over `TH_1` (§5.4) |

**`ClientAuth`** (client → server), length **`= 32`**:

| Off | Len | Field | Notes |
|--:|--:|---|---|
| 0 | 32 | `client_confirm` | client's proof of possession over `TH_2` (§5.4) |

`ClientAuth` is a plaintext handshake block, not an AEAD record. v1 sealed its
third message to obtain key confirmation as a side effect; v2 does not need that,
because `client_confirm` is derived from the same `PRK_session` as the directional
keys, so verifying it already proves the client derived that secret. Removing the
AEAD wrapper removes the last pre-`ESTABLISHED` path through the record decoder
and leaves the handshake decoder reading nothing but three constant byte counts.

**There is no session-type field.** Whether a session is a client session or an
admin session is a property of the credential record, never of a client-supplied
byte (§7.1). A wire field that participated in an authority decision would be
ambient authority with a length prefix.

### 5.2 Credential derivation (once, at enrollment)

`HKDF` is RFC 5869 over SHA-256: `Extract(salt, ikm) = HMAC-SHA256(salt, ikm)`,
and `Expand(prk, info, L)` is the standard counter mode. Every `L` below is a
`const` and every `info` is a fixed-length byte string, so no HKDF call in this
protocol has an input whose length depends on the wire.

```
PRK_enroll = HKDF-Extract(salt = LABEL_ENROLL_SALT, ikm = key_material[32])
handle     = HKDF-Expand(PRK_enroll, LABEL_KEY_HANDLE || role, 16)
K_id       = HKDF-Expand(PRK_enroll, LABEL_KEY_ID     || role, 32)
CK_0       = HKDF-Expand(PRK_enroll, LABEL_CHAIN_INIT || role, 32)
zeroize(key_material, PRK_enroll)
```

Both ends run this identically and both then hold `{handle, K_id, CK_0, 0, role}`.
**The enrolled 32 bytes are destroyed on both ends.** This is load-bearing for §6:
if the root were retained, every past chain key would be recomputable from it by
re-running the ratchet, and the ratchet would buy nothing.

`role` is a single byte and is bound into all three expansions, so a credential
enrolled as a client can never produce the identification or chain material of an
admin credential even if a caller passes the wrong role later.

### 5.3 Identifying the credential without leaking it

```
PRK_id       = HKDF-Extract(salt = LABEL_ID_SALT, ikm = K_id)         # precomputable
key_selector = HKDF-Expand(PRK_id, LABEL_SELECTOR || chain_counter || client_nonce, 16)
```

The `info` is `16 + 8 + 32 = 56` bytes and its length is a compile-time constant.

**`chain_counter` is inside the selector, and that is not cosmetic.** It is what
makes the counter unforgeable by anyone who does not hold `K_id`. Without it, a
party who recorded one `ClientHello` could replay it with an arbitrary counter and
force the server to walk up to `MAX_CHAIN_CATCHUP` chain advances per packet,
before admission control had run — unauthenticated compute amplification bounded
by nothing the attacker did not choose. With it, a modified counter simply fails
to match any credential (§12 row K1), and the only counter a replayer can present
is the one the legitimate client used. The consequence is worth stating: once the
server has advanced past that recorded position, the replay costs **zero** chain
advances, because row K3 rejects it on a comparison.

Identification is still independent of chain *state*, which is what §2.2 requires:
the server computes each candidate over the counter it received, not over its own
position, so a desynchronized client — including one at a position the server can
no longer reach — is still identified, and its failure is reported and audited
rather than presenting as an unknown peer.

The client computes `key_selector` and sends it. The server, on receipt, iterates
**every** slot of its fixed credential table:

- for each of the `MAX_ENROLLED_KEYS` slots, compute the candidate selector and
  compare constant-time against the received value;
- accumulate the match with a constant-time select, do not break early, and run
  all `MAX_ENROLLED_KEYS` iterations regardless of when a match occurs;
- empty slots hold a per-boot random `K_id` so their iteration is
  indistinguishable in work and timing from an occupied slot;
- exactly one match ⇒ proceed with that credential, unless its `flags` mark it
  break-glass, which is an unconditional REJECT + drop on this transport (§2.5,
  §12 row K5). Zero matches ⇒ REJECT + drop. Two matches ⇒ REJECT + drop (a
  16-byte collision is a `2^-128`-scale event per pair; treating it as an attack
  costs nothing and avoids an arbitrary choice).

**Why this rather than a stable key id.** A stable public identifier would be
simpler and would make lookup O(1). It would also put a constant on the wire that
links every session of a given client to every other, and it would let anyone
enumerate which identifiers a server accepts. The blinded selector removes both,
and its price is a fixed **`MAX_ENROLLED_KEYS × 5` SHA-256 compressions per
`ClientHello`** — a `const`, not a client-driven quantity. The cost is restated in
§8 and is the reason `MAX_ENROLLED_KEYS` is a hard bound rather than "however many
are enrolled".

**The multiplier, derived, because §5.7 and §8 rest their DoS argument on it.**
`PRK_id` is precomputed, so a candidate costs exactly one `HKDF-Expand` with
`L = 16`, which is one `HMAC-SHA256` over `info || 0x01`. With `PRK_id` at 32 bytes
the HMAC key needs no pre-hashing, so the cost is:

| Hash | Input | Bytes | Compressions (`⌈(n+9)/64⌉`) |
|---|---|--:|--:|
| inner | `ipad[64] \|\| info[56] \|\| 0x01` | 121 | 3 |
| outer | `opad[64] \|\| inner_digest[32]` | 96 | 2 |
| | | | **5** |

Two honest notes. This figure was previously stated as `× 2`, which was wrong
before the `chain_counter` binding and is wrong by more after it. And the binding
itself raised the number: at the former 48-byte `info` the inner hash fit in 2
blocks rather than 3, so the scan cost **4** compressions per candidate and now
costs **5** — a 25% increase in the one quantity an unauthenticated attacker can
scale with packet rate. That is the price of closing the amplification of §5.7,
and it is a good trade — a fixed 25% on a `const` multiplier, against an attacker
choosing up to `MAX_CHAIN_CATCHUP` HKDF advances per packet — but it is a price
and it is recorded as one. Shrinking `LEN_LABEL` to 8 bytes would put `info` back
at 48 and recover the block; uniform 16-byte labels across every derivation are
worth more than one compression per slot, so the block is not recovered.

### 5.4 Transcript hashes and the session key schedule

```
TH_1 = SHA256( ClientHello[0..64] || ServerHello[0..32] )    # ServerHello's nonce only
TH_2 = SHA256( ClientHello[0..64] || ServerHello[0..64] )    # full ServerHello

PRK_session    = HKDF-Extract(salt = TH_1, ikm = CK_m)

server_confirm = HKDF-Expand(PRK_session, LABEL_SRV_CONFIRM || role,          32)
client_confirm = HKDF-Expand(PRK_session, LABEL_CLI_CONFIRM || role || TH_2,  32)
K_c2s          = HKDF-Expand(PRK_session, LABEL_KEYS_C2S    || role,          64)
K_s2c          = HKDF-Expand(PRK_session, LABEL_KEYS_S2C    || role,          64)
session_id     = TH_2
```

`CK_m` is the chain key at the position the client declared (§6.3). Each 64-byte
directional output splits exactly as the record layer expects: bytes `0..32` are
the payload key `K_2`, bytes `32..64` are the length key `K_1`.

`session_id` is internal — used for audit correlation and for nothing else. It is
**never on the wire** and is never a routable name (`INV-SERVE-001`).

`TH_2` in `client_confirm`'s info is redundant: `server_confirm` is itself a
function of `PRK_session`, so `TH_2` adds no material the derivation did not
already depend on. It is included so the binding is legible in the code and
provable directly, without an argument about determinism.

Labels are fixed 16-byte ASCII constants, NUL-padded:

| Constant | Bytes |
|---|---|
| `LABEL_ENROLL_SALT` | `"BSP2 enroll"` + 5 NUL |
| `LABEL_KEY_HANDLE` | `"BSP2 key-handle"` + 1 NUL |
| `LABEL_KEY_ID` | `"BSP2 key-id"` + 5 NUL |
| `LABEL_CHAIN_INIT` | `"BSP2 chain-init"` + 1 NUL |
| `LABEL_CHAIN_SALT` | `"BSP2 chain-salt"` + 1 NUL |
| `LABEL_CHAIN_STEP` | `"BSP2 chain-step"` + 1 NUL |
| `LABEL_ID_SALT` | `"BSP2 id-salt"` + 4 NUL |
| `LABEL_SELECTOR` | `"BSP2 selector"` + 3 NUL |
| `LABEL_SRV_CONFIRM` | `"BSP2 srv-confirm"` (exactly 16) |
| `LABEL_CLI_CONFIRM` | `"BSP2 cli-confirm"` (exactly 16) |
| `LABEL_KEYS_C2S` | `"BSP2 keys c2s"` + 3 NUL |
| `LABEL_KEYS_S2C` | `"BSP2 keys s2c"` + 3 NUL |

Every value the protocol uses is an HKDF output under a distinct label. **No
credential byte is ever used directly as a cipher key**, and no two derived values
are substitutable for one another.

### 5.5 State machine

Server side (the hostile-input side — this is the fuzz/Kani target):

```
        ┌────────────┐  recv exactly 64 bytes
 START ─┤ WAIT_HELLO ├───────────────► validate ClientHello (§12 rows H1–H2)
        └────────────┘                    │ fail → REJECT+drop
                                          ▼
                            constant-work selector scan over the
                            credential table (§5.3, rows K1–K2)
                                   │ no match → REJECT+drop
                                          ▼
                            break-glass? → REJECT+drop, always (row K5)
                                          │
                                          ▼
                            acquire session slot from the fixed pool
                            (pool or per-credential limit full →
                             REJECT+drop, §12 rows S1–S2)
                                          │
                                          ▼
                            resolve chain position from chain_counter
                            into scratch, uncommitted (§6.3, rows K3–K4)
                                   │ behind / too far → REJECT+drop
                                            (release slot)
                                          │
                                          ▼
                            derive PRK_session, both confirms, K_c2s, K_s2c
                            send ServerHello
                                          │
                                          ▼
                             ┌─────────────────┐  recv exactly 32 bytes
                             │ WAIT_CLIENTAUTH ├──► constant-time compare
                             └─────────────────┘    against client_confirm
                                          │           │ fail → REJECT+drop
                                          │             (release slot, zeroize,
                                          │              do NOT advance chain)
                                          ▼
                            commit the ratchet: monotonic compare-and-swap
                            of (CK_{m+1}, m+1), zeroize CK_m (§6.2)
                                          │
                                          ▼
                            grant CapServe(this slot) or CapAdmin per
                            the credential's role — frozen (§7)
                                          │
                                          ▼
                                  ┌─────────────┐
                                  │ ESTABLISHED │  session live (§9, §10)
                                  └─────────────┘
```

Client side is the mirror: derive the selector, send `ClientHello`; on
`ServerHello`, derive `PRK_session` and compare `server_confirm` constant-time; on
success advance its own chain (§6.3), send `ClientAuth`, and treat the session as
live; on any mismatch abort without sending anything further.

**The order of those steps is normative, and two placements are load-bearing.**
The break-glass check sits immediately after the match, so no later step can be
reached with that credential. Chain resolution sits **after** admission control,
so the only unauthenticated work a peer can force before `MAX_SESSIONS_PER_CREDENTIAL`
applies is the fixed selector scan; the up-to-`MAX_CHAIN_CATCHUP` advances happen
only inside an admitted half-open slot. That reordering is a second bound, not the
primary one — the primary defense against forced catch-up work is that
`chain_counter` is bound into the selector (§5.3) and therefore cannot be chosen
by anyone who does not hold the credential.

**One shot, no negotiation, no retries.** BSP offers a single suite (HKDF-SHA256 /
ChaCha20-Poly1305 / SHA-256) — there is no algorithm negotiation to downgrade, and
`version_minor` and `reserved` are exact-match fields rather than extension
points. The cost is stated: there is no in-band way to evolve the protocol; a v3
is a new magic and a new document. Any handshake fault drops the connection; the
client must open a fresh connection to retry. `HS_TIMEOUT` bounds every
pre-`ESTABLISHED` state so a peer cannot pin a slot by stalling.

### 5.6 Security argument, property by property

Each claim below is argued, not asserted. The assumptions are exactly those
THREAT_MODEL grants: SHA-256, HKDF-SHA256, ChaCha20, and Poly1305 are unbroken,
and HMAC-SHA256 is a PRF.

**(a) The client identifies which credential it holds without leaking it.**
`key_selector` is a 16-byte HKDF-Expand output over `PRK_id`. Recovering `K_id`
from it requires inverting HMAC-SHA256, and `K_id` is in any case not the enrolled
key — the enrolled bytes were destroyed at §5.2 and `K_id` is one of three
independent expansions of them. Because `client_nonce` is in the `info`, the
selector differs every connection, so it is not a stable identifier and does not
link sessions. Because `chain_counter` is also in the `info`, the selector doubles
as an integrity check on the one pre-authentication field that would otherwise
steer server-side work: a counter the sender did not compute the selector over
matches no credential at all. The server-side scan is constant work with
constant-time comparison, so neither the matching slot's index nor the presence of
a match is timing-visible.

**(b) The transcript is bound.** `TH_1` and `TH_2` are SHA-256 over the exact
fixed-length byte images of the messages, covering every field of both: magic,
both version bytes, `reserved`, `chain_counter`, both nonces, the selector, and
(in `TH_2`) `server_confirm`. `PRK_session = Extract(salt = TH_1, ikm = CK_m)`, so
both confirmations and both directional key sets are functions of the entire
transcript. Flipping any bit anywhere in the handshake yields an unrelated
`PRK_session`, an unrelated `server_confirm`, and a failed comparison. Because
every input length is a compile-time constant there is no canonicalization
ambiguity: two distinct transcripts cannot produce the same hash input.

**(c) Replay is closed in both directions.** A replayed `ClientHello` reaches a
server that generates a *fresh* `server_nonce`, producing a different `TH_1`, a
different `PRK_session`, and therefore a different expected `client_confirm`; the
recorded `client_confirm` fails and the connection drops. A replayed `ServerHello`
reaches a client whose `client_nonce` is fresh, so the recorded `server_confirm`
was computed over a different `TH_1` and fails. Within a session, record replay
and reorder fail the Poly1305 check because the sequence is the nonce and is never
on the wire (§4.2). Cross-session record replay fails because `PRK_session` differs
per connection. **The one assumption that must hold** is server nonce freshness:
if the server ever repeats a `server_nonce` against a repeated `ClientHello`, the
entire session is replayable. `server_nonce` MUST come from the kernel CSPRNG
after entropy initialization (`INV-BOOT-005`), and a serving path that cannot
prove entropy is available MUST refuse to accept connections rather than emit a
weak nonce (`INV-FAIL-003`).

**(d) Mutual authentication follows from possession alone.** `server_confirm` is
computable only from `PRK_session`, which is computable only from `CK_m` — so a
peer that produces it holds the credential, and it holds it *now*, because
`PRK_session` incorporates the client's fresh nonce. Symmetrically,
`client_confirm` proves possession over a transcript containing the server's fresh
nonce. Since a credential is shared by exactly two parties, each direction's proof
identifies the peer as the other holder. The two confirmations use **distinct
labels**, so neither can be replayed back at its sender as the other's proof; this
is the reflection attack that symmetric-key handshakes with a single MAC key fall
to, and distinct labels are the whole defense.

**(e) The honest limits of symmetric authentication.** Proof of possession is
symmetric: it establishes that the peer holds the same secret, and cannot
distinguish "the server" from any other holder of that credential. That is
acceptable only because the holder set has size two by construction, which in turn
holds only if enrollment never distributes one credential to two clients — a
policy obligation on the operator, not a property the protocol enforces. There is
also no analogue of asymmetric key-compromise-impersonation resistance: whoever
holds the credential can impersonate **either** party to the other.

**(f) A guessable credential is fatal, and the protocol cannot help.** Every value
on the wire is offline-verifiable against a candidate credential: an attacker who
records one handshake can test guesses against `key_selector` alone, without
interacting further. This handshake is not a PAKE and does not pretend to be.
Enrolled key material MUST therefore be 32 bytes of CSPRNG output. §10.4 makes the
enroller supply it, so the strength of every client's authentication is the
strength of whatever the admin passed to `enroll-key` — see §15 question 3.

**(g) Downgrade is impossible.** One suite, exact-match version bytes, a
MUST-be-zero `reserved` field, and no negotiated parameter of any kind. There is
nothing to negotiate and therefore nothing to negotiate downward.

**(h) Forward secrecy — absent today.** `PRK_session` is a function of `CK_m` and
the transcript, and the transcript is public. Until §6 ships, `CK_m = CK_0` is a
stored constant, so anyone who later obtains the credential store decrypts every
session ever recorded from that machine. Once the ratchet ships, `CK_m` is
zeroized after use and one-wayness of HKDF makes it unrecoverable from `CK_{m+1}`,
so recorded traffic stops being retrospectively readable. The break-glass
credential does not appear on this transport at all, so it neither gains nor loses
anything here (§2.5, §6.5).

### 5.7 Residual observables, stated

None of these is a confidentiality loss; all are real and are recorded rather than
glossed. The last two are what a recorded `ClientHello` is still worth to an
attacker after §5.3 removed its ability to forge the counter.

- **A revocation oracle for an observer who already recorded a handshake.** The
  server answers a matched selector with `ServerHello` and an unmatched one with a
  silent drop, so replaying a captured `ClientHello` reveals whether that
  credential is still enrolled. The alternative — answering unmatched selectors
  with a fabricated `ServerHello` and holding the connection to `HS_TIMEOUT` —
  would close it at the cost of letting any unauthenticated peer pin a session
  slot, which is a worse trade against `INV-SERVE-003`. Manufacturing a *new*
  selector still requires the credential, so this oracle is available only to
  someone who already observed that client.
- **`chain_counter` is a metadata leak.** It is plaintext and monotonic, so an
  observer learns how many sessions a credential has completed and can partially
  re-link sessions the blinded selector unlinked. Binding it into the selector
  (§5.3) makes it unforgeable; it does not make it confidential. §15 question 2
  records the alternative and why it was not taken.
- **Every inbound `ClientHello` costs the full selector scan, matched or not.** An
  unauthenticated peer can spend one 64-byte packet to buy `MAX_ENROLLED_KEYS`
  selector derivations — `MAX_ENROLLED_KEYS × 5` SHA-256 compressions, derived in
  §5.3 — and no admission limit applies before the scan, because the scan is what
  identifies the credential the limit would be applied to. This is
  inherent to blinded lookup, not a defect in it: the alternative that avoids it is
  the stable public key id §5.3 rejected. What matters is that the multiplier is a
  **fixed `const`** an attacker cannot steer — the chain-advance work that *could*
  have been steered is closed by binding `chain_counter` into the selector and
  bounded again by placing catch-up after admission (§5.5). Sizing
  `MAX_ENROLLED_KEYS` is therefore a DoS decision as well as a capacity one, which
  is why it appears in §15 question 7.
- **A recorded `ClientHello` is a targeted denial of service against its owner**,
  for as long as that credential stays enrolled. See §9.1.

---

## 6. The session-key ratchet

Owner decision 9. This is the mechanism that recovers forward secrecy from
symmetric primitives alone (`INV-BOOT-007`). **It is specified here and not
implemented** (§14).

### 6.1 Chain advance

```
PRK_step = HKDF-Extract(salt = LABEL_CHAIN_SALT, ikm = CK_n)
CK_{n+1} = HKDF-Expand(PRK_step, LABEL_CHAIN_STEP, 32)
zeroize(CK_n, PRK_step)
```

`CK_{n+1}` is a one-way function of `CK_n`. Nothing derives `CK_n` from
`CK_{n+1}`, and nothing derives it from `K_id` or `handle`, which came from
independent expansions of material that no longer exists.

### 6.2 Advance is coupled to derivation, and committed only on success

Derivation and advance-with-zeroization are **one operation** — no path derives a
session key without advancing. But the advance is **committed** (persisted to the
credential store, `CK_m` zeroized) only at the transition to `ESTABLISHED`, after
`client_confirm` verifies. Until then the derived material lives in scratch that
teardown zeroizes.

This ordering is not an optimization; it is the difference between a ratchet and a
remote kill switch. If an unauthenticated peer could advance the persisted chain
by replaying a captured `ClientHello`, it could push the server's chain arbitrarily
far forward and lock the legitimate client out permanently, without ever holding
the credential.

**The commit is monotonic.** It is a compare-and-swap against the persisted
position, not an unconditional store: a commit of `(CK_{m+1}, m+1)` takes effect
only if `m + 1 > s_persisted`; otherwise the persisted state is left alone and the
resolved scratch material is zeroized. This is required, not defensive. Two
handshakes under one credential may be in flight simultaneously
(`MAX_SESSIONS_PER_CREDENTIAL` permits two), they may have resolved from different
scratch positions, and they may complete in either order. Without the
compare-and-swap the later commit could move the persisted counter **backwards**
and reinstate a chain key the server had already advanced past — a direct
violation of `INV-BOOT-007`'s "No component retains a chain key it has advanced
past." It is not remotely exploitable, because both commits require an
authenticated peer holding the credential, but the invariant is not conditional on
exploitability.

A consequence worth naming rather than leaving to be discovered: two concurrent
sessions under one credential may derive from the **same** chain position, so the
chain is not a per-session uniqueness mechanism and was never claimed to be. Their
session keys are still distinct, because `PRK_session` incorporates two fresh
nonces (§9.2). Each session zeroizes its own scratch copy at teardown, whether or
not its commit won.

### 6.3 Persisted counter state on both ends, and catch-up

Both ends persist `(CK_n, n)`. The client sends `n` as `chain_counter` and derives
from `CK_n`. The server holds `(CK_s, s)` and compares:

| Relation | Server action |
|---|---|
| `n == s` | Derive from `CK_s`. Normal case. |
| `s < n ≤ s + MAX_CHAIN_CATCHUP` | Compute `CK_n` by `n − s` advances **in scratch**, uncommitted. On success at `ESTABLISHED`, commit `(CK_{n+1}, n+1)` under the monotonic compare-and-swap of §6.2 and zeroize everything between. |
| `n > s + MAX_CHAIN_CATCHUP` | REJECT + drop. Bounds both the work an unauthenticated peer can request and how far a forged counter could push a committed chain (it cannot push it at all — see §6.2). |
| `n < s` | REJECT + drop. The chain is one-way; the server cannot go back. This is the desynchronization failure of §6.4. |

Catch-up exists because the two ends do not advance at the same instant. The
client commits its advance when it accepts `server_confirm`; the server commits
after it verifies `client_confirm`. If the client's `ClientAuth` is lost in
flight, the client is at `s + 1` and the server is still at `s`, and the next
connection resynchronizes with a single catch-up step. In normal operation the
client is therefore never *behind* the server, which is why `n < s` is treated as
an anomaly rather than a routine case.

### 6.4 Desynchronization is an availability failure, not a confidentiality one

If the two ends disagree irreconcilably — the client's store restored from an
older state, the server's chain advanced past a client that lost its own advance,
or a gap wider than `MAX_CHAIN_CATCHUP` — the handshake fails closed
(`INV-FAIL-003`). Nothing is disclosed; the client is locked out. **There is no
fallback to an un-ratcheted key and there MUST never be one**, because a fallback
that any failure can trigger is a downgrade any attacker can trigger.

Recovery is re-enrollment over the admin channel (§10.4). If the credential that
would authorize that re-enrollment is itself desynchronized, recovery is over the
serial console and nowhere else. That is why the serial path is compiled in
unconditionally and is not gated on any network state: a ratchet with no
out-of-band repair path is a remote self-destruct.

### 6.5 The break-glass credential has no chain state on this transport

The break-glass credential never authenticates a network session (§2.5), so the
network listener never derives from its chain, never advances it, and can never
desynchronize it. A `ClientHello` whose selector matches the break-glass record is
refused before any chain resolution runs (§12 row K5). Whether the serial
transport ratchets its own sessions is a property of that path and is out of scope
for this document, which governs the network socket.

This is the second reason the serial-only ruling is the right one: it removes the
question §6.4 would otherwise force — whether the recovery path may itself have a
desynchronization failure mode — instead of answering it with an exception.

---

## 7. Session types: client and admin

Owner decision 8. There is **one** transport and **two** capability grants
(`INV-AUTH-009`). Administration is not a shell, and this section is the
structural reason it cannot become one.

### 7.1 How a session becomes admin

By the credential, and by nothing else. `role` is a field of the credential record
(§2.2), fixed at enrollment. The server reads it after the selector match and
before it grants anything; the client contributes no input to the decision, and
there is no wire field it could contribute through (§5.1).

`CapAdmin` does not imply `CapServe`, and `CapServe` never derives `CapAdmin`
(`INV-AUTH-009`, `INV-AUTH-002`, `INV-AUTH-003`). A credential is one or the
other. An admin session therefore cannot run inference and a client session cannot
administer, and neither can convert.

### 7.2 The grant is frozen at accept

At the transition to `ESTABLISHED` the session receives exactly one capability:

- **role = client:** `CapServe(this slot)` — read this slot's `prompt_buf`, run the
  single served model against it, write tokens back on this connection. Nothing
  else: no other slot, no weights mutation, no spawn, no kernel call, no network
  egress.
- **role = admin:** `CapAdmin` — invoke the six verbs of §10.4. Nothing else: no
  command execution, no arbitrary file read or write, no outbound connection, and
  no capability outside the six.

BSP defines no message that widens either grant. A verb needing authority the six
do not cover requires a **new named capability**, never a widened `CapAdmin`
(`INV-AUTH-009`). An admin session is still a session and still cannot name
another session's state (`INV-SERVE-001`).

### 7.3 Enrollment authority and its limits

`enroll-key` and `revoke-key` are the only network paths that write credential
material, and both are `CapAdmin` verbs, which makes an enrollment exactly as
trustworthy as the admin session that requested it. A compromised admin session
can enroll a credential it controls and thereafter authenticate as a legitimate
peer. Enrollment and revocation are attributable audit events (`INV-AUTH-008`), so
this is visible in the audit record — but visibility is detection after the fact,
not prevention, and the spec says so rather than presenting the audit log as a
control.

Two hard limits bound it:

- **There is no `rotate` verb.** Rotation is `enroll-key` followed by
  `revoke-key`, so it names no authority the frozen set does not already contain
  (`INV-BOOT-008`). Adding a rotate verb would make the set seven, and the set is
  six.
- **Neither verb will touch the break-glass credential.** Both compare the target
  handle against the break-glass handle and refuse, unconditionally and
  non-configurably (`INV-BOOT-008`, §10.4). A compromised admin session cannot lock
  the owner out — and, since the break-glass credential does not authenticate on
  this transport at all (§2.5), a compromised admin session cannot *use* it either.

---

## 8. Explicit maximum sizes (build-time pool sizing)

Every variable-length element and every pool is a compile-time `const`. Proposed
starting values (tune to the boot memory budget in the Stage PR; the *values* are
tunable, the *presence of a hard const bound on each* is not):

| Const | Value | Governs / rationale |
|---|--:|---|
| `BSP_MAGIC` | `"BSP2"` | 4-byte protocol tag |
| `BSP_VERSION` | `2.0` | major/minor; exact match, not a negotiation |
| `LEN_CLIENT_HELLO` | `64` | fixed handshake msg 1 |
| `LEN_SERVER_HELLO` | `64` | fixed handshake msg 2 |
| `LEN_CLIENT_AUTH` | `32` | fixed handshake msg 3 |
| `LEN_PSK` | `32` | enrolled key material; destroyed after §5.2 |
| `LEN_KEY_ID` | `32` | stable identification secret |
| `LEN_CHAIN_KEY` | `32` | chain key `CK_n` |
| `LEN_HANDLE` | `16` | administrative handle; never pre-key on the wire |
| `LEN_SELECTOR` | `16` | per-connection blinded selector |
| `LEN_NONCE` | `32` | each side's handshake nonce |
| `LEN_CONFIRM` | `32` | each confirmation value |
| `LEN_DIR_KEYS` | `64` | one direction: payload key `K_2` ‖ length key `K_1` |
| `LEN_LABEL` | `16` | every HKDF label, NUL-padded |
| `MAX_ENROLLED_KEYS` | `32` | fixed credential table; also the constant-work factor of the §5.3 scan |
| `MAX_CHAIN_CATCHUP` | `64` | bound on forward chain resolution per handshake (§6.3) |
| `BSP_MAX_RECORD_PLAINTEXT` | `4096` | max BSP message bytes per data record; `≤` AEAD internal buffer (§4.2) |
| `MAX_PROMPT_BYTES` | `16384` | total prompt per request; fixed **per-session** BSS buffer, reassembled across `PromptChunk` records |
| `MAX_PROMPT_CHUNK` | `4032` | one `PromptChunk` payload; `≤ BSP_MAX_RECORD_PLAINTEXT − header` |
| `MAX_TOKEN_CHUNK` | `512` | one outbound `TokenChunk` payload |
| `MAX_TOKENS_REQUESTED` | `4096` | ceiling on `max_tokens` a request may ask for |
| `MAX_AUDIT_CHUNK` | `1024` | one outbound `AuditChunk` payload |
| `MAX_AUDIT_RECORDS` | `64` | ceiling on records returned per `ReadAuditLog` |
| `MAX_SESSIONS` | `8` | fixed session-slot pool (whole server) |
| `MAX_ADMIN_SESSIONS` | `1` | admin sessions concurrently live, within `MAX_SESSIONS` |
| `MAX_SESSIONS_PER_CREDENTIAL` | `2` | per-credential admission, **counting half-open handshakes** (`INV-SERVE-003`) |
| `MAX_INFLIGHT_PER_SESSION` | `1` | at most one active inference per session |
| `HS_TIMEOUT` | `5 s` | wall-clock bound on each pre-`ESTABLISHED` state |
| `IDLE_TIMEOUT` | `120 s` | max idle in `ESTABLISHED` before server teardown |
| `MAX_RECORD_SEQ` | `u32::MAX` | per-direction; reaching it forces teardown (§9.4) |

**Total inbound serving memory is therefore fixed at build time:**
`MAX_SESSIONS × (session control block + MAX_PROMPT_BYTES + 2 × BSP_MAX_RECORD_PLAINTEXT + K_c2s + K_s2c + KV region)`
plus `MAX_ENROLLED_KEYS × credential record`. No client input changes this figure
(`INV-MEM`, `INV-SERVE-002`).

**Bounded work, stated per attacker rather than per handshake** — the per-handshake
form of this claim is true and misleading, because an attacker sends many
handshakes:

- **Per inbound `ClientHello`, authenticated or not:** `MAX_ENROLLED_KEYS` selector
  derivations = `MAX_ENROLLED_KEYS × 5` SHA-256 compressions (derived in §5.3).
  This is the floor, it applies to every packet including garbage, and it is the
  standing cost of blinded lookup (§5.3, §5.7).
- **Chain advances: zero for a counter the sender did not derive over; bounded by
  admission for one it did.** `chain_counter` is covered by the selector (§5.3), so
  a forged counter matches nothing and never reaches chain resolution. A **verbatim
  replay** of a recorded `ClientHello` does still reach it — the recorded counter is
  self-consistent — and costs up to `MAX_CHAIN_CATCHUP` advances while the server
  sits at or below the recorded position, dropping to a single integer comparison
  (row K3) once the server has advanced past it. That work is behind admission
  control (§5.5), so it is capped at
  `MAX_SESSIONS_PER_CREDENTIAL × MAX_CHAIN_CATCHUP` concurrently and cannot be
  scaled with packet rate. What the binding removes is the attacker's ability to
  *choose* the distance; it does not remove the replay.
- **Everything downstream of admission** — key derivation, `ServerHello`, the
  session slot — is bounded by `MAX_SESSIONS` and `MAX_SESSIONS_PER_CREDENTIAL`.

So the only quantity an unauthenticated attacker can scale with packet rate is the
selector scan, and its multiplier is a `const` it cannot steer.

---

## 9. Session lifecycle

### 9.1 Session slot (fixed pool)

A `static` array `SESSIONS: [SessionSlot; MAX_SESSIONS]` (BSS). Each slot holds:
directional keys `K_c2s`/`K_s2c`, the two sequence counters, `session_id`
(= `TH_2`, for audit correlation only — never wire-addressable), the credential
handle that authenticated it, the granted capability, the reassembly state, the
per-session `prompt_buf: [u8; MAX_PROMPT_BYTES]`, the reserved KV region handle,
and a state enum. Slots are acquired at §5.5 "acquire session slot" and released
on teardown. **The slot index is server-internal and never appears on the wire.**

Slot acquisition happens after the selector match but **before** the client has
authenticated, so a party replaying a captured `ClientHello` can hold a slot until
`HS_TIMEOUT`. That is bounded by `MAX_SESSIONS_PER_CREDENTIAL`, which counts
half-open handshakes precisely so this cannot consume the pool
(`INV-SERVE-003`). An admin credential additionally cannot exceed
`MAX_ADMIN_SESSIONS`.

**The bound protects every other client and does not protect the victim.** Stated
in full, because the previous sentence is the kind of true statement that reads as
a closed issue: with `MAX_SESSIONS_PER_CREDENTIAL = 2`, an attacker replaying one
captured `ClientHello` twice occupies **both** of that credential's admission
slots, refreshes them every `HS_TIMEOUT`, and thereby denies that one client
service **indefinitely** — at a cost of two 64-byte packets per timeout period,
with no credential and no possibility of authenticating. Every other client is
unaffected, and the fixed pool is never exhausted; the isolation property holds
exactly as designed, and the availability of one tenant does not.

The remedy is revocation and re-enrollment: a new credential has a new `K_id`, so
the captured `ClientHello`'s selector matches nothing and the recording becomes
inert. That is a manual, `CapAdmin`-gated repair for an attack that costs the
attacker almost nothing, which is an unfavourable exchange and is named as one
rather than presented as a mitigation. A per-source-address admission limit would
blunt it, but BSP is specified above the transport's addressing and cannot see the
source; that makes it a `servd` policy question rather than a wire-protocol one.
Recorded here so it is not mistaken for an oversight — see §15 question 7.

### 9.2 Establish

On reaching `ESTABLISHED` (§5.5), the slot is bound 1:1 to this connection.
Per-session key material is unique because `PRK_session` incorporates two fresh
nonces, so no two live sessions share keystream, and a record sealed for one
session **cannot** authenticate under another's keys — cross-session confusion is
cryptographically foreclosed, not merely access-checked (`INV-SERVE-001`).

Two sessions authenticated by the *same* credential are still cryptographically
distinct for the same reason: the nonces differ, so `PRK_session` differs. What
they are not is mutually isolated in authority — the same credential means the
same principal, and that is the intended semantics, bounded by
`MAX_SESSIONS_PER_CREDENTIAL`.

### 9.3 Capability grant (frozen)

Per §7.2. Frozen at accept, never widened, never converted between roles. The
served model runtime that consumes `prompt_buf` runs under its own frozen
capability manifest (`INV-MODEL-001`) and cannot name any other slot regardless of
prompt content.

### 9.4 Teardown

Session ends on: client `Close` (§10.2), server `Close` (idle/limits), any record
that fails to authenticate or decode (§12), `IDLE_TIMEOUT`, or sequence
exhaustion. Teardown **zeroizes** `K_c2s`, `K_s2c`, any scratch chain material,
`prompt_buf`, and the KV region, resets the sequence counters, and returns the
slot to the free pool (`INV-SERVE-004`, `INV-MEM-006`). No teardown path leaks a
slot (else `MAX_SESSIONS` degrades — a DoS). Teardown is idempotent and reachable
from every non-`FREE` state. Teardown never advances or rolls back the persisted
chain: the only chain commit is the one in §6.2.

### 9.5 Audit events

Connection accept, selector match or no-match, authentication success or failure,
capability grant, every admin verb, every denial, and teardown are emitted to
`auditd` (`INV-SERVE-005`, `INV-AUTH-008`). The events carry the credential
`handle` and `session_id`; they never carry key material, prompt bytes, or token
bytes.

---

## 10. Message types (data phase)

Inner payload of an AEAD data record: `type[1] || body`. Unknown tags, and tags
not valid for this session's type or current state, ⇒ REJECT (§12). The tag space
is partitioned so that type confusion is a decoding error rather than a policy
question:

| Range | Direction | Session type |
|---|---|---|
| `0x0X` | client → server | client session |
| `0x1X` | client → server | admin session |
| `0x8X` | server → client | client session |
| `0x9X` | server → client | admin session |

A `0x1X` tag on a client session and a `0x0X` tag on an admin session are both
REJECT. **No message carries a session, KV, or weights selector**
(`INV-SERVE-001`, `INV-MODEL`): the only correlation field is `request_id`.

### 10.1 `request_id` — scoped, inert correlation token

`request_id: u32` is a peer-chosen opaque tag echoed by the server on that
request's responses so the peer can correlate streams **within its own session**.
It is **NOT** an index, handle, offset, or key into any server-side structure. The
server validates it only as: "equals the `request_id` of the in-flight request in
*this* slot." It never selects a session, a KV entry, a weights view, a credential,
or a buffer. A duplicate or garbage `request_id` cannot reach another session
because it is only ever compared within the one slot bound to this connection.

### 10.2 Client session — client → server

| Tag | Name | Body | Rules |
|--:|---|---|---|
| `0x01` | `InferBegin` | `request_id[4]`, `max_tokens[4]`, `temperature[2]` (u16 fixed-point /1000), `top_p[2]` (u16 /1000), `prompt_total_len[4]` | `max_tokens ≤ MAX_TOKENS_REQUESTED`; `prompt_total_len ≤ MAX_PROMPT_BYTES`; slot MUST be idle — else REJECT. Opens a request; server zeroes reassembly, records declared length |
| `0x02` | `PromptChunk` | `request_id[4]`, `chunk[u16 len ≤ MAX_PROMPT_CHUNK]` | `request_id` MUST match the open request; running total `+ len` MUST be `≤ prompt_total_len` **and** `≤ MAX_PROMPT_BYTES` — else REJECT. Appends into fixed `prompt_buf`; the cap is the buffer size, never `len` |
| `0x03` | `InferCommit` | `request_id[4]` | accumulated bytes MUST equal `prompt_total_len` — else REJECT. Hands `prompt_buf[..total]` to the confined model; server enters streaming |
| `0x04` | `Cancel` | `request_id[4]` | cancels the in-flight request; server stops streaming, emits `StreamEnd{finish=CANCELLED}`, returns to idle |
| `0x05` | `Close` | (empty) | graceful teardown (§9.4); server replies `Bye` then closes |

Splitting the prompt into `InferBegin`/`PromptChunk`/`InferCommit` keeps every
record `≤ BSP_MAX_RECORD_PLAINTEXT` while allowing prompts up to
`MAX_PROMPT_BYTES`, with reassembly bounded by a fixed per-session buffer — no
client length ever sizes memory.

### 10.3 Client session — server → client

| Tag | Name | Body | Rules |
|--:|---|---|---|
| `0x81` | `Accepted` | `request_id[4]` | acks a valid `InferCommit`; streaming begins |
| `0x82` | `TokenChunk` | `request_id[4]`, `tokens[u16 len ≤ MAX_TOKEN_CHUNK]` | one or more emitted; `tokens` are opaque model output bytes, rendered by the client and never interpreted as control by BSP (`INV-MODEL-003`) |
| `0x83` | `StreamEnd` | `request_id[4]`, `finish_reason[1]` | `finish_reason ∈ {0 OK, 1 LENGTH, 2 CANCELLED, 3 MODEL_ERROR}`; returns slot to idle |
| `0x8E` | `Error` | `request_id[4]` (or `0` if none), `error_code[2]` | non-fatal protocol error at message level; §12 says which faults are `Error`-then-continue vs. drop |
| `0x8F` | `Bye` | (empty) | teardown ack; connection closes after |

### 10.4 Admin session — the six verbs

The set is frozen at exactly six and is a compile-time enumeration. No verb
dispatches to a command interpreter, names a filesystem path, or grants a
capability (`INV-AUTH-009`).

| Tag | Verb | Body | Rules |
|--:|---|---|---|
| `0x11` | `EnrollKey` | `request_id[4]`, `role[1]`, `key_material[32]` | `role ∈ {0x01 client, 0x02 admin}` — any other value REJECT. Server runs §5.2 and, **before persisting anything**, compares the derived `handle` against the break-glass handle: equal ⇒ `Error{ERR_FORBIDDEN}`, unconditionally and non-configurably (`INV-BOOT-008`, §12 row A4). Otherwise persists the record, zeroizes `key_material` and `PRK_enroll`, and replies `KeyEnrolled{handle}`. Credential table full ⇒ `Error{ERR_NO_CAPACITY}`. Duplicate `handle` ⇒ `Error{ERR_DUPLICATE}` (the caller re-sent the same key material) |
| `0x12` | `RevokeKey` | `request_id[4]`, `handle[16]` | Handle MUST exist ⇒ else `Error{ERR_NO_SUCH_KEY}`. Handle MUST NOT be the break-glass handle ⇒ else `Error{ERR_FORBIDDEN}`, unconditionally and non-configurably (`INV-BOOT-008`). On success the record's `K_id` and `CK_n` are zeroized and the slot is returned to the fixed table; live sessions authenticated by that credential are torn down (§9.4) |
| `0x13` | `LoadWeights` | `request_id[4]`, `weights_digest[32]` | **Reboot-class — see the note below the table.** Activates the weight blob whose measured digest is exactly this value; the digest is verified before first use (`INV-MODEL-002`) and a mismatch, an absent blob, or a blob whose own Ed25519 signature does not verify ⇒ `Error{ERR_NO_SUCH_WEIGHTS}`. **The blob is not carried over BSP** — this verb names a digest, never a path and never a byte stream; see §15 question 4 |
| `0x14` | `ReadAuditLog` | `request_id[4]`, `cursor[8]`, `max_records[2]` | `max_records ≤ MAX_AUDIT_RECORDS` — else `Error{ERR_LIMIT}`. Read-only; returns `AuditChunk` records and a next cursor. Reading grants no authority (`INV-SERVE-005`) |
| `0x15` | `RestartServer` | `request_id[4]`, `target[1]` | `target` is an enumerated server identity (`servd`, `inferd`, `auditd`, `gpud`), not a name and not a path; an unknown value ⇒ `Error{ERR_BAD_TARGET}`. Restart re-launches with the target's existing frozen manifest and mints nothing (`INV-FAIL-002`) |
| `0x16` | `Reboot` | `request_id[4]` | Reboots the machine. The admin session is torn down before the reboot proceeds |

**How `EnrollKey` can target the break-glass identity at all**, since the caller
supplies key material and not a handle: `handle = Expand(PRK_enroll,
LABEL_KEY_HANDLE || role, 16)` is a deterministic function of the material, so the
only way to produce the break-glass handle is to **re-supply the break-glass key
material itself** — which a compromised admin session could do if the break-glass
key ever leaked, precisely in order to re-enroll it under a different `role` or to
displace the record. The refusal is therefore not dead code, and §12 row A4's
`EnrollKey` clause is reachable. `RevokeKey` reaches it the obvious way, by naming
the handle directly.

**`LoadWeights` is reboot-class, not a hot swap** *(specified 2026-08-03 by owner
decision; the dispatch that implements it is P2-T14 and does not exist — §14).*
A weight generation is **destroyed and replaced, never edited**, because
[`MEMORY_MODEL.md`](MEMORY_MODEL.md) §13 admits no path that makes a sealed
weights page writable again. Invoking this verb therefore:

1. **terminates every session**, client and admin alike, including the session
   that issued the verb — the reply is best-effort and a caller must not depend
   on receiving it;
2. tears down the serving stack: `inferd` exits, the weights region is zeroized,
   and the seal is released as a kernel operation belonging to the destroyed
   generation, not as a permission change on any live mapping;
3. re-runs the one-shot loader `modeld`, which verifies the newly named
   generation end to end and exits
   ([`BXW1-weight-format.md`](BXW1-weight-format.md) §10.0, §10.5);
4. relaunches `inferd` against the new sealed generation.

It is written out here, in the verb's own semantics, so that no client can read
`LoadWeights` as an in-place swap that leaves conversations running. **It does
not.** Two consequences follow and are stated rather than implied: in-flight
requests are lost, not drained; and because the weights region is single and
fixed, the previous generation is already gone when the new blob is verified, so
a reload that DENIES leaves the machine **unable to serve** until a
`LoadWeights` naming a verifying digest succeeds (§12 row A5).

**This changes what `LoadWeights` means, not the size of the set.** No verb is
added: there is no reload verb, no `activate`, and no `rotate`.

There is deliberately **no `rotate` verb** (§7.3), no `set-config`, no
`read-file`, no `write-file`, no `exec`, and no verb that adds, removes, or widens
a capability. That is the whole of the administrative surface reachable from the
network, and its finiteness is checkable by reading the table above.

### 10.5 Admin session — server → client

| Tag | Name | Body | Rules |
|--:|---|---|---|
| `0x90` | `AdminOk` | `request_id[4]`, `status[2]` | verb completed; `status` is an enumerated result code |
| `0x91` | `KeyEnrolled` | `request_id[4]`, `handle[16]` | reply to `EnrollKey`; the handle is the non-secret name `RevokeKey` will later use |
| `0x92` | `AuditChunk` | `request_id[4]`, `next_cursor[8]`, `records[u16 len ≤ MAX_AUDIT_CHUNK]` | zero or more; `records` are opaque audit bytes, rendered by the client, never interpreted as control |
| `0x9E` | `Error` | `request_id[4]`, `error_code[2]` | admin-side non-fatal error |
| `0x9F` | `Bye` | (empty) | teardown ack; connection closes after |

### 10.6 What is deliberately absent

On a **client session** there is **no** message to: select or name a model or
weights blob; load, patch, or measure weights; name a session id, KV slot,
credential, or another client; request a kernel operation, spawn, file, or network
action; set arbitrary server config; or carry in-band terminal/control sequences.
The served model is reachable **only** as "run the one confined model over this
slot's prompt bytes." A poisoned or hijacked model therefore cannot use BSP to
escape its session: BSP grants it no nameable target beyond its own slot's output
stream (`INV-MODEL-001`).

On an **admin session** there is no message outside the six verbs, and none of the
six takes a path, a command string, or a capability reference.

---

## 11. Defence of the named dominant threats

Cited by name from THREAT_MODEL §"Dominant threats, re-ranked for this
deployment". Ranks are omitted on purpose: that list is a re-ranking and its
numbering has already moved once. **Every header below is the threat's current
name, verbatim** — a name is stable enough to cite and a rank is not, but names
are not immune either: entry 1 was renamed on 2026-08-03 when x86-64 was dropped
(§0 records the old wording). The discipline is that a name change is visible and
repaired here, in one place, rather than rotting silently the way a rank does.

**Hostile remote clients and the inbound protocol.** The entire
pre-`ESTABLISHED` path (§5) and the message decoder (§10) are `#![no_std]`,
zero-alloc, fail-closed parsers. All three handshake messages are fixed-length ⇒
the decoder is total and Kani-provable, with no length arithmetic on client input
anywhere. Data records are authenticated by the record layer **before** the
message decoder runs, so an unauthenticated attacker cannot reach §10 parsing at
all — only the handshake decoder faces fully-unauthenticated bytes, and it does no
allocation and no client-sized copy. Every malformed length, offset, tag, counter,
or confirmation denies and drops (§12). No pool is grown from client input, and
per-handshake work is bounded by two `const`s (§8). Downgrade is impossible
(single suite, exact-match version). Replay is closed by transcript-bound
confirmations and monotonic implicit AEAD sequence nonces (§5.6c).

**Hostile prompts against the served model.** BSP caps the blast radius to the
attacker's own slot: the prompt is opaque bytes copied into *this session's* fixed
buffer and handed to a model confined by its own frozen capability manifest
(`INV-MODEL-001`). BSP exposes the model no field to name another session, the
weights, the kernel, or the network. Cross-session reads are cryptographically
foreclosed (§9.2). Prompt injection thus stays within the confined tenant, and no
prompt can reach the admin verb set, because `CapServe` never derives `CapAdmin`
and the `0x1X` tag range is a decoding error on a client session.

**Credential-store disclosure, retroactively.** BSP does not defend against this
and must not be described as if it did. The transport's authentication and
confidentiality reduce entirely to secrets held in the credential store, which is
plaintext at rest, permanently and on the only platform there is (§2.4).
What BSP contributes is limited and worth stating exactly: the enrolled
key material is destroyed at enrollment so the stored values are one-way
derivatives rather than the key itself (§5.2); the ratchet, once shipped, deletes
chain keys as it advances so a later disclosure stops being retroactive (§6); and
no credential is ever compiled into an artifact, so disclosure requires the
machine rather than the published image (`INV-BUILD-004`). Until §6 ships, the
honest statement is the one in §5.6h: disclosure decrypts everything ever
recorded.

**No remote attestation, anywhere.** Also undefended, also by
structure — and the threat's name is literal: there is no second platform on which
it would be defended. A completed handshake proves the peer holds the credential
and proves nothing about the software behind it (§0). This spec contains no field,
message, or claim that could be mistaken for an attestation, and adding one would
be a false claim in wire format, on the only platform there is.

---

## 12. Threat / rejection table (fail-closed behavior)

"Drop" = terminate the connection, release any acquired slot, zeroize its key
material and any scratch chain material (§9.4), and **do not commit any chain
advance** (§6.2). "Error+keep" = emit `Error{code}` and remain `ESTABLISHED`,
consuming the offending record. Handshake faults are **always Drop** — there is no
authenticated session to keep and no partial-trust state. Every row is a
Kani/fuzz assertion target.

| # | Malformed-input class | Detected by | Fail-closed action |
|---|---|---|---|
| H1 | `ClientHello` length ≠ `LEN_CLIENT_HELLO` | handshake reader (fixed len) | Drop |
| H2 | `magic` ≠ `"BSP2"`, `version_major` ≠ 2, `version_minor` ≠ 0, or `reserved` ≠ 0 | §5.1 field checks | Drop |
| H3 | client stalls before `ClientAuth` | `HS_TIMEOUT` | Drop |
| H4 | `ClientAuth` length ≠ `LEN_CLIENT_AUTH` | handshake reader | Drop |
| H5 | `client_confirm` mismatch | constant-time compare (§5.4) | Drop (no chain commit; the failure is indistinguishable from H4 to the peer) |
| H6 | (client side) `server_confirm` mismatch | constant-time compare | Drop (client aborts, sends nothing further) |
| K1 | `key_selector` matches no credential | constant-work scan (§5.3) | Drop (uniform with K2; the scan runs all `MAX_ENROLLED_KEYS` slots either way) |
| K2 | `key_selector` matches two credentials | scan | Drop |
| K3 | `chain_counter` < server chain position | §6.3 comparison | Drop (desynchronized; recovery is §6.4, never a fallback key) |
| K4 | `chain_counter` > position + `MAX_CHAIN_CATCHUP` | §6.3 bound | Drop |
| K5 | selector matches the **break-glass** credential | `flags` bit 0, checked at match (§2.5) | Drop, unconditionally and before any chain resolution. The break-glass credential authenticates on the serial transport only; on this listener it is never accepted, whatever else is well-formed |
| S1 | no free session slot | pool acquire | Drop (server at capacity; existing sessions unaffected — `INV-SERVE-001`) |
| S2 | credential already at `MAX_SESSIONS_PER_CREDENTIAL`, or admin at `MAX_ADMIN_SESSIONS` | admission check (§9.1) | Drop (`INV-SERVE-003`) |
| R1 | AEAD `enc_length` decodes `< 2` or `> 35000` | record-layer bound | Drop |
| R2 | AEAD tag mismatch (forged/corrupt/replayed record) | Poly1305, constant-time | Drop |
| R3 | record at unexpected sequence (replay/reorder/gap) | seq mismatch ⇒ auth fail | Drop |
| R4 | inner payload > `BSP_MAX_RECORD_PLAINTEXT` | `payload_out` bound | Drop |
| R5 | sequence would exceed `MAX_RECORD_SEQ` | counter guard | Drop (teardown) |
| M1 | unknown `type` tag | message decoder | Error+keep (`ERR_BAD_TYPE`) or Drop if policy-strict — see §15 question 1 |
| M2 | tag from the wrong range for this session type (`0x1X` on client, `0x0X` on admin) | tag-range guard (§10) | Drop (type confusion inside an authenticated channel ⇒ treat as attack) |
| M3 | message body shorter than its fixed fields | fixed reader | Drop |
| M4 | var-bytes `len` > field MAX | §3 reader | Drop |
| M5 | `InferBegin` over `MAX_TOKENS_REQUESTED` / `MAX_PROMPT_BYTES` | §10.2 check | Error+keep (`ERR_LIMIT`) |
| M6 | second `InferBegin` while a request is in flight | slot state | Error+keep (`ERR_BUSY`) |
| M7 | `request_id` ≠ the open request | slot state | Error+keep (`ERR_NO_REQUEST`) |
| M8 | `PromptChunk` running total > declared or > `MAX_PROMPT_BYTES` | reassembly guard | Drop (declared-length lie ⇒ attack) |
| M9 | `InferCommit` accumulated ≠ declared | commit check | Error+keep (`ERR_INCOMPLETE`) |
| M10 | message of a type invalid in the current state | state guard | Error+keep (`ERR_STATE`) |
| A1 | `EnrollKey` with `role` outside `{0x01, 0x02}` | verb decoder | Drop (an out-of-range authority byte is not a benign mistake) |
| A2 | `EnrollKey` with the credential table full | table bound | Error+keep (`ERR_NO_CAPACITY`) |
| A3 | `RevokeKey` on an unknown handle | table lookup | Error+keep (`ERR_NO_SUCH_KEY`) |
| A4 | `RevokeKey` or `EnrollKey` targeting the break-glass handle | `INV-BOOT-008` check | Error+keep (`ERR_FORBIDDEN`) and an audit event; the refusal is not configurable |
| A5 | `LoadWeights` digest matches no blob, or the blob fails its digest or signature check | `INV-MODEL-002` | Error (`ERR_NO_SUCH_WEIGHTS`). "Keep" applies only while the request is refused **before** the §10.4 teardown begins; once the previous generation has been torn down there is none to keep, and the machine cannot serve until a verifying digest is loaded |
| A6 | `RestartServer` with an unknown `target` | enum guard | Error+keep (`ERR_BAD_TARGET`) |
| A7 | `ReadAuditLog` with `max_records > MAX_AUDIT_RECORDS` | §10.4 check | Error+keep (`ERR_LIMIT`) |
| T1 | idle past `IDLE_TIMEOUT` | timer | Drop (server `Bye` then close) |

**Design rule for the M-rows and A-rows:** anything that could only arise from a
*non-conforming or hostile* peer after authentication and that indicates
framing, type, or state corruption (M2, M3, M4, M8, A1) is **Drop**, because inside
an authenticated channel such corruption implies a broken or hostile peer, not a
recoverable hiccup. Faults a benign peer could plausibly hit — over-limit, busy,
incomplete, unknown handle — are **Error+keep** so the channel is usable without
weakening isolation. Both branches are fail-closed: neither ever allocates, grows
a pool, advances a chain, or advances session state on bad input.

---

## 13. Verification obligations (Kani + fuzz)

The BSP request parser, the transport crypto, and the credential store are all
**Full** proof tier (`docs/security/SECURITY_INVARIANTS.md` §16), which means all
six artifacts: invariant mapping, fuzz, Kani, Prusti, audit report, and
no-regression bars. BSP MUST ship with at least the following before facing real
clients:

- **Fuzz targets** (libFuzzer/AFL, host, `#![no_std]`-compatible harness):
  1. handshake decoder — arbitrary bytes into `WAIT_HELLO` / `WAIT_CLIENTAUTH`;
     assert never panics, never allocates, never commits a chain advance, and only
     ever reaches `ESTABLISHED` on a well-formed authenticated transcript;
  2. message decoder — arbitrary authenticated-plaintext bytes into every slot
     state and both session types; assert total, no panic, no out-of-bounds, no
     state advance on REJECT, and no `0x1X` tag ever dispatching on a client
     session;
  3. reassembly — arbitrary `InferBegin`/`PromptChunk`/`InferCommit` sequences;
     assert `prompt_buf` writes never exceed `MAX_PROMPT_BYTES` and totals are
     exact;
  4. admin verb decoder — arbitrary bodies for all six verbs; assert no verb path
     reaches a capability mutation, and that no input gets past the break-glass
     refusal in `EnrollKey`/`RevokeKey`.
- **Kani harnesses:**
  1. every §3 reader is total and bounds-checked for all inputs;
  2. the handshake state machine reaches `ESTABLISHED` **iff** all H-, K-, and
     S-row checks pass, for all inputs;
  3. no reachable path sizes or indexes a buffer from a client-supplied length,
     offset, or counter (`INV-SERVE-002` proof obligation), including the
     `MAX_CHAIN_CATCHUP` loop;
  4. teardown from every non-`FREE` state returns the slot and zeroizes keys, with
     no slot leak and no chain commit;
  5. the chain is committed on exactly one path — the `ESTABLISHED` transition of
     §6.2 — and on no other; **and that commit is monotonic**: for all
     interleavings of up to `MAX_SESSIONS_PER_CREDENTIAL` concurrent handshakes on
     one credential, the persisted counter never decreases and no chain key the
     server has advanced past is ever reinstated (`INV-BOOT-007`);
  6. `enroll-key` and `revoke-key` cannot reach the break-glass record, and the
     network listener never establishes a session under it (`INV-BOOT-008`, §2.5);
  7. no admin verb path grants, derives, or widens a capability
     (`INV-AUTH-009`).
- **Property tests:**
  1. **Isolation** — two concurrent sessions, including two under the same
     credential: a record sealed for session A never authenticates for session B,
     and no `request_id` routes across slots (`INV-SERVE-001`).
  2. **Selector constant work** — the scan performs `MAX_ENROLLED_KEYS`
     derivations for a matching, non-matching, first-slot, and last-slot input
     alike.
  3. **Ratchet forward secrecy** — material captured after an advance does not
     decrypt records sealed before it (`INV-BOOT-007`).
  4. **Desync fails closed** — a client behind the server's chain position is
     denied and no fallback key is ever derived (`INV-FAIL-003`).
- **Test vectors:** a fixed set of `(key_material, role, nonces) → (selector,
  confirms, directional keys)` vectors, so the host test client
  (`tools/bsp-client/`) and the kernel implementation are checked against the same
  numbers rather than against each other.

---

## 14. Implementation status — what does not exist

Recorded because NORTH_STAR requires that an unbuilt control never be described in
the present tense, and because this document otherwise reads like a description of
a running system. As of 2026-08-02, **none of BSP v2 is implemented**:

- There is no `servd`, no BSP listener, and no BSP parser. The inbound path in
  tree is still `boot/ssh_bridge.rs`, which holds `static mut` session state on a
  single-core cooperative path and is scheduled for deletion at P2-T6.
- `src/kernel/src/boot/credential_store.rs` persists to virtio-blk and **seals
  nothing**. Enrollment, revocation, handles, roles, and the break-glass flag are
  specified here and not built.
- **The ratchet does not exist.** §6 is a design. Until it ships, a deployed
  implementation holds a chain that never advances, which is exactly the
  no-forward-secrecy state of §5.6h.
- `sha2` and `chacha20` are still vendored. The in-tree SHA-256, HKDF, ChaCha20,
  and Poly1305 set is specified and not yet written; the record layer's current
  home is `src/kernel/src/ssh/transport.rs`, which P2-T2 relocates.
- No fuzz target, Kani harness, Prusti obligation, or test vector from §13 exists.
- **The reboot-class `LoadWeights` semantics of §10.4 are unbuilt in every
  part** *(added 2026-08-03)*: there is no admin verb dispatch (P2-T14), no
  teardown sequence, no kernel unseal of a destroyed weight generation (P3-T2),
  and no `modeld` to re-run (P3-T3a). The verb fails closed today because
  nothing implements it, not because a check refuses it.

Nothing in §§1–13 may be cited as an implemented control until the corresponding
line above is struck.

---

## 15. Open questions for the owner

1. **M1 Drop-vs-Error policy.** Carried over from v1 §12 and still open. Should an
   unknown message `type` drop the connection (strict) or emit `Error` and continue
   (lenient)? This spec defaults strict for framing/type/state-corruption rows and
   lenient for limit/busy rows; confirm the boundary. Note that v2 makes one row
   strictly stricter than v1: a tag from the wrong session-type range (M2) is
   always Drop.
2. **`chain_counter` on the wire.** Sending the chain position in plaintext is what
   makes catch-up (§6.3) possible, and catch-up is what turns a lost final
   handshake message into a self-healing event instead of a lockout. It also leaks
   how many sessions a credential has completed and partially re-links sessions the
   blinded selector unlinked (§5.7). The alternative is strict lockstep with no
   counter and no catch-up, where any lost `ClientAuth` requires re-enrollment.
   Confirm the trade.
3. **Who generates enrolled key material.** §10.4 has the admin supply 32 bytes,
   which makes every client's authentication strength depend on the enroller's
   entropy source, and §5.6f shows a guessable credential is offline-recoverable
   from one recorded handshake. The alternative is server-generated material
   returned to the admin in the `KeyEnrolled` reply — same exposure on the wire,
   but entropy guaranteed by `INV-BOOT-005`. Confirm which.
4. **How a weight blob arrives.** `LoadWeights` names a digest and activates a blob
   already on local storage; it deliberately does not stream bytes, because a bulk
   transfer verb would need a growable buffer or a seventh verb. That leaves blob
   delivery out of band (physical media, or storage provisioning) and therefore
   unspecified. Confirm that out-of-band delivery is intended, or name the transfer
   path.
5. **Admin-role enrollment.** §10.4 lets an admin session enroll another *admin*
   credential. This grants no authority the enrolling session did not already hold,
   but it lets a compromised admin persist past revocation of the credential it
   used. The stricter alternative is to allow only `role = client` over the network
   and require serial provisioning for every admin credential. Confirm.
6. *(Answered 2026-08-02 — break-glass is serial only; see §2.5. Retained as a
   numbered placeholder so §-references to later questions do not shift.)*
7. **`MAX_SESSIONS` = 8, `MAX_ENROLLED_KEYS` = 32, `MAX_SESSIONS_PER_CREDENTIAL`
   = 2, `MAX_PROMPT_BYTES` = 16 KiB.** These set the fixed inbound memory budget,
   the standing per-packet selector-scan cost (§5.7), and the targeted-DoS exposure
   of §9.1 — raising `MAX_SESSIONS_PER_CREDENTIAL` makes a replay lockout costlier
   to mount and a legitimate client costlier to serve. Need the real boot memory
   budget to finalize, and a decision on whether `servd` adds a per-source-address
   admission limit below BSP.
8. **Rekeying within a session.** v2, like v1, tears down at `MAX_RECORD_SEQ`
   rather than rekeying. With the ratchet, an in-session rekey would be a natural
   chain step; confirm no long-lived session needs one.
