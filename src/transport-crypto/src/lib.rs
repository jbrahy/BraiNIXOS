//! BSP v2 transport cryptography — P2-T2.
//!
//! The key schedule, the record protection, and the ratchet for the **only
//! authenticated path into the system**. Its specification is
//! [`docs/architecture/BSP-v2-serving-protocol.md`](../../../docs/architecture/BSP-v2-serving-protocol.md):
//! §5.2–§5.4 (enrollment, blinded identification, the session key schedule),
//! §4.2 (the record layer), §5.5 (the handshake state machine), and §6 (the
//! HKDF ratchet). It is a **Full**-tier component
//! (`docs/security/SECURITY_INVARIANTS.md` §16: "Full tier covers the TCB,
//! every parser of hostile input, and all crypto").
//!
//! # The seam with `brainix-bsp`
//!
//! P2-T3 owns **structure**; this crate owns **cryptography**, and the split is
//! visible in the API rather than asserted in prose. Every handshake message,
//! every record frame, and every padding rule comes from `brainix-bsp` — this
//! crate re-parses nothing. It supplies exactly what a decoder holding no key
//! material cannot: the derivation, the keystream, the tag, and the
//! constant-time comparisons.
//!
//! The one byte layout written here is the `ClientHello` encoder in
//! [`handshake`], because P2-T3 encodes only what the *server* sends and the
//! BraiNIX server never sends a `ClientHello`. It is pinned to P2-T3's decoder
//! by a round-trip test.
//!
//! §4.2 additionally states the padding rules as sender obligations that P2-T3
//! enforces on receipt. [`RecordSealer::seal`] satisfies both by framing
//! through P2-T3's own `encode_record_plaintext`, so the sender and the
//! receiver cannot drift apart.
//!
//! # Primitives, and where each one comes from
//!
//! | Primitive | Source |
//! |---|---|
//! | SHA-256 | vendored `sha2` 0.10.9 (`force-soft`) — **not** reimplemented |
//! | ChaCha20 | vendored `chacha20` 0.9.1, `ChaCha20Legacy` (64-bit nonce) — **not** reimplemented |
//! | Constant-time compare / select | vendored `subtle` 2.6.1 |
//! | HMAC-SHA256 | in-tree, [`hmac`] — no `hmac` crate is vendored |
//! | HKDF-SHA256 | in-tree, [`hkdf`] — no `hkdf` crate is vendored |
//! | Poly1305 | in-tree, [`poly1305`] — no `poly1305` crate is vendored; ported from `src/kernel/src/ssh/poly1305.rs` per §4.2's provenance note |
//! | Zeroization | in-tree, [`Secret`] — no `zeroize` crate is vendored |
//!
//! No new dependency enters the tree here. `docs/NORTH_STAR.md` names `sha2`
//! and `chacha20` as future in-tree work; that burn-down is unchanged by this
//! task, and the three in-tree constructions above are additions to it only in
//! the sense that they are already in-tree.
//!
//! # What this crate guarantees
//!
//! - `#![no_std]`, crate-level `forbid(unsafe_code)`, and **no allocation of
//!   any kind**. Every working set is a fixed-size array, a borrowed slice, or
//!   a caller-supplied buffer (`INV-MEM`, `INV-SERVE-002`). Neither the sealer
//!   nor the opener holds a multi-kilobyte scratch of its own, so neither puts
//!   one on a kernel stack.
//! - **No panicking construct.** No `unwrap`, no `expect`, no `panic!`, no
//!   indexing that can be out of range. Every arithmetic operation is
//!   `checked_*`, `saturating_*`, or `wrapping_*`, and the workspace denies
//!   `clippy::arithmetic_side_effects`.
//! - **Constant-time discipline on key material.** The Poly1305 tag comparison,
//!   both confirmation comparisons, and the whole §5.3 selector scan are
//!   constant-time; the scan additionally copies the matched credential out by
//!   constant-time select rather than by indexing with the matched index.
//! - **Zeroization on drop and on advance.** [`Secret`] zeroizes in `Drop`, and
//!   every point §5.2, §6.1, and §9.4 names a `zeroize` calls it explicitly.
//! - **One indistinguishable authentication failure.**
//!   [`TransportCryptoError::AuthenticationFailed`] carries nothing and is
//!   returned identically for a forged tag, a replay, an out-of-range length, a
//!   bad padding field, and either confirmation mismatch.
//!
//! # Residual observables, stated
//!
//! - **`RecordIncomplete` is distinguishable from `AuthenticationFailed`.** §4.2
//!   makes the `packet_length` range check normative *before* the tag check, so
//!   a peer necessarily learns whether its four forged bytes decrypted into
//!   range: in-range means the receiver waits for more bytes, out-of-range means
//!   it drops. This is inherent to the `chacha20-poly1305@openssh.com`
//!   construction §4.2 mandates, not a choice made here, and the information is
//!   one bit about a value the peer cannot otherwise steer.
//! - Everything §5.7 lists — the revocation oracle, the plaintext
//!   `chain_counter`, and the fixed selector-scan cost — is unchanged by this
//!   implementation and is not restated here.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod credential;
mod error;
pub mod handshake;
pub mod hkdf;
pub mod hmac;
mod labels;
pub mod poly1305;
pub mod ratchet;
pub mod record;
pub mod schedule;
mod secret;

pub use crate::credential::{Credential, CredentialTable, MatchedCredential, FLAG_BREAK_GLASS};
pub use crate::error::TransportCryptoError;
pub use crate::handshake::{ClientHandshake, EstablishedSession, ServerHandshake};
pub use crate::hkdf::{expand, extract};
pub use crate::hmac::{hmac_sha256, HmacSha256};
pub use crate::labels::{
    info_client_confirm, info_label_role, info_selector, ALL_LABELS, INFO_CLIENT_CONFIRM_BYTES,
    INFO_LABEL_ROLE_BYTES, INFO_SELECTOR_BYTES, LABEL_CHAIN_INIT, LABEL_CHAIN_SALT,
    LABEL_CHAIN_STEP, LABEL_CLI_CONFIRM, LABEL_ENROLL_SALT, LABEL_ID_SALT, LABEL_KEYS_C2S,
    LABEL_KEYS_S2C, LABEL_KEY_HANDLE, LABEL_KEY_ID, LABEL_SELECTOR, LABEL_SRV_CONFIRM,
};
pub use crate::poly1305::{poly1305_mac, Poly1305};
pub use crate::ratchet::{advance_key, ChainKey, ChainState, ScratchChain};
pub use crate::record::{
    DirectionKeys, OpenedRecord, RecordOpener, RecordSealer, MAX_SEALED_RECORD_BYTES,
    RECORD_PLAINTEXT_CAPACITY,
};
pub use crate::schedule::{transcript_one, transcript_two, SessionSecrets, Side};
pub use crate::secret::{constant_time_eq, Secret};
