//! §5.4's twelve fixed 16-byte HKDF labels, and the `info` builders that place
//! them.
//!
//! Every label is exactly [`LEN_LABEL`] bytes of ASCII, NUL-padded on the
//! right. §5.4: "Every value the protocol uses is an HKDF output under a
//! distinct label. **No credential byte is ever used directly as a cipher
//! key**, and no two derived values are substitutable for one another."
//!
//! Two of them carry the whole reflection-attack defence:
//! [`LABEL_SRV_CONFIRM`] and [`LABEL_CLI_CONFIRM`] are distinct, so neither
//! confirmation can be replayed back at its sender as the other's proof (§5.6d).
//! `every_label_is_distinct_and_sixteen_bytes` pins both properties.
//!
//! The padding is deliberate and is not free: §5.3 records that shrinking
//! `LEN_LABEL` to 8 would put the selector `info` back at 48 bytes and recover
//! one SHA-256 compression per credential slot, and that uniform 16-byte labels
//! are worth more than that compression. The block is not recovered.

use brainix_bsp::{LEN_CONFIRM, LEN_LABEL, LEN_NONCE};

/// Builds a `LEN_LABEL`-byte label from a shorter ASCII string, NUL-padded.
///
/// A `const fn` so every label below is a compile-time constant and a label
/// longer than 16 bytes is a compile error rather than a truncation.
const fn label(text: &[u8]) -> [u8; LEN_LABEL] {
    let mut padded = [0u8; LEN_LABEL];
    let mut position = 0usize;
    while position < text.len() {
        padded[position] = text[position];
        position = position.saturating_add(1);
    }
    padded
}

/// `"BSP2 enroll"` + 5 NUL — the §5.2 `Extract` salt for enrolled key material.
pub const LABEL_ENROLL_SALT: [u8; LEN_LABEL] = label(b"BSP2 enroll");

/// `"BSP2 key-handle"` + 1 NUL — §5.2's `handle` expansion.
pub const LABEL_KEY_HANDLE: [u8; LEN_LABEL] = label(b"BSP2 key-handle");

/// `"BSP2 key-id"` + 5 NUL — §5.2's `K_id` expansion.
pub const LABEL_KEY_ID: [u8; LEN_LABEL] = label(b"BSP2 key-id");

/// `"BSP2 chain-init"` + 1 NUL — §5.2's `CK_0` expansion.
pub const LABEL_CHAIN_INIT: [u8; LEN_LABEL] = label(b"BSP2 chain-init");

/// `"BSP2 chain-salt"` + 1 NUL — §6.1's `Extract` salt for a chain advance.
pub const LABEL_CHAIN_SALT: [u8; LEN_LABEL] = label(b"BSP2 chain-salt");

/// `"BSP2 chain-step"` + 1 NUL — §6.1's `Expand` info for a chain advance.
pub const LABEL_CHAIN_STEP: [u8; LEN_LABEL] = label(b"BSP2 chain-step");

/// `"BSP2 id-salt"` + 4 NUL — §5.3's `Extract` salt over `K_id`.
pub const LABEL_ID_SALT: [u8; LEN_LABEL] = label(b"BSP2 id-salt");

/// `"BSP2 selector"` + 3 NUL — §5.3's `key_selector` expansion.
pub const LABEL_SELECTOR: [u8; LEN_LABEL] = label(b"BSP2 selector");

/// `"BSP2 srv-confirm"`, exactly 16 — §5.4's `server_confirm`.
pub const LABEL_SRV_CONFIRM: [u8; LEN_LABEL] = label(b"BSP2 srv-confirm");

/// `"BSP2 cli-confirm"`, exactly 16 — §5.4's `client_confirm`.
pub const LABEL_CLI_CONFIRM: [u8; LEN_LABEL] = label(b"BSP2 cli-confirm");

/// `"BSP2 keys c2s"` + 3 NUL — §5.4's client-to-server directional keys.
pub const LABEL_KEYS_C2S: [u8; LEN_LABEL] = label(b"BSP2 keys c2s");

/// `"BSP2 keys s2c"` + 3 NUL — §5.4's server-to-client directional keys.
pub const LABEL_KEYS_S2C: [u8; LEN_LABEL] = label(b"BSP2 keys s2c");

/// All twelve labels, in §5.4's table order — the fixture the distinctness and
/// width tests walk.
pub const ALL_LABELS: [[u8; LEN_LABEL]; 12] = [
    LABEL_ENROLL_SALT,
    LABEL_KEY_HANDLE,
    LABEL_KEY_ID,
    LABEL_CHAIN_INIT,
    LABEL_CHAIN_SALT,
    LABEL_CHAIN_STEP,
    LABEL_ID_SALT,
    LABEL_SELECTOR,
    LABEL_SRV_CONFIRM,
    LABEL_CLI_CONFIRM,
    LABEL_KEYS_C2S,
    LABEL_KEYS_S2C,
];

/// Bytes in a `LABEL || role` info: the §5.2 and §5.4 shape.
pub const INFO_LABEL_ROLE_BYTES: usize = LEN_LABEL + 1;

/// Bytes in §5.3's selector info: `LABEL || chain_counter || client_nonce`.
///
/// §5.3 states the figure explicitly — `16 + 8 + 32 = 56` — and rests the DoS
/// arithmetic of §5.7 and §8 on it, so it is asserted here rather than left to
/// be recomputed.
pub const INFO_SELECTOR_BYTES: usize = LEN_LABEL + 8 + LEN_NONCE;

/// Bytes in §5.4's `client_confirm` info: `LABEL || role || TH_2`.
pub const INFO_CLIENT_CONFIRM_BYTES: usize = LEN_LABEL + 1 + LEN_CONFIRM;

/// `LABEL || role` — §5.2's three enrollment expansions and §5.4's
/// `server_confirm`, `K_c2s`, and `K_s2c`.
///
/// §5.2: "`role` is a single byte and is bound into all three expansions, so a
/// credential enrolled as a client can never produce the identification or
/// chain material of an admin credential even if a caller passes the wrong role
/// later."
#[must_use]
pub fn info_label_role(label_bytes: &[u8; LEN_LABEL], role: u8) -> [u8; INFO_LABEL_ROLE_BYTES] {
    let mut info = [0u8; INFO_LABEL_ROLE_BYTES];
    info[..LEN_LABEL].copy_from_slice(label_bytes);
    info[LEN_LABEL] = role;
    info
}

/// `LABEL_SELECTOR || chain_counter || client_nonce` — §5.3.
///
/// `chain_counter` is big-endian, per §3's "All integers big-endian".
///
/// **The counter's presence here is not cosmetic** (§5.3): it is what makes the
/// counter unforgeable by anyone who does not hold `K_id`, and therefore what
/// stops an attacker choosing how many chain advances a `ClientHello` costs the
/// server.
#[must_use]
pub fn info_selector(
    chain_counter: u64,
    client_nonce: &[u8; LEN_NONCE],
) -> [u8; INFO_SELECTOR_BYTES] {
    let mut info = [0u8; INFO_SELECTOR_BYTES];
    info[..LEN_LABEL].copy_from_slice(&LABEL_SELECTOR);
    info[LEN_LABEL..LEN_LABEL + 8].copy_from_slice(&chain_counter.to_be_bytes());
    info[LEN_LABEL + 8..].copy_from_slice(client_nonce);
    info
}

/// `LABEL_CLI_CONFIRM || role || TH_2` — §5.4.
///
/// §5.4 records that `TH_2` here is *redundant*: `PRK_session` already depends
/// on the transcript, so `TH_2` adds no material the derivation did not already
/// have. It is included "so the binding is legible in the code and provable
/// directly, without an argument about determinism", and it is included here
/// for exactly that reason.
#[must_use]
pub fn info_client_confirm(
    role: u8,
    transcript_two: &[u8; LEN_CONFIRM],
) -> [u8; INFO_CLIENT_CONFIRM_BYTES] {
    let mut info = [0u8; INFO_CLIENT_CONFIRM_BYTES];
    info[..LEN_LABEL].copy_from_slice(&LABEL_CLI_CONFIRM);
    info[LEN_LABEL] = role;
    info[LEN_LABEL + 1..].copy_from_slice(transcript_two);
    info
}
