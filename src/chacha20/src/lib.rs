#![no_std]
#![deny(unsafe_code)]

//! ChaCha20, in tree, from RFC 8439 (X-T4).
//!
//! The second of the two crates the north star names for deletion: *"the
//! in-tree set is SHA-256, HKDF, ChaCha20 and Poly1305 … which deletes `sha2`
//! and `chacha20`."* With SHA-256 landed, this is the other one, and together
//! they are what lets a document describe the serving transport's primitive set
//! as in-tree without it being false.
//!
//! # Constant time by construction, and here that matters more than in SHA-256
//!
//! The whole cipher is adds, xors and rotations over a fixed 16-word state, run
//! a fixed twenty rounds. There is **no branch on key or plaintext and no table
//! indexed by either**, so the time a block takes is a function of nothing an
//! attacker supplies. That is not a property to be tested for; it is visible in
//! the code, and it is the reason ChaCha20 was chosen over a cipher whose
//! fast implementations need S-box lookups.
//!
//! The keystream is xored into the caller's buffer, so encryption and
//! decryption are the same function — which is also where the one real hazard
//! lives: **reusing a (key, nonce) pair xors two plaintexts together**. This
//! module cannot prevent that; the record layer's sequence counter is what
//! does, and BSP v2 §4.2 makes the counter's advance the thing that fails
//! closed.

/// Bytes in a ChaCha20 key.
pub const KEY_LEN: usize = 32;

/// Bytes in an RFC 8439 nonce.
pub const NONCE_LEN: usize = 12;

/// Bytes in one keystream block.
pub const BLOCK_LEN: usize = 64;

/// The four constant words: "expand 32-byte k", little-endian.
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// One quarter-round, RFC 8439 §2.1.
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    let Some(&va) = state.get(a) else { return };
    let Some(&vb) = state.get(b) else { return };
    let Some(&vc) = state.get(c) else { return };
    let Some(&vd) = state.get(d) else { return };

    let (mut wa, mut wb, mut wc, mut wd) = (va, vb, vc, vd);
    wa = wa.wrapping_add(wb);
    wd = (wd ^ wa).rotate_left(16);
    wc = wc.wrapping_add(wd);
    wb = (wb ^ wc).rotate_left(12);
    wa = wa.wrapping_add(wb);
    wd = (wd ^ wa).rotate_left(8);
    wc = wc.wrapping_add(wd);
    wb = (wb ^ wc).rotate_left(7);

    if let Some(slot) = state.get_mut(a) {
        *slot = wa;
    }
    if let Some(slot) = state.get_mut(b) {
        *slot = wb;
    }
    if let Some(slot) = state.get_mut(c) {
        *slot = wc;
    }
    if let Some(slot) = state.get_mut(d) {
        *slot = wd;
    }
}

/// Loads little-endian words from `bytes` into `state`, starting at word `at`.
///
/// Every step is fallible so the function needs no indexing and no panic path,
/// which is what lets the crate hold `#![deny(unsafe_code)]` and the
/// workspace's `indexing_slicing` lint at once. None of the failure paths can
/// fire for the fixed-size arrays this is called with — a short read simply
/// leaves the remaining words at their initialized value.
fn load_words(state: &mut [u32; 16], at: usize, bytes: &[u8]) {
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let Ok(word) = <[u8; 4]>::try_from(chunk) else {
            break;
        };
        if let Some(slot) = state.get_mut(at.saturating_add(index)) {
            *slot = u32::from_le_bytes(word);
        }
    }
}

/// The initial state for a key, nonce and block counter (RFC 8439 §2.3).
///
/// The layout is the whole of what distinguishes this from the 64-bit-nonce
/// construction: **one** counter word at 12 and **three** nonce words at 13.
/// The legacy variant splits that differently, which is why the two are not
/// interchangeable and why a crate implementing one cannot stand in for the
/// other.
fn initial_state(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], counter: u32) -> [u32; 16] {
    let mut state = [0u32; 16];
    for (slot, constant) in state.iter_mut().zip(CONSTANTS) {
        *slot = constant;
    }
    load_words(&mut state, 4, key);
    if let Some(slot) = state.get_mut(12) {
        *slot = counter;
    }
    load_words(&mut state, 13, nonce);
    state
}

/// One 64-byte keystream block, RFC 8439 §2.3.
#[must_use]
pub fn block(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], counter: u32) -> [u8; BLOCK_LEN] {
    let start = initial_state(key, nonce, counter);
    let mut working = start;

    // Twenty rounds: ten column rounds each followed by a diagonal round.
    for _ in 0..10 {
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; BLOCK_LEN];
    for (index, (worked, initial)) in working.iter().zip(start.iter()).enumerate() {
        let word = worked.wrapping_add(*initial);
        let at = index.saturating_mul(4);
        if let Some(slot) = out.get_mut(at..at.saturating_add(4)) {
            slot.copy_from_slice(&word.to_le_bytes());
        }
    }
    out
}

/// Xors the keystream into `buffer`, starting at block `counter`.
///
/// Encryption and decryption are the same call. **Never use one (key, nonce)
/// pair for two different buffers**: that xors two plaintexts together, and no
/// property of this function prevents it — the record layer's sequence counter
/// is what does.
///
/// Returns the block counter that would follow, or `None` if the buffer needs
/// more blocks than the counter can express. Denying beats wrapping: a wrapped
/// counter silently reuses keystream, which is the same disaster as reusing a
/// nonce and is harder to see.
pub fn apply_keystream(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    counter: u32,
    buffer: &mut [u8],
) -> Option<u32> {
    let mut current = counter;
    let mut offset = 0usize;

    while offset < buffer.len() {
        let stream = block(key, nonce, current);
        let take = BLOCK_LEN.min(buffer.len().saturating_sub(offset));
        let end = offset.saturating_add(take);
        let chunk = buffer.get_mut(offset..end)?;
        for (byte, key_byte) in chunk.iter_mut().zip(stream.iter()) {
            *byte ^= *key_byte;
        }
        offset = end;
        current = current.checked_add(1)?;
    }
    Some(current)
}
