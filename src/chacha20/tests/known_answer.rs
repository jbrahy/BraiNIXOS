//! Known-answer tests for the in-tree ChaCha20, against RFC 8439.
//!
//! **Why a published vector and not a round-trip.** ChaCha20 is its own inverse:
//! `apply_keystream` twice over the same buffer returns the original bytes
//! whether or not the cipher is ChaCha20 at all. A round-trip test passes
//! against a keystream of zeroes. So the only test that says anything is one
//! where the expected bytes came from somewhere other than this code — here,
//! RFC 8439 §2.3.2 (the block function) and §2.4.2 (the cipher).
//!
//! The vectors below were transcribed from the RFC text, not recalled. If one
//! of them is wrong the test still fails closed: a mistyped expectation makes a
//! correct implementation look broken, which is the safe direction for a
//! transcription error in a cryptographic test.
//!
//! What this file deliberately does **not** do is compare against the vendored
//! `chacha20` crate. That crate is what this one exists to delete (X-T4), and a
//! test that only says "the two agree" would keep passing if both were wrong in
//! the same way — and would quietly make the dependency load-bearing again.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use brainix_chacha20::{apply_keystream, block, BLOCK_LEN, KEY_LEN, NONCE_LEN};

/// Decodes a hex literal, ignoring ASCII whitespace so vectors can be pasted
/// in the RFC's own layout and stay readable against it.
fn hex<const N: usize>(text: &str) -> [u8; N] {
    let mut out = [0u8; N];
    let mut nibbles = text.bytes().filter(|byte| !byte.is_ascii_whitespace());
    for slot in out.iter_mut() {
        let high = from_hex(nibbles.next().expect("vector is shorter than expected"));
        let low = from_hex(nibbles.next().expect("vector has an odd nibble count"));
        *slot = (high << 4) | low;
    }
    assert!(
        nibbles.next().is_none(),
        "vector is longer than the array it decodes into"
    );
    out
}

fn from_hex(character: u8) -> u8 {
    match character {
        b'0'..=b'9' => character - b'0',
        b'a'..=b'f' => character - b'a' + 10,
        b'A'..=b'F' => character - b'A' + 10,
        _ => panic!("non-hex character in a test vector"),
    }
}

/// The key shared by both RFC vectors: bytes 0x00 through 0x1f in order.
const RFC_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

// ---------------------------------------------------------------------------
// RFC 8439 §2.3.2 — the block function
// ---------------------------------------------------------------------------

/// The one vector that pins the state layout, the round schedule, and the
/// final add-and-serialize step all at once.
#[test]
fn block_matches_rfc_8439_section_2_3_2() {
    let key: [u8; KEY_LEN] = hex(RFC_KEY);
    let nonce: [u8; NONCE_LEN] = hex("000000090000004a00000000");

    let expected: [u8; BLOCK_LEN] = hex("10f1e7e4d13b5915500fdd1fa32071c4
         c7d1f4c733c068030422aa9ac3d46c4e
         d2826446079faa0914c2d705d98b02a2
         b5129cd1de164eb9cbd083e8a2503c4e");

    assert_eq!(block(&key, &nonce, 1), expected);
}

/// The counter is a real input, not decoration: a different counter must give a
/// different block. Without this, an implementation that ignored the counter
/// entirely would pass the vector above and reuse one keystream block for every
/// block of a message.
#[test]
fn a_different_counter_gives_a_different_block() {
    let key: [u8; KEY_LEN] = hex(RFC_KEY);
    let nonce: [u8; NONCE_LEN] = hex("000000090000004a00000000");

    assert_ne!(block(&key, &nonce, 1), block(&key, &nonce, 2));
}

// ---------------------------------------------------------------------------
// RFC 8439 §2.4.2 — the cipher over a 114-byte plaintext
// ---------------------------------------------------------------------------

/// 114 bytes is deliberately not a multiple of 64, so this vector also pins the
/// partial-final-block path — the place an off-by-one in the chunking would
/// hide from any whole-block test.
#[test]
fn apply_keystream_matches_rfc_8439_section_2_4_2() {
    let key: [u8; KEY_LEN] = hex(RFC_KEY);
    let nonce: [u8; NONCE_LEN] = hex("000000000000004a00000000");

    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it.";
    assert_eq!(plaintext.len(), 114);

    let expected: [u8; 114] = hex("6e2e359a2568f98041ba0728dd0d6981
         e97e7aec1d4360c20a27afccfd9fae0b
         f91b65c5524733ab8f593dabcd62b357
         1639d624e65152ab8f530c359f0861d8
         07ca0dbf500d6a6156a38e088a22b65e
         52bc514d16ccf806818ce91ab7793736
         5af90bbf74a35be6b40b8eedf2785e42
         874d");

    let mut buffer = *plaintext;
    let next = apply_keystream(&key, &nonce, 1, &mut buffer).expect("114 bytes needs two blocks");

    assert_eq!(buffer, expected);
    assert_eq!(next, 3, "two blocks consumed from counter 1 ends at 3");
}

/// Decryption is the same call, and it has to land back on the plaintext.
#[test]
fn applying_the_keystream_twice_restores_the_plaintext() {
    let key: [u8; KEY_LEN] = hex(RFC_KEY);
    let nonce: [u8; NONCE_LEN] = hex("000000000000004a00000000");

    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it.";

    let mut buffer = *plaintext;
    apply_keystream(&key, &nonce, 1, &mut buffer).expect("encrypt");
    assert_ne!(
        &buffer, plaintext,
        "the cipher must actually change the bytes"
    );
    apply_keystream(&key, &nonce, 1, &mut buffer).expect("decrypt");
    assert_eq!(&buffer, plaintext);
}

// ---------------------------------------------------------------------------
// Boundaries the RFC does not supply a vector for
// ---------------------------------------------------------------------------

/// An empty buffer consumes no keystream and must not advance the counter. A
/// counter that advanced here would desynchronize the record layer's sequence
/// against a peer that did nothing.
#[test]
fn an_empty_buffer_consumes_no_blocks() {
    let key: [u8; KEY_LEN] = hex(RFC_KEY);
    let nonce: [u8; NONCE_LEN] = hex("000000000000004a00000000");

    let mut empty: [u8; 0] = [];
    assert_eq!(apply_keystream(&key, &nonce, 7, &mut empty), Some(7));
}

/// Exactly one block must consume exactly one counter value — the boundary
/// where `<` and `<=` in the chunking loop differ.
#[test]
fn one_whole_block_advances_the_counter_once() {
    let key: [u8; KEY_LEN] = hex(RFC_KEY);
    let nonce: [u8; NONCE_LEN] = hex("000000000000004a00000000");

    let mut buffer = [0u8; BLOCK_LEN];
    assert_eq!(apply_keystream(&key, &nonce, 0, &mut buffer), Some(1));
}

/// Xoring the keystream into zeroes yields the keystream, so this pins that
/// `apply_keystream` and `block` agree about which block is which.
#[test]
fn the_keystream_over_zeroes_is_the_block_function() {
    let key: [u8; KEY_LEN] = hex(RFC_KEY);
    let nonce: [u8; NONCE_LEN] = hex("000000090000004a00000000");

    let mut buffer = [0u8; BLOCK_LEN];
    apply_keystream(&key, &nonce, 1, &mut buffer).expect("one block");
    assert_eq!(buffer, block(&key, &nonce, 1));
}

/// Running off the end of the counter denies rather than wrapping. A wrapped
/// counter silently reuses keystream, which is the same disaster as reusing a
/// nonce and is much harder to see in a packet capture.
#[test]
fn a_counter_that_would_wrap_denies() {
    let key: [u8; KEY_LEN] = hex(RFC_KEY);
    let nonce: [u8; NONCE_LEN] = hex("000000000000004a00000000");

    // Two blocks' worth of buffer starting one short of the end: the first
    // block takes the counter to u32::MAX, the second has nowhere to go.
    let mut buffer = [0u8; BLOCK_LEN * 2];
    assert_eq!(
        apply_keystream(&key, &nonce, u32::MAX - 1, &mut buffer),
        None
    );
}
