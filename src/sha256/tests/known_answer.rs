//! FIPS 180-4 and RFC 6234 vectors, plus the cases vectors never cover.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
#![allow(clippy::cognitive_complexity)]

use brainix_sha256::{digest, Sha256, BLOCK_LEN, DIGEST_LEN};

fn hex(bytes: &[u8; DIGEST_LEN]) -> [u8; 64] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (index, byte) in bytes.iter().enumerate() {
        out[index * 2] = HEX[usize::from(byte >> 4)];
        out[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    out
}

fn assert_digest(message: &[u8], expected: &str) {
    let produced = hex(&digest(message));
    assert_eq!(
        core::str::from_utf8(&produced).expect("hex is ascii"),
        expected,
        "digest of {} bytes",
        message.len()
    );
}

#[test]
fn the_empty_message() {
    // FIPS 180-4's zero-length case, and the one an implementation that forgets
    // to pad at all still gets wrong.
    assert_digest(
        b"",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
}

#[test]
fn the_two_fips_180_4_examples() {
    assert_digest(
        b"abc",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    assert_digest(
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    );
}

#[test]
fn the_two_block_example_and_a_million_a_s() {
    assert_digest(
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
    );

    // RFC 6234's long case: a million 'a's, fed in awkward chunks so the
    // buffering path is exercised rather than the whole-message one.
    let mut hasher = Sha256::new();
    let chunk = [b'a'; 1000];
    for _ in 0..1000 {
        hasher.update(&chunk);
    }
    let produced = hex(&hasher.finalize());
    assert_eq!(
        core::str::from_utf8(&produced).expect("hex is ascii"),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

#[test]
fn a_message_split_at_every_offset_hashes_the_same_as_one_call() {
    // The buffering boundary is where a streaming hash breaks, and no published
    // vector exercises it: they are single calls.
    let message: [u8; 200] = core::array::from_fn(|index| index as u8);
    let whole = digest(&message);

    for split in 0..message.len() {
        let mut hasher = Sha256::new();
        hasher.update(&message[..split]);
        hasher.update(&message[split..]);
        assert_eq!(hasher.finalize(), whole, "split at {split}");
    }
}

#[test]
fn the_block_boundaries_themselves() {
    // 55, 56, 63, 64, 65: the lengths where padding either just fits, just does
    // not, or lands exactly on a block. Every off-by-one in the padding shows
    // up in one of these and in none of the published vectors.
    for length in [55usize, 56, 63, 64, 65, 119, 120, 127, 128] {
        let message = vec![0x61u8; length];
        let streamed = {
            let mut hasher = Sha256::new();
            for byte in &message {
                hasher.update(&[*byte]);
            }
            hasher.finalize()
        };
        assert_eq!(streamed, digest(&message), "length {length}");
    }
}

#[test]
fn a_fresh_hasher_and_the_default_agree() {
    assert_eq!(Sha256::new().finalize(), Sha256::default().finalize());
    assert_eq!(Sha256::new().finalize(), digest(b""));
}

#[test]
fn a_forked_computation_does_not_disturb_its_parent() {
    // `Copy` is what the BXW1 loader's streaming digest wants: fork once, keep
    // hashing, and the fork must not be a shared mutable buffer.
    let mut hasher = Sha256::new();
    hasher.update(b"prefix");
    let forked = hasher;

    hasher.update(b"-parent");
    let parent = hasher.finalize();
    let child = forked.finalize();

    assert_eq!(parent, digest(b"prefix-parent"));
    assert_eq!(child, digest(b"prefix"));
    assert_ne!(parent, child);
}

#[test]
fn one_block_of_input_is_exactly_one_compression() {
    let message = [0x5Au8; BLOCK_LEN];
    assert_eq!(digest(&message).len(), DIGEST_LEN);
    // A block-sized message still gets a whole padding block after it: the
    // digest must differ from the same bytes hashed as two halves plus nothing.
    assert_ne!(digest(&message), digest(&message[..BLOCK_LEN - 1]));
}
