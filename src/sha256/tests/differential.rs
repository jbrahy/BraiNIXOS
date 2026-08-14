//! The vendored crate as an oracle, for as long as it is still here.
//!
//! Published vectors check a handful of inputs. This checks agreement with the
//! implementation currently in production across every length that matters, so
//! the swap X-T4 performs is a swap between two things known to agree rather
//! than between one thing tested and another thing hoped for.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

use sha2::{Digest, Sha256 as VendoredSha256};

#[test]
fn the_in_tree_digest_agrees_with_the_vendored_one_at_every_length_to_two_blocks() {
    for length in 0..=200usize {
        let message: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();

        let mut vendored = VendoredSha256::new();
        vendored.update(&message);
        let expected: [u8; 32] = vendored.finalize().into();

        assert_eq!(
            brainix_sha256::digest(&message),
            expected,
            "disagreement at length {length}"
        );
    }
}

#[test]
fn they_agree_on_a_streamed_message_split_at_awkward_offsets() {
    let message: Vec<u8> = (0..1024).map(|index| (index % 7) as u8).collect();
    for split in [1usize, 55, 56, 63, 64, 65, 127, 128, 1000] {
        let mut ours = brainix_sha256::Sha256::new();
        ours.update(&message[..split]);
        ours.update(&message[split..]);

        let mut vendored = VendoredSha256::new();
        vendored.update(&message);
        let expected: [u8; 32] = vendored.finalize().into();

        assert_eq!(ours.finalize(), expected, "split at {split}");
    }
}
