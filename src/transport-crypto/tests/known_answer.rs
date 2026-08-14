//! Known-answer tests against published RFC vectors.
//!
//! **Why this file exists at all.** A key schedule that is self-consistent but
//! wrong round-trips perfectly and interoperates with nothing. Every primitive
//! below is therefore checked against a vector published by someone other than
//! this project — RFC 4231 for HMAC-SHA256, RFC 5869 for HKDF-SHA256, RFC 8439
//! for ChaCha20, Poly1305, and the AEAD composition of the two, and FIPS 180-4
//! for SHA-256 itself -- which since X-T4 is the in-tree `brainix-sha256`, so
//! that vector now checks our code rather than a vendored crate's.
//!
//! The AEAD case is the important one: `chacha20-poly1305@openssh.com` (§4.2)
//! has no published vector, because §0 says there is no interoperability to
//! preserve. So the *composition* is checked in the one form that does have a
//! vector — RFC 8439 §2.8.2's `AEAD_CHACHA20_POLY1305` — assembled here in
//! test code from the same vendored ChaCha20 and the same in-tree Poly1305 the
//! record layer uses. If either primitive or the "MAC key is keystream block 0"
//! rule were wrong, this test fails.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cognitive_complexity,
    clippy::useless_vec
)]

use brainix_transport_crypto::{expand, extract, hmac_sha256, poly1305_mac, Secret};

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;

/// Decodes a compile-time hex literal into a fixed array.
fn hex<const N: usize>(text: &str) -> [u8; N] {
    let mut out = [0u8; N];
    let bytes = text.as_bytes();
    for (index, slot) in out.iter_mut().enumerate() {
        let high = from_hex(bytes[index * 2]);
        let low = from_hex(bytes[index * 2 + 1]);
        *slot = (high << 4) | low;
    }
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

// ---------------------------------------------------------------------------
// SHA-256 — FIPS 180-4 / NIST CAVP
// ---------------------------------------------------------------------------

#[test]
fn sha256_matches_the_fips_180_4_abc_vector() {
    let digest: [u8; 32] = brainix_sha256::digest(b"abc");
    assert_eq!(
        digest,
        hex::<32>("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 — RFC 4231
// ---------------------------------------------------------------------------

#[test]
fn hmac_sha256_matches_rfc_4231_test_case_1() {
    let key = [0x0bu8; 20];
    assert_eq!(
        hmac_sha256(&key, b"Hi There"),
        hex::<32>("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );
}

#[test]
fn hmac_sha256_matches_rfc_4231_test_case_2() {
    assert_eq!(
        hmac_sha256(b"Jefe", b"what do ya want for nothing?"),
        hex::<32>("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    );
}

#[test]
fn hmac_sha256_matches_rfc_4231_test_case_3() {
    let key = [0xaau8; 20];
    let message = [0xddu8; 50];
    assert_eq!(
        hmac_sha256(&key, &message),
        hex::<32>("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
    );
}

/// RFC 4231 test case 6 — a 131-byte key, which is the **only** case that
/// exercises HMAC's "hash the key if it is longer than a block" branch.
///
/// No BSP v2 derivation reaches that branch; it is tested anyway, because a
/// construction checked only on the inputs it happens to receive is a
/// construction that has not been checked.
#[test]
fn hmac_sha256_matches_rfc_4231_test_case_6_with_an_over_length_key() {
    let key = [0xaau8; 131];
    assert_eq!(
        hmac_sha256(
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        ),
        hex::<32>("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
    );
}

// ---------------------------------------------------------------------------
// HKDF-SHA256 — RFC 5869 appendix A
// ---------------------------------------------------------------------------

#[test]
fn hkdf_sha256_matches_rfc_5869_test_case_1() {
    let input_key_material = [0x0bu8; 22];
    let salt = hex::<13>("000102030405060708090a0b0c");
    let info = hex::<10>("f0f1f2f3f4f5f6f7f8f9");
    let pseudorandom_key = extract(&salt, &input_key_material);
    assert_eq!(
        pseudorandom_key.expose(),
        &hex::<32>("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
    );
    let output = expand::<42>(&pseudorandom_key, &info);
    assert_eq!(
        output.expose(),
        &hex::<42>(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        )
    );
}

#[test]
fn hkdf_sha256_matches_rfc_5869_test_case_2_with_a_multi_block_output() {
    let mut input_key_material = [0u8; 80];
    let mut salt = [0u8; 80];
    let mut info = [0u8; 80];
    for (index, slot) in input_key_material.iter_mut().enumerate() {
        *slot = index as u8;
    }
    for (index, slot) in salt.iter_mut().enumerate() {
        *slot = 0x60 + index as u8;
    }
    for (index, slot) in info.iter_mut().enumerate() {
        *slot = 0xb0 + index as u8;
    }
    let pseudorandom_key = extract(&salt, &input_key_material);
    assert_eq!(
        pseudorandom_key.expose(),
        &hex::<32>("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")
    );
    let output = expand::<82>(&pseudorandom_key, &info);
    assert_eq!(
        output.expose(),
        &hex::<82>(concat!(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c",
            "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71",
            "cc30c58179ec3e87c14c01d5c1f3434f1d87"
        ))
    );
}

#[test]
fn hkdf_sha256_matches_rfc_5869_test_case_3_with_empty_salt_and_info() {
    let input_key_material = [0x0bu8; 22];
    let pseudorandom_key = extract(&[], &input_key_material);
    assert_eq!(
        pseudorandom_key.expose(),
        &hex::<32>("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
    );
    let output = expand::<42>(&pseudorandom_key, &[]);
    assert_eq!(
        output.expose(),
        &hex::<42>(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        )
    );
}

// ---------------------------------------------------------------------------
// Poly1305 — RFC 8439
// ---------------------------------------------------------------------------

#[test]
fn poly1305_matches_rfc_8439_section_2_5_2() {
    let key = hex::<32>(concat!(
        "85d6be7857556d337f4452fe42d506a8",
        "0103808afb0db2fd4abff6af4149f51b"
    ));
    assert_eq!(
        poly1305_mac(&key, b"Cryptographic Forum Research Group"),
        hex::<16>("a8061dc1305136c6c22b8baf0c0127a9")
    );
}

/// RFC 8439 §A.3 test vector #1 — an all-zero key over an all-zero 64-byte
/// message, whose tag is all zeros. The degenerate case the mask select in
/// `select_reduced` decides.
#[test]
fn poly1305_matches_rfc_8439_appendix_a3_vector_1() {
    assert_eq!(poly1305_mac(&[0u8; 32], &[0u8; 64]), [0u8; 16]);
}

/// RFC 8439 §A.3 test vector #2 — `r = 0`, so the tag is `s` regardless of the
/// message.
#[test]
fn poly1305_matches_rfc_8439_appendix_a3_vector_2() {
    let key = hex::<32>(concat!(
        "00000000000000000000000000000000",
        "36e5f6b5c5e06070f0efca96227a863e"
    ));
    let message = b"Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to";
    assert_eq!(
        poly1305_mac(&key, message),
        hex::<16>("36e5f6b5c5e06070f0efca96227a863e")
    );
}

/// RFC 8439 §A.3 test vector #4.
#[test]
fn poly1305_matches_rfc_8439_appendix_a3_vector_4() {
    let key = hex::<32>(concat!(
        "1c9240a5eb55d38af333888604f6b5f0",
        "473917c1402b80099dca5cbc207075c0"
    ));
    let message = b"'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.";
    assert_eq!(
        poly1305_mac(&key, message),
        hex::<16>("4541669a7eaaee61e708dc7cbcc5eb62")
    );
}

/// The streaming API must agree with the one-shot API at every split point,
/// because the record layer feeds it `enc_length` and `ciphertext` separately.
#[test]
fn poly1305_streaming_agrees_with_one_shot_at_every_split() {
    let key = hex::<32>(concat!(
        "85d6be7857556d337f4452fe42d506a8",
        "0103808afb0db2fd4abff6af4149f51b"
    ));
    let message: [u8; 70] = core::array::from_fn(|index| index as u8);
    let expected = poly1305_mac(&key, &message);
    for split in 0..=message.len() {
        let mut state = brainix_transport_crypto::Poly1305::new(&key);
        state.update(&message[..split]);
        state.update(&message[split..]);
        assert_eq!(state.finalize(), expected, "split at {split}");
    }
}

// ---------------------------------------------------------------------------
// ChaCha20 — RFC 8439
// ---------------------------------------------------------------------------

/// RFC 8439 §A.1 test vector #1: all-zero key, all-zero nonce, counter 0.
///
/// Checks the vendored `chacha20` crate itself, not a wrapper around it.
#[test]
fn chacha20_matches_rfc_8439_appendix_a1_vector_1() {
    let mut keystream = [0u8; 64];
    let mut cipher = ChaCha20::new(&[0u8; 32].into(), &[0u8; 12].into());
    cipher.apply_keystream(&mut keystream);
    assert_eq!(
        keystream,
        hex::<64>(concat!(
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
            "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
        ))
    );
}

/// RFC 8439 §2.4.2 — the "Ladies and Gentlemen" encryption vector.
#[test]
fn chacha20_matches_rfc_8439_section_2_4_2() {
    let key: [u8; 32] = core::array::from_fn(|index| index as u8);
    let nonce = hex::<12>("000000000000004a00000000");
    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    cipher.seek(64u32);
    let mut block = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    cipher.apply_keystream(&mut block);
    assert_eq!(
        block[..32],
        hex::<32>("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b")
    );
}

// ---------------------------------------------------------------------------
// The AEAD composition — RFC 8439 §2.8.2
// ---------------------------------------------------------------------------

/// RFC 8439 §2.8.2 `AEAD_CHACHA20_POLY1305`, assembled here from the vendored
/// ChaCha20 and this crate's Poly1305.
///
/// This is not the construction §4.2 uses — that is
/// `chacha20-poly1305@openssh.com`, which has no published vector because §0
/// disclaims interoperability. What the two share is everything that could be
/// wrong in a way a round-trip test cannot see: the cipher, the MAC, and the
/// rule that the one-time MAC key is keystream block 0 under the payload key.
#[test]
fn the_aead_composition_matches_rfc_8439_section_2_8_2() {
    let key: [u8; 32] = core::array::from_fn(|index| index as u8 + 0x80);
    let nonce = hex::<12>("070000004041424344454647");
    let associated_data = hex::<12>("50515253c0c1c2c3c4c5c6c7");
    let mut ciphertext = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    let mut mac_key_block = [0u8; 64];
    cipher.apply_keystream(&mut mac_key_block);
    let mut mac_key = [0u8; 32];
    mac_key.copy_from_slice(&mac_key_block[..32]);
    cipher.apply_keystream(&mut ciphertext);

    assert_eq!(
        ciphertext[..32],
        hex::<32>("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6")
    );

    let mut state = brainix_transport_crypto::Poly1305::new(&mac_key);
    let padding = [0u8; 16];
    state.update(&associated_data);
    state.update(&padding[..(16 - associated_data.len() % 16) % 16]);
    state.update(&ciphertext);
    state.update(&padding[..(16 - ciphertext.len() % 16) % 16]);
    state.update(&(associated_data.len() as u64).to_le_bytes());
    state.update(&(ciphertext.len() as u64).to_le_bytes());
    assert_eq!(
        state.finalize(),
        hex::<16>("1ae10b594f09e26a7e902ecbd0600691")
    );
}

// ---------------------------------------------------------------------------
// The labels themselves
// ---------------------------------------------------------------------------

/// §5.4 requires twelve labels, each exactly `LEN_LABEL` bytes, all distinct.
///
/// Distinctness is not cosmetic: §5.6d makes the difference between
/// `LABEL_SRV_CONFIRM` and `LABEL_CLI_CONFIRM` "the whole defence" against
/// reflecting one party's confirmation back as the other's proof.
#[test]
fn every_label_is_distinct_and_sixteen_bytes() {
    let labels = brainix_transport_crypto::ALL_LABELS;
    assert_eq!(labels.len(), 12);
    for (index, label) in labels.iter().enumerate() {
        assert_eq!(label.len(), 16);
        for other in labels.iter().skip(index + 1) {
            assert_ne!(label, other);
        }
    }
}

/// Secrets are zeroized by `Drop`, and by the explicit call the specification
/// names at §5.2, §6.1, and §9.4.
#[test]
fn an_explicit_zeroize_clears_the_material() {
    let mut secret = Secret::<32>::from_bytes([0xa5u8; 32]);
    assert_eq!(secret.expose(), &[0xa5u8; 32]);
    secret.zeroize();
    assert_eq!(secret.expose(), &[0u8; 32]);
}
