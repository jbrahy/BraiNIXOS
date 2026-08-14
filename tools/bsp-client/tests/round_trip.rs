//! Two implementations, one specification, required to agree.
//!
//! Every test here encodes with this crate and decodes with `brainix-bsp`. A
//! field-offset mistake in either shows up as a disagreement; before this
//! crate existed, the server's decoder was tested against byte arrays written
//! by hand from the same field tables, which is the same reading of the
//! specification checked twice.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
#![allow(clippy::cognitive_complexity)]

use brainix_bsp::{
    BspError, ClientAuth, ClientHello, BSP_MAGIC, LEN_CLIENT_AUTH, LEN_CLIENT_HELLO, LEN_CONFIRM,
    LEN_NONCE, LEN_SELECTOR,
};
use brainix_bsp_client::{encode_client_auth, encode_client_hello};

fn a_hello() -> ClientHello {
    ClientHello {
        chain_counter: 0x0102_0304_0506_0708,
        client_nonce: [0xA5; LEN_NONCE],
        key_selector: [0x5A; LEN_SELECTOR],
    }
}

#[test]
fn a_client_hello_survives_the_servers_decoder_unchanged() {
    let mut buffer = [0u8; LEN_CLIENT_HELLO];
    let written = encode_client_hello(&a_hello(), &mut buffer).expect("room");
    assert_eq!(written, LEN_CLIENT_HELLO);

    let decoded = ClientHello::decode(&buffer).expect("the server accepts what the client sent");
    assert_eq!(decoded, a_hello());
}

#[test]
fn the_preamble_is_written_where_the_field_table_says() {
    let mut buffer = [0u8; LEN_CLIENT_HELLO];
    encode_client_hello(&a_hello(), &mut buffer).expect("room");

    assert_eq!(&buffer[0..4], &BSP_MAGIC);
    assert_eq!(buffer[4], 2, "version_major");
    assert_eq!(buffer[5], 0, "version_minor");
    assert_eq!(&buffer[6..8], &[0, 0], "reserved");
    // chain_counter is big-endian at offset 8.
    assert_eq!(&buffer[8..16], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(&buffer[16..48], &[0xA5; LEN_NONCE]);
    assert_eq!(&buffer[48..64], &[0x5A; LEN_SELECTOR]);
}

#[test]
fn every_chain_counter_round_trips_including_the_boundaries() {
    for counter in [0, 1, u64::MAX - 1, u64::MAX] {
        let hello = ClientHello {
            chain_counter: counter,
            ..a_hello()
        };
        let mut buffer = [0u8; LEN_CLIENT_HELLO];
        encode_client_hello(&hello, &mut buffer).expect("room");
        assert_eq!(ClientHello::decode(&buffer).expect("valid"), hello);
    }
}

#[test]
fn a_client_auth_survives_the_servers_decoder_unchanged() {
    let auth = ClientAuth {
        client_confirm: [0x3C; LEN_CONFIRM],
    };
    let mut buffer = [0u8; LEN_CLIENT_AUTH];
    let written = encode_client_auth(&auth, &mut buffer).expect("room");
    assert_eq!(written, LEN_CLIENT_AUTH);
    assert_eq!(ClientAuth::decode(&buffer).expect("valid"), auth);
}

#[test]
fn encoding_into_a_short_buffer_denies_rather_than_truncating() {
    // A truncated message is one the server rejects for the wrong reason, and
    // the client would never learn which field it lost.
    let mut small = [0u8; LEN_CLIENT_HELLO - 1];
    assert_eq!(
        encode_client_hello(&a_hello(), &mut small),
        Err(BspError::OutputBufferTooSmall)
    );

    let mut small = [0u8; LEN_CLIENT_AUTH - 1];
    assert_eq!(
        encode_client_auth(
            &ClientAuth {
                client_confirm: [0; LEN_CONFIRM]
            },
            &mut small
        ),
        Err(BspError::OutputBufferTooSmall)
    );
}

#[test]
fn a_larger_buffer_is_written_only_where_the_message_reaches() {
    let mut buffer = [0xFFu8; LEN_CLIENT_HELLO + 8];
    let written = encode_client_hello(&a_hello(), &mut buffer).expect("room");
    assert_eq!(written, LEN_CLIENT_HELLO);
    // The tail is untouched: an encoder that zeroed it would be deciding what
    // follows its own message in the caller's buffer.
    assert_eq!(&buffer[LEN_CLIENT_HELLO..], &[0xFF; 8]);
    assert!(ClientHello::decode(&buffer[..LEN_CLIENT_HELLO]).is_ok());
}
