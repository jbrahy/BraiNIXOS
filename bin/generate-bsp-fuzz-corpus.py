#!/usr/bin/env python3
"""Regenerates the seed corpora for the three BSP v2 network-facing fuzz targets.

The corpora are committed, so this script exists to make them auditable rather
than to be run on every build: a reviewer can see how each seed was derived
instead of reading a directory of opaque binaries.

Three corpora are produced, one per target:

    fuzz/corpus/fuzz_bsp_decoder_with_adversarial_wire_messages
    fuzz/corpus/fuzz_transport_crypto_record_open_with_adversarial_ciphertext
    fuzz/corpus/fuzz_transport_crypto_handshake_with_adversarial_messages

The wire images come from the specification
(docs/architecture/BSP-v2-serving-protocol.md §4.2, §5.1, §5.3, §10.2, §10.4)
and from the fixtures in src/bsp/tests/common/mod.rs and
src/transport-crypto/tests/common/mod.rs.

The cryptographic seeds — genuinely sealed records, and `ClientHello`s whose
`key_selector` actually matches an enrolled credential — need ChaCha20,
Poly1305, and HKDF-SHA256. Those are reimplemented below **from the RFCs**
rather than driven through the crate under test, so a seed that the crate
accepts is evidence about the crate rather than a tautology. Each
reimplementation is checked against its published test vector at import time
(`self_test`), so a mistake here fails loudly instead of silently producing
seeds that miss what they claim to target.

Usage:
    bin/generate-bsp-fuzz-corpus.py fuzz/corpus
"""

import hashlib
import hmac
import os
import struct
import sys

# ---------------------------------------------------------------------------
# ChaCha20 (RFC 8439 §2.3), in the original 64-bit-nonce arrangement
#
# `chacha20::ChaCha20Legacy` is DJB's original layout: the four state words
# after the key are a 64-bit little-endian counter and a 64-bit nonce, where the
# IETF variant has a 32-bit counter and a 96-bit nonce. The block function is
# identical, so the RFC's block vector still checks it once the counter and
# nonce words are mapped across (see `self_test`).
# ---------------------------------------------------------------------------

CHACHA_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


def rotl32(value, bits):
    value &= 0xFFFFFFFF
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF


def quarter_round(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = rotl32(state[b] ^ state[c], 7)


def chacha20_block(key, counter, nonce):
    """One 64-byte keystream block. `key` is 32 bytes, `nonce` 8, `counter` u64."""
    assert len(key) == 32 and len(nonce) == 8
    state = list(CHACHA_CONSTANTS)
    state += list(struct.unpack("<8I", key))
    state += [counter & 0xFFFFFFFF, (counter >> 32) & 0xFFFFFFFF]
    state += list(struct.unpack("<2I", nonce))
    working = list(state)
    for _ in range(10):
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)
    mixed = [(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack("<16I", *mixed)


def chacha20_keystream(key, nonce, length, from_block=0):
    """`length` keystream bytes, starting at block `from_block`."""
    out = bytearray()
    block = from_block
    while len(out) < length:
        out += chacha20_block(key, block, nonce)
        block += 1
    return bytes(out[:length])


# ---------------------------------------------------------------------------
# Poly1305 (RFC 8439 §2.5)
# ---------------------------------------------------------------------------

POLY1305_PRIME = (1 << 130) - 5


def poly1305_mac(key, message):
    assert len(key) == 32
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    accumulator = 0
    for offset in range(0, len(message), 16):
        chunk = message[offset : offset + 16]
        block = int.from_bytes(chunk + b"\x01", "little")
        accumulator = ((accumulator + block) * r) % POLY1305_PRIME
    return ((accumulator + s) & ((1 << 128) - 1)).to_bytes(16, "little")


# ---------------------------------------------------------------------------
# HKDF-SHA256 (RFC 5869)
# ---------------------------------------------------------------------------


def hkdf_extract(salt, input_key_material):
    return hmac.new(salt, input_key_material, hashlib.sha256).digest()


def hkdf_expand(pseudorandom_key, info, length):
    out = b""
    previous = b""
    counter = 1
    while len(out) < length:
        previous = hmac.new(
            pseudorandom_key, previous + info + bytes([counter]), hashlib.sha256
        ).digest()
        out += previous
        counter += 1
    return out[:length]


# ---------------------------------------------------------------------------
# §5.4's labels, transcribed from src/transport-crypto/src/labels.rs
# ---------------------------------------------------------------------------

LEN_LABEL = 16


def label(text):
    assert len(text) <= LEN_LABEL
    return text + b"\x00" * (LEN_LABEL - len(text))


LABEL_ENROLL_SALT = label(b"BSP2 enroll")
LABEL_KEY_ID = label(b"BSP2 key-id")
LABEL_ID_SALT = label(b"BSP2 id-salt")
LABEL_SELECTOR = label(b"BSP2 selector")

WIRE_ROLE_CLIENT = 0x01
WIRE_ROLE_ADMIN = 0x02


def key_selector(key_material, role, chain_counter, client_nonce):
    """§5.2 enrollment followed by §5.3 blinded identification."""
    assert len(key_material) == 32 and len(client_nonce) == 32
    enroll_prk = hkdf_extract(LABEL_ENROLL_SALT, key_material)
    key_id = hkdf_expand(enroll_prk, LABEL_KEY_ID + bytes([role]), 32)
    identity_prk = hkdf_extract(LABEL_ID_SALT, key_id)
    info = LABEL_SELECTOR + struct.pack(">Q", chain_counter) + client_nonce
    return hkdf_expand(identity_prk, info, 16)


# ---------------------------------------------------------------------------
# §4.2's record layer, sealed the way `RecordSealer::seal` seals
# ---------------------------------------------------------------------------

RECORD_TAG_BYTES = 16
RECORD_PLAINTEXT_BLOCK = 8
MIN_RECORD_PADDING = 4
BSP_MAX_RECORD_PLAINTEXT = 4096
RECORD_PLAINTEXT_CAPACITY = BSP_MAX_RECORD_PLAINTEXT + 1 + 255
MIN_PACKET_LENGTH = 2
MAX_PACKET_LENGTH = 35000

# The 64 bytes the fuzz target installs as one direction's keys. Must stay in
# step with DIRECTION_MATERIAL in
# fuzz_targets/fuzz_transport_crypto_record_open_with_adversarial_ciphertext.rs.
DIRECTION_MATERIAL = bytes(
    [
        0x2C, 0x91, 0x7F, 0x04, 0xBB, 0x38, 0xE6, 0x5A,
        0x13, 0xCD, 0x70, 0xA2, 0x49, 0x86, 0xF1, 0x0B,
        0xD4, 0x27, 0x63, 0x9E, 0x58, 0xAC, 0x31, 0xE0,
        0x0F, 0x75, 0xB8, 0x42, 0x96, 0x1D, 0xCA, 0x63,
        0x87, 0x3E, 0xD1, 0x6A, 0x05, 0xF4, 0x29, 0xBC,
        0x51, 0x08, 0xE7, 0x93, 0x2A, 0xDF, 0x64, 0x1B,
        0xA8, 0x35, 0xC2, 0x79, 0x0E, 0x96, 0x4D, 0xE3,
        0x21, 0xB7, 0x5C, 0x88, 0x3F, 0xD0, 0x6B, 0x17,
    ]
)
PAYLOAD_KEY = DIRECTION_MATERIAL[:32]
LENGTH_KEY = DIRECTION_MATERIAL[32:]


def frame_plaintext(payload):
    """`padding_length[1] || payload || padding`, per §4.2."""
    padding = MIN_RECORD_PADDING
    while (1 + len(payload) + padding) % RECORD_PLAINTEXT_BLOCK != 0:
        padding += 1
    return bytes([padding]) + payload + b"\x00" * padding


def seal_plaintext(plaintext, sequence=0):
    """Seals an arbitrary record plaintext, well formed or not.

    Taking the plaintext rather than the payload is deliberate: it is how a seed
    can carry a *correctly authenticated* record whose padding rules are wrong,
    which is the only way to reach `decode_record_plaintext` on the opening side
    past a tag check that no forgery gets through.
    """
    nonce = struct.pack(">Q", sequence)
    length_keystream = chacha20_keystream(LENGTH_KEY, nonce, 4)
    declared = struct.pack(">I", len(plaintext))
    enc_length = bytes(a ^ b for a, b in zip(declared, length_keystream))

    payload_stream = chacha20_keystream(PAYLOAD_KEY, nonce, 64 + len(plaintext))
    mac_key = payload_stream[:32]
    ciphertext = bytes(
        a ^ b for a, b in zip(plaintext, payload_stream[64 : 64 + len(plaintext)])
    )
    tag = poly1305_mac(mac_key, enc_length + ciphertext)
    return enc_length + ciphertext + tag


def seal_payload(payload, sequence=0):
    return seal_plaintext(frame_plaintext(payload), sequence)


def encrypted_length_field(value, sequence=0):
    """The four wire bytes that decrypt to `value` at `sequence`."""
    nonce = struct.pack(">Q", sequence)
    keystream = chacha20_keystream(LENGTH_KEY, nonce, 4)
    return bytes(a ^ b for a, b in zip(struct.pack(">I", value), keystream))


def flip(data, at, mask=0x01):
    out = bytearray(data)
    out[at] ^= mask
    return bytes(out)


# ---------------------------------------------------------------------------
# §5.1 and §10 wire images, transcribed from src/bsp/tests/common/mod.rs
# ---------------------------------------------------------------------------

BSP_MAGIC = b"BSP2"
LEN_CLIENT_HELLO = 64
LEN_SERVER_HELLO = 64
LEN_CLIENT_AUTH = 32
MAX_PROMPT_BYTES = 16384
MAX_PROMPT_CHUNK = 4032
MAX_TOKENS_REQUESTED = 4096
MAX_AUDIT_RECORDS = 64
MAX_CHAIN_CATCHUP = 64

# src/transport-crypto/tests/common/mod.rs — the material the handshake target
# enrolls into the table it builds.
CLIENT_MATERIAL = bytes(
    [
        0x9E, 0x1C, 0x44, 0xB7, 0x03, 0xD8, 0x2A, 0x6F,
        0x51, 0xE0, 0x77, 0x13, 0xBC, 0x95, 0x38, 0xAA,
        0x62, 0x0D, 0xF4, 0x81, 0x2C, 0x57, 0x9B, 0x30,
        0xE6, 0x18, 0x73, 0xCF, 0x45, 0xA2, 0x6B, 0xD9,
    ]
)
ADMIN_MATERIAL = bytes([0x5D] * 32)
BREAK_GLASS_MATERIAL = bytes([0xB6] * 32)


def nonce32(seed):
    """The 32-byte pattern src/bsp/tests/common/mod.rs calls `nonce`."""
    return bytes((seed ^ index) & 0xFF for index in range(32))


def sixteen(seed):
    return bytes((seed + index) & 0xFF for index in range(16))


def client_hello(
    chain_counter=7,
    client_nonce=None,
    selector=None,
    magic=BSP_MAGIC,
    version_major=2,
    version_minor=0,
    reserved=0,
):
    client_nonce = nonce32(0xA1) if client_nonce is None else client_nonce
    selector = sixteen(0x30) if selector is None else selector
    return (
        magic
        + bytes([version_major, version_minor])
        + struct.pack(">H", reserved)
        + struct.pack(">Q", chain_counter)
        + client_nonce
        + selector
    )


def server_hello(server_nonce=None, server_confirm=None):
    server_nonce = nonce32(0x5B) if server_nonce is None else server_nonce
    server_confirm = nonce32(0x9D) if server_confirm is None else server_confirm
    return server_nonce + server_confirm


def infer_begin(request_id, max_tokens, temperature, top_p, prompt_total_length):
    return (
        bytes([0x01])
        + struct.pack(">I", request_id)
        + struct.pack(">I", max_tokens)
        + struct.pack(">H", temperature)
        + struct.pack(">H", top_p)
        + struct.pack(">I", prompt_total_length)
    )


def prompt_chunk(request_id, chunk, declared=None):
    declared = len(chunk) if declared is None else declared
    return (
        bytes([0x02]) + struct.pack(">I", request_id) + struct.pack(">H", declared) + chunk
    )


def tagged(tag, request_id):
    return bytes([tag]) + struct.pack(">I", request_id)


def enroll_key(request_id, role, material):
    return tagged(0x11, request_id) + bytes([role]) + material


def read_audit_log(request_id, cursor, max_records):
    return (
        tagged(0x14, request_id) + struct.pack(">Q", cursor) + struct.pack(">H", max_records)
    )


def restart_server(request_id, target):
    return tagged(0x15, request_id) + bytes([target])


# ---------------------------------------------------------------------------
# Corpus A — the BSP v2 wire decoder
# ---------------------------------------------------------------------------


def corpus_bsp_decoder():
    seeds = {}

    # -- valid fixtures, straight out of src/bsp/tests/common/mod.rs ---------
    seeds["valid_client_hello.bin"] = client_hello()
    seeds["valid_server_hello.bin"] = server_hello()
    seeds["valid_client_auth.bin"] = nonce32(0xC3)
    seeds["valid_infer_begin.bin"] = infer_begin(0x1234_5678, 128, 700, 900, 4)
    seeds["valid_prompt_chunk.bin"] = prompt_chunk(0x1234_5678, b"abcd")
    seeds["valid_infer_commit.bin"] = tagged(0x03, 0x1234_5678)
    seeds["valid_cancel.bin"] = tagged(0x04, 0x1234_5678)
    seeds["valid_close.bin"] = bytes([0x05])
    seeds["valid_enroll_key_client_role.bin"] = enroll_key(1, WIRE_ROLE_CLIENT, nonce32(0x11))
    seeds["valid_enroll_key_admin_role.bin"] = enroll_key(1, WIRE_ROLE_ADMIN, nonce32(0x11))
    seeds["valid_revoke_key.bin"] = tagged(0x12, 2) + sixteen(0x22)
    seeds["valid_load_weights.bin"] = tagged(0x13, 3) + nonce32(0x33)
    seeds["valid_read_audit_log.bin"] = read_audit_log(4, 0xDEAD_BEEF_0000_0001, 64)
    seeds["valid_restart_server_inferd.bin"] = restart_server(5, 0x02)
    seeds["valid_reboot.bin"] = tagged(0x16, 6)

    # -- row H2: every exact-match field, wrong ------------------------------
    seeds["client_hello_magic_is_not_bsp2.bin"] = client_hello(magic=b"BSP1")
    seeds["client_hello_version_major_three.bin"] = client_hello(version_major=3)
    seeds["client_hello_version_minor_one.bin"] = client_hello(version_minor=1)
    seeds["client_hello_reserved_is_one.bin"] = client_hello(reserved=1)
    seeds["client_hello_reserved_all_ones.bin"] = client_hello(reserved=0xFFFF)

    # -- rows H1 and H4: the length checks, at their boundaries --------------
    seeds["client_hello_truncated_to_63.bin"] = client_hello()[:63]
    seeds["client_hello_one_byte_too_long_65.bin"] = client_hello() + b"\x00"
    seeds["client_hello_truncated_at_the_nonce_16.bin"] = client_hello()[:16]
    seeds["client_auth_truncated_to_31.bin"] = nonce32(0xC3)[:31]
    seeds["client_auth_one_byte_too_long_33.bin"] = nonce32(0xC3) + b"\x00"
    seeds["server_hello_truncated_to_32.bin"] = server_hello()[:32]

    # -- row M5: the two InferBegin ceilings, straddled ---------------------
    seeds["infer_begin_max_tokens_at_the_ceiling.bin"] = infer_begin(
        1, MAX_TOKENS_REQUESTED, 0, 0, 0
    )
    seeds["infer_begin_max_tokens_one_past_the_ceiling.bin"] = infer_begin(
        1, MAX_TOKENS_REQUESTED + 1, 0, 0, 0
    )
    seeds["infer_begin_max_tokens_all_ones.bin"] = infer_begin(1, 0xFFFF_FFFF, 0, 0, 0)
    seeds["infer_begin_prompt_length_at_the_ceiling.bin"] = infer_begin(
        1, 1, 0, 0, MAX_PROMPT_BYTES
    )
    seeds["infer_begin_prompt_length_one_past_the_ceiling.bin"] = infer_begin(
        1, 1, 0, 0, MAX_PROMPT_BYTES + 1
    )
    seeds["infer_begin_prompt_length_all_ones.bin"] = infer_begin(1, 1, 0, 0, 0xFFFF_FFFF)
    seeds["infer_begin_body_one_byte_short.bin"] = infer_begin(1, 1, 0, 0, 0)[:-1]
    seeds["infer_begin_body_one_byte_long.bin"] = infer_begin(1, 1, 0, 0, 0) + b"\x00"

    # -- §3 form 3: the bounded var-bytes field, at every failure it has -----
    seeds["prompt_chunk_declared_longer_than_present.bin"] = prompt_chunk(
        1, b"abcd", declared=64
    )
    seeds["prompt_chunk_declared_shorter_than_present.bin"] = prompt_chunk(
        1, b"abcd", declared=2
    )
    seeds["prompt_chunk_declared_at_the_chunk_ceiling.bin"] = prompt_chunk(
        1, b"", declared=MAX_PROMPT_CHUNK
    )
    seeds["prompt_chunk_declared_one_past_the_chunk_ceiling.bin"] = prompt_chunk(
        1, b"", declared=MAX_PROMPT_CHUNK + 1
    )
    seeds["prompt_chunk_declared_all_ones.bin"] = prompt_chunk(1, b"", declared=0xFFFF)
    seeds["prompt_chunk_length_prefix_truncated.bin"] = tagged(0x02, 1) + b"\x00"
    seeds["prompt_chunk_empty_value.bin"] = prompt_chunk(1, b"")
    seeds["prompt_chunk_full_at_the_ceiling.bin"] = prompt_chunk(
        1, bytes(MAX_PROMPT_CHUNK)
    )
    seeds["prompt_chunk_no_request_id.bin"] = bytes([0x02])

    # -- §10's tag partition: every quadrant offered to the wrong decoder ----
    seeds["admin_tag_on_the_client_range.bin"] = enroll_key(1, WIRE_ROLE_CLIENT, nonce32(0x11))
    seeds["client_tag_on_the_admin_range.bin"] = infer_begin(1, 1, 0, 0, 0)
    seeds["outbound_client_tag_inbound.bin"] = tagged(0x81, 1)
    seeds["outbound_admin_tag_inbound.bin"] = tagged(0x90, 1)
    seeds["unassigned_tag_0x7f.bin"] = tagged(0x7F, 1)
    seeds["unassigned_tag_0xff.bin"] = tagged(0xFF, 1)
    seeds["unrecognized_client_tag_0x0f.bin"] = tagged(0x0F, 1)
    seeds["unrecognized_admin_tag_0x1f.bin"] = tagged(0x1F, 1)

    # -- rows A1, A6, A7: the enumerated authority bytes ---------------------
    seeds["enroll_key_role_zero.bin"] = enroll_key(1, 0x00, nonce32(0x11))
    seeds["enroll_key_role_three.bin"] = enroll_key(1, 0x03, nonce32(0x11))
    seeds["enroll_key_role_all_ones.bin"] = enroll_key(1, 0xFF, nonce32(0x11))
    seeds["enroll_key_material_one_byte_short.bin"] = enroll_key(
        1, WIRE_ROLE_CLIENT, nonce32(0x11)
    )[:-1]
    seeds["restart_server_target_zero.bin"] = restart_server(1, 0x00)
    seeds["restart_server_target_five.bin"] = restart_server(1, 0x05)
    seeds["restart_server_target_all_ones.bin"] = restart_server(1, 0xFF)
    seeds["read_audit_log_at_the_ceiling.bin"] = read_audit_log(1, 0, MAX_AUDIT_RECORDS)
    seeds["read_audit_log_one_past_the_ceiling.bin"] = read_audit_log(
        1, 0, MAX_AUDIT_RECORDS + 1
    )
    seeds["read_audit_log_records_all_ones.bin"] = read_audit_log(1, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF)

    # -- §4.2: the packet length, at both ends of row R1 --------------------
    filler = bytes([0xAB] * 64)
    seeds["packet_length_zero.bin"] = struct.pack(">I", 0) + filler
    seeds["packet_length_one_below_the_minimum.bin"] = (
        struct.pack(">I", MIN_PACKET_LENGTH - 1) + filler
    )
    seeds["packet_length_at_the_minimum.bin"] = (
        struct.pack(">I", MIN_PACKET_LENGTH)
        + bytes([0xAB] * MIN_PACKET_LENGTH)
        + bytes([0xCD] * RECORD_TAG_BYTES)
    )
    seeds["packet_length_at_the_maximum.bin"] = struct.pack(">I", MAX_PACKET_LENGTH) + filler
    seeds["packet_length_one_past_the_maximum.bin"] = (
        struct.pack(">I", MAX_PACKET_LENGTH + 1) + filler
    )
    seeds["packet_length_all_ones.bin"] = b"\xff\xff\xff\xff" + filler
    seeds["packet_length_names_one_more_byte_than_arrived.bin"] = (
        struct.pack(">I", 8) + bytes([0xAB] * 8) + bytes([0xCD] * (RECORD_TAG_BYTES - 1))
    )

    # -- §4.2: the record plaintext's padding rules -------------------------
    seeds["record_plaintext_minimum_block.bin"] = frame_plaintext(b"abc")
    seeds["record_plaintext_padding_below_the_minimum.bin"] = (
        bytes([3]) + b"abcd" + b"\x00" * 3
    )
    seeds["record_plaintext_padding_length_exceeds_the_packet.bin"] = (
        bytes([0xFF]) + b"\x00" * 7
    )
    seeds["record_plaintext_not_block_aligned.bin"] = bytes([4]) + b"\x00" * 8
    seeds["record_plaintext_padding_is_the_whole_block.bin"] = bytes([7]) + b"\x00" * 7
    seeds["record_plaintext_maximum_padding_byte.bin"] = frame_plaintext(bytes(8))
    seeds["record_plaintext_at_the_payload_ceiling.bin"] = frame_plaintext(
        bytes(BSP_MAX_RECORD_PLAINTEXT)
    )
    seeds["record_plaintext_one_past_the_payload_ceiling.bin"] = frame_plaintext(
        bytes(BSP_MAX_RECORD_PLAINTEXT + 1)
    )

    # -- driver seeds: the session state machine ----------------------------
    #
    # The target reads the input twice — once as wire bytes, once as a stream of
    # transition opcodes — so these seeds steer the second reading. The exact
    # sequence a seed produces is emergent, because the opcode cursor also pays
    # for the payload bytes each transition consumes; what a seed fixes is the
    # *family* of transitions the fuzzer starts from.
    seeds["driver_hello_repeated.bin"] = bytes([0x01]) * 256
    seeds["driver_auth_repeated.bin"] = bytes([0x03]) * 256
    seeds["driver_establish_repeated.bin"] = bytes([0x04]) * 256
    seeds["driver_message_repeated.bin"] = bytes([0x07]) * 256
    seeds["driver_close_repeated.bin"] = bytes([0x05]) * 256
    seeds["driver_walk_to_established.bin"] = bytes([0x01, 0x03, 0x04, 0x07]) * 64
    seeds["driver_handshake_after_established.bin"] = (
        bytes([0x01, 0x03, 0x04]) + bytes([0x01, 0x03]) * 32
    )
    seeds["driver_close_then_everything.bin"] = bytes([0x05, 0x01, 0x03, 0x04, 0x07]) * 32

    # -- degenerate filler --------------------------------------------------
    seeds["empty.bin"] = b""
    seeds["one_zero_byte.bin"] = b"\x00"
    seeds["all_zeros_512.bin"] = bytes(512)
    seeds["all_ones_512.bin"] = bytes([0xFF] * 512)
    seeds["all_zeros_4096.bin"] = bytes(4096)

    return seeds


# ---------------------------------------------------------------------------
# Corpus B — the AEAD record layer
# ---------------------------------------------------------------------------


def corpus_record_open():
    seeds = {}
    honest = seal_payload(b"abcd")

    # -- genuinely sealed records, under the target's fixed key --------------
    seeds["sealed_empty_payload.bin"] = seal_payload(b"")
    seeds["sealed_four_byte_payload.bin"] = honest
    seeds["sealed_payload_at_the_ceiling.bin"] = seal_payload(
        bytes(BSP_MAX_RECORD_PLAINTEXT)
    )
    seeds["sealed_payload_one_below_the_ceiling.bin"] = seal_payload(
        bytes(BSP_MAX_RECORD_PLAINTEXT - 1)
    )
    # Sealed at sequence 1: a fresh opener expects 0, so this is the reorder
    # case (row R3) arriving as a first record rather than as a replay.
    seeds["sealed_at_sequence_one.bin"] = seal_payload(b"abcd", sequence=1)
    seeds["sealed_at_sequence_two.bin"] = seal_payload(b"abcd", sequence=2)
    seeds["sealed_at_the_sequence_ceiling.bin"] = seal_payload(
        b"abcd", sequence=0xFFFF_FFFF
    )

    # -- tampered: one byte, in each of the three regions --------------------
    seeds["tag_last_byte_flipped.bin"] = flip(honest, len(honest) - 1, 0x01)
    seeds["tag_first_byte_flipped.bin"] = flip(honest, len(honest) - RECORD_TAG_BYTES, 0x80)
    seeds["tag_replaced_with_zeros.bin"] = honest[:-RECORD_TAG_BYTES] + bytes(RECORD_TAG_BYTES)
    seeds["tag_replaced_with_ones.bin"] = honest[:-RECORD_TAG_BYTES] + bytes(
        [0xFF] * RECORD_TAG_BYTES
    )
    seeds["ciphertext_first_byte_flipped.bin"] = flip(honest, 4, 0x01)
    seeds["ciphertext_last_byte_flipped.bin"] = flip(
        honest, len(honest) - RECORD_TAG_BYTES - 1, 0x01
    )
    seeds["length_prefix_first_byte_flipped.bin"] = flip(honest, 0, 0x01)
    seeds["length_prefix_last_byte_flipped.bin"] = flip(honest, 3, 0x01)

    # -- truncation, at every structural boundary ---------------------------
    seeds["truncated_to_empty.bin"] = b""
    seeds["truncated_inside_the_length_prefix_3.bin"] = honest[:3]
    seeds["truncated_at_the_length_prefix_4.bin"] = honest[:4]
    seeds["truncated_mid_ciphertext.bin"] = honest[: 4 + 4]
    seeds["truncated_at_the_tag_boundary.bin"] = honest[: len(honest) - RECORD_TAG_BYTES]
    seeds["truncated_one_byte_before_the_end.bin"] = honest[:-1]
    seeds["one_trailing_byte_after_a_whole_record.bin"] = honest + b"\x00"
    seeds["two_whole_records_back_to_back.bin"] = honest + seal_payload(b"efgh", sequence=1)

    # -- an encrypted length that decrypts to each row R1 / capacity boundary
    #
    # The tag will not verify — the peer cannot forge one — but §4.2 makes the
    # range check normative *before* the tag check, so these are the inputs that
    # decide which side of that ordering the implementation is on.
    for name, value in [
        ("zero", 0),
        ("one", 1),
        ("the_row_r1_minimum_2", MIN_PACKET_LENGTH),
        ("the_plaintext_capacity", RECORD_PLAINTEXT_CAPACITY),
        ("one_past_the_plaintext_capacity", RECORD_PLAINTEXT_CAPACITY + 1),
        ("the_row_r1_maximum_35000", MAX_PACKET_LENGTH),
        ("one_past_the_row_r1_maximum", MAX_PACKET_LENGTH + 1),
        ("all_ones", 0xFFFF_FFFF),
    ]:
        seeds[f"enc_length_decrypts_to_{name}.bin"] = encrypted_length_field(value) + bytes(
            [0xAB] * 32
        )

    # -- correctly authenticated records whose *plaintext* is malformed -----
    #
    # The only seeds that reach `decode_record_plaintext` on the opening side.
    # A forgery never gets past `verify_tag`, so without these the whole unpad
    # half of `open` would stay unfuzzed.
    seeds["sealed_plaintext_padding_below_the_minimum.bin"] = seal_plaintext(
        bytes([3]) + b"abcd" + b"\x00" * 3
    )
    seeds["sealed_plaintext_padding_zero.bin"] = seal_plaintext(bytes([0]) + b"\x00" * 7)
    seeds["sealed_plaintext_padding_length_exceeds_the_packet.bin"] = seal_plaintext(
        bytes([200]) + b"\x00" * 15
    )
    seeds["sealed_plaintext_padding_length_all_ones.bin"] = seal_plaintext(
        bytes([0xFF]) + b"\x00" * 7
    )
    seeds["sealed_plaintext_not_block_aligned.bin"] = seal_plaintext(bytes([4]) + b"\x00" * 8)
    seeds["sealed_plaintext_below_the_row_r1_minimum.bin"] = seal_plaintext(b"\x04")
    seeds["sealed_plaintext_padding_is_the_whole_block.bin"] = seal_plaintext(
        bytes([7]) + b"\x00" * 7
    )
    seeds["sealed_plaintext_maximum_padding_255.bin"] = seal_plaintext(
        bytes([255]) + b"\x00" * 255
    )
    seeds["sealed_plaintext_payload_one_past_the_ceiling.bin"] = seal_plaintext(
        frame_plaintext(bytes(BSP_MAX_RECORD_PLAINTEXT + 1))
    )

    # -- driver seeds: the first two bytes choose the sealed payload's length
    for name, length in [
        ("zero", 0),
        ("one", 1),
        ("at_the_ceiling", BSP_MAX_RECORD_PLAINTEXT),
        ("one_past_the_ceiling", BSP_MAX_RECORD_PLAINTEXT + 1),
        ("one_below_a_block_boundary", 7),
        ("on_a_block_boundary", 8),
    ]:
        seeds[f"driver_payload_length_{name}.bin"] = struct.pack(">H", length) + bytes(
            [0x5A] * min(length + 16, BSP_MAX_RECORD_PLAINTEXT + 16)
        )

    # -- degenerate filler --------------------------------------------------
    seeds["all_zeros_64.bin"] = bytes(64)
    seeds["all_ones_64.bin"] = bytes([0xFF] * 64)
    seeds["all_zeros_4096.bin"] = bytes(4096)

    return seeds


# ---------------------------------------------------------------------------
# Corpus C — the handshake state machine
# ---------------------------------------------------------------------------


def corpus_handshake():
    seeds = {}
    hello_nonce = bytes([0x33] * 32)

    def matching_hello(material, role, counter, client_nonce=hello_nonce):
        return client_hello(
            chain_counter=counter,
            client_nonce=client_nonce,
            selector=key_selector(material, role, counter, client_nonce),
        )

    # -- the selectors that actually match the table the target builds -------
    #
    # These are the only seeds that get past the §5.3 scan at all: a random
    # 16-byte selector matches with probability 2^-128, so without them the
    # whole of `derive`, the §5.4 schedule, and row H5 stay unreachable.
    seeds["client_hello_matching_the_enrolled_client.bin"] = matching_hello(
        CLIENT_MATERIAL, WIRE_ROLE_CLIENT, 0
    )
    seeds["client_hello_matching_the_enrolled_admin.bin"] = matching_hello(
        ADMIN_MATERIAL, WIRE_ROLE_ADMIN, 0
    )
    seeds["client_hello_matching_the_break_glass_credential.bin"] = matching_hello(
        BREAK_GLASS_MATERIAL, WIRE_ROLE_ADMIN, 0
    )

    # -- §6.3's catch-up window, straddled with a *matching* selector -------
    for name, counter in [
        ("one_ahead", 1),
        ("at_the_catchup_limit", MAX_CHAIN_CATCHUP),
        ("one_past_the_catchup_limit", MAX_CHAIN_CATCHUP + 1),
        ("far_ahead", 1_000_000),
        ("at_the_u64_ceiling", 0xFFFF_FFFF_FFFF_FFFF),
    ]:
        seeds[f"client_hello_chain_counter_{name}.bin"] = matching_hello(
            CLIENT_MATERIAL, WIRE_ROLE_CLIENT, counter
        )

    # -- well-formed frames whose selector matches nothing (row K1) ---------
    seeds["client_hello_selector_all_zeros.bin"] = client_hello(
        chain_counter=0, client_nonce=hello_nonce, selector=bytes(16)
    )
    seeds["client_hello_selector_all_ones.bin"] = client_hello(
        chain_counter=0, client_nonce=hello_nonce, selector=bytes([0xFF] * 16)
    )
    seeds["client_hello_selector_off_by_one_bit.bin"] = client_hello(
        chain_counter=0,
        client_nonce=hello_nonce,
        selector=flip(key_selector(CLIENT_MATERIAL, WIRE_ROLE_CLIENT, 0, hello_nonce), 15),
    )
    seeds["client_hello_right_selector_wrong_counter.bin"] = client_hello(
        chain_counter=1,
        client_nonce=hello_nonce,
        selector=key_selector(CLIENT_MATERIAL, WIRE_ROLE_CLIENT, 0, hello_nonce),
    )
    seeds["client_hello_right_selector_wrong_nonce.bin"] = client_hello(
        chain_counter=0,
        client_nonce=bytes([0x34] * 32),
        selector=key_selector(CLIENT_MATERIAL, WIRE_ROLE_CLIENT, 0, hello_nonce),
    )

    # -- row H2 and the length checks --------------------------------------
    seeds["client_hello_magic_is_not_bsp2.bin"] = client_hello(magic=b"XXXX")
    seeds["client_hello_version_major_three.bin"] = client_hello(version_major=3)
    seeds["client_hello_reserved_nonzero.bin"] = client_hello(reserved=0x0001)
    seeds["client_hello_truncated_to_63.bin"] = matching_hello(
        CLIENT_MATERIAL, WIRE_ROLE_CLIENT, 0
    )[:63]
    seeds["client_hello_one_byte_too_long.bin"] = (
        matching_hello(CLIENT_MATERIAL, WIRE_ROLE_CLIENT, 0) + b"\x00"
    )

    # -- the client side: what a hostile server sends back ------------------
    seeds["server_hello_all_zeros.bin"] = bytes(LEN_SERVER_HELLO)
    seeds["server_hello_all_ones.bin"] = bytes([0xFF] * LEN_SERVER_HELLO)
    seeds["server_hello_patterned.bin"] = server_hello()
    seeds["server_hello_truncated_to_63.bin"] = server_hello()[:63]
    seeds["server_hello_confirm_all_zeros.bin"] = nonce32(0x5B) + bytes(32)

    # -- driver seeds: the ratchet's window and the commit ------------------
    seeds["driver_all_zeros_256.bin"] = bytes(256)
    seeds["driver_all_ones_256.bin"] = bytes([0xFF] * 256)
    seeds["driver_alternating_256.bin"] = bytes([0xAA, 0x55] * 128)
    seeds["driver_counter_near_the_u64_ceiling.bin"] = (
        bytes([0xFF] * 8) + bytes([0x00] * 8)
    ) * 16

    seeds["empty.bin"] = b""
    seeds["one_zero_byte.bin"] = b"\x00"

    return seeds


# ---------------------------------------------------------------------------


def self_test():
    """Checks each primitive against its published vector.

    A seed that claims to be a sealed record and is not would silently waste a
    corpus slot, so the reimplementations above are verified rather than
    trusted.
    """
    # RFC 8439 §2.3.2 — the ChaCha20 block function. The IETF arrangement's
    # (counter, nonce[0..4]) is the legacy arrangement's 64-bit counter, and its
    # nonce[4..12] is the legacy 64-bit nonce.
    key = bytes(range(32))
    block = chacha20_block(key, 0x0900_0000_0000_0001, bytes.fromhex("0000004a00000000"))
    assert block[:16] == bytes.fromhex("10f1e7e4d13b5915500fdd1fa32071c4"), "ChaCha20"

    # RFC 8439 §2.5.2 — Poly1305.
    poly_key = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b"
    )
    assert poly1305_mac(poly_key, b"Cryptographic Forum Research Group") == bytes.fromhex(
        "a8061dc1305136c6c22b8baf0c0127a9"
    ), "Poly1305"

    # RFC 5869 test case 1 — HKDF-SHA256.
    prk = hkdf_extract(bytes.fromhex("000102030405060708090a0b0c"), bytes([0x0B] * 22))
    assert prk == bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba63"
        "90b6c73bb50f9c3122ec844ad7c2b3e5"
    ), "HKDF-Extract"
    assert hkdf_expand(prk, bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42) == bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    ), "HKDF-Expand"

    # The record layer composes back to itself: a sealed payload's declared
    # length is the framed plaintext's length.
    framed = frame_plaintext(b"abcd")
    assert len(framed) % RECORD_PLAINTEXT_BLOCK == 0 and framed[0] >= MIN_RECORD_PADDING
    sealed = seal_payload(b"abcd")
    assert len(sealed) == 4 + len(framed) + RECORD_TAG_BYTES
    assert sealed[:4] == encrypted_length_field(len(framed))


def write(directory, seeds):
    os.makedirs(directory, exist_ok=True)
    for name, payload in sorted(seeds.items()):
        with open(os.path.join(directory, name), "wb") as handle:
            handle.write(payload)
    return len(seeds)


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    self_test()
    root = sys.argv[1]
    written = 0
    for target, builder in [
        ("fuzz_bsp_decoder_with_adversarial_wire_messages", corpus_bsp_decoder),
        (
            "fuzz_transport_crypto_record_open_with_adversarial_ciphertext",
            corpus_record_open,
        ),
        (
            "fuzz_transport_crypto_handshake_with_adversarial_messages",
            corpus_handshake,
        ),
    ]:
        count = write(os.path.join(root, target), builder())
        print(f"{count:3d} seeds -> {target}")
        written += count
    print(f"{written} seeds total")
    return 0


if __name__ == "__main__":
    sys.exit(main())
