#!/usr/bin/env python3
"""Regenerates the ADT fuzz seed corpus.

The corpus is committed, so this script exists to make it auditable rather than
to be run on every build: a reviewer can see how each of the 46 seeds was
derived instead of reading 46 opaque binaries.

Every seed comes either from the specification's 288-byte worked example
(transcribed in src/adt/tests/common/mod.rs) or from an adversarial fixture in
src/adt/tests/adversarial.rs. The record encoders below mirror that file's.

Usage:
    bin/generate-adt-fuzz-corpus.py \\
        fuzz/corpus/fuzz_adt_parser_with_adversarial_firmware_device_trees
"""

import os
import struct
import sys

OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)

# The specification's 288-byte worked example, transcribed from
# src/adt/tests/common/mod.rs (which transcribed it from the spec hex dump).
GOLDEN = bytes([
    0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x6e, 0x61, 0x6d, 0x65, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x07, 0x00, 0x00, 0x00, 0x61, 0x72, 0x6d, 0x2d,
    0x69, 0x6f, 0x00, 0x00, 0x23, 0x61, 0x64, 0x64,
    0x72, 0x65, 0x73, 0x73, 0x2d, 0x63, 0x65, 0x6c,
    0x6c, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x23, 0x73, 0x69, 0x7a,
    0x65, 0x2d, 0x63, 0x65, 0x6c, 0x6c, 0x73, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x6e, 0x61, 0x6d, 0x65,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
    0x75, 0x61, 0x72, 0x74, 0x30, 0x00, 0x00, 0x00,
    0x63, 0x6f, 0x6d, 0x70, 0x61, 0x74, 0x69, 0x62,
    0x6c, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0f, 0x00, 0x00, 0x00, 0x75, 0x61, 0x72, 0x74,
    0x2d, 0x31, 0x2c, 0x73, 0x61, 0x6d, 0x73, 0x75,
    0x6e, 0x67, 0x00, 0x00, 0x72, 0x65, 0x67, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x20, 0x79, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])
assert len(GOLDEN) == 288


def write(name, data):
    with open(os.path.join(OUT, name), "wb") as handle:
        handle.write(bytes(data))
    print("%-52s %6d bytes" % (name, len(data)))


def prop(name, value):
    out = bytearray(name.encode())
    assert len(out) < 32
    out.extend(b"\0" * (32 - len(out)))
    out.extend(struct.pack("<I", len(value)))
    out.extend(value)
    while len(out) % 4:
        out.append(0)
    return bytes(out)


def node(properties, children):
    out = bytearray(struct.pack("<II", len(properties), len(children)))
    for one in properties:
        out.extend(one)
    for one in children:
        out.extend(one)
    return bytes(out)


def cstr(text):
    return text.encode() + b"\0"


def u32(value):
    return struct.pack("<I", value)


def two_cells(value):
    return struct.pack("<II", value & 0xFFFFFFFF, (value >> 32) & 0xFFFFFFFF)


def patch_u32(blob, offset, value):
    out = bytearray(blob)
    out[offset:offset + 4] = struct.pack("<I", value)
    return bytes(out)


def patch_byte(blob, offset, value):
    out = bytearray(blob)
    out[offset] = value
    return bytes(out)


# --- 1. the accepting seed -------------------------------------------------
write("golden_spec_worked_example_288.bin", GOLDEN)

# --- 2. truncations at structural boundaries -------------------------------
# Offsets chosen at each kind of boundary the walk crosses.
for label, cut in [
    ("empty", 0),
    ("below_root_header", 7),
    ("root_header_only", 8),
    ("mid_name_field", 0x18),
    ("on_length_word", 0x28),
    ("mid_property_value", 0x2E),
    ("end_of_root_properties", 0x84),
    ("mid_child_header", 0x86),
    ("one_byte_before_the_end", 287),
]:
    write("truncated_at_%s_0x%03x.bin" % (label, cut), GOLDEN[:cut])

# --- 3. over-long and hazardous length words -------------------------------
# 0x0028 is the length word of the root's `name` property.
write("length_word_larger_than_the_buffer.bin", patch_u32(GOLDEN, 0x28, 0x1000))
write("length_word_placeholder_flag_set.bin", patch_u32(GOLDEN, 0x28, 0x80000004))
write("length_word_at_the_policy_ceiling.bin", patch_u32(GOLDEN, 0x28, 0x000FFFFF))
write("length_word_above_the_policy_ceiling.bin", patch_u32(GOLDEN, 0x28, 0x00100000))
write("length_word_padding_would_wrap.bin", patch_u32(GOLDEN, 0x28, 0x7FFFFFFD))
# Inflating a length by 4 desynchronises the walk: the first-child offset then
# lands in the middle of what was the child's header.
write("length_word_desynchronises_the_walk.bin", patch_u32(GOLDEN, 0x28, 0x0B))

# --- 4. counts: all-ones, multiplication overflow, ceilings, zero ----------
write("property_count_all_ones.bin", patch_u32(GOLDEN, 0x00, 0xFFFFFFFF))
write("child_count_all_ones.bin", patch_u32(GOLDEN, 0x04, 0xFFFFFFFF))
# 0x08000000 * 36 == 2**32 exactly; 0x20000000 * 8 == 2**32 exactly.
write("property_count_times_36_overflows_u32.bin", patch_u32(GOLDEN, 0x00, 0x08000000))
write("child_count_times_8_overflows_u32.bin", patch_u32(GOLDEN, 0x04, 0x20000000))
write("property_count_just_above_the_ceiling.bin", patch_u32(GOLDEN, 0x00, 2049))
write("child_count_just_above_the_ceiling.bin", patch_u32(GOLDEN, 0x04, 2049))
write("property_count_zero.bin", patch_u32(GOLDEN, 0x00, 0))
write("child_count_claims_a_sibling_that_is_absent.bin", patch_u32(GOLDEN, 0x04, 2))

# --- 5. names -------------------------------------------------------------
# Byte 31 of the root's first name field.
write("property_name_field_not_terminated.bin", patch_byte(GOLDEN, 0x08 + 31, 0x41))
# A `name` value with no NUL inside its declared length.
unterminated_name = node([prop("name", b"arm-io!")], [])
write("node_name_value_has_no_nul.bin", unterminated_name)
# A 64-character node name: one past the policy bound on the decoded string.
write("node_name_64_characters.bin", node([prop("name", b"a" * 64 + b"\0")], []))
# A `name` value of 65 bytes: one past the policy bound on the value.
write("node_name_value_65_bytes.bin", node([prop("name", b"a" * 65)], []))
write("duplicate_critical_property.bin",
      node([prop("name", cstr("root")), prop("chip-id", u32(1)),
            prop("chip-id", u32(2))], []))
write("node_with_no_name_property.bin", node([prop("model", cstr("x"))], []))

# --- 6. depth bombs -------------------------------------------------------
def chain(levels):
    blob = node([prop("name", cstr("leaf"))], [])
    for level in range(levels):
        blob = node([prop("name", cstr("n%d" % level))], [blob])
    return blob


write("depth_chain_at_the_limit_8.bin", chain(8))
write("depth_chain_one_past_the_limit_9.bin", chain(9))
write("depth_bomb_512_levels.bin", chain(512))

# --- 7. overlap and desynchronisation -------------------------------------
# Two siblings; the first sibling's value length is inflated so its extent
# swallows the second sibling's header while staying inside the buffer.
sibling_a = node([prop("name", cstr("a"))], [])
sibling_b = node([prop("name", cstr("b"))], [])
two_siblings = node([prop("name", cstr("root"))], [sibling_a, sibling_b])
# Root header (8) + root `name` record (32 + 4 + padded("root\0") = 44) puts the
# first child's header at 52; its `name` record starts at 60 and its length word
# at 60 + 32 = 92.
first_child_length_word = 8 + len(prop("name", cstr("root"))) + 8 + 32
assert first_child_length_word == 92
write("sibling_extent_swallows_its_neighbour.bin",
      patch_u32(two_siblings, first_child_length_word, 44))
write("sibling_extent_runs_past_the_buffer.bin",
      patch_u32(two_siblings, first_child_length_word, 64))

# --- 8. reg / ranges / translation ----------------------------------------
# A three-level tree that drives translated_reg through a real `ranges` walk.
uart = node([
    prop("name", cstr("uart0")),
    prop("compatible", cstr("uart-1,samsung")),
    prop("reg", two_cells(0x1_4100_0000) + two_cells(0x4000)),
], [])
arm_io = node([
    prop("name", cstr("arm-io")),
    prop("#address-cells", u32(2)),
    prop("#size-cells", u32(2)),
    prop("ranges", two_cells(0) + two_cells(0x2_1000_0000) + two_cells(0x4_0000_0000)),
], [uart])
translating_tree = node([
    prop("name", cstr("device-tree")),
    prop("#address-cells", u32(2)),
    prop("#size-cells", u32(2)),
], [arm_io])
write("ranges_translation_three_levels.bin", translating_tree)

# The §8.2 memory-node trap: an 8-byte `reg` under a parent declaring 2+2.
short_reg_child = node([prop("name", cstr("memory")), prop("reg", two_cells(0))], [])
write("reg_shorter_than_its_cell_counts.bin",
      node([prop("name", cstr("device-tree")), prop("#address-cells", u32(2)),
            prop("#size-cells", u32(2))], [short_reg_child]))

# Cell counts outside 1..=2, and a `reg` whose translation would overflow.
write("cell_counts_out_of_range.bin",
      node([prop("name", cstr("device-tree")), prop("#address-cells", u32(3)),
            prop("#size-cells", u32(3))], []))
overflow_child = node([
    prop("name", cstr("edge")),
    prop("reg", two_cells(0xFFFF_FFFF_FFFF_FF00) + two_cells(0xFFFF_FFFF_FFFF_FFFF)),
], [])
write("reg_whose_containment_sum_overflows.bin",
      node([prop("name", cstr("device-tree")), prop("#address-cells", u32(2)),
            prop("#size-cells", u32(2)), prop("ranges", two_cells(0) +
            two_cells(0) + two_cells(0xFFFF_FFFF_FFFF_FFFF))], [overflow_child]))

# --- 9. fixed-shape and string-typed values -------------------------------
write("fixed_shape_property_of_the_wrong_length.bin",
      node([prop("name", cstr("cpu0")), prop("cpu-impl-reg", b"\0" * 12)], []))
write("string_value_with_no_terminator.bin",
      node([prop("name", cstr("n")), prop("compatible", b"abcde")], []))
write("string_list_with_padding.bin",
      node([prop("name", cstr("n")),
            prop("compatible", cstr("a,b") + cstr("c,d"))], []))

# --- 10. degenerate fillers ------------------------------------------------
write("all_ones_4096.bin", b"\xff" * 4096)
write("all_zeros_4096.bin", b"\x00" * 4096)
write("misaligned_tail_golden_plus_two.bin", GOLDEN + b"\xff\xff")
# A node with the maximum property count the buffer can hold, all identical.
write("many_properties_one_node.bin",
      node([prop("name", cstr("n"))] + [prop("filler%d" % i, u32(i))
                                        for i in range(64)], []))
