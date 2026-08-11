//! Programmatic BXW1 fixtures.
//!
//! There is no golden blob transcribed from the specification: BXW1 has never
//! existed as bytes (§11 — no converter, no loader, no blob), so a "golden"
//! vector would be this crate's own output dressed up as an independent
//! authority. Instead the builder below constructs a blob from the format
//! rules directly — offsets, alignment, derived lengths, and digests all
//! computed here from §3, §4 and §6 rather than read back from the decoder —
//! and every adversarial fixture is a named mutation of it.
//!
//! The builder is deliberately *not* shared with the decoder: it re-derives
//! every layout quantity independently, so a test passes only when two
//! separate implementations of §3/§4 agree.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cognitive_complexity,
    clippy::disallowed_names
)]

use brainix_bxw1::{Bxw1Error, WeightBlob};
use sha2::{Digest, Sha256};

/// Reserved-region capacity handed to every parse: comfortably above the
/// fixtures, so a region rule fires only when a test asks for it.
pub const REGION_CAPACITY: u64 = 16 * 1024 * 1024;

/// Header field offsets (§3.1), restated here so the fixtures do not import
/// the decoder's private view of the format.
pub mod header {
    pub const MAGIC: usize = 0;
    pub const VERSION_MAJOR: usize = 4;
    pub const VERSION_MINOR: usize = 6;
    pub const FLAGS: usize = 8;
    pub const TENSOR_COUNT: usize = 12;
    pub const TOTAL_SIZE: usize = 16;
    pub const TENSOR_TABLE_OFF: usize = 24;
    pub const TENSOR_DATA_OFF: usize = 32;
    pub const TENSOR_DATA_LEN: usize = 40;
    pub const RESERVED_0: usize = 48;
    pub const RESERVED_1: usize = 56;
    pub const TENSOR_TABLE_DIGEST: usize = 64;
    pub const ARCH_ID: usize = 96;
    pub const N_LAYERS: usize = 100;
    pub const D_MODEL: usize = 104;
    pub const N_HEADS: usize = 108;
    pub const N_KV_HEADS: usize = 112;
    pub const D_HEAD: usize = 116;
    pub const D_FFN: usize = 120;
    pub const VOCAB_SIZE: usize = 124;
    pub const MAX_SEQ_LEN: usize = 128;
    pub const ROPE_THETA_BITS: usize = 132;
    pub const NORM_EPS_BITS: usize = 136;
    pub const ROPE_DIM: usize = 140;
    pub const BOS_TOKEN_ID: usize = 144;
    pub const EOS_TOKEN_ID: usize = 148;
    pub const ROPE_PAIRING: usize = 152;
    pub const RESERVED_3: usize = 156;
    pub const VOCAB_DIGEST: usize = 160;
    pub const VOCAB_LEN: usize = 192;
    pub const RESERVED_TAIL: usize = 200;
}

/// Tensor-record field offsets, relative to the record (§3.2).
pub mod record {
    pub const NAME: usize = 0;
    pub const DTYPE: usize = 64;
    pub const RANK: usize = 66;
    pub const RESERVED_A: usize = 68;
    pub const DIMS: usize = 72;
    pub const DATA_OFF: usize = 104;
    pub const DATA_LEN: usize = 112;
    pub const DIGEST: usize = 120;
    pub const RESERVED_B: usize = 152;
}

pub const HEADER_BYTES: usize = 256;
pub const RECORD_BYTES: usize = 160;
pub const ALIGN: usize = 128;
pub const BLOCK: u64 = 32;
pub const DTYPE_F32: u16 = 0;
pub const DTYPE_Q8_0: u16 = 1;

/// The hyperparameters a fixture is built from.
#[derive(Debug, Clone, Copy)]
pub struct ModelShape {
    pub n_layers: u32,
    pub d_model: u32,
    pub n_heads: u32,
    pub n_kv_heads: u32,
    pub d_head: u32,
    pub d_ffn: u32,
    pub vocab_size: u32,
    pub max_seq_len: u32,
    pub tied_output: bool,
}

impl Default for ModelShape {
    /// A one-layer model small enough to hash in milliseconds and awkward
    /// enough to exercise the pads: `vocab_size = 33` makes the `Q8_0`
    /// embedding's scale plane need 120 bytes of inter-plane pad and leaves a
    /// 64-byte gap before the next extent, so rules D17 and D19 have something
    /// real to be checked against.
    fn default() -> Self {
        Self {
            n_layers: 1,
            d_model: 64,
            n_heads: 2,
            n_kv_heads: 1,
            d_head: 32,
            d_ffn: 128,
            vocab_size: 33,
            max_seq_len: 128,
            tied_output: false,
        }
    }
}

/// One tensor to place in the blob.
#[derive(Debug, Clone)]
pub struct TensorSpec {
    pub name: String,
    pub dtype: u16,
    pub dims: Vec<u64>,
}

impl TensorSpec {
    fn new(name: &str, dtype: u16, dims: &[u64]) -> Self {
        Self {
            name: name.to_owned(),
            dtype,
            dims: dims.to_vec(),
        }
    }

    fn elements(&self) -> u64 {
        self.dims.iter().product()
    }

    /// The payload length §4.3 derives, computed here independently of the
    /// decoder's own derivation.
    fn data_length(&self) -> usize {
        let elements = self.elements();
        match self.dtype {
            DTYPE_F32 => (elements * 4) as usize,
            DTYPE_Q8_0 => {
                let blocks = elements / BLOCK;
                round_up((blocks * 4) as usize) + (blocks * 32) as usize
            }
            _ => panic!("fixture dtype {} is not a format dtype", self.dtype),
        }
    }

    /// Deterministic, always-valid payload bytes: finite normal `F32`
    /// elements, positive normal `Q8_0` scales, zero inter-plane pad, and
    /// quants covering every `i8` bit pattern.
    fn payload(&self) -> Vec<u8> {
        let elements = self.elements();
        match self.dtype {
            DTYPE_F32 => {
                let mut bytes = Vec::with_capacity((elements * 4) as usize);
                for index in 0..elements {
                    let value = 1.0_f32 + (index % 8) as f32 / 8.0;
                    bytes.extend_from_slice(&value.to_le_bytes());
                }
                bytes
            }
            DTYPE_Q8_0 => {
                let blocks = elements / BLOCK;
                let mut bytes = Vec::with_capacity(self.data_length());
                for _ in 0..blocks {
                    bytes.extend_from_slice(&0.031_25_f32.to_le_bytes());
                }
                bytes.resize(round_up((blocks * 4) as usize), 0);
                for index in 0..(blocks * BLOCK) {
                    bytes.push((index % 256) as u8);
                }
                bytes
            }
            _ => panic!("fixture dtype {} is not a format dtype", self.dtype),
        }
    }
}

/// The required tensor set for `arch_id = 1` (§6.2), in a natural order.
///
/// `tok_embeddings.weight` is `Q8_0` so the split-plane path is exercised;
/// everything else is `F32`, and the norm weights must be (§6.2).
pub fn required_tensors(shape: &ModelShape) -> Vec<TensorSpec> {
    let d_model = u64::from(shape.d_model);
    let d_ffn = u64::from(shape.d_ffn);
    let vocab = u64::from(shape.vocab_size);
    let q_width = u64::from(shape.n_heads) * u64::from(shape.d_head);
    let kv_width = u64::from(shape.n_kv_heads) * u64::from(shape.d_head);

    let mut specs = vec![
        TensorSpec::new("tok_embeddings.weight", DTYPE_Q8_0, &[vocab, d_model]),
        TensorSpec::new("norm.weight", DTYPE_F32, &[d_model]),
    ];
    if !shape.tied_output {
        specs.push(TensorSpec::new(
            "output.weight",
            DTYPE_F32,
            &[vocab, d_model],
        ));
    }
    for layer in 0..shape.n_layers {
        specs.push(TensorSpec::new(
            &format!("layers.{layer}.attention_norm.weight"),
            DTYPE_F32,
            &[d_model],
        ));
        specs.push(TensorSpec::new(
            &format!("layers.{layer}.attention.wq.weight"),
            DTYPE_F32,
            &[q_width, d_model],
        ));
        specs.push(TensorSpec::new(
            &format!("layers.{layer}.attention.wk.weight"),
            DTYPE_F32,
            &[kv_width, d_model],
        ));
        specs.push(TensorSpec::new(
            &format!("layers.{layer}.attention.wv.weight"),
            DTYPE_F32,
            &[kv_width, d_model],
        ));
        specs.push(TensorSpec::new(
            &format!("layers.{layer}.attention.wo.weight"),
            DTYPE_F32,
            &[d_model, q_width],
        ));
        specs.push(TensorSpec::new(
            &format!("layers.{layer}.ffn_norm.weight"),
            DTYPE_F32,
            &[d_model],
        ));
        specs.push(TensorSpec::new(
            &format!("layers.{layer}.feed_forward.w1.weight"),
            DTYPE_F32,
            &[d_ffn, d_model],
        ));
        specs.push(TensorSpec::new(
            &format!("layers.{layer}.feed_forward.w3.weight"),
            DTYPE_F32,
            &[d_ffn, d_model],
        ));
        specs.push(TensorSpec::new(
            &format!("layers.{layer}.feed_forward.w2.weight"),
            DTYPE_F32,
            &[d_model, d_ffn],
        ));
    }
    specs
}

/// A built blob, plus the offsets a test needs to mutate it.
#[derive(Debug, Clone)]
pub struct Blob {
    pub bytes: Vec<u8>,
    pub tensor_count: u32,
    pub data_off: usize,
    /// `(offset, length)` of every extent, in table order.
    pub extents: Vec<(usize, usize)>,
}

impl Blob {
    /// Offset of record `index` in the table.
    pub fn record_at(&self, index: usize) -> usize {
        HEADER_BYTES + index * RECORD_BYTES
    }

    /// Offset of `field` within record `index`.
    pub fn record_field(&self, index: usize, field: usize) -> usize {
        self.record_at(index) + field
    }

    pub fn patch_byte(&mut self, at: usize, value: u8) {
        self.bytes[at] = value;
    }

    pub fn patch_u16(&mut self, at: usize, value: u16) {
        self.bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    pub fn patch_u32(&mut self, at: usize, value: u32) {
        self.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    pub fn patch_u64(&mut self, at: usize, value: u64) {
        self.bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// Writes a name into record `index`, NUL-padded to 64 bytes.
    pub fn patch_name(&mut self, index: usize, name: &str) {
        let at = self.record_field(index, record::NAME);
        self.bytes[at..at + 64].fill(0);
        self.bytes[at..at + name.len()].copy_from_slice(name.as_bytes());
    }

    /// Recomputes record `index`'s per-tensor digest over its **original**
    /// extent, so a test that mutates a payload can still reach the rule it is
    /// aiming at instead of stopping at rule C2.
    pub fn reseal_tensor(&mut self, index: usize) {
        let (offset, length) = self.extents[index];
        let digest = sha256(&self.bytes[offset..offset + length]);
        let at = self.record_field(index, record::DIGEST);
        self.bytes[at..at + 32].copy_from_slice(&digest);
    }

    /// Recomputes `tensor_table_digest`, so a test that mutates a record can
    /// reach the rule it is aiming at instead of stopping at rule C1.
    pub fn reseal_table(&mut self) {
        let table_end = HEADER_BYTES + self.tensor_count as usize * RECORD_BYTES;
        let digest = sha256(&self.bytes[HEADER_BYTES..table_end]);
        self.bytes[header::TENSOR_TABLE_DIGEST..header::TENSOR_TABLE_DIGEST + 32]
            .copy_from_slice(&digest);
    }

    /// Parses at the standard region capacity.
    pub fn parse(&self) -> Result<WeightBlob<'_>, Bxw1Error> {
        WeightBlob::parse(&self.bytes, REGION_CAPACITY)
    }

    /// The error this blob denies with. Panics if it parses.
    pub fn error(&self) -> Bxw1Error {
        match self.parse() {
            Ok(_) => panic!("fixture parsed but was expected to deny"),
            Err(error) => error,
        }
    }
}

/// Builds the default fixture.
pub fn valid_blob() -> Blob {
    let shape = ModelShape::default();
    build(&shape, required_tensors(&shape))
}

/// Builds a fixture from an explicit shape.
pub fn blob_for(shape: &ModelShape) -> Blob {
    build(shape, required_tensors(shape))
}

/// Lays out and serializes a blob from a shape and a tensor list.
pub fn build(shape: &ModelShape, specs: Vec<TensorSpec>) -> Blob {
    let tensor_count = specs.len();
    let table_end = HEADER_BYTES + tensor_count * RECORD_BYTES;
    let data_off = round_up(table_end);

    let mut extents = Vec::with_capacity(tensor_count);
    let mut cursor = data_off;
    for spec in &specs {
        let length = spec.data_length();
        extents.push((cursor, length));
        cursor = round_up(cursor + length);
    }
    let total_size = cursor;

    let mut bytes = vec![0_u8; total_size];
    for (spec, (offset, length)) in specs.iter().zip(extents.iter()) {
        let payload = spec.payload();
        assert_eq!(payload.len(), *length, "fixture payload length disagrees");
        bytes[*offset..*offset + *length].copy_from_slice(&payload);
    }

    write_table(&mut bytes, &specs, &extents);
    write_header(&mut bytes, shape, tensor_count, data_off, total_size);

    let table_digest = sha256(&bytes[HEADER_BYTES..table_end]);
    bytes[header::TENSOR_TABLE_DIGEST..header::TENSOR_TABLE_DIGEST + 32]
        .copy_from_slice(&table_digest);

    Blob {
        bytes,
        tensor_count: tensor_count as u32,
        data_off,
        extents,
    }
}

fn write_table(bytes: &mut [u8], specs: &[TensorSpec], extents: &[(usize, usize)]) {
    for (index, (spec, (offset, length))) in specs.iter().zip(extents.iter()).enumerate() {
        let at = HEADER_BYTES + index * RECORD_BYTES;
        let name = spec.name.as_bytes();
        assert!(name.len() < 64, "fixture name does not fit its field");
        bytes[at..at + name.len()].copy_from_slice(name);
        bytes[at + record::DTYPE..at + record::DTYPE + 2]
            .copy_from_slice(&spec.dtype.to_le_bytes());
        let rank = spec.dims.len() as u16;
        bytes[at + record::RANK..at + record::RANK + 2].copy_from_slice(&rank.to_le_bytes());
        for (slot, dim) in spec.dims.iter().enumerate() {
            let dim_at = at + record::DIMS + slot * 8;
            bytes[dim_at..dim_at + 8].copy_from_slice(&dim.to_le_bytes());
        }
        bytes[at + record::DATA_OFF..at + record::DATA_OFF + 8]
            .copy_from_slice(&(*offset as u64).to_le_bytes());
        bytes[at + record::DATA_LEN..at + record::DATA_LEN + 8]
            .copy_from_slice(&(*length as u64).to_le_bytes());
        let digest = sha256(&bytes[*offset..*offset + *length]);
        bytes[at + record::DIGEST..at + record::DIGEST + 32].copy_from_slice(&digest);
    }
}

fn write_header(
    bytes: &mut [u8],
    shape: &ModelShape,
    tensor_count: usize,
    data_off: usize,
    total_size: usize,
) {
    bytes[header::MAGIC..header::MAGIC + 4].copy_from_slice(b"BXW1");
    put_u16(bytes, header::VERSION_MAJOR, 1);
    put_u16(bytes, header::VERSION_MINOR, 0);
    put_u32(bytes, header::FLAGS, u32::from(shape.tied_output));
    put_u32(bytes, header::TENSOR_COUNT, tensor_count as u32);
    put_u64(bytes, header::TOTAL_SIZE, total_size as u64);
    put_u64(bytes, header::TENSOR_TABLE_OFF, HEADER_BYTES as u64);
    put_u64(bytes, header::TENSOR_DATA_OFF, data_off as u64);
    put_u64(
        bytes,
        header::TENSOR_DATA_LEN,
        (total_size - data_off) as u64,
    );
    put_u32(bytes, header::ARCH_ID, 1);
    put_u32(bytes, header::N_LAYERS, shape.n_layers);
    put_u32(bytes, header::D_MODEL, shape.d_model);
    put_u32(bytes, header::N_HEADS, shape.n_heads);
    put_u32(bytes, header::N_KV_HEADS, shape.n_kv_heads);
    put_u32(bytes, header::D_HEAD, shape.d_head);
    put_u32(bytes, header::D_FFN, shape.d_ffn);
    put_u32(bytes, header::VOCAB_SIZE, shape.vocab_size);
    put_u32(bytes, header::MAX_SEQ_LEN, shape.max_seq_len);
    put_u32(bytes, header::ROPE_THETA_BITS, 10_000.0_f32.to_bits());
    put_u32(bytes, header::NORM_EPS_BITS, 1.0e-5_f32.to_bits());
    put_u32(bytes, header::ROPE_DIM, shape.d_head);
    put_u32(bytes, header::BOS_TOKEN_ID, 1);
    put_u32(bytes, header::EOS_TOKEN_ID, 2);
    put_u32(bytes, header::ROPE_PAIRING, 1);
    // `vocab_digest` is the SHA-256 of a vocabulary blob this crate never
    // sees; any 32 bytes are structurally valid. `vocab_len` must be nonzero.
    bytes[header::VOCAB_DIGEST..header::VOCAB_DIGEST + 32].copy_from_slice(&sha256(b"vocab"));
    put_u64(bytes, header::VOCAB_LEN, 4096);
}

fn put_u16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

pub fn round_up(value: usize) -> usize {
    (value + ALIGN - 1) & !(ALIGN - 1)
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let computed = hasher.finalize();
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&computed);
    digest
}
