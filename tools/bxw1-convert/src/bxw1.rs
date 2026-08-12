//! BXW1 blob emission, including `Q8_0` quantization.
//!
//! Every rule identifier in this file is
//! `docs/architecture/BXW1-weight-format.md`'s, so a producer obligation can be
//! traced to the line of the specification that imposes it. The obligations
//! that are easy to miss when reading the layout section alone, and are
//! therefore discharged explicitly here:
//!
//! - **`total_size` is a multiple of `BXW1_ALIGN`** (§4.4). It follows from
//!   rules D18 and H11 together and is named by neither; a producer that sizes
//!   the file to the last extent's end is refused by every conforming loader.
//! - **The `Q8_0` inter-plane pad is zero** (rule D21). It is inside the
//!   extent, so it is inside the region the tensor's digest covers.
//! - **Subnormals are flushed** (§4.7). A checkpoint may legitimately contain
//!   them; a BXW1 blob may not, because their meaning depends on `FPCR.FZ`.
//! - **An all-zero `Q8_0` block is `scale = +0.0` with 32 zero quants** (§4.2).
//!   The quantization formula divides by zero there, so the encoding is
//!   specified rather than derived.

use crate::sha256;

/// Fixed header length.
pub const HEADER_BYTES: usize = 256;
/// Fixed tensor-record length.
pub const RECORD_BYTES: usize = 160;
/// Tensor-data alignment.
pub const ALIGN: u64 = 128;
/// Elements per `Q8_0` block.
pub const Q8_0_BLOCK: usize = 32;

/// A tensor's element type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dtype {
    /// IEEE-754 binary32.
    F32,
    /// Split-plane, 32-element-block 8-bit.
    Q8_0,
}

impl Dtype {
    fn code(self) -> u16 {
        match self {
            Self::F32 => 0x0000,
            Self::Q8_0 => 0x0001,
        }
    }
}

/// Counters the converter reports so the numeric cost of conversion is
/// measured rather than asserted.
#[derive(Debug, Default, Clone, Copy)]
pub struct Adjustments {
    /// `F32` elements that were subnormal in the checkpoint and were flushed.
    pub flushed_elements: u64,
    /// `Q8_0` blocks whose derived scale was subnormal and became `+0.0`.
    pub flushed_scales: u64,
    /// `Q8_0` blocks that were entirely zero in the checkpoint.
    pub zero_blocks: u64,
    /// Non-finite elements found. Any of these aborts the conversion.
    pub non_finite: u64,
}

impl Adjustments {
    fn absorb(&mut self, other: Adjustments) {
        self.flushed_elements += other.flushed_elements;
        self.flushed_scales += other.flushed_scales;
        self.zero_blocks += other.zero_blocks;
        self.non_finite += other.non_finite;
    }
}

/// The model metadata that lands in header bytes 96–199.
#[derive(Debug, Clone, Copy)]
pub struct Metadata {
    /// Architecture family. Only `1` is defined.
    pub arch_id: u32,
    /// Transformer block count.
    pub n_layers: u32,
    /// Residual-stream width.
    pub d_model: u32,
    /// Query head count.
    pub n_heads: u32,
    /// Key/value head count.
    pub n_kv_heads: u32,
    /// Per-head width.
    pub d_head: u32,
    /// Feed-forward inner width.
    pub d_ffn: u32,
    /// Token count.
    pub vocab_size: u32,
    /// Weights-supported context length.
    pub max_seq_len: u32,
    /// RoPE base.
    pub rope_theta: f32,
    /// Normalization epsilon, inside the root.
    pub norm_eps: f32,
    /// Leading per-head dimensions RoPE rotates.
    pub rope_dim: u32,
    /// Beginning-of-sequence token.
    pub bos_token_id: u32,
    /// End-of-sequence token.
    pub eos_token_id: u32,
    /// `1` interleaved, `2` half-split. No zero value and no default (§5.5).
    pub rope_pairing: u32,
    /// SHA-256 of the tokenizer vocabulary blob.
    pub vocab_digest: [u8; 32],
    /// That blob's exact byte length.
    pub vocab_len: u64,
}

struct Record {
    name: String,
    dtype: Dtype,
    dims: Vec<u64>,
    data_off: u64,
    data_len: u64,
    digest: [u8; 32],
}

/// Accumulates tensors and emits the finished blob.
pub struct Builder {
    data: Vec<u8>,
    records: Vec<Record>,
    data_off: u64,
    tied_output: bool,
    /// Conversion counters, reported by the caller.
    pub adjustments: Adjustments,
}

fn round_up(value: u64, multiple: u64) -> u64 {
    value.div_ceil(multiple) * multiple
}

impl Builder {
    /// A builder for a model with `tensor_count` tensors.
    ///
    /// `tensor_data_off` depends only on the tensor count, so it is fixed here
    /// and every extent is placed relative to it.
    pub fn new(tensor_count: usize, tied_output: bool) -> Self {
        let table_end = HEADER_BYTES as u64 + (RECORD_BYTES as u64) * tensor_count as u64;
        Self {
            data: Vec::new(),
            records: Vec::new(),
            data_off: round_up(table_end, ALIGN),
            tied_output,
            adjustments: Adjustments::default(),
        }
    }

    /// Appends a tensor, quantizing if `dtype` asks for it.
    ///
    /// Extents are emitted strictly ascending and disjoint (rule D16), with a
    /// zero pad of fewer than `ALIGN` bytes between them (rules D17, D19).
    pub fn push(
        &mut self,
        name: &str,
        dtype: Dtype,
        dims: &[u64],
        values: &[f32],
    ) -> Result<(), String> {
        let elements: u64 = dims.iter().product();
        if elements != values.len() as u64 {
            return Err(format!(
                "{name}: {} values for shape {dims:?}",
                values.len()
            ));
        }
        if name.len() > 63 {
            return Err(format!("{name}: name does not fit the 64-byte field"));
        }

        // Pad the running data region so this extent starts 128-aligned.
        let extent_start = round_up(self.data_off + self.data.len() as u64, ALIGN);
        let pad = extent_start - (self.data_off + self.data.len() as u64);
        self.data.extend(std::iter::repeat_n(0u8, pad as usize));

        let (payload, adjustments) = match dtype {
            Dtype::F32 => encode_f32(values),
            Dtype::Q8_0 => {
                let last = *dims.last().ok_or_else(|| format!("{name}: rank 0"))?;
                if last % Q8_0_BLOCK as u64 != 0 {
                    return Err(format!(
                        "{name}: last dimension {last} is not a multiple of 32 (rule D8)"
                    ));
                }
                encode_q8_0(values)
            }
        };
        if adjustments.non_finite > 0 {
            return Err(format!(
                "{name}: {} non-finite values in the checkpoint — BXW1 rule C4 refuses them and \
                 the converter will not silently substitute",
                adjustments.non_finite
            ));
        }
        self.adjustments.absorb(adjustments);

        let digest = sha256::digest(&payload);
        let data_len = payload.len() as u64;
        self.data.extend_from_slice(&payload);
        self.records.push(Record {
            name: name.to_string(),
            dtype,
            dims: dims.to_vec(),
            data_off: extent_start,
            data_len,
            digest,
        });
        Ok(())
    }

    /// Emits the finished blob.
    pub fn finish(mut self, metadata: &Metadata) -> Result<Vec<u8>, String> {
        let tensor_count = self.records.len() as u32;
        let last_end = self
            .records
            .last()
            .map(|record| record.data_off + record.data_len)
            .ok_or("no tensors")?;
        // Rule D18 with H11: the blob ends at the last extent's end rounded up
        // to ALIGN, with the trailing bytes present and zero (rule D19).
        let total_size = round_up(last_end, ALIGN);
        let trailing = total_size - (self.data_off + self.data.len() as u64);
        self.data.extend(std::iter::repeat_n(0u8, trailing as usize));
        let tensor_data_len = self.data.len() as u64;
        if self.data_off + tensor_data_len != total_size {
            return Err("internal: tensor-data region does not end at the blob end".to_string());
        }

        let mut table = Vec::with_capacity(self.records.len() * RECORD_BYTES);
        for record in &self.records {
            let mut name = [0u8; 64];
            name[..record.name.len()].copy_from_slice(record.name.as_bytes());
            table.extend_from_slice(&name);
            table.extend_from_slice(&record.dtype.code().to_le_bytes());
            table.extend_from_slice(&(record.dims.len() as u16).to_le_bytes());
            table.extend_from_slice(&0u32.to_le_bytes()); // reserved_a
            for index in 0..4 {
                let extent = record.dims.get(index).copied().unwrap_or(0);
                table.extend_from_slice(&extent.to_le_bytes());
            }
            table.extend_from_slice(&record.data_off.to_le_bytes());
            table.extend_from_slice(&record.data_len.to_le_bytes());
            table.extend_from_slice(&record.digest);
            table.extend_from_slice(&0u64.to_le_bytes()); // reserved_b
        }
        let table_digest = sha256::digest(&table);

        let mut header = Vec::with_capacity(HEADER_BYTES);
        header.extend_from_slice(b"BXW1");
        header.extend_from_slice(&1u16.to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        header.extend_from_slice(&u32::from(self.tied_output).to_le_bytes());
        header.extend_from_slice(&tensor_count.to_le_bytes());
        header.extend_from_slice(&total_size.to_le_bytes());
        header.extend_from_slice(&(HEADER_BYTES as u64).to_le_bytes());
        header.extend_from_slice(&self.data_off.to_le_bytes());
        header.extend_from_slice(&tensor_data_len.to_le_bytes());
        header.extend_from_slice(&0u64.to_le_bytes()); // reserved_0
        header.extend_from_slice(&0u64.to_le_bytes()); // reserved_1
        header.extend_from_slice(&table_digest);
        for field in [
            metadata.arch_id,
            metadata.n_layers,
            metadata.d_model,
            metadata.n_heads,
            metadata.n_kv_heads,
            metadata.d_head,
            metadata.d_ffn,
            metadata.vocab_size,
            metadata.max_seq_len,
            metadata.rope_theta.to_bits(),
            metadata.norm_eps.to_bits(),
            metadata.rope_dim,
            metadata.bos_token_id,
            metadata.eos_token_id,
            metadata.rope_pairing,
            0, // reserved_3
        ] {
            header.extend_from_slice(&field.to_le_bytes());
        }
        header.extend_from_slice(&metadata.vocab_digest);
        header.extend_from_slice(&metadata.vocab_len.to_le_bytes());
        header.resize(HEADER_BYTES, 0); // reserved_tail

        let table_pad = self.data_off as usize - HEADER_BYTES - table.len();
        let mut blob = Vec::with_capacity(total_size as usize);
        blob.extend_from_slice(&header);
        blob.extend_from_slice(&table);
        blob.extend(std::iter::repeat_n(0u8, table_pad));
        blob.extend_from_slice(&self.data);
        if blob.len() as u64 != total_size {
            return Err(format!(
                "internal: assembled {} bytes, declared {total_size}",
                blob.len()
            ));
        }
        Ok(blob)
    }
}

/// Encodes `F32` elements, flushing subnormals (§4.7).
fn encode_f32(values: &[f32]) -> (Vec<u8>, Adjustments) {
    let mut adjustments = Adjustments::default();
    let mut out = Vec::with_capacity(values.len() * 4);
    for value in values {
        let cleaned = if value.is_nan() || value.is_infinite() {
            adjustments.non_finite += 1;
            *value
        } else if *value != 0.0 && value.abs() < f32::MIN_POSITIVE {
            adjustments.flushed_elements += 1;
            0.0
        } else if *value == 0.0 {
            // −0.0 is a legal element bit pattern (the sign bit is
            // unconstrained for elements), but +0.0 is the canonical form and
            // the two are numerically identical everywhere they are used.
            0.0
        } else {
            *value
        };
        out.extend_from_slice(&cleaned.to_le_bytes());
    }
    (out, adjustments)
}

/// Encodes `Q8_0` in the split-plane layout of §4.2.
fn encode_q8_0(values: &[f32]) -> (Vec<u8>, Adjustments) {
    let mut adjustments = Adjustments::default();
    let blocks = values.len() / Q8_0_BLOCK;
    let mut scales = Vec::with_capacity(blocks * 4);
    let mut quants = Vec::with_capacity(blocks * Q8_0_BLOCK);

    for block in values.chunks_exact(Q8_0_BLOCK) {
        let mut peak = 0.0f32;
        for value in block {
            if value.is_nan() || value.is_infinite() {
                adjustments.non_finite += 1;
                continue;
            }
            let magnitude = value.abs();
            if magnitude > peak {
                peak = magnitude;
            }
        }
        // §4.2: an all-zero block is +0.0 and 32 zero quants, and so is a block
        // whose derived scale would be subnormal — §4.7 admits no subnormal
        // scale, and such a block's values are all below 1.5e-36.
        let scale = peak / 127.0;
        if peak == 0.0 || scale < f32::MIN_POSITIVE {
            if peak == 0.0 {
                adjustments.zero_blocks += 1;
            } else {
                adjustments.flushed_scales += 1;
            }
            scales.extend_from_slice(&0.0f32.to_le_bytes());
            quants.extend(std::iter::repeat_n(0i8 as u8, Q8_0_BLOCK));
            continue;
        }
        scales.extend_from_slice(&scale.to_le_bytes());
        for value in block {
            let scaled = f64::from(*value) / f64::from(scale);
            let rounded = round_ties_even(scaled).clamp(-127.0, 127.0) as i8;
            quants.push(rounded as u8);
        }
    }

    let scale_span = round_up(scales.len() as u64, ALIGN) as usize;
    let mut out = Vec::with_capacity(scale_span + quants.len());
    out.extend_from_slice(&scales);
    // Rule D21: the inter-plane pad is inside the digest-covered extent, so it
    // is zero by requirement rather than by convention.
    out.resize(scale_span, 0);
    out.extend_from_slice(&quants);
    (out, adjustments)
}

fn round_ties_even(value: f64) -> f64 {
    let rounded = value.round();
    if (value - value.trunc()).abs() == 0.5 && rounded % 2.0 != 0.0 {
        rounded - value.signum()
    } else {
        rounded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ties_round_to_even() {
        assert_eq!(round_ties_even(0.5), 0.0);
        assert_eq!(round_ties_even(1.5), 2.0);
        assert_eq!(round_ties_even(2.5), 2.0);
        assert_eq!(round_ties_even(-1.5), -2.0);
        assert_eq!(round_ties_even(-2.5), -2.0);
        assert_eq!(round_ties_even(1.4), 1.0);
    }

    #[test]
    fn a_zero_block_is_the_canonical_encoding() {
        let (payload, adjustments) = encode_q8_0(&[0.0f32; 32]);
        assert_eq!(adjustments.zero_blocks, 1);
        assert_eq!(&payload[..4], &0.0f32.to_le_bytes());
        assert!(payload[4..128].iter().all(|byte| *byte == 0));
        assert_eq!(payload.len(), 128 + 32);
    }

    #[test]
    fn quantization_round_trips_within_the_block_step() {
        let values: Vec<f32> = (0..32).map(|index| (index as f32 - 16.0) * 0.37).collect();
        let (payload, _) = encode_q8_0(&values);
        let scale = f32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        for (index, value) in values.iter().enumerate() {
            let quant = payload[128 + index] as i8;
            let restored = scale * f32::from(quant);
            assert!((restored - value).abs() <= scale * 0.5 + 1e-6);
        }
    }
}
