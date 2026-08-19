//! Emits a small, deterministic BXW1 model and BXV1 vocabulary.
//!
//! # Why this exists
//!
//! Every numerics change in the tensor kernels is supposed to be priced by the
//! perplexity harness, and the harness needs a model. Converting a real
//! checkpoint needs the checkpoint, which is gigabytes and is not in the tree.
//! So the quality gate that governs the hottest code in the project was, in
//! practice, unavailable -- and "blocked on an artifact" was used more than
//! once as a reason not to measure.
//!
//! A synthetic model closes that. It is not a language model and its perplexity
//! is meaningless as a number: the weights are deterministic noise. What it is
//! good for is the only thing the gate is actually used for -- **comparing two
//! builds on the same input** -- and for that, meaningless-but-identical is
//! sufficient. If a kernel change moves the perplexity of this model, it moves
//! the perplexity of a real one.
//!
//! It also gives an end-to-end tokens-per-second number on a shape the caller
//! chooses, which the per-kernel benchmarks cannot.
//!
//! Usage:
//!     bxw1-synth <destination-dir> [--layers N] [--d-model N] [--f32]

#[path = "../../bxw1-convert/src/bxw1.rs"]
mod bxw1;
#[path = "../../bxw1-convert/src/json.rs"]
mod json;
#[path = "../../bxw1-convert/src/sha256.rs"]
mod sha256;
#[path = "../../bxw1-convert/src/vocab.rs"]
mod vocab;

use bxw1::Dtype;
use std::path::PathBuf;
use std::process::ExitCode;

/// Deterministic values in a range a trained weight plausibly occupies.
///
/// Not a random number generator with a system seed: the whole point is that
/// two builds see identical input, so the sequence is a pure function of the
/// tensor's name and its index.
fn values(count: usize, salt: u64) -> Vec<f32> {
    let mut state = salt | 1;
    (0..count)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            // Small and centred, like a normalized initialization.
            (((state >> 33) as f32 / 2_147_483_648.0) - 0.5) * 0.08
        })
        .collect()
}

fn salt_of(name: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in name.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

struct Shape {
    layers: usize,
    d_model: usize,
    heads: usize,
    kv_heads: usize,
    d_head: usize,
    d_ffn: usize,
    vocab: usize,
    max_seq: usize,
}

fn build(shape: &Shape, dtype: Dtype) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Per layer: two norms and seven matrices. Plus embeddings, final norm and
    // the output projection.
    let tensor_count = shape.layers * 9 + 3;
    let mut builder = bxw1::Builder::new(tensor_count, false);

    let mut push = |builder: &mut bxw1::Builder, name: String, dims: Vec<u64>, quantize: bool| {
        let count: u64 = dims.iter().product();
        let v = values(count as usize, salt_of(&name));
        // Norms stay f32: they are a vector per layer, quantizing them saves
        // nothing and BXW1 keeps them full precision.
        let d = if quantize { dtype } else { Dtype::F32 };
        builder.push(&name, d, &dims, &v)
    };

    let q_width = (shape.heads * shape.d_head) as u64;
    let kv_width = (shape.kv_heads * shape.d_head) as u64;
    let d_model = shape.d_model as u64;
    let d_ffn = shape.d_ffn as u64;

    // Embeddings stay F32: `brainix-transformer` requires it, because a row is
    // gathered per token rather than streamed like a projection, so quantizing
    // it saves a rounding error's worth of nothing.
    push(
        &mut builder,
        "tok_embeddings.weight".into(),
        vec![shape.vocab as u64, d_model],
        false,
    )?;

    for layer in 0..shape.layers {
        push(
            &mut builder,
            format!("layers.{layer}.attention_norm.weight"),
            vec![d_model],
            false,
        )?;
        push(
            &mut builder,
            format!("layers.{layer}.attention.wq.weight"),
            vec![q_width, d_model],
            true,
        )?;
        push(
            &mut builder,
            format!("layers.{layer}.attention.wk.weight"),
            vec![kv_width, d_model],
            true,
        )?;
        push(
            &mut builder,
            format!("layers.{layer}.attention.wv.weight"),
            vec![kv_width, d_model],
            true,
        )?;
        push(
            &mut builder,
            format!("layers.{layer}.attention.wo.weight"),
            vec![d_model, q_width],
            true,
        )?;
        push(
            &mut builder,
            format!("layers.{layer}.ffn_norm.weight"),
            vec![d_model],
            false,
        )?;
        push(
            &mut builder,
            format!("layers.{layer}.feed_forward.w1.weight"),
            vec![d_ffn, d_model],
            true,
        )?;
        push(
            &mut builder,
            format!("layers.{layer}.feed_forward.w3.weight"),
            vec![d_ffn, d_model],
            true,
        )?;
        push(
            &mut builder,
            format!("layers.{layer}.feed_forward.w2.weight"),
            vec![d_model, d_ffn],
            true,
        )?;
    }

    push(&mut builder, "norm.weight".into(), vec![d_model], false)?;
    push(
        &mut builder,
        "output.weight".into(),
        vec![shape.vocab as u64, d_model],
        true,
    )?;

    // A byte-level vocabulary with no merges: every identifier is one byte,
    // padded out to `vocab_size`. The tokenizer is not what is being measured.
    let vocabulary = vocab::Vocabulary {
        tokens: (0..256u32).map(|b| vec![b as u8]).collect(),
        merges: Vec::new(),
        pretokenizer: 1,
        padding_tokens: shape.vocab.saturating_sub(256),
    };
    let vocabulary_blob = vocab::emit(&vocabulary)?;

    let metadata = bxw1::Metadata {
        arch_id: 1,
        n_layers: shape.layers as u32,
        d_model: shape.d_model as u32,
        n_heads: shape.heads as u32,
        n_kv_heads: shape.kv_heads as u32,
        d_head: shape.d_head as u32,
        d_ffn: shape.d_ffn as u32,
        vocab_size: shape.vocab as u32,
        max_seq_len: shape.max_seq as u32,
        rope_theta: 10_000.0,
        norm_eps: 1.0e-5,
        rope_dim: shape.d_head as u32,
        bos_token_id: 1,
        eos_token_id: 2,
        rope_pairing: 2,
        vocab_digest: sha256::digest(&vocabulary_blob),
        vocab_len: vocabulary_blob.len() as u64,
    };
    let blob = builder.finish(&metadata)?;

    Ok((blob, vocabulary_blob))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: bxw1-synth <destination-dir> [--layers N] [--d-model N] [--f32]");
        return ExitCode::FAILURE;
    }
    let destination = PathBuf::from(&args[0]);

    let number = |flag: &str, default: usize| -> usize {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    };
    let shape = Shape {
        layers: number("--layers", 4),
        d_model: number("--d-model", 256),
        heads: number("--heads", 8),
        kv_heads: number("--kv-heads", 4),
        d_head: number("--d-head", 32),
        d_ffn: number("--d-ffn", 704),
        vocab: number("--vocab", 512),
        max_seq: number("--max-seq", 256),
    };
    let dtype = if args.iter().any(|a| a == "--f32") {
        Dtype::F32
    } else {
        Dtype::Q8_0
    };

    let (blob, vocabulary_blob) = match build(&shape, dtype) {
        Ok(pair) => pair,
        Err(reason) => {
            eprintln!("bxw1-synth: {reason}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(reason) = std::fs::create_dir_all(&destination) {
        eprintln!("bxw1-synth: {destination:?}: {reason}");
        return ExitCode::FAILURE;
    }
    let name = if matches!(dtype, Dtype::F32) {
        "model-f32.bxw1"
    } else {
        "model.bxw1"
    };
    let path = destination.join(name);
    if let Err(reason) = std::fs::write(&path, &blob) {
        eprintln!("bxw1-synth: {path:?}: {reason}");
        return ExitCode::FAILURE;
    }
    // The harness wants both, and the model's header carries the vocabulary's
    // digest, so writing one without the other produces a pair that refuses to
    // load with a message about a mismatch rather than a missing file.
    let vocabulary_path = destination.join("vocab.bxv1");
    if let Err(reason) = std::fs::write(&vocabulary_path, &vocabulary_blob) {
        eprintln!("bxw1-synth: {vocabulary_path:?}: {reason}");
        return ExitCode::FAILURE;
    }
    println!("wrote {} ({} bytes)", path.display(), blob.len());
    println!(
        "wrote {} ({} bytes)",
        vocabulary_path.display(),
        vocabulary_blob.len()
    );
    println!(
        "  {} layers, d_model {}, d_ffn {}, vocab {}",
        shape.layers, shape.d_model, shape.d_ffn, shape.vocab
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::{build, salt_of, values, Dtype, Shape};

    fn tiny() -> Shape {
        Shape {
            layers: 1,
            d_model: 64,
            heads: 2,
            kv_heads: 1,
            d_head: 32,
            d_ffn: 128,
            vocab: 288,
            max_seq: 64,
        }
    }

    /// The property the gate depends on: two runs produce the same bytes.
    ///
    /// A generator seeded from the clock or the allocator would make every
    /// comparison between two builds meaningless, which is the one thing this
    /// tool exists to support.
    #[test]
    fn the_same_shape_produces_byte_identical_blobs() {
        let (a, va) = build(&tiny(), Dtype::Q8_0).expect("build");
        let (b, vb) = build(&tiny(), Dtype::Q8_0).expect("build");
        assert_eq!(a, b, "the model blob must be reproducible");
        assert_eq!(va, vb, "the vocabulary blob must be reproducible");
    }

    #[test]
    fn different_tensors_get_different_values() {
        // Salted by name, so two tensors of the same size are not copies of
        // each other -- a model whose every matrix is identical would hide a
        // whole class of indexing bug.
        let left = values(64, salt_of("layers.0.attention.wq.weight"));
        let right = values(64, salt_of("layers.0.attention.wk.weight"));
        assert_ne!(left, right);
    }

    #[test]
    fn the_quantized_and_f32_builds_differ_in_size_but_not_shape() {
        let (quantized, _) = build(&tiny(), Dtype::Q8_0).expect("build");
        let (full, _) = build(&tiny(), Dtype::F32).expect("build");
        assert!(
            quantized.len() < full.len(),
            "Q8_0 must be smaller than F32: {} vs {}",
            quantized.len(),
            full.len()
        );
    }
}
