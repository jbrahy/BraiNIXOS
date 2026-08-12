//! `bxw1-convert` — a pretrained checkpoint into a BXW1 weight blob and a BXV1
//! vocabulary blob.
//!
//! ```text
//! python3 fetch.py ahxt/LiteLlama-460M-1T models/LiteLlama-460M-1T
//! cargo run --release -- models/LiteLlama-460M-1T out [--dtype f32]
//! ```
//!
//! # The two fields that are read, never assumed
//!
//! `rope_pairing` (BXW1 §5.5) and `pretokenizer` (BXV1 §5.4) are the two values
//! in the pair of formats whose wrong setting produces fluent, confident, wrong
//! output rather than a refusal. Both are derived here from the checkpoint's
//! own declarations, and an unrecognized declaration **stops the conversion**
//! rather than falling back to the common case:
//!
//! - `rope_pairing` comes from the architecture class the checkpoint names.
//!   A HuggingFace `LlamaForCausalLM` checkpoint has had its Q and K projection
//!   rows permuted at conversion time to suit `rotate_half`, which pairs
//!   `(x[i], x[i + rope_dim/2])` — half-split, value `2`. A checkpoint that
//!   states `rope_interleaved: true` is the other convention, value `1`.
//! - `pretokenizer` comes from `tokenizer_class`. `GPT2Tokenizer` is the
//!   GPT-2 regular expression, which is BXV1 mode `2`. Any other class is
//!   refused: BXV1 implements three modes, and approximating a fourth is the
//!   failure the field exists to prevent.
//!
//! `arch_id` is `1` only after the checkpoint is checked against every
//! structural commitment `arch_id = 1` makes — including that its attention
//! scale really is `d_head^(-1/2)`, which §5.6 binds to the value.

mod bxw1;
mod json;
mod safetensors;
mod sha256;
mod vocab;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bxw1::Dtype;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.len() < 2 {
        eprintln!("usage: bxw1-convert <model-dir> <out-dir> [--dtype q8|f32]");
        return ExitCode::from(2);
    }
    let source = PathBuf::from(&arguments[0]);
    let destination = PathBuf::from(&arguments[1]);
    let quantize = match arguments.get(2).map(String::as_str) {
        None | Some("--dtype=q8") => true,
        Some("--dtype=f32") => false,
        Some(other) => {
            eprintln!("unrecognized option {other}");
            return ExitCode::from(2);
        }
    };
    match convert(&source, &destination, quantize) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("bxw1-convert: {message}");
            ExitCode::FAILURE
        }
    }
}

/// The hyperparameters, after every architectural commitment has been checked.
struct Hyperparameters {
    layers: usize,
    d_model: usize,
    heads: usize,
    kv_heads: usize,
    d_head: usize,
    d_ffn: usize,
    vocab: usize,
    max_seq: usize,
    rope_theta: f32,
    norm_eps: f32,
    rope_pairing: u32,
    bos: u32,
    eos: u32,
    tied: bool,
}

fn read_json(path: &Path) -> Result<json::Value, String> {
    let raw = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    json::parse(&raw).map_err(|error| format!("{}: {error}", path.display()))
}

/// Reads `config.json` and refuses anything `arch_id = 1` cannot express.
fn hyperparameters(source: &Path) -> Result<Hyperparameters, String> {
    let config = read_json(&source.join("config.json"))?;
    let architectures = config
        .get("architectures")
        .and_then(json::Value::as_array)
        .ok_or("config.json has no architectures")?;
    let architecture = architectures
        .first()
        .and_then(json::Value::as_str)
        .ok_or("config.json has an empty architectures list")?;
    if architecture != "LlamaForCausalLM" && architecture != "MistralForCausalLM" {
        return Err(format!(
            "{architecture} is not a family BXW1 arch_id = 1 describes; a second family is a new \
             arch_id, a new tensor-name set and new kernels"
        ));
    }
    let integer = |key: &str| -> Result<usize, String> {
        config
            .get(key)
            .and_then(json::Value::as_usize)
            .ok_or(format!("config.json has no {key}"))
    };
    let activation = config
        .get("hidden_act")
        .and_then(json::Value::as_str)
        .unwrap_or("silu");
    if activation != "silu" {
        return Err(format!(
            "hidden_act is {activation}; arch_id = 1 is SwiGLU, which is SiLU-gated"
        ));
    }
    if config
        .get("attention_bias")
        .and_then(json::Value::as_bool)
        .unwrap_or(false)
    {
        return Err("attention_bias is set; arch_id = 1 has no field for an attention bias".into());
    }
    if config
        .get("rope_scaling")
        .is_some_and(|value| *value != json::Value::Null)
    {
        return Err("rope_scaling is set; BXW1 carries a single RoPE base and no scaling".into());
    }

    let d_model = integer("hidden_size")?;
    let heads = integer("num_attention_heads")?;
    let kv_heads = config
        .get("num_key_value_heads")
        .and_then(json::Value::as_usize)
        .unwrap_or(heads);
    let d_head = match config.get("head_dim").and_then(json::Value::as_usize) {
        Some(value) => value,
        None => d_model / heads,
    };
    if d_head * heads != d_model {
        return Err(format!(
            "n_heads × d_head = {} but d_model = {d_model}; BXW1 rule H16 refuses that",
            heads * d_head
        ));
    }

    // §5.5. The pairing is a property of the weight file, and the only honest
    // source for it is what the checkpoint's own runtime does with the rows.
    let rope_pairing = match config.get("rope_interleaved").and_then(json::Value::as_bool) {
        Some(true) => 1,
        Some(false) | None => 2,
    };

    Ok(Hyperparameters {
        layers: integer("num_hidden_layers")?,
        d_model,
        heads,
        kv_heads,
        d_head,
        d_ffn: integer("intermediate_size")?,
        vocab: integer("vocab_size")?,
        max_seq: integer("max_position_embeddings")?,
        // Absent means the family default, which is what the reference runtime
        // uses; the checkpoint's own `rotary_emb.inv_freq` buffer is a rounded
        // copy and is not authoritative.
        rope_theta: config
            .get("rope_theta")
            .and_then(json::Value::as_f64)
            .unwrap_or(10_000.0) as f32,
        norm_eps: config
            .get("rms_norm_eps")
            .and_then(json::Value::as_f64)
            .ok_or("config.json has no rms_norm_eps")? as f32,
        rope_pairing,
        bos: config
            .get("bos_token_id")
            .and_then(json::Value::as_usize)
            .ok_or("config.json has no bos_token_id")? as u32,
        eos: config
            .get("eos_token_id")
            .and_then(json::Value::as_usize)
            .ok_or("config.json has no eos_token_id")? as u32,
        tied: config
            .get("tie_word_embeddings")
            .and_then(json::Value::as_bool)
            .unwrap_or(false),
    })
}

/// Maps `tokenizer_class` onto a BXV1 pre-tokenizer mode, or stops.
fn pretokenizer(source: &Path) -> Result<u32, String> {
    let config = read_json(&source.join("tokenizer_config.json"))?;
    let class = config
        .get("tokenizer_class")
        .and_then(json::Value::as_str)
        .ok_or("tokenizer_config.json has no tokenizer_class")?;
    match class {
        "GPT2Tokenizer" | "GPT2TokenizerFast" => Ok(vocab::PRETOKENIZER_GPT2),
        other => Err(format!(
            "{other} does not map onto a BXV1 pre-tokenizer mode. BXV1 implements None, Gpt2 and \
             WhitespacePrefixed (§5.4); approximating a fourth rule is the silent failure the \
             field exists to prevent, so the conversion stops here"
        )),
    }
}

fn convert(source: &Path, destination: &Path, quantize: bool) -> Result<(), String> {
    let parameters = hyperparameters(source)?;
    let mode = pretokenizer(source)?;

    println!("architecture");
    println!("  arch_id            1 (decoder, RMSNorm pre-norm, RoPE, GQA, SwiGLU)");
    println!("  attention scale    d_head^(-1/2) = {}^(-1/2)  [bound to arch_id by BXW1 §5.6]", parameters.d_head);
    println!(
        "  rope_pairing       {} ({})",
        parameters.rope_pairing,
        if parameters.rope_pairing == 1 {
            "interleaved"
        } else {
            "half-split"
        }
    );
    println!("  pretokenizer       {mode} (Gpt2)");
    println!(
        "  layers {} d_model {} heads {} kv_heads {} d_head {} d_ffn {} vocab {} max_seq {}",
        parameters.layers,
        parameters.d_model,
        parameters.heads,
        parameters.kv_heads,
        parameters.d_head,
        parameters.d_ffn,
        parameters.vocab,
        parameters.max_seq
    );
    println!(
        "  rope_theta {} norm_eps {} tied_output {}",
        parameters.rope_theta, parameters.norm_eps, parameters.tied
    );

    let vocabulary = vocab::load(source, parameters.vocab)?;
    let vocabulary_blob = vocab::emit(&vocabulary)?;
    println!(
        "vocabulary: {} tokens ({} padding), {} merges, {} bytes",
        vocabulary.tokens.len(),
        vocabulary.padding_tokens,
        vocabulary.merges.len(),
        vocabulary_blob.len()
    );

    std::fs::create_dir_all(destination)
        .map_err(|error| format!("{}: {error}", destination.display()))?;
    let vocabulary_path = destination.join("vocab.bxv1");
    std::fs::write(&vocabulary_path, &vocabulary_blob)
        .map_err(|error| format!("{}: {error}", vocabulary_path.display()))?;

    let mut checkpoint = safetensors::SafeTensors::open(&source.join("model.safetensors"))?;
    let unexpected: Vec<&str> = checkpoint
        .names()
        .filter(|name| {
            !name.ends_with(".weight") && !name.ends_with("rotary_emb.inv_freq")
        })
        .collect();
    if !unexpected.is_empty() {
        return Err(format!(
            "checkpoint carries tensors arch_id = 1 has no name for: {unexpected:?}"
        ));
    }

    let tensor_count = if parameters.tied { 2 } else { 3 } + 9 * parameters.layers;
    let mut builder = bxw1::Builder::new(tensor_count, parameters.tied);
    let matrix = if quantize { Dtype::Q8_0 } else { Dtype::F32 };

    let d_model = parameters.d_model as u64;
    let query_width = (parameters.heads * parameters.d_head) as u64;
    let kv_width = (parameters.kv_heads * parameters.d_head) as u64;
    let d_ffn = parameters.d_ffn as u64;
    let vocab = parameters.vocab as u64;

    // `tok_embeddings` is F32 whatever the requested dtype: the embedding
    // lookup needs one row, and `brainix_transformer` takes the table as
    // `&[f32]` (see its `weights` module). A Q8_0 table is format-legal and not
    // servable through that crate today, so writing one would produce a blob
    // that validates and cannot run.
    let copy = |builder: &mut bxw1::Builder,
                    checkpoint: &mut safetensors::SafeTensors,
                    from: &str,
                    to: &str,
                    dtype: Dtype,
                    dims: &[u64]|
     -> Result<(), String> {
        let entry = checkpoint.entry(from)?.clone();
        if entry.shape != dims {
            return Err(format!(
                "{from}: checkpoint shape {:?} disagrees with the shape BXW1 requires for {to}: \
                 {dims:?}",
                entry.shape
            ));
        }
        let values = checkpoint.read(from)?;
        builder.push(to, dtype, dims, &values)
    };

    copy(
        &mut builder,
        &mut checkpoint,
        "model.embed_tokens.weight",
        "tok_embeddings.weight",
        Dtype::F32,
        &[vocab, d_model],
    )?;
    for layer in 0..parameters.layers {
        for (from, to, dtype, dims) in [
            (
                format!("model.layers.{layer}.input_layernorm.weight"),
                format!("layers.{layer}.attention_norm.weight"),
                Dtype::F32,
                vec![d_model],
            ),
            (
                format!("model.layers.{layer}.self_attn.q_proj.weight"),
                format!("layers.{layer}.attention.wq.weight"),
                matrix,
                vec![query_width, d_model],
            ),
            (
                format!("model.layers.{layer}.self_attn.k_proj.weight"),
                format!("layers.{layer}.attention.wk.weight"),
                matrix,
                vec![kv_width, d_model],
            ),
            (
                format!("model.layers.{layer}.self_attn.v_proj.weight"),
                format!("layers.{layer}.attention.wv.weight"),
                matrix,
                vec![kv_width, d_model],
            ),
            (
                format!("model.layers.{layer}.self_attn.o_proj.weight"),
                format!("layers.{layer}.attention.wo.weight"),
                matrix,
                vec![d_model, query_width],
            ),
            (
                format!("model.layers.{layer}.post_attention_layernorm.weight"),
                format!("layers.{layer}.ffn_norm.weight"),
                Dtype::F32,
                vec![d_model],
            ),
            (
                format!("model.layers.{layer}.mlp.gate_proj.weight"),
                format!("layers.{layer}.feed_forward.w1.weight"),
                matrix,
                vec![d_ffn, d_model],
            ),
            (
                format!("model.layers.{layer}.mlp.up_proj.weight"),
                format!("layers.{layer}.feed_forward.w3.weight"),
                matrix,
                vec![d_ffn, d_model],
            ),
            (
                format!("model.layers.{layer}.mlp.down_proj.weight"),
                format!("layers.{layer}.feed_forward.w2.weight"),
                matrix,
                vec![d_model, d_ffn],
            ),
        ] {
            copy(&mut builder, &mut checkpoint, &from, &to, dtype, &dims)?;
        }
    }
    copy(
        &mut builder,
        &mut checkpoint,
        "model.norm.weight",
        "norm.weight",
        Dtype::F32,
        &[d_model],
    )?;
    if !parameters.tied {
        copy(
            &mut builder,
            &mut checkpoint,
            "lm_head.weight",
            "output.weight",
            matrix,
            &[vocab, d_model],
        )?;
    }

    let adjustments = builder.adjustments;
    let metadata = bxw1::Metadata {
        arch_id: 1,
        n_layers: parameters.layers as u32,
        d_model: parameters.d_model as u32,
        n_heads: parameters.heads as u32,
        n_kv_heads: parameters.kv_heads as u32,
        d_head: parameters.d_head as u32,
        d_ffn: parameters.d_ffn as u32,
        vocab_size: parameters.vocab as u32,
        max_seq_len: parameters.max_seq as u32,
        rope_theta: parameters.rope_theta,
        norm_eps: parameters.norm_eps,
        rope_dim: parameters.d_head as u32,
        bos_token_id: parameters.bos,
        eos_token_id: parameters.eos,
        rope_pairing: parameters.rope_pairing,
        vocab_digest: sha256::digest(&vocabulary_blob),
        vocab_len: vocabulary_blob.len() as u64,
    };
    let blob = builder.finish(&metadata)?;
    let weights_path = destination.join(if quantize {
        "model.bxw1"
    } else {
        "model-f32.bxw1"
    });
    std::fs::write(&weights_path, &blob)
        .map_err(|error| format!("{}: {error}", weights_path.display()))?;

    println!("conversion adjustments");
    println!("  subnormal F32 elements flushed to zero : {}", adjustments.flushed_elements);
    println!("  Q8_0 blocks that were entirely zero    : {}", adjustments.zero_blocks);
    println!("  Q8_0 scales that were subnormal        : {}", adjustments.flushed_scales);
    println!("wrote {} ({} bytes)", weights_path.display(), blob.len());
    println!("  blob sha256  {}", sha256::hex(&sha256::digest(&blob)));
    println!("wrote {} ({} bytes)", vocabulary_path.display(), vocabulary_blob.len());
    println!("  vocab sha256 {}", sha256::hex(&metadata.vocab_digest));
    Ok(())
}
