//! Perplexity of a BXW1 model over a text sample.
//!
//! # Why this exists
//!
//! It is the **quality gate for quantization changes**. `NORTH_STAR.md` ranks
//! throughput above the invariants as of 2026-08-17, but it does not rank it
//! above correctness, and a change that makes the model faster and worse is not
//! a win it is willing to take blind. The specific change waiting on this is
//! `SDOT`: quantizing *activations* to `i8` so the inner loop can use the
//! 16-multiply-accumulate dot product instruction. That is a model-quality
//! change and needs a number on both sides of it.
//!
//! Perplexity is `exp(mean cross-entropy)` over the next-token predictions of a
//! held-out passage. Lower is better. **Its absolute value is not the point**
//! here — a 460M model on a short sample is not a benchmark of anything — the
//! point is the *delta* between two implementations on identical input, which
//! is the only comparison this file is designed to support.
//!
//!
//! # Six decimal places, not three
//!
//! The delta this gate exists to see is small. Three decimals on a perplexity
//! of 512 resolves about `2e-6` relative, which is coarser than several of the
//! numerics changes worth pricing: the all-f32 `exp` measured on 2026-08-19
//! carries a worst-case relative error of `1.95e-6` and would have printed as
//! an exact tie. Six decimals is enough to tell "did not move" from "moved
//! below the print width", and those are different findings.
//!
//! # Running it
//!
//! ```sh
//! cargo run --release --example perplexity --target aarch64-apple-darwin -- \
//!     ../../tools/bxw1-convert/out/model.bxw1 \
//!     ../../tools/bxw1-convert/out/vocab.bxv1
//! ```
//!
//! Release is not optional: the forward pass is the same kernel
//! `benches/matmul.rs` measures, and a debug build takes minutes per token.

use brainix_bxw1::{Dtype, WeightBlob};
use brainix_tensor::Q8Weights;
use brainix_tensor::RopePairing;
use brainix_tokenizer::Vocabulary;
use brainix_transformer::{Dispatch, Serial};
use brainix_transformer::{
    LayerWeights, LogitProjection, Model, ModelConfig, ModelWeights, WeightMatrix,
};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Barrier, Mutex};
use std::thread;

/// A `Dispatch` that spawns threads per call.
///
/// Kept as the control. It measured **0.99x** end to end: four spawns cost about
/// 37 us and five of a layer's seven projections take less than that, so the
/// creation cost consumes the entire gain.
struct SpawnPerCall(usize);

impl Dispatch for SpawnPerCall {
    fn chunks(&self) -> usize {
        self.0
    }

    fn for_each_chunk<F>(&self, out: &mut [f32], chunk_len: usize, body: F)
    where
        F: Fn(usize, &mut [f32]) + Sync,
    {
        thread::scope(|scope| {
            for (index, chunk) in out.chunks_mut(chunk_len.max(1)).enumerate() {
                let body = &body;
                scope.spawn(move || body(index, chunk));
            }
        });
    }
}

/// One unit of work, with its types erased so parked threads can hold it.
///
/// The closure is reached through a monomorphic trampoline rather than a fat
/// pointer, which keeps the erasure to a single `*const ()` and puts the only
/// transmute-shaped step in one generic function.
#[derive(Clone, Copy)]
struct Job {
    closure: *const (),
    trampoline: fn(*const (), usize, &mut [f32]),
    base: *mut f32,
    total: usize,
    chunk_len: usize,
}

// SAFETY: a `Job` is only ever read by a worker between the two barriers of one
// `for_each_chunk` call, and that call cannot return until every worker has
// passed the second barrier. The pointers therefore never outlive what they
// point at, and the chunks each worker derives are disjoint by construction.
unsafe impl Send for Job {}
unsafe impl Sync for Job {}

/// Workers spawned once and parked on a barrier.
///
/// This is the shape a kernel must use. Threads cannot be created per
/// projection -- a decode performs 168 of them per token against a ~12 ms
/// budget, and creation alone would cost half of it -- so a real implementation
/// parks cores and wakes them with an IPI. This is that structure, with an OS
/// barrier standing in for the doorbell.
struct Pool<'scope> {
    workers: usize,
    minimum_bytes: usize,
    start: &'scope Barrier,
    finish: &'scope Barrier,
    job: &'scope Mutex<Option<Job>>,
}

impl Dispatch for Pool<'_> {
    fn chunks(&self) -> usize {
        self.workers
    }

    fn minimum_split_bytes(&self) -> usize {
        self.minimum_bytes
    }

    fn for_each_chunk<F>(&self, out: &mut [f32], chunk_len: usize, body: F)
    where
        F: Fn(usize, &mut [f32]) + Sync,
    {
        fn call<F: Fn(usize, &mut [f32])>(closure: *const (), index: usize, chunk: &mut [f32]) {
            // SAFETY: `closure` was produced from a `&F` in the same call and
            // the barriers keep that borrow alive for the whole of this use.
            let body = unsafe { &*(closure as *const F) };
            body(index, chunk);
        }
        let total = out.len();
        let posted = Job {
            closure: core::ptr::from_ref(&body) as *const (),
            trampoline: call::<F>,
            base: out.as_mut_ptr(),
            total,
            chunk_len: chunk_len.max(1),
        };
        match self.job.lock() {
            Ok(mut slot) => *slot = Some(posted),
            Err(_) => return,
        }
        self.start.wait();
        self.finish.wait();
    }
}

/// The body every parked worker runs.
fn worker_loop(
    index: usize,
    start: &Barrier,
    finish: &Barrier,
    job: &Mutex<Option<Job>>,
    shutting_down: &AtomicBool,
) {
    loop {
        start.wait();
        if shutting_down.load(Ordering::Acquire) {
            return;
        }
        let posted = job.lock().ok().and_then(|slot| *slot);
        if let Some(posted) = posted {
            let begin = index.saturating_mul(posted.chunk_len);
            if begin < posted.total {
                let len = posted.chunk_len.min(posted.total.saturating_sub(begin));
                // SAFETY: `begin` is a multiple of `chunk_len` and `len` is
                // clamped to the remainder, so this worker's range is disjoint
                // from every other worker's, and the barriers bound its validity
                // to the posting call. This is the same argument
                // `slice::chunks_mut` makes, reconstructed across threads
                // because the borrow cannot cross the park.
                let chunk = unsafe { core::slice::from_raw_parts_mut(posted.base.add(begin), len) };
                (posted.trampoline)(posted.closure, index, chunk);
            }
        }
        finish.wait();
    }
}

/// The passage perplexity is measured over.
///
/// Held in the source rather than read from a file so that two runs of this
/// example are comparable by construction. A quality delta measured against
/// different text is not a delta.
const SAMPLE: &str = "The capital of France is Paris. The capital of Germany is Berlin. \
Water freezes at zero degrees Celsius and boils at one hundred. The Earth orbits the Sun \
once every year, and the Moon orbits the Earth roughly once a month. Computers store \
information as sequences of bits, each of which is either zero or one. A byte is eight bits, \
and a kilobyte is one thousand and twenty-four bytes.";

/// Every `F32` tensor of the blob, in load order, plus the slot each name maps
/// to.
///
/// `ModelWeights` is a tree of `&[f32]` and borrowed `Q8Weights` -- right for a
/// kernel that must not allocate, and wrong for a loader that must. This is the
/// allocation, built in one pass so that the borrows taken in the second pass
/// are stable.
struct Floats {
    stored: Vec<Vec<f32>>,
}

impl Floats {
    fn take(&mut self, bytes: &[u8]) -> usize {
        self.stored.push(
            bytes
                .chunks_exact(4)
                .filter_map(|word| word.try_into().ok().map(f32::from_le_bytes))
                .collect(),
        );
        self.stored.len().saturating_sub(1)
    }
}

/// Where each tensor of one layer lives after the first pass.
struct LayerSlots {
    attention_norm: usize,
    feed_forward_norm: usize,
    /// `(name, f32 slot)` -- `None` when the tensor is `Q8_0` and stays borrowed.
    matrices: [(String, Option<usize>); 7],
}

/// Tensor names of one layer, in the order `LayerSlots::matrices` holds them.
const LAYER_MATRICES: [&str; 7] = [
    "attention.wq.weight",
    "attention.wk.weight",
    "attention.wv.weight",
    "attention.wo.weight",
    "feed_forward.w1.weight",
    "feed_forward.w3.weight",
    "feed_forward.w2.weight",
];

/// Builds a `WeightMatrix` for a tensor that stayed quantized, or borrows the
/// `F32` copy taken in the first pass.
fn build_matrix<'a>(
    blob: &WeightBlob<'a>,
    floats: &'a Floats,
    name: &str,
    slot: Option<usize>,
) -> Result<WeightMatrix<'a>, String> {
    match slot {
        Some(index) => {
            let values = floats
                .stored
                .get(index)
                .ok_or_else(|| format!("{name}: missing f32 slot"))?;
            Ok(WeightMatrix::Float32(values))
        }
        None => {
            let tensor = blob
                .tensor_by_name(name.as_bytes())
                .map_err(|error| format!("{name}: {error:?}"))?;
            let dims = tensor.dims();
            let n_out = *dims.first().ok_or_else(|| format!("{name}: rank 0"))? as usize;
            let n_in = *dims.get(1).ok_or_else(|| format!("{name}: rank 1"))? as usize;
            let view = Q8Weights::new(tensor.data(), n_out, n_in)
                .map_err(|error| format!("{name}: {error:?}"))?;
            Ok(WeightMatrix::Quantized8(view))
        }
    }
}

/// Cross-entropy of `target` under `logits`, in nats.
///
/// Computed through the log-sum-exp shift rather than by exponentiating the
/// logits directly: a 50304-wide row of a real model contains values large
/// enough that `exp` overflows `f32`, and the overflow presents as a perplexity
/// of `inf` rather than as an error.
fn cross_entropy(logits: &[f32], target: u32) -> Option<f32> {
    let peak = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    if !peak.is_finite() {
        return None;
    }
    let sum: f32 = logits.iter().map(|value| (value - peak).exp()).sum();
    let target_logit = *logits.get(target as usize)?;
    Some((peak + sum.ln()) - target_logit)
}

/// Every buffer one evaluation borrows, in one place.
///
/// Grouped rather than passed loose. Twelve positional parameters of which six
/// were `&mut` slices is how a call site ends up with two of them swapped and a
/// result that still looks plausible, and it is what the suppression this file
/// used to carry was hiding.
struct Buffers<'a> {
    workspace_storage: &'a mut [f32],
    quant_scratch: &'a mut [u8],
    cache_storage: &'a mut [f32],
    logits: &'a mut [f32],
}

/// What is being evaluated, and under how many workers.
struct Passage<'a> {
    label: &'a str,
    tokens: &'a [u32],
    count: usize,
    workers: usize,
}

/// Runs the whole passage under one dispatcher and reports perplexity and rate.
fn evaluate<D: Dispatch>(
    passage: &Passage<'_>,
    model: &Model<'_>,
    config: &ModelConfig,
    buffers: &mut Buffers<'_>,
    geometry: brainix_transformer::CacheGeometry,
    dispatch: &D,
) -> Result<(f64, f64), String> {
    let Passage {
        label,
        tokens,
        count,
        workers,
    } = *passage;
    let mut workspace = brainix_transformer::Workspace::new(
        buffers.workspace_storage,
        buffers.quant_scratch,
        config,
        1,
    )
    .map_err(|error| format!("workspace: {error:?}"))?;
    let mut arena = brainix_transformer::KeyValueArena::new(buffers.cache_storage, geometry)
        .map_err(|error| format!("arena: {error:?}"))?;
    let mut cache = arena
        .issue_session()
        .map_err(|e| format!("session: {e:?}"))?;
    println!();
    println!("evaluating {count} tokens -- {label} ({workers} workers)");
    let start = std::time::Instant::now();
    let mut total_nats = 0.0f64;
    let mut predictions = 0usize;
    for position in 0..count.saturating_sub(1) {
        let token = *tokens.get(position).ok_or("token index")?;
        let target = *tokens.get(position + 1).ok_or("target index")?;
        model
            .forward(
                dispatch,
                &mut workspace,
                &mut cache,
                &[token],
                buffers.logits,
            )
            .map_err(|error| format!("forward at {position}: {error:?}"))?;
        let nats = cross_entropy(buffers.logits, target)
            .ok_or_else(|| format!("non-finite logits at {position}"))?;
        total_nats += f64::from(nats);
        predictions = predictions.saturating_add(1);
    }
    let elapsed = start.elapsed().as_secs_f64();
    let mean = total_nats / predictions as f64;
    println!("  PERPLEXITY  {:.6}", mean.exp());
    println!(
        "  throughput  {:.2} tok/s  ({elapsed:.1}s)",
        predictions as f64 / elapsed
    );
    Ok((mean.exp(), predictions as f64 / elapsed))
}

fn run(model_path: &str, vocab_path: &str) -> Result<(), String> {
    let blob_bytes = std::fs::read(model_path).map_err(|e| format!("{model_path}: {e}"))?;
    let vocab_bytes = std::fs::read(vocab_path).map_err(|e| format!("{vocab_path}: {e}"))?;
    println!("model  {model_path}  ({} bytes)", blob_bytes.len());
    println!("vocab  {vocab_path}  ({} bytes)", vocab_bytes.len());

    let blob = WeightBlob::parse(&blob_bytes, blob_bytes.len() as u64)
        .map_err(|error| format!("blob: {error:?}"))?;
    let header = blob.header();

    let config = ModelConfig {
        architecture_id: header.arch_id,
        layer_count: header.n_layers as usize,
        model_width: header.d_model as usize,
        query_head_count: header.n_heads as usize,
        key_value_head_count: header.n_kv_heads as usize,
        head_width: header.d_head as usize,
        feed_forward_width: header.d_ffn as usize,
        vocabulary_size: header.vocab_size as usize,
        maximum_sequence_length: header.max_seq_len as usize,
        rope_theta: header.rope_theta,
        normalization_epsilon: header.norm_eps,
        rope_dimensions: header.rope_dim as usize,
        rope_pairing: match header.rope_pairing {
            brainix_bxw1::RopePairing::Interleaved => RopePairing::Interleaved,
            brainix_bxw1::RopePairing::HalfSplit => RopePairing::HalfSplit,
        },
    };
    println!(
        "config layers {} d_model {} heads {}/{} d_ffn {} vocab {} tied_output {}",
        config.layer_count,
        config.model_width,
        config.query_head_count,
        config.key_value_head_count,
        config.feed_forward_width,
        config.vocabulary_size,
        header.tied_output
    );

    let vocabulary =
        Vocabulary::parse(&vocab_bytes).map_err(|error| format!("vocab: {error:?}"))?;
    let mut tokens = vec![0u32; SAMPLE.len() + 2];
    let mut scratch = vec![0u32; SAMPLE.len() + 2];
    let count = vocabulary
        .encode(SAMPLE.as_bytes(), &mut scratch, &mut tokens)
        .map_err(|error| format!("encode: {error:?}"))?;
    tokens.truncate(count);
    println!("sample {} bytes -> {} tokens", SAMPLE.len(), count);
    if count < 2 {
        return Err("sample produced fewer than two tokens".to_string());
    }

    // ---- pass one: copy out every F32 tensor -------------------------------
    let mut floats = Floats { stored: Vec::new() };
    let named = |name: &str, floats: &mut Floats| -> Result<Option<usize>, String> {
        let tensor = blob
            .tensor_by_name(name.as_bytes())
            .map_err(|error| format!("{name}: {error:?}"))?;
        Ok(match tensor.dtype() {
            Dtype::F32 => Some(floats.take(tensor.data())),
            Dtype::Q8 => None,
        })
    };

    let embeddings_slot = named("tok_embeddings.weight", &mut floats)?
        .ok_or("tok_embeddings.weight must be F32 for this crate")?;
    let final_norm_slot = named("norm.weight", &mut floats)?.ok_or("norm.weight must be F32")?;
    let output_slot = if header.tied_output {
        None
    } else {
        Some(named("output.weight", &mut floats)?)
    };

    let mut layer_slots = Vec::with_capacity(config.layer_count);
    for layer in 0..config.layer_count {
        let attention_norm = named(
            &format!("layers.{layer}.attention_norm.weight"),
            &mut floats,
        )?
        .ok_or("attention_norm must be F32")?;
        let feed_forward_norm = named(&format!("layers.{layer}.ffn_norm.weight"), &mut floats)?
            .ok_or("ffn_norm must be F32")?;
        let mut matrices: [(String, Option<usize>); 7] = Default::default();
        for (index, suffix) in LAYER_MATRICES.iter().enumerate() {
            let name = format!("layers.{layer}.{suffix}");
            let slot = named(&name, &mut floats)?;
            if let Some(entry) = matrices.get_mut(index) {
                *entry = (name, slot);
            }
        }
        layer_slots.push(LayerSlots {
            attention_norm,
            feed_forward_norm,
            matrices,
        });
    }
    println!(
        "loaded {} F32 tensors ({:.1} MB copied), rest borrowed as Q8_0",
        floats.stored.len(),
        floats.stored.iter().map(|v| v.len() * 4).sum::<usize>() as f64 / 1e6
    );

    // ---- pass two: build the borrowed view ---------------------------------
    let mut layers = Vec::with_capacity(config.layer_count);
    for slots in &layer_slots {
        let mut built = Vec::with_capacity(7);
        for (name, slot) in &slots.matrices {
            built.push(build_matrix(&blob, &floats, name, *slot)?);
        }
        let get = |index: usize| -> Result<WeightMatrix<'_>, String> {
            built
                .get(index)
                .copied()
                .ok_or_else(|| "layer matrix missing".to_string())
        };
        layers.push(LayerWeights {
            attention_norm: floats
                .stored
                .get(slots.attention_norm)
                .ok_or("attention_norm slot")?,
            query_projection: get(0)?,
            key_projection: get(1)?,
            value_projection: get(2)?,
            attention_output_projection: get(3)?,
            feed_forward_norm: floats
                .stored
                .get(slots.feed_forward_norm)
                .ok_or("ffn_norm slot")?,
            gate_projection: get(4)?,
            up_projection: get(5)?,
            down_projection: get(6)?,
        });
    }

    let logit_projection = match output_slot {
        None => LogitProjection::Tied,
        Some(slot) => {
            LogitProjection::Separate(build_matrix(&blob, &floats, "output.weight", slot)?)
        }
    };

    let weights = ModelWeights {
        token_embeddings: floats
            .stored
            .get(embeddings_slot)
            .ok_or("embeddings slot")?,
        layers: &layers,
        final_norm: floats.stored.get(final_norm_slot).ok_or("norm slot")?,
        logit_projection,
    };

    let model = Model::new(config, weights).map_err(|error| format!("model: {error:?}"))?;

    // ---- evaluate ----------------------------------------------------------
    let workspace_len = brainix_transformer::workspace_floats(&config, 1)
        .map_err(|error| format!("workspace: {error:?}"))?;
    let cache_len = brainix_transformer::session_cache_floats(&config, 1)
        .map_err(|error| format!("cache: {error:?}"))?;
    let mut workspace_storage = vec![0.0f32; workspace_len];
    let mut cache_storage = vec![0.0f32; cache_len];
    let geometry = brainix_transformer::CacheGeometry {
        layer_count: config.layer_count,
        maximum_sequence_length: config.maximum_sequence_length,
        key_value_width: config
            .key_value_head_count
            .saturating_mul(config.head_width),
    };
    // Two runs: the f32-activation kernel (empty scratch) and the SDOT path
    // (scratch supplied). Same weights, same tokens, same everything else, so
    // the gap between the two perplexities is the cost of quantizing
    // activations and nothing else.
    let scratch_len = brainix_transformer::quantized_activation_bytes(&config, 1)
        .map_err(|error| format!("scratch: {error:?}"))?;
    let mut quant_scratch = vec![0u8; scratch_len];
    println!("activation scratch {scratch_len} bytes");

    let mut logits = vec![0.0f32; config.vocabulary_size];
    let mut results = Vec::new();
    let workers: usize = std::env::args()
        .nth(3)
        .and_then(|value| value.parse().ok())
        .unwrap_or(4);
    for (label, use_sdot) in [
        ("f32 activations", false),
        ("Q8_0 activations (SDOT)", true),
    ] {
        let scratch: &mut [u8] = if use_sdot {
            &mut quant_scratch
        } else {
            &mut []
        };
        let mut workspace =
            brainix_transformer::Workspace::new(&mut workspace_storage, scratch, &config, 1)
                .map_err(|error| format!("workspace: {error:?}"))?;
        let mut arena = brainix_transformer::KeyValueArena::new(&mut cache_storage, geometry)
            .map_err(|error| format!("arena: {error:?}"))?;
        let mut cache = arena
            .issue_session()
            .map_err(|error| format!("session: {error:?}"))?;

        println!();
        println!("evaluating {count} tokens -- {label}");
        let start = std::time::Instant::now();
        let mut total_nats = 0.0f64;
        let mut predictions = 0usize;
        for position in 0..count.saturating_sub(1) {
            let token = *tokens.get(position).ok_or("token index")?;
            let target = *tokens.get(position + 1).ok_or("target index")?;
            model
                .forward(&Serial, &mut workspace, &mut cache, &[token], &mut logits)
                .map_err(|error| format!("forward at {position}: {error:?}"))?;
            let nats = cross_entropy(&logits, target)
                .ok_or_else(|| format!("non-finite logits at position {position}"))?;
            total_nats += f64::from(nats);
            predictions = predictions.saturating_add(1);
        }
        let elapsed = start.elapsed().as_secs_f64();
        let mean = total_nats / predictions as f64;
        println!("  mean CE     {mean:.4} nats");
        println!("  PERPLEXITY  {:.6}", mean.exp());
        println!(
            "  throughput  {:.2} tok/s  ({elapsed:.1}s)",
            predictions as f64 / elapsed
        );
        results.push((label, mean.exp(), predictions as f64 / elapsed));
    }

    // Sweep the split threshold. 0 splits everything (the previous behaviour);
    // the larger values progressively exclude the small projections whose work
    // is smaller than a barrier pair.
    for threshold in [
        0usize,
        512 * 1024,
        2 * 1024 * 1024,
        4 * 1024 * 1024,
        usize::MAX,
    ] {
        let start = Barrier::new(workers + 1);
        let finish = Barrier::new(workers + 1);
        let job: Mutex<Option<Job>> = Mutex::new(None);
        let shutting_down = AtomicBool::new(false);
        let mut outcome = None;
        thread::scope(|scope| {
            for index in 0..workers {
                let (start, finish, job, shutting_down) = (&start, &finish, &job, &shutting_down);
                scope.spawn(move || worker_loop(index, start, finish, job, shutting_down));
            }
            let pool = Pool {
                workers,
                minimum_bytes: threshold,
                start: &start,
                finish: &finish,
                job: &job,
            };
            let label = if threshold == usize::MAX {
                "pool, split nothing".to_string()
            } else {
                format!("pool, split >= {} KB", threshold / 1024)
            };
            let passage = Passage {
                label: &label,
                tokens: &tokens,
                count,
                workers,
            };
            let mut buffers = Buffers {
                workspace_storage: &mut workspace_storage,
                quant_scratch: &mut quant_scratch,
                cache_storage: &mut cache_storage,
                logits: &mut logits,
            };
            outcome = Some(evaluate(
                &passage,
                &model,
                &config,
                &mut buffers,
                geometry,
                &pool,
            ));
            shutting_down.store(true, Ordering::Release);
            start.wait();
        });
        if let Some(Ok((ppl, rate))) = outcome {
            let name: &'static str = match threshold {
                0 => "all",
                524_288 => ">=512K",
                2_097_152 => ">=2M",
                4_194_304 => ">=4M",
                _ => "none",
            };
            results.push((name, ppl, rate));
        }
    }

    if let (Some(base), Some(fast)) = (results.first(), results.get(1)) {
        println!();
        println!(
            "  QUALITY  {:.6} -> {:.6}  ({:+.4}% perplexity)",
            base.1,
            fast.1,
            (fast.1 / base.1 - 1.0) * 100.0
        );
        println!(
            "  SPEED    {:.2} -> {:.2} tok/s  ({:.2}x)",
            base.2,
            fast.2,
            fast.2 / base.2
        );
        for entry in results.iter().skip(2) {
            println!(
                "  {:<8} {:.2} -> {:.2} tok/s  ({:.2}x over 1 core)   PPL {:.6}",
                entry.0,
                fast.2,
                entry.2,
                entry.2 / fast.2,
                entry.1
            );
        }
    }

    Ok(())
}
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let (Some(model), Some(vocab)) = (args.get(1), args.get(2)) else {
        eprintln!("usage: perplexity <model.bxw1> <vocab.bxv1>");
        return ExitCode::FAILURE;
    };
    match run(model, vocab) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("perplexity: {message}");
            ExitCode::FAILURE
        }
    }
}
