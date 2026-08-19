//! The project's first performance measurement.
//!
//! # Why this exists, and why it reports GB/s rather than wall time
//!
//! `NORTH_STAR.md` states that inference on the reference machine is
//! memory-bandwidth-bound, and every priority in the tree descends from that
//! claim. As of 2026-08-17 the claim had never been checked: this repository
//! contained zero benchmarks over its own code, and the owner had just promoted
//! performance above the security invariants — a ranking under which every trade
//! requires a *measured* win.
//!
//! The number that settles it is **GB/s of weight bytes**, because that is
//! directly comparable against the machine's memory bandwidth (~200 GB/s on an
//! M2 Pro). Wall time is not comparable to anything.
//!
//! - If the kernel achieves a figure near the bus, the system is
//!   bandwidth-bound, the north star's arithmetic holds, and the remaining
//!   lever is quantization.
//! - If it achieves far less, the system is **compute-bound**, "bytes moved
//!   dominate" describes a regime the code has not reached, and the binding
//!   constraint is instruction throughput — which means NEON, not quantization.
//!
//! # Why no benchmark framework
//!
//! `criterion` is an external crate, and NORTH_STAR's dependency-closure rule
//! says the standing job is to remove the ones already vendored, not add more.
//! A dev-dependency is still a dependency. What this measurement needs —
//! elapsed time over a loop long enough to swamp timer granularity — is a few
//! lines of `std::time::Instant`, so the rule costs nothing here and is kept.
//!
//! # Running it
//!
//! ```sh
//! cargo run --release --bench matmul --target aarch64-apple-darwin
//! ```
//!
//! **Release is not optional.** A debug build measures the optimiser's absence,
//! not the kernel.
//!
//! # What this measurement is not
//!
//! It is a **single-core, single-kernel** figure on the development workstation,
//! which is aarch64 but is not the reference machine. It bounds what one core
//! can feed the bus; it does not predict end-to-end tokens per second, and the
//! workstation's memory system is not the Mac mini's. Both machines are aarch64,
//! so the instruction-throughput conclusion transfers; the bandwidth conclusion
//! does not, and must be re-measured on the target.

use brainix_tensor::{
    matmul_q4_0_q8a, matmul_q8_0, matmul_q8_0_q8a, matmul_q8_0_q8a_rows, quantize_activations,
    quantize_q4_0, rmsnorm, rope, softmax, swiglu, MatMulShape, Q4Weights, Q8Weights, RopePairing,
    RopeParams, Q8_0_BLOCK,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Barrier;
use std::thread;
use std::time::Instant;

/// Bytes a `Q8_0` weight element costs: one quant byte plus 4/32 of a scale.
const BYTES_PER_WEIGHT_ELEMENT: f64 = 1.125;

/// Approximate unified-memory bandwidth of the reference machine, in GB/s.
///
/// Vendor figure for the M2 Pro, used only to express the result as a fraction
/// of the ceiling. It is not measured here and is labelled as vendor-supplied
/// wherever it is printed.
const REFERENCE_BANDWIDTH_GB_S: f64 = 200.0;

/// Builds a deterministic `Q8_0` payload of the given shape.
///
/// The values matter only in that they must not be uniform: a constant quant
/// plane would let the compiler or the hardware prefetcher behave differently
/// than it will on real weights. They are otherwise arbitrary and the benchmark
/// makes no claim about the numerical result.
fn synthetic_payload(n_out: usize, n_in: usize) -> Vec<u8> {
    let len = Q8Weights::derived_payload_len(n_out, n_in).expect("shape is valid");
    let mut payload = vec![0u8; len];
    let n_blocks = n_out * (n_in / Q8_0_BLOCK);
    let scale_plane_len = len - n_blocks * Q8_0_BLOCK;

    // Scale plane: a small positive binary32 per block, varied so the values
    // are not all identical.
    for (index, chunk) in payload[..scale_plane_len].chunks_exact_mut(4).enumerate() {
        let scale = 0.01_f32 + (index % 17) as f32 * 0.001;
        chunk.copy_from_slice(&scale.to_le_bytes());
    }
    // Quant plane: a repeating non-uniform pattern.
    for (index, byte) in payload[scale_plane_len..].iter_mut().enumerate() {
        *byte = ((index % 251) as i32 - 125) as i8 as u8;
    }
    payload
}

/// Times `matmul_q8_0` over one shape and prints the achieved bandwidth.
fn measure(label: &str, n_tokens: usize, n_in: usize, n_out: usize) {
    let payload = synthetic_payload(n_out, n_in);
    let weights = Q8Weights::new(&payload, n_out, n_in).expect("payload is well formed");
    let shape = MatMulShape {
        n_tokens,
        n_in,
        n_out,
    };
    let x = vec![0.5_f32; n_tokens * n_in];
    let mut y = vec![0.0_f32; n_tokens * n_out];

    let weight_bytes = n_out as f64 * n_in as f64 * BYTES_PER_WEIGHT_ELEMENT;

    // One untimed call. The first pass pays for cold caches and first-touch
    // page faults on the freshly allocated payload, neither of which is what is
    // being measured.
    matmul_q8_0(shape, &weights, &x, &mut y).expect("matmul succeeds");

    // Enough iterations that the run is long relative to timer granularity,
    // scaled so a large matrix does not run for minutes.
    let iterations = (2_000_000_000.0 / weight_bytes).max(3.0) as usize;

    let start = Instant::now();
    for _ in 0..iterations {
        matmul_q8_0(shape, &weights, &x, &mut y).expect("matmul succeeds");
    }
    let elapsed = start.elapsed();

    // Read the output so the loop cannot be optimised away entirely. `y` is
    // written by every iteration, so a compiler that elided the calls would
    // have to prove the writes dead, and this use prevents that.
    std::hint::black_box(&y);

    let seconds = elapsed.as_secs_f64();
    let total_bytes = weight_bytes * iterations as f64;
    let gb_per_second = total_bytes / seconds / 1e9;
    let percent_of_bus = gb_per_second / REFERENCE_BANDWIDTH_GB_S * 100.0;

    println!(
        "  {label:<28} {gb_per_second:7.2} GB/s   {percent_of_bus:5.1}% of bus   \
         ({iterations} iters, {seconds:.2} s, {:.1} MB/call)",
        weight_bytes / 1e6
    );
}

/// Times `matmul_q8_0_q8a`, activation quantization included.
///
/// The quantization is inside the timed region on purpose: it is work the
/// f32-activation path does not do, and excluding it would flatter the
/// comparison. It is amortized -- `n_in` elements quantized once against
/// `n_out x n_in` multiply-accumulates -- so it should barely register, and if
/// it does register that is a finding rather than a nuisance.
fn measure_sdot(label: &str, n_tokens: usize, n_in: usize, n_out: usize) {
    let payload = synthetic_payload(n_out, n_in);
    let weights = Q8Weights::new(&payload, n_out, n_in).expect("payload is well formed");
    let shape = MatMulShape {
        n_tokens,
        n_in,
        n_out,
    };
    let x = vec![0.5_f32; n_tokens * n_in];
    let mut y = vec![0.0_f32; n_tokens * n_out];
    let mut scratch =
        vec![0u8; Q8Weights::derived_payload_len(n_tokens, n_in).expect("activation len")];

    let weight_bytes = n_out as f64 * n_in as f64 * BYTES_PER_WEIGHT_ELEMENT;

    quantize_activations(n_tokens, n_in, &x, &mut scratch).expect("quantize");
    {
        let view = Q8Weights::new(&scratch, n_tokens, n_in).expect("view");
        matmul_q8_0_q8a(shape, &weights, &view, &mut y).expect("warm up");
    }

    let iterations = (2_000_000_000.0 / weight_bytes).max(3.0) as usize;
    let start = Instant::now();
    for _ in 0..iterations {
        quantize_activations(n_tokens, n_in, &x, &mut scratch).expect("quantize");
        let view = Q8Weights::new(&scratch, n_tokens, n_in).expect("view");
        matmul_q8_0_q8a(shape, &weights, &view, &mut y).expect("matmul");
    }
    let elapsed = start.elapsed();
    std::hint::black_box(&y);

    let seconds = elapsed.as_secs_f64();
    let gb_per_second = weight_bytes * iterations as f64 / seconds / 1e9;
    println!(
        "  {label:<28} {gb_per_second:7.2} GB/s   {:5.1}% of bus   ({iterations} iters, {seconds:.2} s)",
        gb_per_second / REFERENCE_BANDWIDTH_GB_S * 100.0
    );
}

/// Aggregate weight-byte throughput with `threads` cores running the same
/// matmul over the **same** weights.
///
/// # What this measures and why it is the shape that matters
///
/// Single-core throughput bounds one core. It says nothing about whether N
/// cores get N times as much, because they share one memory bus -- and on this
/// machine the bus is the thing everything is eventually bounded by. Sharing
/// one weight matrix across all threads is the realistic case: a server serving
/// one model streams the same weights on every core.
///
/// The number to watch is not the aggregate but its **shape**. Linear growth
/// means cores are still cheap and the bus has headroom. A knee means the bus
/// is saturated and further cores buy nothing -- which is also the answer to
/// whether spare cores exist for anything else, and therefore to how much
/// isolation in the scheduler costs.
fn measure_scaling(n_tokens: usize, n_in: usize, n_out: usize) {
    let payload = synthetic_payload(n_out, n_in);
    let weights = Q8Weights::new(&payload, n_out, n_in).expect("payload is well formed");
    let shape = MatMulShape {
        n_tokens,
        n_in,
        n_out,
    };
    let x = vec![0.5_f32; n_tokens * n_in];
    let weight_bytes = n_out as f64 * n_in as f64 * BYTES_PER_WEIGHT_ELEMENT;
    let iterations = (1_000_000_000.0 / weight_bytes).max(3.0) as usize;

    let mut single = 0.0f64;
    for threads in [1usize, 2, 4, 6, 8] {
        let start = Instant::now();
        thread::scope(|scope| {
            for _ in 0..threads {
                scope.spawn(|| {
                    let mut y = vec![0.0_f32; n_tokens * n_out];
                    let mut scratch = vec![
                        0u8;
                        Q8Weights::derived_payload_len(n_tokens, n_in)
                            .expect("activation len")
                    ];
                    for _ in 0..iterations {
                        quantize_activations(n_tokens, n_in, &x, &mut scratch).expect("quantize");
                        let view = Q8Weights::new(&scratch, n_tokens, n_in).expect("view");
                        matmul_q8_0_q8a(shape, &weights, &view, &mut y).expect("matmul");
                    }
                    std::hint::black_box(&y);
                });
            }
        });
        let seconds = start.elapsed().as_secs_f64();
        let aggregate = weight_bytes * iterations as f64 * threads as f64 / seconds / 1e9;
        if threads == 1 {
            single = aggregate;
        }
        println!(
            "  {threads} thread{}   {aggregate:7.2} GB/s   {:5.1}% of bus   {:.2}x vs 1 core",
            if threads == 1 { " " } else { "s" },
            aggregate / REFERENCE_BANDWIDTH_GB_S * 100.0,
            aggregate / single
        );
    }
}

/// Workers splitting the output rows of **one** matmul.
///
/// # Why this differs from `measure_scaling`, and which one decode cares about
///
/// `measure_scaling` runs N independent matmuls at once and reports aggregate
/// bandwidth -- a throughput figure, right for many concurrent clients. Decode
/// is the opposite shape: **one** token at a time, and the question is whether a
/// single matmul finishes N times sooner when N cores share it. That is latency
/// parallelism, and it pays for a barrier at the end of every projection that
/// the throughput measurement never pays.
///
/// A real forward pass has hundreds of these barriers per token -- seven
/// projections per layer, twenty-four layers -- so the per-call overhead here is
/// the thing that decides whether a multi-core decode is worth building.
fn measure_row_split(label: &str, n_in: usize, n_out: usize) {
    let payload = synthetic_payload(n_out, n_in);
    let weights = Q8Weights::new(&payload, n_out, n_in).expect("payload is well formed");
    let shape = MatMulShape {
        n_tokens: 1,
        n_in,
        n_out,
    };
    let x = vec![0.5_f32; n_in];
    let mut scratch = vec![0u8; Q8Weights::derived_payload_len(1, n_in).expect("len")];
    quantize_activations(1, n_in, &x, &mut scratch).expect("quantize");
    let quantized = Q8Weights::new(&scratch, 1, n_in).expect("view");

    let weight_bytes = n_out as f64 * n_in as f64 * BYTES_PER_WEIGHT_ELEMENT;
    let iterations = (500_000_000.0 / weight_bytes).max(20.0) as usize;
    println!("  {label}");

    let mut single = 0.0f64;
    for workers in [1usize, 2, 4, 6] {
        let per = n_out / workers;
        let mut y = vec![0.0_f32; n_out];
        let start = Instant::now();
        for _ in 0..iterations {
            thread::scope(|scope| {
                for (index, chunk) in y.chunks_mut(per).enumerate() {
                    let weights = &weights;
                    let quantized = &quantized;
                    scope.spawn(move || {
                        matmul_q8_0_q8a_rows(
                            shape,
                            weights,
                            quantized,
                            index * per,
                            chunk.len(),
                            chunk,
                        )
                        .expect("range matmul");
                    });
                }
            });
        }
        let seconds = start.elapsed().as_secs_f64();
        std::hint::black_box(&y);
        let gb = weight_bytes * iterations as f64 / seconds / 1e9;
        if workers == 1 {
            single = gb;
        }
        println!(
            "    {workers} worker{}  {gb:7.2} GB/s   {:.2}x   ({:.1} us/call)",
            if workers == 1 { " " } else { "s" },
            gb / single,
            seconds / iterations as f64 * 1e6
        );
    }
}

/// Row-split across a **persistent** worker pool.
///
/// # What this isolates
///
/// [`measure_row_split`] spawns threads inside the timed loop, so its figure is
/// (useful work + thread creation) and its six-worker regression is creation
/// cost overtaking the work. A kernel cannot pay that: a decode performs 168
/// projections per token against a 12.2 ms budget, and four spawns per
/// projection at 10-20 us costs 6.7-13.4 ms of that budget on thread creation
/// alone.
///
/// So the workers here are spawned **once** and park on a barrier. Waking a
/// parked thread is what a real implementation pays -- an IPI on the target --
/// and the gap between this measurement and the previous one is the cost of
/// getting that wrong.
///
/// # Why each worker owns its output
///
/// Handing every worker a disjoint `&mut` sub-slice of one buffer is what
/// `chunks_mut` does inside a `scope`, and it does not survive the workers
/// outliving the call. Each worker owning its rows sidesteps the lifetime
/// problem entirely and costs one 16 KB copy per projection -- about 0.4% of a
/// token budget, measured rather than waved at.
fn measure_pool(label: &str, n_in: usize, n_out: usize) {
    let payload = synthetic_payload(n_out, n_in);
    let weights = Q8Weights::new(&payload, n_out, n_in).expect("payload is well formed");
    let shape = MatMulShape {
        n_tokens: 1,
        n_in,
        n_out,
    };
    let x = vec![0.5_f32; n_in];
    let mut scratch = vec![0u8; Q8Weights::derived_payload_len(1, n_in).expect("len")];
    quantize_activations(1, n_in, &x, &mut scratch).expect("quantize");
    let quantized = Q8Weights::new(&scratch, 1, n_in).expect("view");

    let weight_bytes = n_out as f64 * n_in as f64 * BYTES_PER_WEIGHT_ELEMENT;
    let iterations = (500_000_000.0 / weight_bytes).max(20.0) as usize;
    println!("  {label}");

    let mut single = 0.0f64;
    for workers in [1usize, 2, 4, 6] {
        let per = n_out / workers;
        let mut outputs: Vec<Vec<f32>> = (0..workers).map(|_| vec![0.0_f32; per]).collect();
        let start_gate = Barrier::new(workers + 1);
        let finish_gate = Barrier::new(workers + 1);
        let shutting_down = AtomicBool::new(false);
        let mut seconds = 0.0f64;

        thread::scope(|scope| {
            for (index, output) in outputs.iter_mut().enumerate() {
                let (weights, quantized) = (&weights, &quantized);
                let (start_gate, finish_gate, shutting_down) =
                    (&start_gate, &finish_gate, &shutting_down);
                scope.spawn(move || loop {
                    start_gate.wait();
                    if shutting_down.load(Ordering::Acquire) {
                        break;
                    }
                    matmul_q8_0_q8a_rows(
                        shape,
                        weights,
                        quantized,
                        index * per,
                        output.len(),
                        output,
                    )
                    .expect("range matmul");
                    finish_gate.wait();
                });
            }

            // One untimed round so the pool is warm and every worker has
            // reached its park before the clock starts.
            start_gate.wait();
            finish_gate.wait();

            let began = Instant::now();
            for _ in 0..iterations {
                start_gate.wait();
                finish_gate.wait();
            }
            seconds = began.elapsed().as_secs_f64();

            // Release the workers to exit. They break before `finish_gate`, so
            // the main thread must not wait on it again.
            shutting_down.store(true, Ordering::Release);
            start_gate.wait();
        });

        std::hint::black_box(&outputs);
        let gb = weight_bytes * iterations as f64 / seconds / 1e9;
        if workers == 1 {
            single = gb;
        }
        println!(
            "    {workers} worker{}  {gb:7.2} GB/s   {:.2}x   ({:.1} us/call)",
            if workers == 1 { " " } else { "s" },
            gb / single,
            seconds / iterations as f64 * 1e6
        );
    }
}

/// Bytes a `Q4_0` weight element costs: half a nibble byte plus 4/32 of a scale.
const Q4_BYTES_PER_ELEMENT: f64 = 0.625;

/// `Q4_0` against `Q8_0` on identical shapes.
///
/// Reports **both** weight-byte throughput and time per call, because they
/// answer different questions and `Q4_0` can win one while losing the other.
/// GB/s is bytes moved per second, and `Q4_0` moves 1.8x fewer of them for the
/// same result -- so the honest comparison of *speed* is microseconds per call.
fn measure_q4(label: &str, n_in: usize, n_out: usize, threads: usize) {
    let q8_payload = synthetic_payload(n_out, n_in);
    let q8 = Q8Weights::new(&q8_payload, n_out, n_in).expect("q8");

    // Same underlying values in both formats, so the comparison is of encodings
    // rather than of two different matrices.
    let mut dense = vec![0.0f32; n_out * n_in];
    q8.dequantize_into(&mut dense).expect("dequantize");
    let mut q4_payload = vec![0u8; Q4Weights::derived_payload_len(n_out, n_in).expect("len")];
    quantize_q4_0(n_out, n_in, &dense, &mut q4_payload).expect("quantize q4");
    let q4 = Q4Weights::new(&q4_payload, n_out, n_in).expect("q4");

    let shape = MatMulShape {
        n_tokens: 1,
        n_in,
        n_out,
    };
    let x = vec![0.5_f32; n_in];
    let mut scratch = vec![0u8; Q8Weights::derived_payload_len(1, n_in).expect("len")];
    quantize_activations(1, n_in, &x, &mut scratch).expect("quantize");
    let activations = Q8Weights::new(&scratch, 1, n_in).expect("view");
    let mut y = vec![0.0_f32; n_out];

    let q8_bytes = n_out as f64 * n_in as f64 * BYTES_PER_WEIGHT_ELEMENT;
    let q4_bytes = n_out as f64 * n_in as f64 * Q4_BYTES_PER_ELEMENT;
    let iterations = (500_000_000.0 / q8_bytes).max(20.0) as usize;

    let _ = &mut y;
    let began = Instant::now();
    thread::scope(|scope| {
        for _ in 0..threads {
            let (q8, activations) = (&q8, &activations);
            scope.spawn(move || {
                let mut y = vec![0.0_f32; n_out];
                for _ in 0..iterations {
                    matmul_q8_0_q8a(shape, q8, activations, &mut y).expect("q8");
                }
                std::hint::black_box(&y);
            });
        }
    });
    let q8_seconds = began.elapsed().as_secs_f64();

    let began = Instant::now();
    thread::scope(|scope| {
        for _ in 0..threads {
            let (q4, activations) = (&q4, &activations);
            scope.spawn(move || {
                let mut y = vec![0.0_f32; n_out];
                for _ in 0..iterations {
                    matmul_q4_0_q8a(shape, q4, activations, &mut y).expect("q4");
                }
                std::hint::black_box(&y);
            });
        }
    });
    let q4_seconds = began.elapsed().as_secs_f64();

    println!("  {label}  [{threads} thread(s)]");
    println!(
        "    Q8_0  {:7.2} GB/s   {:8.1} us/call   ({:.1} MB)",
        q8_bytes * iterations as f64 * threads as f64 / q8_seconds / 1e9,
        q8_seconds / iterations as f64 * 1e6,
        q8_bytes / 1e6
    );
    println!(
        "    Q4_0  {:7.2} GB/s   {:8.1} us/call   ({:.1} MB)",
        q4_bytes * iterations as f64 * threads as f64 / q4_seconds / 1e9,
        q4_seconds / iterations as f64 * 1e6,
        q4_bytes / 1e6
    );
    println!(
        "    ---> Q4_0 moves 1.80x fewer bytes and is {:.2}x the speed",
        q8_seconds / q4_seconds
    );
}

/// Times `rope` at the shape a decode actually calls it with.
///
/// # Why this exists
///
/// It did not, and that is why nobody noticed what the rotation loop does. RoPE
/// runs once per layer per token for the query heads and again for the key
/// heads, and inside its per-pair loop it calls `powf` and `sin_cos` -- both
/// hand-written polynomial routines, because `core` has no libm.
///
/// `powf`'s argument depends only on `pair_index`. It is the same value for
/// every token, every layer and every head, recomputed every single call.
fn measure_rope(label: &str, heads: usize, d_head: usize, calls: usize) {
    let params = RopeParams {
        d_head,
        rope_dim: d_head,
        base: 10_000.0,
        pairing: RopePairing::HalfSplit,
        position: 1,
    };
    let x: Vec<f32> = (0..heads * d_head)
        .map(|i| ((i % 97) as f32 - 48.0) / 48.0)
        .collect();
    let mut out = vec![0.0_f32; x.len()];

    rope(&x, &params, &mut out).expect("warm up");

    let start = Instant::now();
    for call in 0..calls {
        let stepped = RopeParams {
            position: (call % 2048) as u32,
            ..params
        };
        rope(&x, &stepped, &mut out).expect("rope");
    }
    let elapsed = start.elapsed().as_secs_f64();

    // Rotations per second is the figure that matters: a decode does
    // layers x (query heads + key heads) of these per token.
    let rotations = (calls * heads * (d_head / 2)) as f64;
    println!(
        "  {label:<32} {:>8.2} M rot/s   ({:.2} us per call, {calls} calls)",
        rotations / elapsed / 1e6,
        elapsed / calls as f64 * 1e6,
    );
    std::hint::black_box(&out);
}

/// Times the non-matmul kernels a decode calls, at realistic widths.
///
/// # Why this is here
///
/// To answer one question with a number instead of an argument: does anything
/// besides the matmul matter? Four optimizations were proposed from reading
/// code today and three were refuted by measurement, two of them making things
/// slower. The cheapest way to stop doing that is to know the shares first.
///
/// Each is timed per DECODE TOKEN: a 32-layer model calls rmsnorm twice per
/// layer, swiglu once, and softmax once per head.
fn measure_elementwise(d_model: usize, d_ffn: usize, heads: usize, context: usize, layers: usize) {
    let x: Vec<f32> = (0..d_model).map(|i| (i % 23) as f32 * 0.05 - 0.5).collect();
    let weight: Vec<f32> = (0..d_model).map(|i| 1.0 + (i % 7) as f32 * 0.01).collect();
    let mut out = vec![0.0_f32; d_model];

    let reps = 2000;
    let start = Instant::now();
    for _ in 0..reps {
        rmsnorm(&x, &weight, 1.0e-5, &mut out).expect("rmsnorm");
    }
    let rms_each = start.elapsed().as_secs_f64() / reps as f64;
    std::hint::black_box(&out);

    let gate: Vec<f32> = (0..d_ffn).map(|i| (i % 19) as f32 * 0.1 - 0.9).collect();
    let up: Vec<f32> = (0..d_ffn).map(|i| (i % 13) as f32 * 0.1 - 0.6).collect();
    let mut ffn_out = vec![0.0_f32; d_ffn];
    let start = Instant::now();
    for _ in 0..reps {
        swiglu(&gate, &up, &mut ffn_out).expect("swiglu");
    }
    let swiglu_each = start.elapsed().as_secs_f64() / reps as f64;
    std::hint::black_box(&ffn_out);

    let scores: Vec<f32> = (0..context).map(|i| (i % 29) as f32 * 0.1 - 1.4).collect();
    let mut probabilities = vec![0.0_f32; context];
    let start = Instant::now();
    for _ in 0..reps {
        softmax(&scores, &mut probabilities).expect("softmax");
    }
    let softmax_each = start.elapsed().as_secs_f64() / reps as f64;
    std::hint::black_box(&probabilities);

    // Per token: rmsnorm twice a layer plus a final one, swiglu once a layer,
    // softmax once per head per layer.
    let rms_total = rms_each * (layers * 2 + 1) as f64;
    let swiglu_total = swiglu_each * layers as f64;
    let softmax_total = softmax_each * (layers * heads) as f64;
    let sum = rms_total + swiglu_total + softmax_total;

    println!("  d_model={d_model} d_ffn={d_ffn} heads={heads} context={context} layers={layers}");
    println!(
        "  rmsnorm   {:>9.3} ms/token   ({:.2} us each)",
        rms_total * 1e3,
        rms_each * 1e6
    );
    println!(
        "  swiglu    {:>9.3} ms/token   ({:.2} us each)",
        swiglu_total * 1e3,
        swiglu_each * 1e6
    );
    println!(
        "  softmax   {:>9.3} ms/token   ({:.2} us each)",
        softmax_total * 1e3,
        softmax_each * 1e6
    );
    println!("  ---------------------------");
    println!("  elementwise total {:>6.3} ms/token", sum * 1e3);
}

fn main() {
    println!();
    println!("  matmul_q8_0 — weight-byte throughput, single core");
    println!(
        "  reference bus: {REFERENCE_BANDWIDTH_GB_S:.0} GB/s (M2 Pro, vendor figure, not measured)"
    );
    println!();

    // Single-stream decode is n_tokens = 1 and is the case the north star's
    // ceiling arithmetic is about.
    //
    // The 8-token row is the **control experiment**, and it discriminates
    // between the two regimes far more sharply than the absolute figure does.
    // Weight bytes per call are identical at 1 and 8 tokens — the loop reads
    // each weight row once either way — while the arithmetic is 8x. So:
    //
    //   bandwidth-bound -> time is roughly FLAT as tokens rise, and the
    //                      weight-byte GB/s figure rises toward the bus
    //   compute-bound   -> time scales LINEARLY with tokens, and the
    //                      weight-byte GB/s figure falls by the same factor
    //
    // This distinction does not depend on knowing the machine's real bandwidth,
    // which makes it the trustworthy half of this benchmark: the vendor's
    // 200 GB/s is an unmeasured constant, but the ratio between these two rows
    // is measured.
    measure("4096x4096, 1 token", 1, 4096, 4096);
    measure("4096x4096, 8 tokens", 8, 4096, 4096);
    measure("4096x11008 (ffn), 1 token", 1, 4096, 11008);
    measure("2048x2048, 1 token", 1, 2048, 2048);

    println!();
    println!("  Q8_0 activations (SDOT path) — same weights, both operands i8");
    println!();
    measure_sdot("4096x4096, 1 token", 1, 4096, 4096);
    measure_sdot("4096x11008 (ffn), 1 token", 1, 4096, 11008);
    measure_sdot("2048x2048, 1 token", 1, 2048, 2048);

    println!();
    println!("  Multi-core scaling — same weights, SDOT path, 1 token");
    println!();
    // Two working sets, and the gap between them is the point.
    //
    // 18.9 MB may sit largely in the system-level cache, so threads sharing it
    // are not all reaching DRAM and the scaling flatters itself. 151 MB exceeds
    // any cache on a current Apple part, and a real decode streams ~460 MB per
    // token, so the larger figure is the representative one.
    println!("  [18.9 MB matrix -- may be substantially SLC-resident]");
    measure_scaling(1, 4096, 4096);
    println!();
    println!("  [151 MB matrix -- exceeds any cache, streams from DRAM]");
    measure_scaling(1, 4096, 32768);

    println!();
    println!("  Row-split within ONE matmul — the decode shape");
    println!();
    measure_row_split("4096x4096 (attention proj, 18.9 MB)", 4096, 4096);
    println!();
    measure_row_split("4096x11008 (ffn up, 50.7 MB)", 4096, 11008);

    println!();
    println!("  Persistent pool — workers parked on a barrier, spawned once");
    println!();
    measure_pool("4096x4096 (attention proj, 18.9 MB)", 4096, 4096);
    println!();
    measure_pool("4096x11008 (ffn up, 50.7 MB)", 4096, 11008);

    println!();
    println!("  Q4_0 vs Q8_0 — same values, single core");
    println!();
    for threads in [1usize, 4, 6] {
        measure_q4("4096x11008 (50.7 -> 28.2 MB)", 4096, 11008, threads);
        println!();
    }

    println!();
    println!("  Interpretation:");
    println!("    absolute GB/s near the bus     -> bandwidth-bound");
    println!("    absolute GB/s far below        -> compute-bound");
    println!("    8-token row ~= 1-token row     -> bandwidth-bound (weights read once, dominate)");
    println!("    8-token row ~= 1/8 of 1-token  -> compute-bound (time tracks FLOPs, not bytes)");
    println!();

    println!();
    println!("  RoPE — the rotation loop, never benchmarked until now");
    println!();
    measure_rope("12 heads x 64, 2000 calls", 12, 64, 2000);
    measure_rope("32 heads x 128, 500 calls", 32, 128, 500);
    println!();

    println!();
    println!("  Everything that is NOT a matmul, per decode token");
    println!();
    measure_elementwise(4096, 11008, 32, 2048, 32);
    println!();
}
