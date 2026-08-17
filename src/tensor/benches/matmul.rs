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
    matmul_q8_0, matmul_q8_0_q8a, matmul_q8_0_q8a_rows, quantize_activations, MatMulShape,
    Q8Weights, Q8_0_BLOCK,
};
use std::time::Instant;
use std::thread;

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
    let shape = MatMulShape { n_tokens, n_in, n_out };
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
    let shape = MatMulShape { n_tokens, n_in, n_out };
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
                        let view =
                            Q8Weights::new(&scratch, n_tokens, n_in).expect("view");
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
    let shape = MatMulShape { n_tokens: 1, n_in, n_out };
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
                            shape, weights, quantized, index * per, chunk.len(), chunk,
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

fn main() {
    println!();
    println!("  matmul_q8_0 — weight-byte throughput, single core");
    println!("  reference bus: {REFERENCE_BANDWIDTH_GB_S:.0} GB/s (M2 Pro, vendor figure, not measured)");
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
    println!("  Interpretation:");
    println!("    absolute GB/s near the bus     -> bandwidth-bound");
    println!("    absolute GB/s far below        -> compute-bound");
    println!("    8-token row ~= 1-token row     -> bandwidth-bound (weights read once, dominate)");
    println!("    8-token row ~= 1/8 of 1-token  -> compute-bound (time tracks FLOPs, not bytes)");
    println!();
}
