//! The decoder-only transformer forward pass — P3-T6.
//!
//! The piece that turns validated weights and working kernels into tokens. It
//! composes `brainix_tensor`'s kernels — matmul, RMSNorm, softmax, RoPE,
//! SwiGLU — into the architecture BXW1 `arch_id = 1` describes: pre-norm RMSNorm,
//! rotary position embedding, grouped-query attention, SwiGLU feed-forward,
//! tied or untied output projection. Like the kernels it builds on, it is
//! architecture-neutral and host-testable: no hardware, no capability, no
//! syscall, no device, no allocator.
//!
//! # What this crate guarantees
//!
//! - `#![no_std]`, `#![forbid(unsafe_code)]`, and **zero allocation**. Every
//!   buffer — activations, scratch, key/value cache, logits — is caller-supplied
//!   or a fixed-size array (`INV-MEM`). [`workspace_floats`],
//!   [`session_cache_floats`] and [`sampler_scratch_floats`] are `const fn`s of
//!   the hyperparameters, so a deployment sizes every region at build time and a
//!   model that does not fit is a constant that does not fit.
//! - **Sessions cannot overlap.** A [`SessionCache`] is obtainable only from
//!   [`KeyValueArena::issue_session`], which cuts it out of the arena with
//!   `split_at_mut_checked`. Disjointness is the borrow checker's conclusion,
//!   not a convention (`INV-SERVE`). See [`cache`] for the full argument.
//! - **Shape agreement is established before anything is computed.** Every
//!   hyperparameter bound and every weight shape is checked once, at
//!   [`Model::new`]; every per-call bound is checked before the first
//!   arithmetic operation. A mismatch is an error in either direction, never a
//!   silent truncation.
//! - **No panicking construct.** No `unwrap`, no `expect`, no `panic!`, no
//!   slice index that can be out of range, no `copy_from_slice`, no
//!   `split_at_mut`, and no unchecked integer arithmetic.
//! - **No model constant is compiled in.** The RoPE base, the RoPE pairing
//!   convention, the normalization epsilon, the head counts and the context
//!   length all arrive in [`ModelConfig`], which has no `Default`. BXW1 §5's
//!   opening sentence is that the transformer must run with no model constant
//!   compiled into it, and `rope_pairing` in particular is threaded from the
//!   header to every rotation (§5.5).
//! - **Scalar, no intrinsics.** There is no SIMD here, on purpose: P3-T0 has
//!   not landed and the context switch does not preserve vector state, so a NEON
//!   kernel today would be a correctness bug wearing a performance costume. The
//!   seams are named in [`attention`] and in `brainix_tensor`'s own
//!   documentation.
//!
//! # Correctness is the deliverable
//!
//! A transformer that is subtly wrong does not crash. It produces fluent,
//! confident, wrong text, and no unit test on any individual kernel detects it —
//! every kernel can be right while the composition is wrong. The tests are
//! therefore built around four whole-model properties rather than around
//! coverage:
//!
//! 1. **Logits parity** against an independent reference forward pass written
//!    for clarity in the test module, over a two-layer fixture whose dimensions
//!    make grouped-query attention, a partial RoPE rotation and the SwiGLU
//!    feed-forward all engage.
//! 2. **One pass equals many.** A prompt of `n` tokens in one call must produce
//!    the same logits as those `n` tokens fed one at a time through the
//!    incremental path — bit for bit, because it is the same arithmetic in the
//!    same order. This is the assertion that catches key/value indexing bugs.
//! 3. **Session isolation.** Two sessions with disjoint partitions, interleaved,
//!    must produce exactly the logits they produce alone. `INV-SERVE` as an
//!    executable test.
//! 4. **The pairing is load bearing.** The two `rope_pairing` conventions must
//!    produce *different* logits end to end, proving the header field is read
//!    rather than silently ignored.
//!
//! # Sizing a deployment
//!
//! ```
//! use brainix_tensor::RopePairing;
//! use brainix_transformer::{
//!     session_cache_floats, workspace_floats, sampler_scratch_floats, ModelConfig,
//! };
//!
//! const CONFIG: ModelConfig = ModelConfig {
//!     architecture_id: 1,
//!     layer_count: 2,
//!     model_width: 32,
//!     query_head_count: 4,
//!     key_value_head_count: 2,
//!     head_width: 8,
//!     feed_forward_width: 64,
//!     vocabulary_size: 48,
//!     maximum_sequence_length: 16,
//!     rope_theta: 1.0e4,
//!     normalization_epsilon: 1.0e-5,
//!     rope_dimensions: 4,
//!     rope_pairing: RopePairing::Interleaved,
//! };
//! const MAXIMUM_BATCH: usize = 8;
//! const SESSIONS: usize = 4;
//!
//! const WORKSPACE: usize = match workspace_floats(&CONFIG, MAXIMUM_BATCH) {
//!     Ok(floats) => floats,
//!     Err(_) => 0,
//! };
//! const CACHE: usize = match session_cache_floats(&CONFIG, SESSIONS) {
//!     Ok(floats) => floats,
//!     Err(_) => 0,
//! };
//! const SAMPLER: usize = match sampler_scratch_floats(CONFIG.vocabulary_size) {
//!     Ok(floats) => floats,
//!     Err(_) => 0,
//! };
//!
//! let mut workspace_storage = [0.0_f32; WORKSPACE];
//! let mut cache_storage = [0.0_f32; CACHE];
//! let mut sampler_storage = [0.0_f32; SAMPLER];
//! let mut logits = [0.0_f32; CONFIG.vocabulary_size];
//! assert!(WORKSPACE > 0 && CACHE > 0 && SAMPLER > 0);
//! ```
//!
//! # What is not here
//!
//! No batching across sessions, no continuous batching, no speculative decode,
//! no paged attention. Those trade client isolation or fixed memory for
//! throughput, and NORTH_STAR forbids both trades. No `Q8_0` token-embedding
//! table either — the kernel it needed now exists, and taking it up is a change
//! to this crate that has not been made; see [`weights`].

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(test)]
extern crate std;

pub mod attention;
pub mod cache;
mod config;
mod error;
mod forward;
mod math;
mod sampling;
mod slices;
pub mod weights;
mod workspace;

pub use crate::cache::{session_cache_floats, CacheGeometry, KeyValueArena, SessionCache};
pub mod dispatch;
pub use crate::config::ModelConfig;
pub use crate::dispatch::{Dispatch, Serial};
pub use crate::error::TransformerError;
pub use crate::forward::Model;
pub use crate::sampling::{
    sample, sampler_scratch_floats, Sampler, SamplingRequest, MAXIMUM_TOP_K,
};
pub use crate::weights::{LayerWeights, LogitProjection, ModelWeights, WeightMatrix};
pub use crate::workspace::{quantized_activation_bytes, workspace_floats, Workspace};
