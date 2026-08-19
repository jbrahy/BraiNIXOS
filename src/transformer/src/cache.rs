//! The key/value cache: one fixed region, partitioned per session, with
//! overlapping partitions unconstructible.
//!
//! # `INV-MEM`
//!
//! There is no allocator here and no growth path. [`KeyValueArena`] borrows one
//! caller-supplied `&mut [f32]` — a build-time-sized region — and hands out
//! disjoint sub-slices of it. [`session_cache_floats`] is a `const fn`, so the
//! region is sized at build time from the hyperparameters and the session
//! ceiling, and a model that would not fit is a compile-time constant that does
//! not fit rather than a runtime allocation that fails.
//!
//! # `INV-SERVE`, and why overlap is hard to construct rather than merely
//! documented
//!
//! Two sessions sharing key/value storage is not a performance bug; it is one
//! client reading another's context. The API is shaped so that arranging it
//! takes deliberate effort:
//!
//! 1. [`SessionCache`] has **no public constructor**. The only way to obtain
//!    one is [`KeyValueArena::issue_session`].
//! 2. `issue_session` splits the arena's remaining storage with
//!    `split_at_mut_checked` and keeps the tail. The disjointness is therefore
//!    the borrow checker's own conclusion, not a comment: the returned
//!    `&'a mut [f32]` and the arena's retained `&'a mut [f32]` are provably
//!    non-overlapping, and every later session comes out of the retained tail.
//! 3. The arena itself borrows the region mutably, so two arenas over
//!    overlapping memory would need two overlapping `&mut` — which safe Rust
//!    does not admit, and this crate is `#![forbid(unsafe_code)]`.
//!
//! Together those close the loop: **there is no safe program in which two
//! `SessionCache` values address the same float.**
//!
//! # Layout inside a partition
//!
//! ```text
//! [layer 0 keys   ][layer 0 values ][layer 1 keys   ][layer 1 values ]…
//!  max_seq_len ×    max_seq_len ×
//!  kv_width         kv_width
//! ```
//!
//! Keys and values for one layer are adjacent, and one position's row is
//! contiguous across all `n_kv_heads` heads. Attention reads a strided
//! selection of that plane — one head's `d_head` window per position — which is
//! the access pattern grouped-query attention has regardless of layout, since
//! `n_heads / n_kv_heads` query heads read the same window.

use crate::config::{checked_product, scale, ModelConfig};
use crate::error::TransformerError;
use crate::slices::copy_into;

/// Planes per layer: keys and values.
const PLANES_PER_LAYER: usize = 2;

/// Plane index of the keys.
const KEY_PLANE: usize = 0;

/// Plane index of the values.
const VALUE_PLANE: usize = 1;

/// The extents a session cache is shaped by.
///
/// Carried by both the arena and every session it issues, and compared for
/// equality before a forward pass touches either. That comparison is what stops
/// model A's cache from being handed to model B — a mismatch that does not
/// crash, it just serves plausible nonsense.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheGeometry {
    /// BXW1 `n_layers`.
    pub layer_count: usize,
    /// BXW1 `max_seq_len` — the fixed context capacity of one session.
    pub maximum_sequence_length: usize,
    /// `n_kv_heads × d_head` — the width of one cached row.
    pub key_value_width: usize,
}

impl CacheGeometry {
    /// The geometry `config` implies.
    ///
    /// # Errors
    ///
    /// [`TransformerError::DimensionOverflow`].
    pub const fn for_config(config: &ModelConfig) -> Result<Self, TransformerError> {
        match config.key_value_width() {
            Ok(key_value_width) => Ok(Self {
                layer_count: config.layer_count,
                maximum_sequence_length: config.maximum_sequence_length,
                key_value_width,
            }),
            // COVERAGE-EXEMPT: propagates key_value_width()'s refusal, which ModelConfig::validate has already ruled out before any CacheGeometry is built.
            Err(error) => Err(error),
        }
    }

    /// Floats one session's partition occupies:
    /// `n_layers × 2 × max_seq_len × kv_width`.
    ///
    /// # Errors
    ///
    /// [`TransformerError::DimensionOverflow`].
    pub const fn floats_per_session(&self) -> Result<usize, TransformerError> {
        let planes = checked_product(self.layer_count, PLANES_PER_LAYER);
        let positions = scale(planes, self.maximum_sequence_length);
        scale(positions, self.key_value_width)
    }

    /// Floats one plane — keys or values for one layer — occupies.
    const fn floats_per_plane(&self) -> Result<usize, TransformerError> {
        checked_product(self.maximum_sequence_length, self.key_value_width)
    }
}

/// Floats a caller must reserve for `session_count` sessions of `config`.
///
/// A `const fn`, so a serving build states its own ceiling:
///
/// ```
/// # use brainix_transformer::{session_cache_floats, ModelConfig};
/// # use brainix_tensor::RopePairing;
/// const CONFIG: ModelConfig = ModelConfig {
///     architecture_id: 1,
///     layer_count: 2, model_width: 32, query_head_count: 4,
///     key_value_head_count: 2, head_width: 8, feed_forward_width: 64,
///     vocabulary_size: 48, maximum_sequence_length: 16,
///     rope_theta: 1.0e4, normalization_epsilon: 1.0e-5,
///     rope_dimensions: 4, rope_pairing: RopePairing::Interleaved,
/// };
/// const SESSIONS: usize = 4;
/// const FLOATS: usize = match session_cache_floats(&CONFIG, SESSIONS) {
///     Ok(floats) => floats,
///     Err(_) => 0,
/// };
/// // n_layers × 2 planes × max_seq_len × (n_kv_heads × d_head) × sessions
/// assert_eq!(FLOATS, 2 * 2 * 16 * 16 * SESSIONS);
/// let mut region = [0.0_f32; FLOATS];
/// ```
///
/// # Errors
///
/// [`TransformerError::DimensionOverflow`].
pub const fn session_cache_floats(
    config: &ModelConfig,
    session_count: usize,
) -> Result<usize, TransformerError> {
    match CacheGeometry::for_config(config) {
        Ok(geometry) => scale(geometry.floats_per_session(), session_count),
        // COVERAGE-EXEMPT: propagates a const-fn size refusal that ModelConfig::validate has already ruled out at runtime.
        Err(error) => Err(error),
    }
}

/// The one fixed key/value region, handed out one session partition at a time.
///
/// Holds no buffer of its own: it borrows the region and tracks what is left.
#[derive(Debug)]
pub struct KeyValueArena<'a> {
    /// The part of the region not yet issued to a session.
    remaining: &'a mut [f32],
    geometry: CacheGeometry,
}

impl<'a> KeyValueArena<'a> {
    /// Borrows a region and prepares to partition it.
    ///
    /// `storage` need not be an exact multiple of the per-session size; the
    /// remainder is simply never issued. A region too small for even one
    /// session is accepted here and refused by the first
    /// [`Self::issue_session`], so "how many sessions fit" is answered by
    /// [`Self::sessions_remaining`] rather than by a constructor that has to
    /// guess what the caller meant.
    ///
    /// # Errors
    ///
    /// [`TransformerError::ZeroDimension`] if any extent of `geometry` is zero,
    /// or [`TransformerError::DimensionOverflow`].
    pub fn new(storage: &'a mut [f32], geometry: CacheGeometry) -> Result<Self, TransformerError> {
        if geometry.layer_count == 0
            || geometry.maximum_sequence_length == 0
            || geometry.key_value_width == 0
        {
            return Err(TransformerError::ZeroDimension);
        }
        geometry.floats_per_session()?;
        Ok(Self {
            remaining: storage,
            geometry,
        })
    }

    /// Sessions the arena can still issue.
    ///
    /// # Errors
    ///
    /// [`TransformerError::DimensionOverflow`].
    pub fn sessions_remaining(&self) -> Result<usize, TransformerError> {
        let per_session = self.geometry.floats_per_session()?;
        self.remaining
            .len()
            .checked_div(per_session)
            .ok_or(TransformerError::ZeroDimension)
    }

    /// Splits off one session's partition.
    ///
    /// The returned cache addresses storage the arena has permanently given
    /// up, and every subsequent session comes out of what is left. **This is
    /// the `INV-SERVE` boundary**, and `split_at_mut_checked` is what enforces
    /// it — not this paragraph.
    ///
    /// # Errors
    ///
    /// [`TransformerError::SessionArenaExhausted`] when the remainder is
    /// shorter than one partition.
    pub fn issue_session(&mut self) -> Result<SessionCache<'a>, TransformerError> {
        let per_session = self.geometry.floats_per_session()?;
        if self.remaining.len() < per_session {
            return Err(TransformerError::SessionArenaExhausted);
        }
        let storage = core::mem::take(&mut self.remaining);
        let (partition, rest) = storage
            .split_at_mut_checked(per_session)
            .ok_or(TransformerError::SessionArenaExhausted)?;
        self.remaining = rest;
        Ok(SessionCache::new(partition, self.geometry))
    }
}

/// One client's key/value context: a fixed partition plus the number of
/// positions committed to it.
///
/// **Constructible only through [`KeyValueArena::issue_session`].** That is the
/// whole of the isolation argument at the type level; see the module
/// documentation for the rest.
#[derive(Debug)]
pub struct SessionCache<'a> {
    storage: &'a mut [f32],
    geometry: CacheGeometry,
    /// Positions already committed. Never advanced by a call that failed.
    position: usize,
}

impl<'a> SessionCache<'a> {
    /// Private on purpose: see the module documentation.
    fn new(storage: &'a mut [f32], geometry: CacheGeometry) -> Self {
        Self {
            storage,
            geometry,
            position: 0,
        }
    }

    /// The geometry this partition was cut for.
    #[must_use]
    pub const fn geometry(&self) -> CacheGeometry {
        self.geometry
    }

    /// Positions committed so far — the absolute position the next token gets.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.position
    }

    /// Drops the session's context without releasing its storage.
    ///
    /// The stale floats are not zeroed, because they are unreachable: every
    /// read is bounded by [`Self::position`], which is now zero, and every
    /// position is overwritten before it is read. Zeroing
    /// `n_layers × 2 × max_seq_len × kv_width` floats to establish a property
    /// the bound already establishes would be the most expensive no-op in the
    /// serving path.
    pub fn reset(&mut self) {
        self.position = 0;
    }

    /// The position `count` more tokens would leave the session at, refusing if
    /// that is past the fixed context capacity.
    ///
    /// Called before anything is computed, and again — as the same function —
    /// to commit, so the admission check and the update cannot drift apart.
    pub(crate) fn position_after(&self, count: usize) -> Result<usize, TransformerError> {
        let advanced = self
            .position
            .checked_add(count)
            .ok_or(TransformerError::DimensionOverflow)?;
        if advanced > self.geometry.maximum_sequence_length {
            return Err(TransformerError::ContextExhausted);
        }
        Ok(advanced)
    }

    /// Commits `count` positions. Crate-internal so only the forward pass can
    /// move a session's clock, and called only after that pass has succeeded.
    pub(crate) fn commit(&mut self, count: usize) -> Result<(), TransformerError> {
        self.position = self.position_after(count)?;
        Ok(())
    }

    /// Byte-free offset of one plane's first float.
    fn plane_offset(&self, layer: usize, plane: usize) -> Result<usize, TransformerError> {
        let planes = checked_product(layer, PLANES_PER_LAYER)?;
        let index = planes
            .checked_add(plane)
            .ok_or(TransformerError::DimensionOverflow)?;
        checked_product(index, self.geometry.floats_per_plane()?)
    }

    /// One plane of one layer, `[max_seq_len, kv_width]` row-major.
    fn plane(&self, layer: usize, plane: usize) -> Result<&[f32], TransformerError> {
        let start = self.plane_offset(layer, plane)?;
        let end = start
            .checked_add(self.geometry.floats_per_plane()?)
            .ok_or(TransformerError::DimensionOverflow)?;
        self.storage
            .get(start..end)
            .ok_or(TransformerError::CacheGeometryMismatch)
    }

    /// The keys of one layer, `[max_seq_len, kv_width]`.
    pub(crate) fn keys(&self, layer: usize) -> Result<&[f32], TransformerError> {
        self.plane(layer, KEY_PLANE)
    }

    /// The values of one layer, `[max_seq_len, kv_width]`.
    pub(crate) fn values(&self, layer: usize) -> Result<&[f32], TransformerError> {
        self.plane(layer, VALUE_PLANE)
    }

    /// The `kv_width` slot one position of one plane occupies.
    fn slot(
        &mut self,
        layer: usize,
        plane: usize,
        position: usize,
    ) -> Result<&mut [f32], TransformerError> {
        let base = self.plane_offset(layer, plane)?;
        let within = checked_product(position, self.geometry.key_value_width)?;
        let start = base
            .checked_add(within)
            .ok_or(TransformerError::DimensionOverflow)?;
        let end = start
            .checked_add(self.geometry.key_value_width)
            .ok_or(TransformerError::DimensionOverflow)?;
        self.storage
            .get_mut(start..end)
            .ok_or(TransformerError::ContextExhausted)
    }

    /// Writes one token's rotated key and its value at `position`.
    ///
    /// Both rows are `kv_width` wide. The lengths are checked rather than
    /// copied with `copy_from_slice`, which panics on disagreement.
    pub(crate) fn store(
        &mut self,
        layer: usize,
        position: usize,
        key: &[f32],
        value: &[f32],
    ) -> Result<(), TransformerError> {
        if key.len() != self.geometry.key_value_width
            || value.len() != self.geometry.key_value_width
        {
            return Err(TransformerError::WeightShapeMismatch);
        }
        copy_into(key, self.slot(layer, KEY_PLANE, position)?);
        copy_into(value, self.slot(layer, VALUE_PLANE, position)?);
        Ok(())
    }
}

/// `store` against a row of the wrong width.
///
/// # The reason this was exempt described a different check
///
/// The note read: *"the logit matrix's shape is validated by
/// `ModelWeights::validate_global` before a Model exists, so this second check
/// cannot fail on a constructed model."* This function stores a key and a value
/// into the KV cache and compares their widths against the cache geometry. The
/// logit matrix is not involved, and `validate_global` does not check this.
///
/// The reason was copy-pasted from a genuine exemption elsewhere. It was
/// plausible enough to survive review precisely because it was true SOMEWHERE,
/// which is the failure mode a boilerplate justification has.
///
/// The real argument is narrower and is now written where it belongs: callers
/// pass rows sized from the same `ModelConfig` that sized the geometry. And it
/// is reachable from inside the crate, so it need not be argued at all.
#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::{CacheGeometry, KeyValueArena};
    use crate::error::TransformerError;

    const GEOMETRY: CacheGeometry = CacheGeometry {
        layer_count: 2,
        maximum_sequence_length: 4,
        key_value_width: 8,
    };

    #[test]
    fn a_row_of_the_wrong_width_is_refused_rather_than_panicking() {
        let mut storage = [0.0_f32; 4096];
        let mut arena = KeyValueArena::new(&mut storage, GEOMETRY).expect("geometry");
        let mut session = arena.issue_session().expect("one session");

        let correct = [1.0_f32; 8];
        let short = [1.0_f32; 7];
        let long = [1.0_f32; 9];

        // The doc says why this is a length check and not `copy_from_slice`:
        // that function panics on disagreement, and a panic here takes the
        // whole server down on a shape bug that a refusal would merely report.
        assert_eq!(
            session.store(0, 0, &short, &correct),
            Err(TransformerError::WeightShapeMismatch)
        );
        assert_eq!(
            session.store(0, 0, &correct, &long),
            Err(TransformerError::WeightShapeMismatch)
        );
        assert_eq!(
            session.store(0, 0, &short, &short),
            Err(TransformerError::WeightShapeMismatch)
        );

        // Both correct is accepted, so the test above is not passing because
        // `store` refuses everything.
        assert_eq!(session.store(0, 0, &correct, &correct), Ok(()));
    }

    #[test]
    fn an_empty_row_is_refused_too() {
        // Zero is the width a caller reaches by passing a slice it forgot to
        // fill, and it must not be read as "store nothing, successfully".
        let mut storage = [0.0_f32; 4096];
        let mut arena = KeyValueArena::new(&mut storage, GEOMETRY).expect("geometry");
        let mut session = arena.issue_session().expect("one session");
        assert_eq!(
            session.store(0, 0, &[], &[]),
            Err(TransformerError::WeightShapeMismatch)
        );
    }
}
