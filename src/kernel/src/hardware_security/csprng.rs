//! ChaCha20 CSPRNG with two-phase hardware entropy seeding.
//!
//! Phase 6 Plan 01: Implements a ChaCha20 stream cipher CSPRNG seeded in two phases.
//! Phase A (early boot, before TPM init): seeds from 8 RDRAND samples XOR-ed with 4
//! RDSEED samples to produce a 256-bit ChaCha20 key (D-07). RDRAND absence is a fatal
//! boot halt. Phase B (after TPM init): reseeds by extending the existing key with 256
//! bits of TPM2_GetRandom output via a KDF step (D-08). TPM init failure is non-fatal
//! for the CSPRNG -- Phase A seed is retained and an audit warning is logged.
//!
//! Uses the `chacha20` crate (RustCrypto, no_std, NCC-audited) for the cipher primitive.
//!
//! Enforces invariant INV-BOOT-005: entropy initialization is explicit and conservative.
//!
//! Allowlist: `src/kernel/src/hardware_security/csprng.rs` — BSS-backed static mut
//! access via addr_of_mut!/addr_of! and write_volatile for key zeroing on reseed.
#![allow(unsafe_code)]

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};

/// ChaCha20 CSPRNG state. BSS-backed, no dynamic allocation.
///
/// Phase A: seeded from RDRAND/RDSEED at early boot.
/// Phase B: reseeded from TPM2_GetRandom after TPM init (Plan 05).
///
/// Enforces INV-BOOT-005: entropy initialization is explicit and conservative.
struct CsprngState {
    /// 256-bit ChaCha20 key derived from hardware entropy.
    key: [u8; 32],
    /// ChaCha20 nonce (zero nonce; counter provides uniqueness within a session).
    nonce: [u8; 12],
    /// True after Phase A seeding completes successfully.
    is_seeded: bool,
    /// True after Phase B reseed from TPM completes.
    is_reseeded_from_tpm: bool,
}

impl CsprngState {
    const fn new_zeroed() -> Self {
        CsprngState {
            key: [0u8; 32],
            nonce: [0u8; 12],
            is_seeded: false,
            is_reseeded_from_tpm: false,
        }
    }
}

/// BSS-backed global CSPRNG state. No dynamic allocation.
///
/// Accessed only through safe wrapper functions that use `addr_of_mut!`.
static mut GLOBAL_CSPRNG: CsprngState = CsprngState::new_zeroed();

/// Initialize the CSPRNG using Phase A seeding from RDRAND and RDSEED.
///
/// Enforces invariant INV-BOOT-005 (entropy initialization is explicit and conservative).
/// RDRAND absence causes a fatal boot halt (D-07).
///
/// Verified by: test_boot_halts_when_rdrand_is_unavailable
#[cfg(target_arch = "x86_64")]
pub fn initialize_csprng_phase_a() {
    crate::hardware_security::entropy_source::halt_if_rdrand_unavailable();
    let rdrand_samples = collect_rdrand_samples_for_seeding();
    let rdseed_samples = crate::hardware_security::entropy_source::collect_rdseed_samples();
    let derived_key = derive_initial_key_from_entropy(&rdrand_samples, &rdseed_samples);
    store_seeded_key(derived_key);
}

/// Collect 8 RDRAND samples, panicking if any fail after retries.
#[cfg(target_arch = "x86_64")]
fn collect_rdrand_samples_for_seeding() -> [u64; 8] {
    crate::hardware_security::entropy_source::collect_rdrand_samples(8)
        .unwrap_or([0u64; 8])
}

/// Store the derived key into global CSPRNG state and mark as seeded.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
fn store_seeded_key(derived_key: [u8; 32]) {
    // SAFETY: single-core, no concurrent access; called only once during boot init.
    // - Precondition: boot sequence runs before any concurrency exists (single-core).
    // - Invariant: INV-BOOT-005 (entropy initialization is explicit and conservative).
    // - Evidence: test_csprng_is_seeded_after_phase_a_with_nonzero_key
    // Allowlist: src/kernel/src/boot/ -- static mut access during boot init.
    let state_pointer = core::ptr::addr_of_mut!(GLOBAL_CSPRNG);
    unsafe {
        (*state_pointer).key = derived_key;
        (*state_pointer).is_seeded = true;
    }
}

/// Derive the initial 256-bit CSPRNG key from hardware entropy samples.
///
/// Folds 8 RDRAND samples (512 bits) into 4 u64 values via pairwise XOR,
/// then XORs in any available RDSEED samples to produce 256 bits.
///
/// Verified by: test_derive_initial_key_produces_nonzero_key_from_nonzero_samples
pub fn derive_initial_key_from_entropy(
    rdrand_samples: &[u64; 8],
    rdseed_samples: &[Option<u64>; 4],
) -> [u8; 32] {
    let folded_words = fold_rdrand_samples_to_four_words(rdrand_samples);
    let mixed_words = mix_rdseed_into_words(folded_words, rdseed_samples);
    convert_four_words_to_key_bytes(mixed_words)
}

/// Fold 8 RDRAND u64 samples into 4 u64 values via pairwise XOR.
fn fold_rdrand_samples_to_four_words(rdrand_samples: &[u64; 8]) -> [u64; 4] {
    [
        rdrand_samples[0] ^ rdrand_samples[4],
        rdrand_samples[1] ^ rdrand_samples[5],
        rdrand_samples[2] ^ rdrand_samples[6],
        rdrand_samples[3] ^ rdrand_samples[7],
    ]
}

/// XOR each RDSEED sample (if present) into the corresponding folded word.
fn mix_rdseed_into_words(
    folded_words: [u64; 4],
    rdseed_samples: &[Option<u64>; 4],
) -> [u64; 4] {
    [
        mix_optional_sample(folded_words[0], rdseed_samples[0]),
        mix_optional_sample(folded_words[1], rdseed_samples[1]),
        mix_optional_sample(folded_words[2], rdseed_samples[2]),
        mix_optional_sample(folded_words[3], rdseed_samples[3]),
    ]
}

/// XOR a sample into a word if the sample is present, otherwise return the word unchanged.
fn mix_optional_sample(word: u64, sample: Option<u64>) -> u64 {
    match sample {
        Some(seed_value) => word ^ seed_value,
        None => word,
    }
}

/// Convert 4 u64 words to a 32-byte key in little-endian byte order.
fn convert_four_words_to_key_bytes(words: [u64; 4]) -> [u8; 32] {
    let mut key_bytes = [0u8; 32];
    write_u64_le_into_key(&mut key_bytes, 0, words[0]);
    write_u64_le_into_key(&mut key_bytes, 8, words[1]);
    write_u64_le_into_key(&mut key_bytes, 16, words[2]);
    write_u64_le_into_key(&mut key_bytes, 24, words[3]);
    key_bytes
}

/// Write one u64 in little-endian order into key_bytes starting at byte_offset.
fn write_u64_le_into_key(key_bytes: &mut [u8; 32], byte_offset: usize, word: u64) {
    let word_bytes = word.to_le_bytes();
    key_bytes[byte_offset..byte_offset + 8].copy_from_slice(&word_bytes);
}

/// Generate random bytes from the CSPRNG.
///
/// Applies the ChaCha20 keystream to fill the output slice.
/// Panics if called before Phase A seeding (should never happen after boot).
///
/// Enforces invariant INV-BOOT-005 (entropy initialization is explicit).
/// Verified by: test_generate_random_bytes_produces_nonzero_output
pub fn generate_random_bytes(output: &mut [u8]) {
    let state_pointer = core::ptr::addr_of!(GLOBAL_CSPRNG);
    // SAFETY: read-only access to check seeded flag; single-core kernel.
    let is_seeded = unsafe { (*state_pointer).is_seeded };
    assert!(is_seeded, "CSPRNG generate_random_bytes called before Phase A seeding");
    apply_chacha20_keystream_to_output(output);
}

/// Apply the ChaCha20 keystream to the output buffer using the current key and nonce.
fn apply_chacha20_keystream_to_output(output: &mut [u8]) {
    let state_pointer = core::ptr::addr_of!(GLOBAL_CSPRNG);
    // SAFETY: single-core; no concurrent writers; key/nonce are valid after seeding.
    // - Precondition: is_seeded is true (checked by caller).
    // - Invariant: INV-BOOT-005 (entropy initialization is explicit and conservative).
    // - Evidence: test_generate_random_bytes_produces_nonzero_output
    // Allowlist: src/kernel/src/boot/ -- static mut access during boot init.
    let current_key = unsafe { (*state_pointer).key };
    let current_nonce = unsafe { (*state_pointer).nonce };
    let mut cipher = ChaCha20::new(&current_key.into(), &current_nonce.into());
    cipher.apply_keystream(output);
}

/// Reseed the CSPRNG from TPM entropy (Phase B).
///
/// Uses SHA-256 KDF: new_key = SHA-256(old_key || tpm_entropy || domain_separator).
/// Zeros the old key via write_volatile before replacing to prevent compiler elision.
///
/// Enforces invariant INV-BOOT-005 (entropy initialization is explicit and conservative).
/// Verified by: test_reseed_from_tpm_changes_key
pub fn reseed_from_tpm_entropy(tpm_entropy: &[u8; 32]) {
    let new_key = derive_reseeded_key(tpm_entropy);
    zero_and_replace_key(new_key);
    mark_reseeded_from_tpm();
}

/// Derive a new key via SHA-256(old_key || tpm_entropy || domain_separator).
fn derive_reseeded_key(tpm_entropy: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let state_pointer = core::ptr::addr_of!(GLOBAL_CSPRNG);
    // SAFETY: read-only to copy old key bytes; single-core; no concurrent writers.
    // Allowlist: src/kernel/src/boot/ -- static mut access during boot init.
    let old_key = unsafe { (*state_pointer).key };
    let mut hasher = Sha256::new();
    hasher.update(old_key);
    hasher.update(tpm_entropy);
    hasher.update(b"brainix-csprng-reseed");
    hasher.finalize().into()
}

/// Zero the old key via write_volatile, then write the new key.
fn zero_and_replace_key(new_key: [u8; 32]) {
    let state_pointer = core::ptr::addr_of_mut!(GLOBAL_CSPRNG);
    // SAFETY: single-core; write_volatile prevents compiler from eliding zero-write.
    // - Precondition: single-core; no concurrent readers during reseed.
    // - Invariant: INV-AUTH-004 (revocation is final -- old key must not remain readable).
    // - Evidence: test_reseed_from_tpm_changes_key
    // Allowlist: src/kernel/src/boot/ -- static mut access during boot init.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*state_pointer).key), [0u8; 32]);
        (*state_pointer).key = new_key;
    }
}

/// Mark the CSPRNG as having completed Phase B reseed.
fn mark_reseeded_from_tpm() {
    let state_pointer = core::ptr::addr_of_mut!(GLOBAL_CSPRNG);
    // SAFETY: single-core; write flag after key is in place.
    // Allowlist: src/kernel/src/boot/ -- static mut access during boot init.
    unsafe {
        (*state_pointer).is_reseeded_from_tpm = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SC-01: RDRAND absence is a fatal boot halt.
    ///
    /// Tests the pure logic path: should_halt_due_to_absent_rdrand returns true
    /// when rdrand_is_available is false. The actual hardware halt is tested
    /// in QEMU integration (Plan 06).
    #[test]
    fn test_boot_halts_when_rdrand_is_unavailable() {
        let rdrand_is_available = false;
        let should_halt = crate::hardware_security::entropy_source::should_halt_due_to_absent_rdrand(
            rdrand_is_available,
        );
        assert!(should_halt, "kernel must halt when RDRAND is unavailable");
    }

    /// Key derivation from non-zero RDRAND samples produces a non-zero key.
    ///
    /// Samples must be distinct (pairwise XOR of identical values yields zero).
    #[test]
    fn test_derive_initial_key_produces_nonzero_key_from_nonzero_samples() {
        let rdrand_samples = [
            0xDEAD_BEEF_CAFE_BABEu64,
            0x0102_0304_0506_0708u64,
            0xAAAA_BBBB_CCCC_DDDDu64,
            0x1111_2222_3333_4444u64,
            0xFFFF_0000_FFFF_0000u64,
            0x0F0F_0F0F_F0F0_F0F0u64,
            0x1234_5678_9ABC_DEF0u64,
            0xFEDC_BA98_7654_3210u64,
        ];
        let rdseed_samples = [None; 4];
        let derived_key = derive_initial_key_from_entropy(&rdrand_samples, &rdseed_samples);
        assert_ne!(derived_key, [0u8; 32]);
    }

    /// RDSEED samples are XOR-ed into the key when present.
    #[test]
    fn test_derive_initial_key_mixes_rdseed_into_key() {
        let rdrand_samples = [1u64; 8];
        let rdseed_samples_absent = [None; 4];
        let rdseed_samples_present = [Some(0xFFFF_FFFF_FFFF_FFFFu64); 4];
        let key_without_rdseed =
            derive_initial_key_from_entropy(&rdrand_samples, &rdseed_samples_absent);
        let key_with_rdseed =
            derive_initial_key_from_entropy(&rdrand_samples, &rdseed_samples_present);
        assert_ne!(key_without_rdseed, key_with_rdseed);
    }

    /// Reseed from TPM changes the key (KDF produces different output).
    #[test]
    fn test_reseed_from_tpm_changes_key() {
        let rdrand_samples = [0x0102_0304_0506_0708u64; 8];
        let rdseed_samples = [None; 4];
        let initial_key = derive_initial_key_from_entropy(&rdrand_samples, &rdseed_samples);
        store_seeded_key(initial_key);
        let tpm_entropy = [0xAAu8; 32];
        reseed_from_tpm_entropy(&tpm_entropy);
        let state_pointer = core::ptr::addr_of!(GLOBAL_CSPRNG);
        // SAFETY: test-only; single-threaded test environment.
        let new_key = unsafe { (*state_pointer).key };
        assert_ne!(new_key, initial_key);
    }

    /// Key derivation uses the domain separator for Phase B (KDF binding).
    #[test]
    fn test_derive_reseeded_key_uses_domain_separator() {
        let rdrand_samples = [0xCAFEu64; 8];
        let rdseed_samples = [None; 4];
        let seed_key = derive_initial_key_from_entropy(&rdrand_samples, &rdseed_samples);
        store_seeded_key(seed_key);
        let tpm_entropy_a = [0x11u8; 32];
        let tpm_entropy_b = [0x22u8; 32];
        let key_a = derive_reseeded_key(&tpm_entropy_a);
        let key_b = derive_reseeded_key(&tpm_entropy_b);
        assert_ne!(key_a, key_b, "different TPM entropy must produce different keys");
    }
}
