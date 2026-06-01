#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz target: verify that arbitrary slot index values never cause panics
// in capability space operations. The u8 type guarantees all indices are
// in range 0..=255 for a 256-element array — this target confirms no
// arithmetic escapes that bound.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let slot_index = data[0];

    let mut capability_space =
        brainix_kernel::capability::capability_space::CapabilitySpace::new();

    // lookup_slot_ref returns a shared reference without state checks.
    // Any u8 index must return a valid reference — never panic or abort.
    let _slot_reference = capability_space.lookup_slot_ref(slot_index);

    // lookup_slot_mut returns a mutable reference for any u8 index.
    let _slot_mutable = capability_space.lookup_slot_mut(slot_index);

    if data.len() >= 2 {
        let second_index = data[1];
        let _second_reference = capability_space.lookup_slot_ref(second_index);
    }
});
