#![no_main]

//! Fuzz target: linkd ingress with adversarial Ethernet frames.
//!
//! Verifies that arbitrary bytes delivered to the linkd Ethernet frame parser
//! cannot cause panics, out-of-bounds accesses, or undefined behavior.
//!
//! The fuzz input simulates raw Ethernet frame data that a compromised
//! devd-nic might send to linkd's endpoint. Success criteria: no panic,
//! no out-of-bounds access, deterministic Result returned for all inputs.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _result = brainix_linkd::parse_ethernet_frame(data);
});
