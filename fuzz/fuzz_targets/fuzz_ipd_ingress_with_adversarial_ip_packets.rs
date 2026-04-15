#![no_main]

//! Fuzz target: ipd ingress with adversarial IP packets.
//!
//! Verifies that arbitrary bytes delivered to the ipd IPv4 header parser
//! cannot cause panics, out-of-bounds accesses, or undefined behavior.
//!
//! The fuzz input simulates raw IPv4 packet data that a compromised linkd
//! might send to ipd's endpoint. Success criteria: no panic, no out-of-bounds
//! access, deterministic Result returned for all inputs.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _result = brainix_ipd::parse_ipv4_header(data);
});
