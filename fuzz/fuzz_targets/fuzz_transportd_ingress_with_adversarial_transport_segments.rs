#![no_main]

//! Fuzz target: transportd ingress with adversarial transport segments.
//!
//! Verifies that arbitrary bytes delivered to the transportd ICMP message
//! parser cannot cause panics, out-of-bounds accesses, or undefined behavior.
//!
//! The fuzz input simulates raw ICMP message data that a compromised ipd
//! might send to transportd's endpoint. Success criteria: no panic, no
//! out-of-bounds access, deterministic Result returned for all inputs.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _result = brainix_transportd::parse_icmp_message(data);
});
