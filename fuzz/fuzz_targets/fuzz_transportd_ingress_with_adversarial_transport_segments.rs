#![no_main]

//! Fuzz target: transportd ingress with adversarial transport segments.
//!
//! Exercises the same `parse_icmp_message` entry point used in production
//! when transportd receives ICMP data from ipd via CapFrame page.
//! Also exercises `generate_icmp_echo_reply` with adversarial input.
//! Verifies that no adversarial input causes a panic, buffer overflow,
//! or undefined behavior in the ICMP parser or reply generator.
//!
//! Coverage: truncated messages, bad checksums, zero-length messages,
//! all-0xFF input, echo request payloads of varying sizes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise the transportd ICMP parser boundary.
    let _parse_result = brainix_transportd::parse_icmp_message(data);

    // Also exercise echo reply generation with the same adversarial data.
    let mut reply_buffer = [0u8; 4096];
    let _reply_result = brainix_transportd::generate_icmp_echo_reply(
        data,
        &mut reply_buffer,
    );
});
