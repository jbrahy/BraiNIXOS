#![no_std]
#![deny(unsafe_code)]

//! The host-run serving datapath (P3-T9a): the components, composed.
//!
//! Seven library crates have been landing for weeks without anything putting
//! two of them together. This crate is where a client credential, a real PSK
//! handshake, a session slot, and a KV partition meet — on a host, with no
//! kernel and no socket, which is the only place they can meet before AS-4c.
//!
//! # What it proves, and what it cannot
//!
//! The roadmap is careful about this and so is this crate: **a host-level test
//! of composed components is not a system claim.** What runs here is the real
//! key schedule, the real wire decoder, the real slot pool and the real KV
//! binding. What does not run is a kernel, an address space, an IPC boundary,
//! or the model — so an isolation result here says the *components* keep two
//! clients apart, not that a booted BraiNIX does. The system claim is AS-4c, on
//! hardware, and nothing before it substitutes.
//!
//! **Token streaming is absent, not stubbed silently.** P3-T9a's criteria name
//! streamed tokens, and producing one means `brainix-transformer` over real
//! weights, which means `modeld`, a region, and a blob. That chain is A3's and
//! is not built. Every other criterion — the handshake, the request parse, two
//! isolated sessions, teardown — is exercised here in full.

/// A fixed test vector: what a caller would take from the kernel CSPRNG.
///
/// Named rather than inlined because it carries an obligation: `INV-BOOT-005`
/// requires these bytes to come from the CSPRNG after entropy initialization,
/// and §5.6c makes server-nonce freshness the one assumption replay resistance
/// rests on. A constant is correct for a deterministic test and would be a
/// vulnerability in a server, which is exactly why it lives behind a name that
/// says so.
pub const DETERMINISTIC_TEST_NONCE: [u8; 32] = [0x11; 32];
