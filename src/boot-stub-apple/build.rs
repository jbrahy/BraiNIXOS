//! Wires the linker script into the bare-metal link only.
//!
//! Done here rather than in `.cargo/config.toml` because config `rustflags`
//! resolve relative to the invoking directory, so `-T linker.ld` would break
//! the moment the crate is built from anywhere but its own directory. A build
//! script knows its own manifest path.
//!
//! Host builds must not see any of this: `cargo test` links an ordinary macOS
//! test binary, and handing it a bare-metal linker script would fail the link.

use std::env;
use std::path::PathBuf;

fn main() {
    let target = env::var("TARGET").unwrap_or_default();

    // Only the bare-metal target gets the script. Everything else — the host
    // test build in particular — links normally.
    if !target.starts_with("aarch64-unknown-none") {
        return;
    }

    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("cargo always sets this"));
    let script = manifest_dir.join("linker.ld");

    println!("cargo:rustc-link-arg-bins=-T{}", script.display());
    // No `-nostartfiles` here: that is a compiler-driver flag, and this target
    // invokes `rust-lld` directly, which rejects it. A `no_std` binary on a
    // bare-metal target links no crt0 to begin with, so there is nothing to
    // suppress — `_start` from start.S is the entry point and nothing runs
    // beneath it.

    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-changed=src/start.S");
}
