//! Build script for the BraiNIX shell binary.
//!
//! Tells cargo to pass our linker script (linker.ld) when linking the
//! `brainix-shell` binary. Only applies on bare-metal targets; host builds
//! (for running tests on the developer machine) use the default linker.

fn main() {
    let target_triple = std::env::var("TARGET").unwrap_or_default();
    if target_triple != "x86_64-unknown-none" {
        return;
    }
    let manifest_directory = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rustc-link-arg-bin=brainix-shell=-T{}/linker.ld", manifest_directory);
    println!("cargo:rustc-link-arg-bin=brainix-shell=-nostdlib");
    println!("cargo:rustc-link-arg-bin=brainix-shell=-static");
    println!("cargo:rustc-link-arg-bin=brainix-shell=-no-pie");
}
