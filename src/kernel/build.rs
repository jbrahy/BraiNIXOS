//! Build script for the BraiNIX kernel.
//!
//! Passes `-T src/kernel/linker.ld` to the linker for the `brainix`
//! binary target (gated by the `kernel-binary` feature). The linker
//! script defines `_kernel_start`, `_text_start`, `_text_end`,
//! `_rodata_start`, `_rodata_end` and the higher-half virtual load
//! address the bootloader jumps to.
//!
//! Host-target builds (tests on the developer machine) and lib-only
//! builds do not link a binary, so the linker script is not needed.

fn main() {
    let target_triple = std::env::var("TARGET").unwrap_or_default();
    if target_triple != "x86_64-unknown-none" {
        return;
    }
    let manifest_directory = env!("CARGO_MANIFEST_DIR");
    println!("cargo:rerun-if-changed=linker.ld");
    println!(
        "cargo:rustc-link-arg-bin=brainix=-T{}/linker.ld",
        manifest_directory
    );
    println!("cargo:rustc-link-arg-bin=brainix=-nostdlib");
    println!("cargo:rustc-link-arg-bin=brainix=-static");
    println!("cargo:rustc-link-arg-bin=brainix=-no-pie");
}
