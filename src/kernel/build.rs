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
    emit_bare_metal_x86_cfg();

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

/// Emits `bare_metal_x86` for the frozen x86-64 reference target only.
///
/// `cfg(target_arch = "x86_64")` is NOT a usable stand-in, and the difference is
/// what broke the Kani job: on an x86_64 *hosted* target — the Linux CI runner,
/// or `x86_64-apple-darwin` — that cfg is equally true, so host verification
/// builds compiled bare-metal-only code and pulled in the `x86_64` and
/// `multiboot2` crates. Kani ships its own, newer nightly, under which vendored
/// `x86_64` 0.15.4 does not compile (it uses the unstable `Step` trait, since
/// moved to `core::range::Step`), so every Kani harness in the repository
/// failed — the project's entire evidence model, silently off.
///
/// It hid on this workstation because aarch64 makes `target_arch = "x86_64"`
/// false, so the crates were already excluded and everything looked green.
///
/// One named cfg, emitted in one place, is deliberate: the alternative was 139
/// hand-edited `cfg(all(target_arch = ..., target_os = ...))` sites, where a
/// single missed one reintroduces the bug in a way only CI can see.
fn emit_bare_metal_x86_cfg() {
    println!("cargo:rustc-check-cfg=cfg(bare_metal_x86)");

    let architecture = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let operating_system = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if architecture == "x86_64" && operating_system == "none" {
        println!("cargo:rustc-cfg=bare_metal_x86");
    }
}
