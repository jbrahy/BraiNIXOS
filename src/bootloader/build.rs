// Bootloader build script.
//
// 1. Passes the linker script (-T linker.ld) so the multiboot2 header section
//    is placed before .text and _kernel_start is defined at the fixed address.
// 2. Disables PIE (-no-pie) because the 32-bit entry stub uses R_X86_64_32
//    absolute relocations for OFFSET references to BSS/data symbols. The
//    linker rejects these when PIE (-pie) is active (which rust-lld enables
//    by default for x86_64-unknown-none). The bootloader has a fixed load
//    address (0x100000) so position independence is neither needed nor valid.
// 3. Passes -static to prevent dynamic linking (not available for bare metal).

fn pass_linker_flags() {
    let manifest_directory = env!("CARGO_MANIFEST_DIR");
    println!("cargo:rustc-link-arg=-T{}/linker.ld", manifest_directory);
    println!("cargo:rustc-link-arg=-no-pie");
    println!("cargo:rustc-link-arg=-static");
    println!("cargo:rerun-if-changed=linker.ld");
}

fn main() {
    // Only emit the bare-metal linker flags when building for the
    // x86_64-unknown-none bootloader binary target. On host test targets
    // (e.g. aarch64-apple-darwin) the macOS linker rejects -T / -no-pie /
    // -static. The lib-test target only exercises pure-data parsing logic
    // and does not need a custom linker script.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "none" {
        pass_linker_flags();
    }
}
