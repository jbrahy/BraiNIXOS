// Bootloader build script.
//
// Passes the linker script to rustc so the multiboot2 header is placed in
// the correct section and the bootloader binary is laid out for GRUB2.
// The assembly entry stub is included via global_asm! in lib.rs, so no
// external assembler crate is needed here.

fn pass_linker_script() {
    let manifest_directory = env!("CARGO_MANIFEST_DIR");
    println!(
        "cargo:rustc-link-arg=-T{}/linker.ld",
        manifest_directory
    );
    println!("cargo:rerun-if-changed=linker.ld");
}

fn main() {
    pass_linker_script();
}
