//! Multiboot2 module discovery and server binary loading.
//!
//! The bootloader places server ELF binaries as multiboot2 modules in physical memory.
//! This module iterates the multiboot2 module tags, validates each binary, and loads
//! each server into its own isolated address space before transferring control to init.
//!
//! # Security invariant
//!
//! No module byte is executed or mapped before ELF validation succeeds.
//! Failed modules cause a halt, not a degraded boot (fail-secure per INV-BOOT-001).

/// Errors that can occur when discovering or loading a multiboot2 server module.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ModuleLoadError {
    /// The multiboot2 info structure contained no module tags.
    NoModulesFound,
    /// ELF validation of the server binary failed.
    ElfLoadFailed(super::elf_loader::ElfLoadError),
    /// Address space creation for the server process failed.
    AddressSpaceFailed(super::address_space::AddressSpaceError),
}
