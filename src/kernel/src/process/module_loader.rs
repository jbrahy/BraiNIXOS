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

use brainix_libsyscall::ProcessType;
use brainix_libsyscall::SpawnError;

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

/// Command line tag string identifying the init server module.
const INIT_SERVER_COMMAND_LINE: &str = "--init";

/// Command line tag string identifying the spawn daemon module.
const SPAWND_SERVER_COMMAND_LINE: &str = "--spawnd";

/// Command line tag string identifying the audit daemon module.
const AUDITD_SERVER_COMMAND_LINE: &str = "--auditd";

/// Descriptor holding all load-time information for a single discovered server module.
pub struct ServerModuleDescriptor {
    /// The role assigned to this server process.
    pub process_type: ProcessType,
    /// Physical start address of the binary in multiboot2 module memory.
    pub binary_start_address: u64,
    /// Total size in bytes of the binary in multiboot2 module memory.
    pub binary_size: usize,
    /// ELF entry point virtual address extracted during validation.
    pub entry_point_address: u64,
}

/// Compile-time whitelist of process types that spawnd is permitted to create.
///
/// Enforces INV-SPAWN-001: only explicitly whitelisted process types can be spawned.
/// DeviceServer and NetworkServer are reserved for Phase 8 and Phase 9 respectively.
const SPAWN_WHITELIST: [ProcessType; 3] =
    [ProcessType::Init, ProcessType::Spawnd, ProcessType::Auditd];

/// Identifies the process type for a server module from its multiboot2 command line string.
///
/// Returns `Some(ProcessType)` on an exact match to a known server command line tag.
/// Returns `None` if the command line does not match any known server.
pub fn identify_process_type_from_command_line(command_line: &str) -> Option<ProcessType> {
    match command_line {
        INIT_SERVER_COMMAND_LINE => Some(ProcessType::Init),
        SPAWND_SERVER_COMMAND_LINE => Some(ProcessType::Spawnd),
        AUDITD_SERVER_COMMAND_LINE => Some(ProcessType::Auditd),
        _ => None,
    }
}

/// Validates a server binary's ELF header and extracts its entry point address.
///
/// Calls `elf_loader::extract_entry_point`, which validates the full header then
/// extracts the entry point. Maps ELF errors to `ModuleLoadError::ElfLoadFailed`.
///
/// Returns the entry point virtual address on success.
pub fn validate_server_module_binary(binary_bytes: &[u8]) -> Result<u64, ModuleLoadError> {
    let entry_point_result = super::elf_loader::extract_entry_point(binary_bytes);
    map_elf_result_to_module_result(entry_point_result)
}

/// Maps an ElfLoadError result to a ModuleLoadError result.
fn map_elf_result_to_module_result(
    elf_result: Result<u64, super::elf_loader::ElfLoadError>,
) -> Result<u64, ModuleLoadError> {
    match elf_result {
        Ok(entry_point_address) => Ok(entry_point_address),
        Err(elf_load_error) => Err(ModuleLoadError::ElfLoadFailed(elf_load_error)),
    }
}

/// Returns true if the given process type is in the compile-time spawn whitelist.
///
/// Enforces INV-SPAWN-001: only whitelisted process types may be spawned.
/// Verified by: tests::test_spawnd_refuses_process_type_not_in_whitelist
#[allow(clippy::arithmetic_side_effects)]
pub fn is_process_type_in_spawn_whitelist(process_type: ProcessType) -> bool {
    let mut whitelist_index = 0;
    while whitelist_index < SPAWN_WHITELIST.len() {
        if SPAWN_WHITELIST[whitelist_index] == process_type {
            return true;
        }
        whitelist_index += 1;
    }
    false
}

/// Validates a spawn request against the compile-time whitelist.
///
/// Returns `Ok(())` if the process type is whitelisted.
/// Returns `Err(SpawnError::ProcessTypeNotPermitted)` if not.
///
/// Enforces INV-SPAWN-001: only whitelisted process types can be spawned.
/// Verified by: process::tests::test_spawnd_refuses_process_type_not_in_whitelist
pub fn validate_spawn_request(process_type: ProcessType) -> Result<(), SpawnError> {
    let process_type_is_permitted = is_process_type_in_spawn_whitelist(process_type);
    build_spawn_validation_result(process_type_is_permitted)
}

/// Converts the whitelist check boolean into a spawn validation Result.
fn build_spawn_validation_result(process_type_is_permitted: bool) -> Result<(), SpawnError> {
    if process_type_is_permitted {
        Ok(())
    } else {
        Err(SpawnError::ProcessTypeNotPermitted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that "--init" maps to ProcessType::Init.
    #[test]
    fn test_identify_init_from_init_command_line() {
        let result = identify_process_type_from_command_line("--init");
        assert_eq!(result, Some(ProcessType::Init));
    }

    /// Verifies that "--spawnd" maps to ProcessType::Spawnd.
    #[test]
    fn test_identify_spawnd_from_spawnd_command_line() {
        let result = identify_process_type_from_command_line("--spawnd");
        assert_eq!(result, Some(ProcessType::Spawnd));
    }

    /// Verifies that "--auditd" maps to ProcessType::Auditd.
    #[test]
    fn test_identify_auditd_from_auditd_command_line() {
        let result = identify_process_type_from_command_line("--auditd");
        assert_eq!(result, Some(ProcessType::Auditd));
    }

    /// Verifies that an unknown command line returns None.
    #[test]
    fn test_identify_returns_none_for_unknown_command_line() {
        let result = identify_process_type_from_command_line("--unknown");
        assert_eq!(result, None);
    }

    /// Verifies that an empty command line returns None.
    #[test]
    fn test_identify_returns_none_for_empty_command_line() {
        let result = identify_process_type_from_command_line("");
        assert_eq!(result, None);
    }

    /// Builds a minimal valid ELF64 header for use in tests.
    fn build_valid_elf64_header_bytes() -> [u8; 64] {
        let mut header = [0u8; 64];
        header[0] = 0x7f;
        header[1] = b'E';
        header[2] = b'L';
        header[3] = b'F';
        header[4] = 2; // ELFCLASS64
        header[5] = 1; // ELFDATA2LSB
        header[6] = 1; // EV_CURRENT
        header[16] = 2; // ET_EXEC
        header[17] = 0;
        header[18] = 0x3E; // EM_X86_64
        header[19] = 0;
        header[24] = 0x00;
        header[25] = 0x00;
        header[26] = 0x40;
        header[27] = 0x00; // e_entry = 0x400000
        header[32] = 64; // e_phoff = 64
        header[54] = 56; // e_phentsize
        header[55] = 0;
        header[56] = 0; // e_phnum = 0
        header[57] = 0;
        header
    }

    /// Verifies that a valid ELF binary returns Ok with the entry point.
    #[test]
    fn test_validate_server_module_binary_with_valid_elf_succeeds() {
        let header = build_valid_elf64_header_bytes();
        let result = validate_server_module_binary(&header);
        assert!(result.is_ok(), "valid ELF must return Ok");
    }

    /// Verifies that invalid binary bytes return Err.
    #[test]
    fn test_validate_server_module_binary_with_invalid_bytes_returns_error() {
        let invalid_bytes = [0u8; 64];
        let result = validate_server_module_binary(&invalid_bytes);
        assert!(result.is_err(), "invalid binary must return Err");
    }

    /// Verifies Init is in the spawn whitelist.
    #[test]
    fn test_init_process_type_is_in_spawn_whitelist() {
        let result = is_process_type_in_spawn_whitelist(ProcessType::Init);
        assert!(result, "Init must be in spawn whitelist");
    }

    /// Verifies Spawnd is in the spawn whitelist.
    #[test]
    fn test_spawnd_process_type_is_in_spawn_whitelist() {
        let result = is_process_type_in_spawn_whitelist(ProcessType::Spawnd);
        assert!(result, "Spawnd must be in spawn whitelist");
    }

    /// Verifies Auditd is in the spawn whitelist.
    #[test]
    fn test_auditd_process_type_is_in_spawn_whitelist() {
        let result = is_process_type_in_spawn_whitelist(ProcessType::Auditd);
        assert!(result, "Auditd must be in spawn whitelist");
    }

    /// Verifies DeviceServer is not in the spawn whitelist (Phase 8 reserved).
    #[test]
    fn test_device_server_process_type_is_not_in_spawn_whitelist() {
        let result = is_process_type_in_spawn_whitelist(ProcessType::DeviceServer);
        assert!(
            !result,
            "DeviceServer must not be in spawn whitelist (Phase 8)"
        );
    }

    /// Verifies NetworkServer is not in the spawn whitelist (Phase 9 reserved).
    #[test]
    fn test_network_server_process_type_is_not_in_spawn_whitelist() {
        let result = is_process_type_in_spawn_whitelist(ProcessType::NetworkServer);
        assert!(
            !result,
            "NetworkServer must not be in spawn whitelist (Phase 9)"
        );
    }
}
