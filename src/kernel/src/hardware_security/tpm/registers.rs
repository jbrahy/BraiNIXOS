//! TPM TIS (TPM Interface Specification) register definitions and MMIO accessors.
//!
//! Phase 6 Plan 05: Defines the TPM TIS register layout at base address 0xFED40000.
//! Provides safe wrappers for TPM status, data FIFO, and locality register access.
//!
//! All MMIO access is delegated to `src/kernel/src/arch/hardware_registers.rs`
//! per the UNSAFE_CODE_POLICY.md allowlist for TPM TIS MMIO operations.
//!
//! Enforces invariant INV-BOOT-001 (measured boot path integrity).
//! Verified by: integration_swtpm_attestation_chain_completes_with_expected_pcr_values

/// Base MMIO address of the TPM TIS interface.
///
/// Enforces INV-BOOT-001 (measured boot path).
/// Verified by: integration_swtpm_attestation_chain_completes_with_expected_pcr_values
pub const TPM_BASE_ADDRESS: u64 = 0xFED4_0000;

/// TPM_ACCESS register offset (locality 0).
pub const TPM_ACCESS_REGISTER_OFFSET: u32 = 0x000;

/// TPM_STS (status) register offset (locality 0).
pub const TPM_STATUS_REGISTER_OFFSET: u32 = 0x018;

/// TPM_DATA_FIFO register offset (locality 0).
pub const TPM_DATA_FIFO_REGISTER_OFFSET: u32 = 0x024;

/// TPM_DID_VID (device/vendor ID) register offset.
pub const TPM_DEVICE_VENDOR_ID_REGISTER_OFFSET: u32 = 0xF00;

/// TPM_ACCESS bit: request to use this locality.
pub const TPM_ACCESS_REQUEST_USE_BIT: u8 = 0x02;

/// TPM_ACCESS bit: this locality is currently active.
pub const TPM_ACCESS_ACTIVE_LOCALITY_BIT: u8 = 0x20;

/// TPM_STS bit: TPM is ready to accept a new command.
pub const TPM_STATUS_COMMAND_READY_BIT: u32 = 0x40;

/// TPM_STS bit: response data is available in the FIFO.
pub const TPM_STATUS_DATA_AVAILABLE_BIT: u32 = 0x10;

/// TPM_STS bit: TPM is expecting more data bytes.
pub const TPM_STATUS_EXPECT_BIT: u32 = 0x08;

/// TPM_STS bit: execute the command in the FIFO.
pub const TPM_STATUS_GO_BIT: u32 = 0x20;

/// Maximum number of MMIO wait-loop iterations before reporting a timeout.
const TPM_WAIT_LOOP_ITERATION_LIMIT: u32 = 1_000_000;

/// Errors that can occur during TPM communication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmError {
    /// TPM did not grant locality access within the wait limit.
    LocalityRequestFailed,
    /// TPM did not become ready for a command within the wait limit.
    CommandNotReady,
    /// TPM returned a non-zero response code.
    CommandFailed(u32),
    /// TPM data FIFO did not become available within the wait limit.
    DataNotAvailable,
    /// TPM response buffer was shorter than the minimum header size.
    ResponseTooShort,
    /// TPM response tag was not the expected session-free tag (0x8002).
    InvalidResponseTag,
}

/// Request use of TPM locality 0 and wait until it is granted.
///
/// Enforces INV-BOOT-001 (measured boot path integrity).
/// Verified by: integration_swtpm_attestation_chain_completes_with_expected_pcr_values
pub fn request_tpm_locality() -> Result<(), TpmError> {
    write_tpm_access_byte(TPM_ACCESS_REQUEST_USE_BIT);
    wait_for_active_locality()
}

/// Write a byte to the TPM_ACCESS register.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
fn write_tpm_access_byte(value: u8) {
    #[cfg(target_arch = "x86_64")]
    crate::arch::hardware_registers::write_tpm_data_fifo_byte(TPM_ACCESS_REGISTER_OFFSET, value);
    #[cfg(not(target_arch = "x86_64"))]
    let _ = value;
}

/// Poll the TPM_ACCESS register until the active-locality bit is set.
fn wait_for_active_locality() -> Result<(), TpmError> {
    let active_bit = TPM_ACCESS_ACTIVE_LOCALITY_BIT;
    for _ in 0..TPM_WAIT_LOOP_ITERATION_LIMIT {
        if read_tpm_access_byte() & active_bit != 0 {
            return Ok(());
        }
    }
    Err(TpmError::LocalityRequestFailed)
}

/// Read a byte from the TPM_ACCESS register.
fn read_tpm_access_byte() -> u8 {
    #[cfg(target_arch = "x86_64")]
    return crate::arch::hardware_registers::read_tpm_data_fifo_byte(TPM_ACCESS_REGISTER_OFFSET);
    #[cfg(not(target_arch = "x86_64"))]
    return TPM_ACCESS_ACTIVE_LOCALITY_BIT;
}

/// Wait until the TPM status register indicates command-ready.
///
/// Enforces INV-BOOT-001 (measured boot path integrity).
pub fn wait_for_command_ready() -> Result<(), TpmError> {
    for _ in 0..TPM_WAIT_LOOP_ITERATION_LIMIT {
        if is_tpm_status_bit_set(TPM_STATUS_COMMAND_READY_BIT) {
            return Ok(());
        }
    }
    Err(TpmError::CommandNotReady)
}

/// Wait until the TPM status register indicates data is available.
///
/// Enforces INV-BOOT-001 (measured boot path integrity).
pub fn wait_for_data_available() -> Result<(), TpmError> {
    for _ in 0..TPM_WAIT_LOOP_ITERATION_LIMIT {
        if is_tpm_status_bit_set(TPM_STATUS_DATA_AVAILABLE_BIT) {
            return Ok(());
        }
    }
    Err(TpmError::DataNotAvailable)
}

/// Check whether a given bit mask is set in the TPM status register.
fn is_tpm_status_bit_set(bit_mask: u32) -> bool {
    read_tpm_status_register() & bit_mask != 0
}

/// Read the TPM_STS (status) register as a u32.
fn read_tpm_status_register() -> u32 {
    #[cfg(target_arch = "x86_64")]
    return crate::arch::hardware_registers::read_tpm_register(TPM_STATUS_REGISTER_OFFSET);
    #[cfg(not(target_arch = "x86_64"))]
    return TPM_STATUS_COMMAND_READY_BIT | TPM_STATUS_DATA_AVAILABLE_BIT;
}

/// Write a command-ready request to the TPM_STS register.
pub fn send_command_ready_to_tpm_status() {
    #[cfg(target_arch = "x86_64")]
    crate::arch::hardware_registers::write_tpm_register(
        TPM_STATUS_REGISTER_OFFSET,
        TPM_STATUS_COMMAND_READY_BIT,
    );
    #[cfg(not(target_arch = "x86_64"))]
    {}
}

/// Write a go-command request to the TPM_STS register to start execution.
pub fn send_execute_command_to_tpm_status() {
    #[cfg(target_arch = "x86_64")]
    crate::arch::hardware_registers::write_tpm_register(
        TPM_STATUS_REGISTER_OFFSET,
        TPM_STATUS_GO_BIT,
    );
    #[cfg(not(target_arch = "x86_64"))]
    {}
}

/// Write a single byte to the TPM_DATA_FIFO register.
pub fn write_byte_to_tpm_data_fifo(byte_value: u8) {
    #[cfg(target_arch = "x86_64")]
    crate::arch::hardware_registers::write_tpm_data_fifo_byte(
        TPM_DATA_FIFO_REGISTER_OFFSET,
        byte_value,
    );
    #[cfg(not(target_arch = "x86_64"))]
    let _ = byte_value;
}

/// Read a single byte from the TPM_DATA_FIFO register.
pub fn read_byte_from_tpm_data_fifo() -> u8 {
    #[cfg(target_arch = "x86_64")]
    return crate::arch::hardware_registers::read_tpm_data_fifo_byte(TPM_DATA_FIFO_REGISTER_OFFSET);
    #[cfg(not(target_arch = "x86_64"))]
    return 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TPM_BASE_ADDRESS constant has the correct TIS base value.
    #[test]
    fn test_tpm_base_address_is_correct_tis_mmio_value() {
        assert_eq!(TPM_BASE_ADDRESS, 0xFED4_0000u64);
    }

    /// TPM_ACCESS_REGISTER_OFFSET is at offset 0 from base (locality 0).
    #[test]
    fn test_tpm_access_register_offset_is_zero() {
        assert_eq!(TPM_ACCESS_REGISTER_OFFSET, 0x000u32);
    }

    /// TPM_STATUS_COMMAND_READY_BIT is bit 6 (value 0x40) of TPM_STS.
    #[test]
    fn test_tpm_status_command_ready_bit_is_bit_six() {
        assert_eq!(TPM_STATUS_COMMAND_READY_BIT, 0x40u32);
    }

    /// TPM_STATUS_GO_BIT is bit 5 (value 0x20) of TPM_STS.
    #[test]
    fn test_tpm_status_go_bit_is_bit_five() {
        assert_eq!(TPM_STATUS_GO_BIT, 0x20u32);
    }

    /// On host target the is_tpm_status_bit_set check works with mock data.
    ///
    /// On host, read_tpm_status_register returns COMMAND_READY|DATA_AVAILABLE.
    #[test]
    fn test_is_tpm_status_bit_set_returns_true_for_command_ready_on_host() {
        assert!(is_tpm_status_bit_set(TPM_STATUS_COMMAND_READY_BIT));
    }

    /// On host target, wait_for_command_ready returns Ok immediately.
    #[test]
    fn test_wait_for_command_ready_returns_ok_on_host_target() {
        let result = wait_for_command_ready();
        assert!(
            result.is_ok(),
            "wait_for_command_ready must return Ok on host"
        );
    }

    /// On host target, wait_for_data_available returns Ok immediately.
    #[test]
    fn test_wait_for_data_available_returns_ok_on_host_target() {
        let result = wait_for_data_available();
        assert!(
            result.is_ok(),
            "wait_for_data_available must return Ok on host"
        );
    }

    /// On host target, request_tpm_locality returns Ok immediately.
    #[test]
    fn test_request_tpm_locality_returns_ok_on_host_target() {
        let result = request_tpm_locality();
        assert!(
            result.is_ok(),
            "request_tpm_locality must return Ok on host"
        );
    }
}
