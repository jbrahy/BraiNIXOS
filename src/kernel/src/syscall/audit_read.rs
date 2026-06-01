//! sys_audit_read handler (syscall number 8). Per D-10, D-11.
//!
//! Validates that the caller holds a typed AuditRead capability with Read right
//! but not Write right. Enforces INV-AUTH-002: authority is explicit and typed.
//! Actual buffer copy to userspace is wired in Plan 05.

use crate::capability::capability_rights;
use crate::capability::capability_rights::CapabilityRights;
use crate::capability::capability_type::CapabilityType;

/// Errors returned by `validate_audit_read_capability`.
///
/// Each variant corresponds to a distinct enforcement point (D-11).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AuditReadError {
    /// The capability type was not CapabilityType::AuditRead.
    InvalidCapabilityType,
    /// The capability holds Write right, which is forbidden for audit readers (D-11).
    WriteRightNotGranted,
    /// The capability does not hold Read right, which is required.
    ReadRightNotGranted,
    /// The requested sequence range is out of bounds.
    InvalidSequenceRange,
}

/// Validates that a capability is suitable for sys_audit_read invocation.
///
/// Enforces INV-AUTH-002: authority is explicit and typed.
/// Verified by: syscall::audit_read::tests::test_validate_audit_read_capability_*
///
/// Checks (in order):
/// 1. Type must be CapabilityType::AuditRead.
/// 2. Rights must NOT include Write (D-11).
/// 3. Rights must include Read.
pub fn validate_audit_read_capability(
    capability_type: CapabilityType,
    rights: CapabilityRights,
) -> Result<(), AuditReadError> {
    let type_is_valid = check_capability_type_is_audit_read(capability_type);
    let write_right_is_absent = check_write_right_is_absent(rights);
    let read_right_is_present = check_read_right_is_present(rights);
    build_validation_result(type_is_valid, write_right_is_absent, read_right_is_present)
}

/// Returns true if the capability type is AuditRead.
fn check_capability_type_is_audit_read(capability_type: CapabilityType) -> bool {
    capability_type == CapabilityType::AuditRead
}

/// Returns true if the Write right is absent from the rights bitmask.
fn check_write_right_is_absent(rights: CapabilityRights) -> bool {
    !rights.contains(capability_rights::WRITE)
}

/// Returns true if the Read right is present in the rights bitmask.
fn check_read_right_is_present(rights: CapabilityRights) -> bool {
    rights.contains(capability_rights::READ)
}

/// Converts the three boolean validation results into a Result.
fn build_validation_result(
    type_is_valid: bool,
    write_right_is_absent: bool,
    read_right_is_present: bool,
) -> Result<(), AuditReadError> {
    if !type_is_valid {
        return Err(AuditReadError::InvalidCapabilityType);
    }
    if !write_right_is_absent {
        return Err(AuditReadError::WriteRightNotGranted);
    }
    if !read_right_is_present {
        return Err(AuditReadError::ReadRightNotGranted);
    }
    Ok(())
}

/// Handles the sys_audit_read system call.
///
/// Phase 7 stub: actual buffer copy to userspace is wired in Plan 05.
/// Returns 0 to indicate success (no entries copied yet).
pub fn handle_audit_read_syscall() -> i64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::capability_rights;

    /// Verifies that a valid AuditRead capability with Read right passes validation.
    #[test]
    fn test_validate_audit_read_capability_with_read_right_succeeds() {
        let capability_type = CapabilityType::AuditRead;
        let rights = capability_rights::READ;
        let result = validate_audit_read_capability(capability_type, rights);
        assert!(result.is_ok(), "AuditRead + Read right must succeed");
    }

    /// Verifies that a capability with Write right returns WriteRightNotGranted (D-11).
    #[test]
    fn test_validate_audit_read_capability_with_write_right_returns_error() {
        let capability_type = CapabilityType::AuditRead;
        let rights = capability_rights::READ | capability_rights::WRITE;
        let result = validate_audit_read_capability(capability_type, rights);
        assert_eq!(
            result,
            Err(AuditReadError::WriteRightNotGranted),
            "Write right must be rejected per D-11"
        );
    }

    /// Verifies that a wrong capability type returns InvalidCapabilityType.
    #[test]
    fn test_validate_audit_read_capability_with_wrong_type_returns_error() {
        let capability_type = CapabilityType::Endpoint;
        let rights = capability_rights::READ;
        let result = validate_audit_read_capability(capability_type, rights);
        assert_eq!(
            result,
            Err(AuditReadError::InvalidCapabilityType),
            "Wrong capability type must return InvalidCapabilityType"
        );
    }

    /// Verifies that missing Read right returns ReadRightNotGranted.
    #[test]
    fn test_validate_audit_read_capability_without_read_right_returns_error() {
        let capability_type = CapabilityType::AuditRead;
        let rights = CapabilityRights::empty();
        let result = validate_audit_read_capability(capability_type, rights);
        assert_eq!(
            result,
            Err(AuditReadError::ReadRightNotGranted),
            "Missing Read right must return ReadRightNotGranted"
        );
    }
}
