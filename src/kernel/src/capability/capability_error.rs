//! Capability system error type.
//!
//! All capability operations return typed errors per INV-FAIL-001 and INV-SCHED-004.
//! No operation silently succeeds, silently fails, or panics.

/// Errors returned by capability operations.
///
/// Every error is explicit (INV-SCHED-004: exhaustion is explicit, never silent).
/// Enforces INV-FAIL-001: failure modes are defined.
///
/// Verified by: tests::test_ungranted_slot_returns_error
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CapabilityError {
    /// The capability slot contains the null sentinel (no capability is present).
    NullCapability,
    /// The capability type does not match the expected type for this operation.
    TypeMismatch,
    /// The requested rights exceed those present in the parent capability.
    RightsExceedParent,
    /// The target capability slot is already occupied by a non-null capability.
    SlotOccupied,
    /// The security domain has exhausted its capability slot budget.
    QuotaExhausted,
    /// The object type discriminant is not a recognized CapabilityType value.
    InvalidObjectType,
    /// The capability has expired (use-count reached zero or tick window elapsed).
    CapabilityExpired,
    /// The temporal constraint requested exceeds that of the parent capability.
    TemporalExceedsParent,
    /// The generation counter does not match the current object generation.
    GenerationMismatch,
    /// The Write right is not present in the capability's rights bitmask.
    WriteRightNotGranted,
    /// The Read right is not present in the capability's rights bitmask.
    ReadRightNotGranted,
    /// The Grant right is not present in the capability's rights bitmask.
    GrantRightNotGranted,
    /// The target IPC endpoint capability is not present in the caller's CSpace.
    EndpointNotInCSpace,
    /// The requested frame access exceeds the bounds of the frame capability.
    OutOfBoundsFrameAccess,
}
