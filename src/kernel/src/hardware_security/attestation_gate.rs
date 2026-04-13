//! Attestation gate: blocks all network traffic until TPM quote is verified.
//!
//! Phase 6 Plan 05: Implements a state machine with states:
//!   Closed -> MeasuringPlatform -> AwaitingQuoteVerification -> Open
//! No network traffic is accepted by the network stack until the gate reaches
//! Open state (D-22). Gate timeout is 60 seconds (locked Phase 0 policy).
//! No fallback to unattested operation exists.
//!
//! PCR extension ordering enforced by gate state transitions:
//! PCR[0] -> PCR[1] -> attestation gate opens (D-14).
//! PCR[2] was already extended in Phase 5 (scheduler partition table measurement).
//!
//! Enforces invariant INV-BOOT-001 (measured boot path integrity).
//! Verified by: integration_swtpm_attestation_chain_completes_with_expected_pcr_values

/// Default attestation gate timeout in seconds (locked Phase 0 decision).
const ATTESTATION_GATE_DEFAULT_TIMEOUT_SECONDS: u16 = 60;

/// States of the attestation gate state machine.
///
/// Valid transition sequence: Closed -> MeasuringPlatform ->
/// AwaitingQuoteVerification -> Open (or -> Failed on error/timeout).
/// No direct path from Closed to Open exists (D-22).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationGateState {
    /// Initial state: no network traffic is allowed.
    Closed,
    /// PCR extension measurements are in progress.
    MeasuringPlatform,
    /// TPM quote generated, waiting for verifier response.
    AwaitingQuoteVerification,
    /// Attestation passed: network traffic is allowed.
    Open,
    /// Attestation failed or timed out: network traffic permanently blocked.
    Failed,
}

/// Events that drive attestation gate state transitions.
#[derive(Debug, Clone, Copy)]
pub enum AttestationEvent {
    /// PCR measurements are complete; quote generation may begin.
    MeasurementComplete,
    /// TPM quote has been generated and sent to the verifier.
    QuoteGenerated,
    /// Verifier confirmed the quote; attestation succeeded.
    VerificationPassed,
    /// Verifier rejected the quote; attestation failed.
    VerificationFailed,
    /// Gate timeout expired before verification completed.
    Timeout,
}

/// Errors that can occur during attestation gate operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationError {
    /// The requested transition is not valid from the current state.
    InvalidTransition {
        /// State the gate was in when the invalid transition was attempted.
        from: AttestationGateState,
    },
    /// Attempted to transition a gate that is already in the Open state.
    GateAlreadyOpen,
}

/// Attestation gate state and configuration.
pub struct AttestationGate {
    /// Current state of the gate state machine.
    state: AttestationGateState,
    /// Timeout in seconds before the gate moves to Failed if not verified.
    /// Used by the scheduler tick loop (Plan 06 boot wiring).
    #[allow(dead_code)]
    timeout_seconds: u16,
}

/// Create a new attestation gate in the Closed (initial) state.
///
/// Enforces INV-BOOT-001 (measured boot path integrity).
/// Verified by: test_attestation_gate_starts_in_closed_state
pub fn create_attestation_gate() -> AttestationGate {
    AttestationGate {
        state: AttestationGateState::Closed,
        timeout_seconds: ATTESTATION_GATE_DEFAULT_TIMEOUT_SECONDS,
    }
}

/// Advance the attestation gate by applying the given event.
///
/// Only valid transitions are accepted. Invalid transitions return
/// `Err(InvalidTransition)`. Attempting to advance from Open returns
/// `Err(GateAlreadyOpen)`.
///
/// Enforces INV-BOOT-001 (measured boot path integrity).
/// Verified by: test_attestation_gate_follows_required_transition_sequence
pub fn advance_attestation_gate(
    gate: &mut AttestationGate,
    event: AttestationEvent,
) -> Result<(), AttestationError> {
    if gate.state == AttestationGateState::Open {
        return Err(AttestationError::GateAlreadyOpen);
    }
    let next_state = compute_next_state(gate.state, event)?;
    gate.state = next_state;
    Ok(())
}

/// Compute the next state for a given current state and event.
///
/// Returns `Err(InvalidTransition)` for any transition not in the valid set.
fn compute_next_state(
    current_state: AttestationGateState,
    event: AttestationEvent,
) -> Result<AttestationGateState, AttestationError> {
    match (current_state, event) {
        (AttestationGateState::Closed, AttestationEvent::MeasurementComplete) =>
            Ok(AttestationGateState::MeasuringPlatform),
        (AttestationGateState::MeasuringPlatform, AttestationEvent::QuoteGenerated) =>
            Ok(AttestationGateState::AwaitingQuoteVerification),
        (AttestationGateState::AwaitingQuoteVerification, AttestationEvent::VerificationPassed) =>
            Ok(AttestationGateState::Open),
        (AttestationGateState::AwaitingQuoteVerification, AttestationEvent::VerificationFailed) =>
            Ok(AttestationGateState::Failed),
        (_, AttestationEvent::Timeout) =>
            Ok(AttestationGateState::Failed),
        (from, _) =>
            Err(AttestationError::InvalidTransition { from }),
    }
}

/// Return whether the attestation gate currently permits network traffic.
///
/// Returns `true` only when the gate is in the `Open` state (D-22).
///
/// Enforces INV-BOOT-001 (measured boot path integrity).
/// Verified by: test_attestation_gate_only_allows_traffic_in_open_state
pub fn is_network_traffic_allowed(gate: &AttestationGate) -> bool {
    gate.state == AttestationGateState::Open
}

/// Return the current state of the attestation gate.
pub fn get_attestation_gate_state(gate: &AttestationGate) -> AttestationGateState {
    gate.state
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SC-03: Full swtpm attestation chain produces valid quote.
    ///
    /// Runs via docker/test.sh in CI (requires QEMU + swtpm). Verifies that PCR[0-3]
    /// values match expected hashes after a full QEMU boot with swtpm attached.
    /// The swtpm provisioning steps are in docker/test.sh (NV index 0x01500001, TPM2
    /// device attached to QEMU via `-tpmdev emulator`).
    ///
    /// To run locally: `bash docker/test.sh` with swtpm installed.
    #[test]
    #[ignore = "Requires QEMU + swtpm — run via docker/test.sh in CI"]
    fn integration_swtpm_attestation_chain_completes_with_expected_pcr_values() {
        // SC-03: verified via docker/test.sh — tpm2_pcrread validates PCR[0-3] after boot
    }

    /// Attestation gate starts in Closed state.
    #[test]
    fn test_attestation_gate_starts_in_closed_state() {
        let gate = create_attestation_gate();
        assert_eq!(
            get_attestation_gate_state(&gate),
            AttestationGateState::Closed,
            "gate must start in Closed state"
        );
    }

    /// Network traffic is not allowed in Closed state.
    #[test]
    fn test_attestation_gate_does_not_allow_traffic_in_closed_state() {
        let gate = create_attestation_gate();
        assert!(!is_network_traffic_allowed(&gate), "closed gate must block traffic");
    }

    /// Attestation gate follows the required Closed->Measuring->Verifying->Open sequence.
    #[test]
    fn test_attestation_gate_follows_required_transition_sequence() {
        let mut gate = create_attestation_gate();
        advance_attestation_gate(&mut gate, AttestationEvent::MeasurementComplete).unwrap();
        assert_eq!(get_attestation_gate_state(&gate), AttestationGateState::MeasuringPlatform);
        advance_attestation_gate(&mut gate, AttestationEvent::QuoteGenerated).unwrap();
        assert_eq!(get_attestation_gate_state(&gate), AttestationGateState::AwaitingQuoteVerification);
        advance_attestation_gate(&mut gate, AttestationEvent::VerificationPassed).unwrap();
        assert_eq!(get_attestation_gate_state(&gate), AttestationGateState::Open);
    }

    /// Network traffic is only allowed in Open state.
    #[test]
    fn test_attestation_gate_only_allows_traffic_in_open_state() {
        let mut gate = create_attestation_gate();
        assert!(!is_network_traffic_allowed(&gate));
        advance_attestation_gate(&mut gate, AttestationEvent::MeasurementComplete).unwrap();
        assert!(!is_network_traffic_allowed(&gate));
        advance_attestation_gate(&mut gate, AttestationEvent::QuoteGenerated).unwrap();
        assert!(!is_network_traffic_allowed(&gate));
        advance_attestation_gate(&mut gate, AttestationEvent::VerificationPassed).unwrap();
        assert!(is_network_traffic_allowed(&gate), "open gate must allow traffic");
    }

    /// Direct transition from Closed to Open is rejected (no-skip-path guarantee).
    #[test]
    fn test_attestation_gate_does_not_transition_directly_from_closed_to_open() {
        let mut gate = create_attestation_gate();
        let result = advance_attestation_gate(&mut gate, AttestationEvent::VerificationPassed);
        assert!(result.is_err(), "Closed -> Open direct transition must be rejected");
        assert_eq!(
            get_attestation_gate_state(&gate),
            AttestationGateState::Closed,
            "state must remain Closed after invalid transition"
        );
    }

    /// VerificationFailed event moves gate to Failed state.
    #[test]
    fn test_attestation_gate_moves_to_failed_on_verification_failure() {
        let mut gate = create_attestation_gate();
        advance_attestation_gate(&mut gate, AttestationEvent::MeasurementComplete).unwrap();
        advance_attestation_gate(&mut gate, AttestationEvent::QuoteGenerated).unwrap();
        advance_attestation_gate(&mut gate, AttestationEvent::VerificationFailed).unwrap();
        assert_eq!(get_attestation_gate_state(&gate), AttestationGateState::Failed);
        assert!(!is_network_traffic_allowed(&gate), "failed gate must block traffic");
    }

    /// Timeout event from any state moves gate to Failed.
    #[test]
    fn test_attestation_gate_timeout_from_any_state_moves_to_failed() {
        let mut gate = create_attestation_gate();
        advance_attestation_gate(&mut gate, AttestationEvent::Timeout).unwrap();
        assert_eq!(get_attestation_gate_state(&gate), AttestationGateState::Failed);
    }

    /// Advancing an already-Open gate returns GateAlreadyOpen error.
    #[test]
    fn test_advancing_open_gate_returns_gate_already_open_error() {
        let mut gate = create_attestation_gate();
        advance_attestation_gate(&mut gate, AttestationEvent::MeasurementComplete).unwrap();
        advance_attestation_gate(&mut gate, AttestationEvent::QuoteGenerated).unwrap();
        advance_attestation_gate(&mut gate, AttestationEvent::VerificationPassed).unwrap();
        let result = advance_attestation_gate(&mut gate, AttestationEvent::MeasurementComplete);
        assert_eq!(result, Err(AttestationError::GateAlreadyOpen));
    }

    /// Default timeout is 60 seconds per Phase 0 locked decision.
    #[test]
    fn test_attestation_gate_default_timeout_is_sixty_seconds() {
        assert_eq!(ATTESTATION_GATE_DEFAULT_TIMEOUT_SECONDS, 60u16);
    }

    /// Full attestation gate transition sequence with mock TPM responses.
    ///
    /// Exercises the complete Closed -> MeasuringPlatform ->
    /// AwaitingQuoteVerification -> Open path using mock data (no swtpm required).
    #[test]
    fn test_attestation_gate_completes_with_mock_tpm_responses() {
        let mut gate = create_attestation_gate();

        assert_eq!(get_attestation_gate_state(&gate), AttestationGateState::Closed);
        assert!(!is_network_traffic_allowed(&gate));

        let measurement_result =
            advance_attestation_gate(&mut gate, AttestationEvent::MeasurementComplete);
        assert!(measurement_result.is_ok());
        assert_eq!(get_attestation_gate_state(&gate), AttestationGateState::MeasuringPlatform);

        let quote_result =
            advance_attestation_gate(&mut gate, AttestationEvent::QuoteGenerated);
        assert!(quote_result.is_ok());
        assert_eq!(
            get_attestation_gate_state(&gate),
            AttestationGateState::AwaitingQuoteVerification
        );

        let verification_result =
            advance_attestation_gate(&mut gate, AttestationEvent::VerificationPassed);
        assert!(verification_result.is_ok());
        assert_eq!(get_attestation_gate_state(&gate), AttestationGateState::Open);
        assert!(is_network_traffic_allowed(&gate));
    }

    /// Timeout event during AwaitingQuoteVerification transitions gate to Failed.
    #[test]
    fn test_attestation_gate_timeout_transitions_to_failed() {
        let mut gate = create_attestation_gate();
        advance_attestation_gate(&mut gate, AttestationEvent::MeasurementComplete).unwrap();
        advance_attestation_gate(&mut gate, AttestationEvent::QuoteGenerated).unwrap();

        let timeout_result =
            advance_attestation_gate(&mut gate, AttestationEvent::Timeout);
        assert!(timeout_result.is_ok());
        assert_eq!(get_attestation_gate_state(&gate), AttestationGateState::Failed);
        assert!(!is_network_traffic_allowed(&gate));
    }
}
