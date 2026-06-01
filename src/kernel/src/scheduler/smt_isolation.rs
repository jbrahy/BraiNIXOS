//! Domain compatibility check for simultaneous multithreading (SMT) siblings.
//!
//! The scheduler must not assign threads from different security domains to
//! sibling logical CPUs. In the single-core v1.0 configuration this guard
//! is always satisfied, but the architectural constraint must be present
//! for future SMP support (SCHED-03).

use super::SchedulerError;

/// Returns true if two threads may co-execute on sibling SMT logical CPUs.
///
/// Two threads are SMT-compatible only if they belong to the same security domain.
/// Cross-domain co-execution on sibling hyperthreads creates side channels.
/// Enforces SCHED-03.
pub fn are_threads_smt_compatible(domain_slot_a: u8, domain_slot_b: u8) -> bool {
    domain_slot_a == domain_slot_b
}

/// Checks whether scheduling a candidate thread would violate SMT isolation.
///
/// On single-core v1.0, sibling_cpu_domain_slot is always None so this returns
/// Ok(()) unconditionally. When SMP is introduced, the sibling slot is Some(slot)
/// and cross-domain scheduling returns Err(SmtIsolationViolation).
/// Enforces SCHED-03.
pub fn check_smt_isolation_for_scheduling(
    candidate_domain_slot: u8,
    sibling_cpu_domain_slot: Option<u8>,
) -> Result<(), SchedulerError> {
    match sibling_cpu_domain_slot {
        None => Ok(()),
        Some(sibling_slot) if sibling_slot == candidate_domain_slot => Ok(()),
        Some(_) => Err(SchedulerError::SmtIsolationViolation),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::SchedulerError;

    #[test]
    fn test_same_domain_threads_are_smt_compatible() {
        let compatible = are_threads_smt_compatible(3, 3);
        assert!(
            compatible,
            "threads in the same domain must be SMT-compatible"
        );
    }

    #[test]
    fn test_different_domain_threads_are_not_smt_compatible() {
        let compatible = are_threads_smt_compatible(1, 2);
        assert!(
            !compatible,
            "threads in different domains must not be SMT-compatible"
        );
    }

    #[test]
    fn test_check_smt_isolation_returns_ok_for_same_domain_pair() {
        let result = check_smt_isolation_for_scheduling(5, Some(5));
        assert_eq!(
            result,
            Ok(()),
            "same-domain pair must pass SMT isolation check"
        );
    }

    #[test]
    fn test_check_smt_isolation_returns_violation_for_cross_domain_pair() {
        let result = check_smt_isolation_for_scheduling(1, Some(2));
        assert_eq!(
            result,
            Err(SchedulerError::SmtIsolationViolation),
            "cross-domain pair must return SmtIsolationViolation"
        );
    }
}
