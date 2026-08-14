//! The one rule with no exception: break-glass is untouchable.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::cognitive_complexity)]

use brainix_bsp::{CredentialRole, LEN_HANDLE};
use brainix_servd::credentials::{CredentialPolicyError, EnrollmentPolicy, Transport};

const BREAK_GLASS: [u8; LEN_HANDLE] = [0xBE; LEN_HANDLE];
const ORDINARY: [u8; LEN_HANDLE] = [0x01; LEN_HANDLE];

fn policy() -> EnrollmentPolicy {
    EnrollmentPolicy::protecting(BREAK_GLASS)
}

#[test]
fn neither_enrollment_nor_revocation_may_touch_the_break_glass_handle() {
    // A compromised admin session can enroll keys, revoke keys, replace the
    // weights and reboot the machine. What bounds that compromise is exactly
    // this: it cannot lock the owner out.
    for role in [CredentialRole::Client, CredentialRole::Admin] {
        assert_eq!(
            policy().may_enroll(&BREAK_GLASS, role),
            Err(CredentialPolicyError::BreakGlassIsUntouchable)
        );
    }
    assert_eq!(
        policy().may_revoke(&BREAK_GLASS),
        Err(CredentialPolicyError::BreakGlassIsUntouchable)
    );
}

#[test]
fn ordinary_credentials_enroll_and_revoke_in_both_roles() {
    for role in [CredentialRole::Client, CredentialRole::Admin] {
        assert!(policy().may_enroll(&ORDINARY, role).is_ok());
    }
    assert!(policy().may_revoke(&ORDINARY).is_ok());
}

#[test]
fn the_break_glass_credential_never_authenticates_over_the_network() {
    // Row K5, and it is refused before any chain resolution, so a replayed
    // break-glass hello costs the server nothing beyond the scan.
    assert_eq!(
        policy().may_authenticate(&BREAK_GLASS, Transport::Network),
        Err(CredentialPolicyError::BreakGlassOnNetwork)
    );
    assert!(policy()
        .may_authenticate(&BREAK_GLASS, Transport::Serial)
        .is_ok());
}

#[test]
fn ordinary_credentials_authenticate_on_either_transport() {
    for transport in [Transport::Network, Transport::Serial] {
        assert!(policy().may_authenticate(&ORDINARY, transport).is_ok());
    }
}

#[test]
fn the_check_is_on_the_derived_handle_not_on_a_name_the_requester_supplied() {
    // An attacker who could pick the handle by picking the key material would
    // otherwise collide with break-glass deliberately. `may_enroll` takes what
    // enrollment produced, so choosing the material chooses nothing.
    assert!(policy().is_break_glass(&BREAK_GLASS));
    assert!(!policy().is_break_glass(&ORDINARY));

    let mut near_miss = BREAK_GLASS;
    near_miss[LEN_HANDLE - 1] ^= 0x01;
    assert!(!policy().is_break_glass(&near_miss));
    assert!(policy()
        .may_enroll(&near_miss, CredentialRole::Client)
        .is_ok());
}

#[test]
fn a_policy_protecting_a_different_handle_protects_that_one_and_no_other() {
    // The policy holds a handle rather than a rule about handles: there is no
    // pattern, no prefix, and nothing an operator can widen by accident.
    let other = EnrollmentPolicy::protecting(ORDINARY);
    assert_eq!(
        other.may_revoke(&ORDINARY),
        Err(CredentialPolicyError::BreakGlassIsUntouchable)
    );
    assert!(other.may_revoke(&BREAK_GLASS).is_ok());
}
