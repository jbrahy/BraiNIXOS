//! Runtime enrollment policy: what may be enrolled, and what may never be
//! touched (P2-T12, part).
//!
//! `brainix-transport-crypto` already owns the cryptography — `Credential::enroll`
//! runs §5.2 over 32 bytes and destroys them, `CredentialTable` scans and
//! revokes, and `ChainState` is the ratchet. What it does not own is the
//! **policy**: which enrollments are permitted, which are refused
//! unconditionally, and which path a request arrived on. That is `servd`'s, and
//! this module is it.
//!
//! # The one rule that has no exception
//!
//! The break-glass credential is provisioned over the serial console and
//! authenticates over the serial transport **and nowhere else**
//! (`INV-BOOT-008`). Two consequences, and both are enforced here rather than
//! documented:
//!
//! - `enroll` and `revoke` refuse that handle **unconditionally and
//!   non-configurably**, so a compromised admin session cannot revoke the
//!   owner's way back in;
//! - the network listener refuses it outright at authentication, before any
//!   chain resolution, which is [`Transport::Network`] here.
//!
//! Together those mean the worst an admin compromise achieves is bounded: it
//! can enroll keys, revoke other keys, replace the weights and reboot the
//! machine — and it cannot lock the owner out. Physical presence at the serial
//! console wins, which is the property the whole break-glass design exists for.
//!
//! # No secret ever enters a build artifact
//!
//! Nothing here has a default key, a test key, or a seed. `enroll` takes
//! material from its caller and `Credential::enroll` destroys it. A compiled-in
//! secret would break the reproducible-build clause of `INV-BOOT` in the way
//! the north star names precisely: either the published payload contains the
//! secret, or the deployed payload differs from the published one, and
//! reproducibility that describes an image nobody runs is not reproducibility.

use brainix_bsp::{CredentialRole, LEN_HANDLE};

/// Which transport a request arrived on.
///
/// Carried explicitly rather than inferred, because the whole point is that two
/// requests with identical contents are treated differently depending on where
/// they came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// The network listener: the authenticated BSP socket.
    Network,
    /// The serial console, which grants physical-access authority.
    Serial,
}

/// Why an enrollment or revocation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialPolicyError {
    /// The request names the break-glass handle. Refused on every transport,
    /// unconditionally (`INV-BOOT-008`).
    BreakGlassIsUntouchable,
    /// A break-glass credential was offered to the network listener, which
    /// refuses it outright before any chain resolution (row K5).
    BreakGlassOnNetwork,
}

/// The policy layer over the credential table.
///
/// Holds no key material: the break-glass *handle* is not a secret — it is what
/// the audit record names — and holding it is what lets every path refuse it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrollmentPolicy {
    break_glass: [u8; LEN_HANDLE],
}

impl EnrollmentPolicy {
    /// A policy protecting `break_glass`.
    #[must_use]
    pub const fn protecting(break_glass: [u8; LEN_HANDLE]) -> Self {
        Self { break_glass }
    }

    /// Whether this handle is the one nothing may touch.
    #[must_use]
    pub fn is_break_glass(&self, handle: &[u8; LEN_HANDLE]) -> bool {
        // Ordinary comparison: the break-glass handle is not secret, so there
        // is nothing here for a timing side channel to learn. The constant-time
        // comparisons in this system are over key material, and calling for one
        // where no secret exists would blur the distinction that makes the real
        // ones legible.
        handle == &self.break_glass
    }

    /// Whether an enrollment may proceed.
    ///
    /// `derived_handle` is what `Credential::enroll` produced from the caller's
    /// material — so the check is on the *result*, not on a name the requester
    /// supplied. An attacker who could pick the handle by picking the material
    /// would otherwise be able to collide with break-glass deliberately.
    ///
    /// # Errors
    ///
    /// [`CredentialPolicyError::BreakGlassIsUntouchable`] if the derived handle
    /// is the break-glass one.
    pub fn may_enroll(
        &self,
        derived_handle: &[u8; LEN_HANDLE],
        _role: CredentialRole,
    ) -> Result<(), CredentialPolicyError> {
        if self.is_break_glass(derived_handle) {
            return Err(CredentialPolicyError::BreakGlassIsUntouchable);
        }
        Ok(())
    }

    /// Whether a revocation may proceed.
    ///
    /// # Errors
    ///
    /// [`CredentialPolicyError::BreakGlassIsUntouchable`] for the break-glass
    /// handle, on every transport and with no configuration that changes it.
    pub fn may_revoke(&self, handle: &[u8; LEN_HANDLE]) -> Result<(), CredentialPolicyError> {
        if self.is_break_glass(handle) {
            return Err(CredentialPolicyError::BreakGlassIsUntouchable);
        }
        Ok(())
    }

    /// Whether a credential may authenticate on this transport.
    ///
    /// Row K5: the break-glass credential authenticates over serial alone. The
    /// network listener refuses it **before any chain resolution**, so a
    /// replayed break-glass `ClientHello` costs the server nothing beyond the
    /// scan every hello costs.
    ///
    /// # Errors
    ///
    /// [`CredentialPolicyError::BreakGlassOnNetwork`] for the break-glass
    /// credential arriving over the network.
    pub fn may_authenticate(
        &self,
        handle: &[u8; LEN_HANDLE],
        transport: Transport,
    ) -> Result<(), CredentialPolicyError> {
        if self.is_break_glass(handle) && matches!(transport, Transport::Network) {
            return Err(CredentialPolicyError::BreakGlassOnNetwork);
        }
        Ok(())
    }
}
