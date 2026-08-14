//! The auditor's manifest: the whole of `INV-AUDIT`'s proof.
//!
//! The threat model does not hedge about how this invariant is upheld: *"the
//! auditor's frozen capability manifest is the proof. It physically cannot name
//! the capabilities it lacks, so it cannot spawn, mutate the kernel, or reach
//! the network regardless of what its model decides."*
//!
//! So the invariant is a list, and the list is here, countable. Its violation
//! would not be a bug in the auditor's logic — there is no logic that could
//! violate it — but an entry in this array that should not be.
//!
//! # Why "its compromise costs visibility, never privilege"
//!
//! Read the list and the sentence follows. An attacker who owns `auditd`
//! entirely gains: the ability to read the audit log, and the ability to stop
//! reporting. It gains no spawn, no kernel mutation, no network, and no session
//! — so it can blind the operator and can do nothing else. That is a real loss
//! and a bounded one, and the bound is this array's length.

/// One capability in the auditor's manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestEntry {
    /// What the capability names.
    pub subject: &'static str,
    /// Why observing requires it.
    pub because: &'static str,
}

/// `auditd`'s manifest: **two capabilities**, and neither confers authority
/// over anything but reading.
pub const MANIFEST: [ManifestEntry; 2] = [
    ManifestEntry {
        subject: "CapAuditRead (read-only)",
        because: "reading the log is the whole of what an observer does",
    },
    ManifestEntry {
        subject: "CapEndpoint -> servd (receive-only, serving events)",
        because: "events arrive; nothing is sent back, so observing grants no authority to act",
    },
];

/// Capabilities the auditor must never hold, in `INV-AUD-002`'s own terms.
///
/// "Audit consumers do not become omnipotent": the component that reads or
/// exports audit data must not automatically gain broad system authority,
/// because audit pipelines accidentally become privileged chokepoints.
pub const FORBIDDEN_SUBJECTS: [&str; 5] = ["spawn", "kernel", "network", "capadmin", "capserve"];

/// Whether the manifest names any authority to *write* the log.
///
/// It does not, and that is `INV-AUD-001`'s integrity clause: an auditor that
/// could write its own log could erase the record of its own compromise.
#[must_use]
pub fn holds_write_authority() -> bool {
    // `no_std`: there is no owned String to lowercase into, so the comparison
    // is over the byte patterns this crate actually writes above.
    MANIFEST
        .iter()
        .any(|entry| entry.subject.contains("write") || entry.subject.contains("Write"))
}
