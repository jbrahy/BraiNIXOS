//! CPU feature detection, decoded from the identification registers.
//!
//! Pure functions over register *values*, like `aarch64_ident`, so the decode
//! is host-testable while the `mrs` that produces the value is not.
//!
//! # Why detection is separate from use
//!
//! Every field here gates something the kernel would otherwise assume. A kernel
//! that uses `RNDR` on a part without `FEAT_RNG` takes an undefined-instruction
//! exception at the first call for entropy -- during early boot, before the
//! console, on a platform where that is indistinguishable from a hang. Reading
//! the field costs nothing and cannot fault.

/// Whether the hardware random number generator is present.
///
/// `ID_AA64ISAR0_EL1.RNDR`, bits [63:60]. `0b0001` means `RNDR` and `RNDRRS`
/// exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomSupport {
    /// `RNDR` and `RNDRRS` are implemented.
    pub present: bool,
}

impl RandomSupport {
    /// Decode from `ID_AA64ISAR0_EL1`.
    pub fn from_isar0(value: u64) -> Self {
        Self {
            present: (value >> 60) & 0xF == 0b0001,
        }
    }
}

/// Pointer authentication and branch-target identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlFlowSupport {
    /// Address authentication, QARMA5 (`ID_AA64ISAR1_EL1.APA`, bits [7:4]).
    pub address_auth_qarma: bool,
    /// Address authentication, implementation defined
    /// (`ID_AA64ISAR1_EL1.API`, bits [11:8]). **This is the Apple one.**
    pub address_auth_impdef: bool,
    /// Generic authentication, QARMA5 (`GPA`, bits [27:24]).
    pub generic_auth_qarma: bool,
    /// Generic authentication, implementation defined (`GPI`, bits [31:28]).
    pub generic_auth_impdef: bool,
    /// Branch target identification (`ID_AA64PFR1_EL1.BT`, bits [3:0]).
    pub branch_target_identification: bool,
}

impl ControlFlowSupport {
    /// Decode from `ID_AA64ISAR1_EL1` and `ID_AA64PFR1_EL1`.
    ///
    /// The two implementation-defined fields matter more than they look. Apple
    /// implements pointer authentication with its own algorithm, so a kernel
    /// that checks only the QARMA fields concludes PAC is absent on hardware
    /// that has it, and silently gives up a mitigation it could have had.
    pub fn from_id_registers(isar1: u64, pfr1: u64) -> Self {
        Self {
            address_auth_qarma: (isar1 >> 4) & 0xF != 0,
            address_auth_impdef: (isar1 >> 8) & 0xF != 0,
            generic_auth_qarma: (isar1 >> 24) & 0xF != 0,
            generic_auth_impdef: (isar1 >> 28) & 0xF != 0,
            branch_target_identification: pfr1 & 0xF != 0,
        }
    }

    /// Whether any form of address authentication is available.
    pub fn address_auth(&self) -> bool {
        self.address_auth_qarma || self.address_auth_impdef
    }
}
