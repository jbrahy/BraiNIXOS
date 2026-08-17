//! The CPU topology, read out of the Apple Device Tree.
//!
//! Pure over a byte slice, so it is host-testable against the real tree read off
//! the target. Same split as `aarch64_devices` and `aarch64_entropy`: the
//! parsing is a function over bytes, and the MMIO that starts a core lives in
//! `arch::aarch64::smp`.
//!
//! # What the tree says about this machine
//!
//! Ten cores, and nine of them are marked `waiting`:
//!
//! | node | `reg` | cluster | type | state |
//! | --- | --- | --- | --- | --- |
//! | cpu0 | `0x000` | 0 | E | **running** |
//! | cpu1-3 | `0x001`-`0x003` | 0 | E | waiting |
//! | cpu4-6 | `0x100`-`0x102` | 1 | P | waiting |
//! | cpu8-10 | `0x200`-`0x202` | 2 | P | waiting |
//!
//! `cpu-id` skips 7. The numbering has a gap; the hardware does not.
//!
//! # Which core am I?
//!
//! By the `state` property, not by `MPIDR`. That looks backwards and is what
//! XNU does, and m1n1 copied it with the comment "this seems silly but it's what
//! XNU does". The reason it is right: `MPIDR` gives an affinity encoding that
//! still has to be matched against the tree to mean anything, and the tree
//! already answers the question directly. Exactly one node says `running`, and
//! it is the node describing whoever is asking.
//!
//! # `cpu-impl-reg` is per core and is the reset vector
//!
//! Each core has an MMIO window -- `0x210050000` for cpu0 on this part, stride
//! `0x100000` -- whose first 64-bit word holds `RVBAR`: bits 43:12 are the
//! address a released core begins executing at, and bit 0 is a lock.
//!
//! **Not** `GENMASK(47, 12)`, which is the mask m1n1 uses. Bits 47:44 carry
//! die/cluster/core identity on this part and read back unchanged whatever is
//! written to them, so a mask that includes them makes a successful write look
//! like a rejected one. Measured: writing `0x90ace0000` reads back as
//! `0x001110090ace0000` -- address taken, identity preserved, lock cleared.

use brainix_adt::DeviceTree;

/// Bits 43:12 of the reset-vector register: the address a core starts at.
pub const RVBAR_ADDRESS: u64 = 0x0000_0FFF_FFFF_F000;
/// Bit 0 of the reset-vector register. Cleared by a successful write.
pub const RVBAR_LOCK: u64 = 1;

/// Offset from the PMGR base to the CPU start registers, on T6020.
///
/// SoC-specific and reverse-engineered; every Apple part has a different one.
/// Taken from m1n1's `CPU_START_OFF_T6020`.
pub const CPU_START_OFFSET_T6020: u64 = 0x28000;

/// One core, as the tree describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Cpu {
    /// `cpu-id`. Not an index: this machine's ids skip 7.
    pub cpu_id: u32,
    /// `reg`, which encodes cluster in bits [10:8] and core in [7:0].
    pub reg: u64,
    /// `die-id`.
    pub die: u32,
    /// `cluster-id`.
    pub cluster: u32,
    /// `cluster-core-id`: position within the cluster, which is what the start
    /// register's bit position is derived from.
    pub core: u32,
    /// Base of the `cpu-impl-reg` window, holding `RVBAR`.
    pub impl_reg: u64,
    /// Whether `state` reads `running`. True for exactly one core.
    pub running: bool,
}

/// Fill `out` with the cores described by `adt_blob`, returning how many.
///
/// Stops at `out.len()` rather than failing, because a caller that only wants
/// the first few should not have to size for a part it has never seen.
pub fn cpus(adt_blob: &[u8], out: &mut [Cpu]) -> usize {
    let Ok(tree) = DeviceTree::parse(adt_blob) else {
        return 0;
    };
    let Ok(node) = tree.find_node(b"/cpus") else {
        return 0;
    };
    let Ok(children) = node.children() else {
        return 0;
    };

    let mut found = 0usize;
    for child in children {
        // The iterator yields a `Result` per node: a malformed child ends the
        // walk rather than being skipped, because a parse error means the
        // offsets after it are no longer trustworthy.
        let Ok(child) = child else {
            break;
        };
        let Some(slot) = out.get_mut(found) else {
            break;
        };
        let Some(cpu) = parse_cpu(&child) else {
            continue;
        };
        *slot = cpu;
        found = found.saturating_add(1);
    }
    found
}

/// Read one `u32` property, or a default.
fn u32_property(node: &brainix_adt::Node<'_>, name: &[u8], default: u32) -> u32 {
    match node.find_property(name) {
        Ok(Some(property)) => property.as_u32().unwrap_or(default),
        _ => default,
    }
}

/// The first 64-bit value of `cpu-impl-reg`: the register window's base.
///
/// The property is an (address, size) pair and only the address is wanted. It
/// is **not** under `/arm-io`, so it needs no `ranges` translation -- the
/// address is already physical.
fn impl_reg_base(node: &brainix_adt::Node<'_>) -> u64 {
    let Ok(Some(property)) = node.find_property(b"cpu-impl-reg") else {
        return 0;
    };
    let Some(bytes) = property.value().get(0..8) else {
        return 0;
    };
    let mut buffer = [0u8; 8];
    buffer.copy_from_slice(bytes);
    u64::from_le_bytes(buffer)
}

/// Decode one `/cpus` child, or `None` if it does not identify a core.
fn parse_cpu(node: &brainix_adt::Node<'_>) -> Option<Cpu> {
    // `cpu-id` first, `reg` as the fallback, which is the order m1n1 uses.
    // They differ on this machine: cpu4's id is 4 and its reg is 0x100, and
    // using one where the other is meant addresses a different core.
    let cpu_id = match node.find_property(b"cpu-id") {
        Ok(Some(property)) => property.as_u32().ok()?,
        _ => match node.find_property(b"reg") {
            Ok(Some(property)) => property.as_u32().ok()?,
            _ => return None,
        },
    };

    let running = match node.find_property(b"state") {
        Ok(Some(property)) => property.value().starts_with(b"running"),
        _ => false,
    };

    Some(Cpu {
        cpu_id,
        reg: u64::from(u32_property(node, b"reg", 0)),
        die: u32_property(node, b"die-id", 0),
        cluster: u32_property(node, b"cluster-id", 0),
        core: u32_property(node, b"cluster-core-id", 0),
        impl_reg: impl_reg_base(node),
        running,
    })
}

/// The core currently executing, identified the way XNU does it.
pub fn running_cpu(list: &[Cpu]) -> Option<Cpu> {
    list.iter().copied().find(|cpu| cpu.running)
}

/// The first core that is not running, i.e. a candidate to release.
pub fn first_waiting_cpu(list: &[Cpu]) -> Option<Cpu> {
    list.iter().copied().find(|cpu| !cpu.running)
}

/// Bit to set in the CPU start register for `cpu`.
///
/// `1 << (4 * cluster + core)` for the enable word, per m1n1. Four bits of core
/// per cluster, which is why a five-core cluster would need a different formula
/// and why this is asserted against the tree rather than assumed.
pub fn start_enable_bit(cpu: &Cpu) -> u32 {
    1u32
        .checked_shl(cpu.cluster.saturating_mul(4).saturating_add(cpu.core))
        .unwrap_or(0)
}

/// Bit to set in the per-cluster start word for `cpu`.
pub fn start_core_bit(cpu: &Cpu) -> u32 {
    1u32.checked_shl(cpu.core).unwrap_or(0)
}
