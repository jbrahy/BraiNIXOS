//! CPU topology, checked against the tree read off the target.
//!
//! The fixture is the real ADT from the M2 Pro (`Mac14,12`, `J474s`), and the
//! numbers below were independently confirmed by reading the live machine
//! through m1n1's proxy. A parser tested only against a tree this repository
//! invented would confirm nothing about Apple's layout.

#![cfg(not(target_os = "none"))]

use brainix_kernel::aarch64_cpus::{
    cpus, first_waiting_cpu, running_cpu, start_core_bit, start_enable_bit, Cpu,
};

static REAL_ADT: &[u8] = include_bytes!("../../adt/tests/fixtures/mac14-12-j474s-adt.bin");

fn all() -> ([Cpu; 16], usize) {
    let mut list = [Cpu::default(); 16];
    let found = cpus(REAL_ADT, &mut list);
    (list, found)
}

#[test]
fn the_machine_has_ten_cores() {
    let (_, found) = all();
    assert_eq!(found, 10, "M2 Pro: four E cores and six P cores");
}

#[test]
fn exactly_one_core_is_running() {
    let (list, found) = all();
    let running: Vec<_> = list[..found].iter().filter(|c| c.running).collect();
    assert_eq!(running.len(), 1, "the tree names exactly one running core");
    assert_eq!(running[0].cpu_id, 0);
}

#[test]
fn cpu_ids_skip_seven() {
    // Not a parser bug and not a typo. The hardware has ten cores; the
    // numbering has a gap. A parser that "fixed" this by indexing sequentially
    // would address the wrong core's registers from cpu8 onward.
    let (list, found) = all();
    let ids: Vec<u32> = list[..found].iter().map(|c| c.cpu_id).collect();
    assert_eq!(ids, vec![0, 1, 2, 3, 4, 5, 6, 8, 9, 10]);
}

#[test]
fn reg_encodes_the_cluster_and_cpu_id_does_not() {
    // cpu4 has id 4 and reg 0x100. Using one where the other is meant picks a
    // different core, and both are small integers that look interchangeable.
    let (list, found) = all();
    let regs: Vec<u64> = list[..found].iter().map(|c| c.reg).collect();
    assert_eq!(
        regs,
        vec![0, 1, 2, 3, 0x100, 0x101, 0x102, 0x200, 0x201, 0x202]
    );
}

#[test]
fn the_clusters_are_one_efficiency_and_two_performance() {
    let (list, found) = all();
    let clusters: Vec<u32> = list[..found].iter().map(|c| c.cluster).collect();
    assert_eq!(clusters, vec![0, 0, 0, 0, 1, 1, 1, 2, 2, 2]);
    let cores: Vec<u32> = list[..found].iter().map(|c| c.core).collect();
    assert_eq!(cores, vec![0, 1, 2, 3, 0, 1, 2, 0, 1, 2]);
}

#[test]
fn impl_registers_match_what_was_read_from_the_live_machine() {
    // Confirmed over the proxy, not derived from the stride: cpu0 0x210050000,
    // then 0x100000 per core, and the P clusters step by 0x1000000.
    let (list, _) = all();
    assert_eq!(list[0].impl_reg, 0x2_1005_0000);
    assert_eq!(list[1].impl_reg, 0x2_1015_0000);
    assert_eq!(list[2].impl_reg, 0x2_1025_0000);
    assert_eq!(list[4].impl_reg, 0x2_1105_0000);
    assert_eq!(list[7].impl_reg, 0x2_1205_0000);
}

#[test]
fn the_first_waiting_core_is_cpu1() {
    let (list, found) = all();
    let waiting = first_waiting_cpu(&list[..found]).expect("nine cores are waiting");
    assert_eq!(waiting.cpu_id, 1);
    assert_eq!(
        waiting.cluster, 0,
        "an E core, in the same cluster as the boot core"
    );
    assert_eq!(waiting.impl_reg, 0x2_1015_0000);
}

#[test]
fn the_running_core_is_found_by_state_not_by_position() {
    let (list, found) = all();
    let running = running_cpu(&list[..found]).expect("one core is running");
    assert_eq!(running.cpu_id, 0);
    assert!(running.running);
}

#[test]
fn start_bits_follow_four_bits_of_core_per_cluster() {
    // cpu1: cluster 0, core 1 -> enable bit 1, core bit 1.
    // cpu4: cluster 1, core 0 -> enable bit 4, core bit 0.
    let (list, _) = all();
    assert_eq!(start_enable_bit(&list[1]), 1 << 1);
    assert_eq!(start_core_bit(&list[1]), 1 << 1);
    assert_eq!(start_enable_bit(&list[4]), 1 << 4);
    assert_eq!(start_core_bit(&list[4]), 1 << 0);
    assert_eq!(start_enable_bit(&list[7]), 1 << 8);
}

#[test]
fn a_short_output_slice_truncates_rather_than_failing() {
    let mut list = [Cpu::default(); 3];
    assert_eq!(cpus(REAL_ADT, &mut list), 3);
    assert_eq!(list[2].cpu_id, 2);
}

#[test]
fn a_tree_without_cpus_yields_nothing() {
    let mut list = [Cpu::default(); 16];
    assert_eq!(cpus(&[0u8; 64], &mut list), 0);
    assert_eq!(cpus(&[], &mut list), 0);
}
