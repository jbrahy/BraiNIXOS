//! Thread representation for IPC and scheduler integration.
//!
//! `Thread` holds all scheduler-relevant fields (D-01). Phase 4 defines
//! the struct shape; Phase 5 wires up scheduling logic on top without
//! changing the struct layout.
//!
//! No cfg(target_arch) gate — pure Rust data types, host-testable.

/// The state of a kernel thread in the IPC and scheduler state machines.
///
/// Transitions (D-02): Ready -> Running -> Blocked -> Ready.
/// IPC performs Running->Blocked on send/receive with no partner,
/// and Blocked->Ready on rendezvous completion or timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    /// Thread is eligible to run but not currently executing.
    Ready,
    /// Thread is currently executing on the CPU.
    Running,
    /// Thread is waiting for an IPC rendezvous or a timeout to fire.
    Blocked,
}

/// Register save area for a thread's full x86-64 register state.
///
/// Saved during SYSCALL entry and restored on SYSRET/IRETQ exit.
/// Fields named by full register name per CODE_STANDARDS.md Rule 1.
#[derive(Debug, Clone, Copy, Default)]
pub struct RegisterSaveArea {
    pub register_rax: u64,
    pub register_rbx: u64,
    pub register_rcx: u64,
    pub register_rdx: u64,
    pub register_rdi: u64,
    pub register_rsi: u64,
    pub register_r8:  u64,
    pub register_r9:  u64,
    pub register_r10: u64,
    pub register_r11: u64,
    pub register_r12: u64,
    pub register_r13: u64,
    pub register_r14: u64,
    pub register_r15: u64,
    pub register_rbp: u64,
    pub register_rsp: u64,
}

/// A kernel thread with all IPC and scheduler-relevant fields (D-01).
///
/// Phase 4 defines this struct; Phase 5 adds scheduling logic on top
/// without changing the shape, avoiding a two-phase struct migration.
#[derive(Debug)]
pub struct Thread {
    /// Saved register state during SYSCALL trap.
    pub register_save_area: RegisterSaveArea,
    /// Absolute kernel tick at which this thread's timeout fires.
    /// Zero means the thread is not in a timed blocking operation.
    pub timeout_deadline_tick: u64,
    /// Current state in the Ready/Running/Blocked state machine.
    pub thread_state: ThreadState,
    /// Fixed priority for Phase 5 preemptive scheduler (higher = more urgent).
    pub priority: u8,
    /// CPU budget in scheduler ticks before preemption.
    pub cpu_budget_ticks: u64,
    /// Time partition domain slot assigned by the Phase 5 compile-time slot table.
    pub domain_slot: u8,
}

/// Returns a zeroed RegisterSaveArea with all registers set to zero.
const fn zeroed_register_save_area() -> RegisterSaveArea {
    RegisterSaveArea {
        register_rax: 0,
        register_rbx: 0,
        register_rcx: 0,
        register_rdx: 0,
        register_rdi: 0,
        register_rsi: 0,
        register_r8:  0,
        register_r9:  0,
        register_r10: 0,
        register_r11: 0,
        register_r12: 0,
        register_r13: 0,
        register_r14: 0,
        register_r15: 0,
        register_rbp: 0,
        register_rsp: 0,
    }
}

impl Thread {
    /// Returns a new thread in the Ready state with zeroed register save area.
    pub const fn new() -> Self {
        Thread {
            register_save_area: zeroed_register_save_area(),
            timeout_deadline_tick: 0,
            thread_state: ThreadState::Ready,
            priority: 0,
            cpu_budget_ticks: 0,
            domain_slot: 0,
        }
    }
}
