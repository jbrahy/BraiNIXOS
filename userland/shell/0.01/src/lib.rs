//! BraiNIX userspace shell (v0.01 skeleton).
//!
//! This crate is the capability-native shell for BraiNIX. It is written from
//! scratch in Rust no_std and must not depend on any POSIX-style surface:
//! no fork, exec, pipes, file descriptors, signals, or tty ioctls. All
//! interaction with the outside world flows through explicit IPC endpoint
//! capabilities held in the shell process's CSpace.
//!
//! Status at v0.01: skeleton only. The console IPC contract, capability
//! slot indices, and entry point shape are declared, but no parser, no
//! builtins, no line editing, and no console server wiring exist yet.
//!
//! Enforces invariant INV-AUTH-001: the shell holds no ambient authority.
//! Every effect the shell performs is reached through an explicit capability
//! granted by the spawner at process creation time.
#![no_std]
#![deny(unsafe_code)]
