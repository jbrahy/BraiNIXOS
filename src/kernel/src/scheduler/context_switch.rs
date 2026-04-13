//! Thread selection and state transitions for context switching.
//!
//! Contains pure logic for selecting the next thread to run and performing
//! Ready/Running/Blocked state transitions. Hardware-specific register
//! save and restore lives in arch/ under the unsafe allowlist.
