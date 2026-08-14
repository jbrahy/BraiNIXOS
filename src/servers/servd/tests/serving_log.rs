//! Non-interference: no session's read ever returns another session's row.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
#![allow(clippy::cognitive_complexity)]

use brainix_bsp::MAX_SESSIONS;
use brainix_servd::serving_log::{LogRow, ServingLog, LOG_CAPACITY};

fn blank_row() -> LogRow {
    LogRow {
        session_slot: usize::MAX,
        event_tag: 0,
        sequence: 0,
    }
}

#[test]
fn a_fresh_log_is_empty() {
    let log = ServingLog::new();
    assert!(log.is_empty());
    assert_eq!(log.len(), 0);
    assert_eq!(ServingLog::default().len(), 0);
}

#[test]
fn a_read_returns_only_the_readers_own_rows() {
    let mut log = ServingLog::new();
    for slot in 0..MAX_SESSIONS {
        log.append(slot, slot as u8).expect("admissible slot");
        log.append(slot, (slot as u8).wrapping_add(100))
            .expect("admissible slot");
    }

    for slot in 0..MAX_SESSIONS {
        let mut out = [blank_row(); LOG_CAPACITY];
        let written = log.read(slot, &mut out);
        assert_eq!(written, 2, "each session wrote two rows");
        for row in &out[..written] {
            assert_eq!(
                row.session_slot, slot,
                "a read returned another session's row"
            );
        }
    }
}

#[test]
fn rows_come_back_oldest_first_and_carry_their_sequence() {
    let mut log = ServingLog::new();
    let first = log.append(3, 1).expect("admissible");
    log.append(4, 9).expect("admissible");
    let second = log.append(3, 2).expect("admissible");

    let mut out = [blank_row(); 4];
    let written = log.read(3, &mut out);
    assert_eq!(written, 2);
    assert_eq!(out[0].sequence, first);
    assert_eq!(out[1].sequence, second);
    assert!(out[0].sequence < out[1].sequence);
}

#[test]
fn a_row_for_a_slot_the_server_cannot_admit_is_refused() {
    // A row nothing could ever read back would only mislead.
    let mut log = ServingLog::new();
    assert_eq!(log.append(MAX_SESSIONS, 1), None);
    assert_eq!(log.append(usize::MAX, 1), None);
    assert!(log.is_empty());
}

#[test]
fn a_full_log_overwrites_its_oldest_row_rather_than_refusing_new_ones() {
    // The honest trade: losing the oldest event is a known cost, and refusing
    // new ones would let one noisy session blind the trail for everybody else.
    let mut log = ServingLog::new();
    for index in 0..LOG_CAPACITY + 10 {
        log.append(1, index as u8).expect("admissible");
    }
    assert_eq!(log.len(), LOG_CAPACITY);

    let mut out = [blank_row(); LOG_CAPACITY];
    let written = log.read(1, &mut out);
    assert_eq!(written, LOG_CAPACITY);
    // Every surviving row is this session's, and the earliest sequences are the
    // ones that went.
    for row in &out[..written] {
        assert_eq!(row.session_slot, 1);
        assert!(row.sequence >= 10);
    }
}

#[test]
fn an_output_buffer_smaller_than_the_result_is_filled_and_not_overrun() {
    let mut log = ServingLog::new();
    for index in 0..8 {
        log.append(2, index).expect("admissible");
    }
    let mut out = [blank_row(); 3];
    assert_eq!(log.read(2, &mut out), 3);
    for row in &out {
        assert_eq!(row.session_slot, 2);
    }
}

#[test]
fn teardown_forgets_a_sessions_rows_so_the_next_occupant_cannot_read_them() {
    // Slot reuse again, in a different table: rows outliving their session
    // would be readable by whoever takes the slot next.
    let mut log = ServingLog::new();
    log.append(5, 1).expect("admissible");
    log.append(6, 2).expect("admissible");

    log.forget_session(5);

    let mut out = [blank_row(); 4];
    assert_eq!(
        log.read(5, &mut out),
        0,
        "the departed session's rows are gone"
    );
    assert_eq!(log.read(6, &mut out), 1, "its neighbour's are untouched");
    assert_eq!(log.len(), 1);
}

#[test]
fn reading_as_a_session_that_wrote_nothing_returns_nothing() {
    let mut log = ServingLog::new();
    log.append(0, 1).expect("admissible");
    let mut out = [blank_row(); 4];
    assert_eq!(log.read(7, &mut out), 0);
}
