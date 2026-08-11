//! The §5.5 state machine and the §10.2 request phase, exhaustively.
//!
//! Two obligations are discharged here:
//!
//! 1. **Every legal transition is walked** and lands where §5.5 says.
//! 2. **Every illegal transition denies**, with the specific reason, and — when
//!    §12 makes it a Drop — leaves the session closed rather than merely
//!    returning an error the caller might ignore.
//!
//! The (state × message) grid is enumerated rather than sampled. A guard that
//! is only exercised on the paths someone thought of is a guard whose other
//! paths are untested by construction.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cognitive_complexity,
    clippy::useless_vec
)]

mod common;

use brainix_bsp::{
    BspError, Disposition, InboundMessage, RequestPhase, Session, SessionState, SessionType,
    MAX_PROMPT_BYTES,
};
use common::{
    all_six_verbs, cancel, close, collecting, established, infer_begin, infer_commit, prompt_chunk,
    streaming, valid_client_auth, valid_client_hello,
};

/// Every state a session can be in, together with a session already there.
fn every_state() -> Vec<(SessionState, Session)> {
    let mut wait_client_auth = Session::new();
    wait_client_auth
        .accept_client_hello(&valid_client_hello())
        .unwrap();

    let mut auth_pending = wait_client_auth;
    auth_pending
        .accept_client_auth(&valid_client_auth())
        .unwrap();

    let mut closed = Session::new();
    closed.close();

    vec![
        (SessionState::WaitHello, Session::new()),
        (SessionState::WaitClientAuth, wait_client_auth),
        (SessionState::AuthPending, auth_pending),
        (SessionState::Established, established(SessionType::Client)),
        (SessionState::Closed, closed),
    ]
}

// ---------------------------------------------------------------------------
// Legal transitions
// ---------------------------------------------------------------------------

#[test]
fn the_handshake_walks_its_three_legal_transitions_in_order() {
    let mut session = Session::new();
    assert_eq!(session.state(), SessionState::WaitHello);
    assert_eq!(session.session_type(), None);

    session.accept_client_hello(&valid_client_hello()).unwrap();
    assert_eq!(session.state(), SessionState::WaitClientAuth);
    assert_eq!(session.session_type(), None, "no grant before ESTABLISHED");

    session.accept_client_auth(&valid_client_auth()).unwrap();
    assert_eq!(session.state(), SessionState::AuthPending);
    assert_eq!(
        session.session_type(),
        None,
        "decoding ClientAuth is not verifying it"
    );

    session.establish(SessionType::Admin).unwrap();
    assert_eq!(session.state(), SessionState::Established);
    assert_eq!(session.session_type(), Some(SessionType::Admin));
}

#[test]
fn both_capability_grants_are_reachable_and_neither_converts() {
    for granted in [SessionType::Client, SessionType::Admin] {
        let session = established(granted);
        assert_eq!(session.session_type(), Some(granted));
    }
}

#[test]
fn every_legal_request_phase_transition_lands_where_the_spec_says() {
    // Idle -> Collecting
    let mut session = established(SessionType::Client);
    session.accept_message(&infer_begin(4, 1, 0, 0, 8)).unwrap();
    assert_eq!(
        session.request_phase(),
        RequestPhase::Collecting {
            request_id: 4,
            declared_length: 8,
            accumulated_length: 0,
        }
    );

    // Collecting -> Collecting, accumulating exactly
    session.accept_message(&prompt_chunk(4, b"abcd")).unwrap();
    assert_eq!(
        session.request_phase(),
        RequestPhase::Collecting {
            request_id: 4,
            declared_length: 8,
            accumulated_length: 4,
        }
    );

    // Collecting -> Streaming
    session.accept_message(&prompt_chunk(4, b"efgh")).unwrap();
    session.accept_message(&infer_commit(4)).unwrap();
    assert_eq!(
        session.request_phase(),
        RequestPhase::Streaming { request_id: 4 }
    );

    // Streaming -> Idle
    session.accept_message(&cancel(4)).unwrap();
    assert_eq!(session.request_phase(), RequestPhase::Idle);

    // Idle -> Collecting again: the slot is genuinely reusable.
    session.accept_message(&infer_begin(5, 1, 0, 0, 0)).unwrap();
    assert_eq!(
        session.request_phase(),
        RequestPhase::Collecting {
            request_id: 5,
            declared_length: 0,
            accumulated_length: 0,
        }
    );

    // A zero-length prompt commits immediately: accumulated == declared == 0.
    session.accept_message(&infer_commit(5)).unwrap();
    assert_eq!(
        session.request_phase(),
        RequestPhase::Streaming { request_id: 5 }
    );
}

#[test]
fn cancel_is_legal_while_collecting_as_well_as_while_streaming() {
    let mut session = collecting(11, 16);
    session.accept_message(&cancel(11)).unwrap();
    assert_eq!(session.request_phase(), RequestPhase::Idle);
    assert_eq!(session.state(), SessionState::Established);
}

#[test]
fn close_is_legal_in_every_request_phase() {
    let sessions = [
        established(SessionType::Client),
        collecting(1, 16),
        streaming(2),
        established(SessionType::Admin),
    ];
    for mut session in sessions {
        let phase = session.request_phase();
        if session.session_type() == Some(SessionType::Client) {
            session.accept_message(&close()).unwrap();
            assert_eq!(session.state(), SessionState::Closed, "from {phase:?}");
            assert_eq!(session.request_phase(), RequestPhase::Idle);
        }
    }
}

// ---------------------------------------------------------------------------
// Illegal transitions — the handshake guards
// ---------------------------------------------------------------------------

#[test]
fn a_client_hello_mid_session_denies() {
    // There is no renegotiation in BSP. A second handshake on a live channel
    // could only be an attempt to reset one.
    for (state, mut session) in every_state() {
        if state == SessionState::WaitHello {
            continue;
        }
        let reason = session
            .accept_client_hello(&valid_client_hello())
            .unwrap_err();
        assert_eq!(
            reason,
            BspError::HandshakeMessageInWrongState,
            "from {state:?}"
        );
        assert_eq!(reason.disposition(), Disposition::Drop);
        assert_eq!(session.state(), SessionState::Closed, "from {state:?}");
    }
}

#[test]
fn a_client_auth_outside_wait_client_auth_denies() {
    for (state, mut session) in every_state() {
        if state == SessionState::WaitClientAuth {
            continue;
        }
        let reason = session
            .accept_client_auth(&valid_client_auth())
            .unwrap_err();
        assert_eq!(
            reason,
            BspError::HandshakeMessageInWrongState,
            "from {state:?}"
        );
        assert_eq!(session.state(), SessionState::Closed, "from {state:?}");
    }
}

#[test]
fn establishing_before_client_auth_denies() {
    // §7.2: the grant happens at exactly one transition. This is the guard that
    // makes every other route to a capability unreachable.
    for (state, mut session) in every_state() {
        if state == SessionState::AuthPending {
            continue;
        }
        let reason = session.establish(SessionType::Admin).unwrap_err();
        assert_eq!(
            reason,
            BspError::EstablishBeforeAuthentication,
            "from {state:?}"
        );
        assert_eq!(session.session_type(), None, "from {state:?}");
        assert_eq!(session.state(), SessionState::Closed, "from {state:?}");
    }
}

#[test]
fn a_request_before_the_keys_exist_denies() {
    // Pre-key bytes must never reach the message decoder: §11's whole argument
    // is that an unauthenticated attacker cannot reach §10 parsing.
    for (state, mut session) in every_state() {
        if state == SessionState::Established || state == SessionState::Closed {
            continue;
        }
        let reason = session
            .accept_message(&infer_begin(1, 1, 0, 0, 0))
            .unwrap_err();
        assert_eq!(
            reason,
            BspError::DataMessageBeforeEstablished,
            "from {state:?}"
        );
        assert_eq!(session.state(), SessionState::Closed, "from {state:?}");
    }
}

#[test]
fn every_message_on_a_closed_session_denies() {
    let mut session = established(SessionType::Client);
    session.close();
    for payload in [infer_begin(1, 1, 0, 0, 0), close(), cancel(1)] {
        let mut closed = session;
        assert_eq!(
            closed.accept_message(&payload).unwrap_err(),
            BspError::SessionClosed
        );
    }
}

#[test]
fn close_is_idempotent_and_reachable_from_every_state() {
    for (state, mut session) in every_state() {
        session.close();
        assert_eq!(session.state(), SessionState::Closed, "from {state:?}");
        assert_eq!(session.session_type(), None);
        assert_eq!(session.request_phase(), RequestPhase::Idle);
        session.close();
        assert_eq!(
            session.state(),
            SessionState::Closed,
            "twice from {state:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Illegal transitions — the tag partition, enforced by the granted capability
// ---------------------------------------------------------------------------

#[test]
fn an_admin_verb_on_a_client_session_denies_and_drops() {
    for verb in all_six_verbs() {
        let mut session = established(SessionType::Client);
        let reason = session.accept_message(&verb).unwrap_err();
        assert_eq!(
            reason,
            BspError::WrongSessionTypeRange,
            "verb {:#04x}",
            verb[0]
        );
        assert_eq!(session.state(), SessionState::Closed);
    }
}

#[test]
fn a_client_request_on_an_admin_session_denies_and_drops() {
    // No prompt can reach the admin verb set, and no admin session can run
    // inference: `CapServe` never derives `CapAdmin` and neither converts.
    for payload in [
        infer_begin(1, 1, 0, 0, 0),
        prompt_chunk(1, b"x"),
        infer_commit(1),
        cancel(1),
        close(),
    ] {
        let mut session = established(SessionType::Admin);
        let reason = session.accept_message(&payload).unwrap_err();
        assert_eq!(
            reason,
            BspError::WrongSessionTypeRange,
            "tag {:#04x}",
            payload[0]
        );
        assert_eq!(session.state(), SessionState::Closed);
    }
}

#[test]
fn an_admin_session_stays_established_across_every_verb() {
    let mut session = established(SessionType::Admin);
    for verb in all_six_verbs() {
        assert!(matches!(
            session.accept_message(&verb).unwrap(),
            InboundMessage::Admin(_)
        ));
    }
    assert_eq!(session.state(), SessionState::Established);
}

// ---------------------------------------------------------------------------
// Rows M6..M10 — the request phase grid
// ---------------------------------------------------------------------------

#[test]
fn a_second_infer_begin_while_a_request_is_in_flight_answers_and_keeps() {
    for mut session in [collecting(1, 16), streaming(2)] {
        let phase = session.request_phase();
        let reason = session
            .accept_message(&infer_begin(99, 1, 0, 0, 0))
            .unwrap_err();
        assert_eq!(reason, BspError::RequestAlreadyInFlight, "from {phase:?}");
        assert_eq!(reason.disposition(), Disposition::ErrorKeep);
        assert_eq!(session.state(), SessionState::Established);
        assert_eq!(session.request_phase(), phase, "phase must not advance");
    }
}

#[test]
fn a_prompt_chunk_outside_collecting_answers_and_keeps() {
    for mut session in [established(SessionType::Client), streaming(2)] {
        let phase = session.request_phase();
        let reason = session
            .accept_message(&prompt_chunk(2, b"abc"))
            .unwrap_err();
        assert_eq!(reason, BspError::MessageInvalidInState, "from {phase:?}");
        assert_eq!(session.state(), SessionState::Established);
        assert_eq!(session.request_phase(), phase);
    }
}

#[test]
fn an_infer_commit_outside_collecting_answers_and_keeps() {
    for mut session in [established(SessionType::Client), streaming(2)] {
        let phase = session.request_phase();
        assert_eq!(
            session.accept_message(&infer_commit(2)).unwrap_err(),
            BspError::MessageInvalidInState
        );
        assert_eq!(session.request_phase(), phase);
    }
}

#[test]
fn a_cancel_while_idle_answers_and_keeps() {
    let mut session = established(SessionType::Client);
    assert_eq!(
        session.accept_message(&cancel(1)).unwrap_err(),
        BspError::MessageInvalidInState
    );
    assert_eq!(session.request_phase(), RequestPhase::Idle);
    assert_eq!(session.state(), SessionState::Established);
}

#[test]
fn a_request_id_that_is_not_the_open_one_answers_and_keeps() {
    // §10.1: the comparison is scoped to this slot, so a garbage value cannot
    // reach another session — there is no path along which it could travel.
    let mut session = collecting(7, 16);
    for stranger in [0u32, 6, 8, u32::MAX] {
        let reason = session
            .accept_message(&prompt_chunk(stranger, b"abc"))
            .unwrap_err();
        assert_eq!(reason, BspError::RequestIdMismatch, "id {stranger}");
        assert_eq!(session.state(), SessionState::Established);
        assert_eq!(
            session.request_phase(),
            RequestPhase::Collecting {
                request_id: 7,
                declared_length: 16,
                accumulated_length: 0,
            },
            "nothing accumulates on a mismatch"
        );
    }

    let mut live = streaming(7);
    assert_eq!(
        live.accept_message(&cancel(8)).unwrap_err(),
        BspError::RequestIdMismatch
    );
    assert_eq!(
        live.request_phase(),
        RequestPhase::Streaming { request_id: 7 }
    );
}

#[test]
fn a_prompt_chunk_past_the_declared_length_drops() {
    // Row M8: a declared-length lie is an attack, not an over-limit request.
    let mut session = collecting(3, 4);
    let reason = session
        .accept_message(&prompt_chunk(3, b"abcde"))
        .unwrap_err();
    assert_eq!(reason, BspError::PromptChunkExceedsDeclaredLength);
    assert_eq!(reason.disposition(), Disposition::Drop);
    assert_eq!(session.state(), SessionState::Closed);
}

#[test]
fn a_running_total_past_the_declared_length_drops_on_the_chunk_that_crosses_it() {
    let mut session = collecting(3, 8);
    session.accept_message(&prompt_chunk(3, b"abcd")).unwrap();
    assert_eq!(
        session.request_phase(),
        RequestPhase::Collecting {
            request_id: 3,
            declared_length: 8,
            accumulated_length: 4,
        }
    );
    assert_eq!(
        session
            .accept_message(&prompt_chunk(3, b"efghi"))
            .unwrap_err(),
        BspError::PromptChunkExceedsDeclaredLength
    );
    assert_eq!(session.state(), SessionState::Closed);
}

#[test]
fn a_chunk_that_exactly_fills_the_declared_length_is_accepted() {
    let mut session = collecting(3, 8);
    session
        .accept_message(&prompt_chunk(3, b"abcdefgh"))
        .unwrap();
    assert_eq!(
        session.request_phase(),
        RequestPhase::Collecting {
            request_id: 3,
            declared_length: 8,
            accumulated_length: 8,
        }
    );
}

#[test]
fn the_prompt_buffer_bound_holds_at_the_ceiling() {
    // The declared length may be exactly MAX_PROMPT_BYTES, so the last chunk
    // lands exactly on the buffer bound and must be accepted, while one byte
    // more must not.
    let mut session = collecting(1, MAX_PROMPT_BYTES);
    let mut sent = 0u32;
    while sent < MAX_PROMPT_BYTES {
        let this_chunk = ((MAX_PROMPT_BYTES - sent) as usize).min(brainix_bsp::MAX_PROMPT_CHUNK);
        session
            .accept_message(&prompt_chunk(1, &vec![0u8; this_chunk]))
            .unwrap();
        sent += this_chunk as u32;
    }
    assert_eq!(
        session.request_phase(),
        RequestPhase::Collecting {
            request_id: 1,
            declared_length: MAX_PROMPT_BYTES,
            accumulated_length: MAX_PROMPT_BYTES,
        }
    );
    assert_eq!(
        session.accept_message(&prompt_chunk(1, b"x")).unwrap_err(),
        BspError::PromptChunkExceedsDeclaredLength
    );
    assert_eq!(session.state(), SessionState::Closed);
}

#[test]
fn an_infer_commit_with_the_wrong_accumulated_total_answers_and_keeps() {
    let mut session = collecting(6, 8);
    session.accept_message(&prompt_chunk(6, b"abcd")).unwrap();
    let reason = session.accept_message(&infer_commit(6)).unwrap_err();
    assert_eq!(reason, BspError::PromptIncomplete);
    assert_eq!(reason.disposition(), Disposition::ErrorKeep);
    assert_eq!(session.state(), SessionState::Established);
    assert_eq!(
        session.request_phase(),
        RequestPhase::Collecting {
            request_id: 6,
            declared_length: 8,
            accumulated_length: 4,
        },
        "the request stays open so the client can finish sending"
    );

    // Finishing the prompt afterwards still works: Error+keep really keeps.
    session.accept_message(&prompt_chunk(6, b"efgh")).unwrap();
    session.accept_message(&infer_commit(6)).unwrap();
    assert_eq!(
        session.request_phase(),
        RequestPhase::Streaming { request_id: 6 }
    );
}

// ---------------------------------------------------------------------------
// The whole grid
// ---------------------------------------------------------------------------

#[test]
fn every_message_in_every_request_phase_has_a_defined_outcome() {
    // Nine (phase × message) pairs, every one of them asserted. A pair that is
    // legal advances; a pair that is not denies with its named reason and never
    // advances the phase.
    let expectations: Vec<(&str, RequestPhase, u8, Option<BspError>)> = vec![
        ("idle/begin", RequestPhase::Idle, 0x01, None),
        (
            "idle/chunk",
            RequestPhase::Idle,
            0x02,
            Some(BspError::MessageInvalidInState),
        ),
        (
            "idle/commit",
            RequestPhase::Idle,
            0x03,
            Some(BspError::MessageInvalidInState),
        ),
        (
            "idle/cancel",
            RequestPhase::Idle,
            0x04,
            Some(BspError::MessageInvalidInState),
        ),
        (
            "collecting/begin",
            RequestPhase::Collecting {
                request_id: 1,
                declared_length: 8,
                accumulated_length: 0,
            },
            0x01,
            Some(BspError::RequestAlreadyInFlight),
        ),
        (
            "collecting/chunk",
            RequestPhase::Collecting {
                request_id: 1,
                declared_length: 8,
                accumulated_length: 0,
            },
            0x02,
            None,
        ),
        (
            "collecting/commit",
            RequestPhase::Collecting {
                request_id: 1,
                declared_length: 8,
                accumulated_length: 0,
            },
            0x03,
            Some(BspError::PromptIncomplete),
        ),
        (
            "collecting/cancel",
            RequestPhase::Collecting {
                request_id: 1,
                declared_length: 8,
                accumulated_length: 0,
            },
            0x04,
            None,
        ),
        (
            "streaming/begin",
            RequestPhase::Streaming { request_id: 1 },
            0x01,
            Some(BspError::RequestAlreadyInFlight),
        ),
        (
            "streaming/chunk",
            RequestPhase::Streaming { request_id: 1 },
            0x02,
            Some(BspError::MessageInvalidInState),
        ),
        (
            "streaming/commit",
            RequestPhase::Streaming { request_id: 1 },
            0x03,
            Some(BspError::MessageInvalidInState),
        ),
        (
            "streaming/cancel",
            RequestPhase::Streaming { request_id: 1 },
            0x04,
            None,
        ),
    ];

    for (name, phase, tag, expected) in expectations {
        let mut session = match phase {
            RequestPhase::Idle => established(SessionType::Client),
            RequestPhase::Collecting { .. } => collecting(1, 8),
            RequestPhase::Streaming { .. } => streaming(1),
        };
        assert_eq!(session.request_phase(), phase, "{name} setup");

        let payload = match tag {
            0x01 => infer_begin(1, 1, 0, 0, 8),
            0x02 => prompt_chunk(1, b"abcd"),
            0x03 => infer_commit(1),
            _ => cancel(1),
        };
        let outcome = session.accept_message(&payload);
        match expected {
            None => {
                outcome.unwrap_or_else(|reason| panic!("{name} must be legal, got {reason:?}"));
            }
            Some(reason) => {
                assert_eq!(outcome.unwrap_err(), reason, "{name}");
                assert_eq!(session.request_phase(), phase, "{name} must not advance");
            }
        }
    }
}
