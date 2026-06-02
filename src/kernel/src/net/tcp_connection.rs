//! A minimal server-side TCP connection state machine (one connection).
//!
//! Drives the passive-open path: LISTEN -> SYN_RECEIVED -> ESTABLISHED, ACKs
//! inbound data, lets the application send data, and handles FIN teardown.
//! Pure logic over byte buffers (no hardware) so it is host-testable; the
//! kernel net loop wraps the TCP segments it produces in IPv4 + Ethernet.
//!
//! Scope: enough for an interactive byte stream (the SSH transport). Not a
//! full RFC 793 implementation — no out-of-order reassembly, no retransmit
//! queue (the peer retransmits; we re-ACK), single connection.

use crate::net::tcp::{
    build_segment, TcpSegmentView, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST,
    TCP_FLAG_SYN,
};

/// TCP connection state (passive open subset plus active open `SynSent`).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TcpState {
    Listen,
    /// Active open: our SYN has been sent, awaiting the peer's SYN-ACK.
    SynSent,
    SynReceived,
    Established,
    CloseWait,
    Closed,
}

/// Ticks (caller-driven poll iterations) between SYN retransmissions.
const SYN_RETRANSMIT_INTERVAL_TICKS: u64 = 2_000_000;

/// Maximum SYN retransmissions before the active open is abandoned (Closed).
const SYN_RETRANSMIT_MAXIMUM: u8 = 5;

/// A single passive TCP connection.
pub struct TcpConnection {
    state: TcpState,
    local_ipv4: [u8; 4],
    local_port: u16,
    remote_ipv4: [u8; 4],
    remote_port: u16,
    /// Next sequence number we will send.
    send_next: u32,
    /// Next sequence number we expect from the peer (what we acknowledge).
    receive_next: u32,
    /// SYN retransmissions performed so far (active open only).
    syn_retransmit_count: u8,
    /// Tick at which the SYN was last (re)sent (active open only).
    last_send_tick: u64,
}

/// What the caller should do after `on_segment`.
pub struct SegmentOutcome {
    /// Length of a response TCP segment written to the caller's buffer, if any.
    pub response_length: Option<usize>,
    /// Number of application bytes delivered into the caller's data buffer.
    pub delivered_length: usize,
}

impl TcpConnection {
    /// A connection listening on `local_port` at `local_ipv4`, with the given
    /// initial send sequence number.
    pub fn new_listening(local_ipv4: [u8; 4], local_port: u16, initial_sequence: u32) -> Self {
        Self {
            state: TcpState::Listen,
            local_ipv4,
            local_port,
            remote_ipv4: [0; 4],
            remote_port: 0,
            send_next: initial_sequence,
            receive_next: 0,
            syn_retransmit_count: 0,
            last_send_tick: 0,
        }
    }

    /// An active-open connection toward `remote_ipv4:remote_port` from
    /// `local_ipv4:local_port`, with the given client initial send sequence.
    /// Starts in `SynSent`; call [`start_connect`](Self::start_connect) to emit
    /// the first SYN.
    pub fn new_connecting(
        local_ipv4: [u8; 4],
        local_port: u16,
        remote_ipv4: [u8; 4],
        remote_port: u16,
        initial_sequence: u32,
    ) -> Self {
        Self {
            state: TcpState::SynSent,
            local_ipv4,
            local_port,
            remote_ipv4,
            remote_port,
            send_next: initial_sequence,
            receive_next: 0,
            syn_retransmit_count: 0,
            last_send_tick: 0,
        }
    }

    /// Emits the initial SYN for an active open into `out`. The SYN occupies
    /// sequence `send_next` (the ISN); `send_next` is advanced only once the
    /// peer's SYN-ACK completes the handshake. Returns the segment length.
    pub fn start_connect(&mut self, out: &mut [u8]) -> usize {
        self.last_send_tick = 0;
        self.emit(TCP_FLAG_SYN, &[], out)
    }

    /// If still in `SynSent` and the retransmit interval has elapsed, re-emits
    /// the SYN (same ISN) and returns its length; abandons the open (→ `Closed`)
    /// after [`SYN_RETRANSMIT_MAXIMUM`] attempts. Returns `None` otherwise.
    pub fn poll_retransmit(&mut self, current_tick: u64, out: &mut [u8]) -> Option<usize> {
        if self.state != TcpState::SynSent || !self.retransmit_interval_elapsed(current_tick) {
            return None;
        }
        if self.syn_retransmit_count >= SYN_RETRANSMIT_MAXIMUM {
            self.state = TcpState::Closed;
            return None;
        }
        Some(self.retransmit_syn(current_tick, out))
    }

    fn retransmit_interval_elapsed(&self, current_tick: u64) -> bool {
        current_tick.saturating_sub(self.last_send_tick) >= SYN_RETRANSMIT_INTERVAL_TICKS
    }

    fn retransmit_syn(&mut self, current_tick: u64, out: &mut [u8]) -> usize {
        self.syn_retransmit_count = self.syn_retransmit_count.saturating_add(1);
        self.last_send_tick = current_tick;
        self.emit(TCP_FLAG_SYN, &[], out)
    }

    pub fn state(&self) -> TcpState {
        self.state
    }

    pub fn remote_ipv4(&self) -> [u8; 4] {
        self.remote_ipv4
    }

    pub fn remote_port(&self) -> u16 {
        self.remote_port
    }

    /// Processes one inbound segment addressed to this connection. Writes any
    /// response segment to `response_out` (TCP segment, checksummed) and copies
    /// any newly-received application bytes to `delivered_out`.
    pub fn on_segment(
        &mut self,
        view: &TcpSegmentView,
        inbound_payload: &[u8],
        response_out: &mut [u8],
        delivered_out: &mut [u8],
    ) -> SegmentOutcome {
        if view.destination_port != self.local_port {
            return SegmentOutcome {
                response_length: None,
                delivered_length: 0,
            };
        }
        if view.flags & TCP_FLAG_RST != 0 && self.reset_is_from_peer(view) {
            self.state = TcpState::Closed;
            return SegmentOutcome {
                response_length: None,
                delivered_length: 0,
            };
        }
        match self.state {
            TcpState::Listen => self.handle_listen(view, response_out),
            TcpState::SynSent => self.handle_syn_sent(view, response_out),
            TcpState::SynReceived => self.handle_syn_received(view),
            TcpState::Established => {
                self.handle_established(view, inbound_payload, response_out, delivered_out)
            }
            TcpState::CloseWait | TcpState::Closed => SegmentOutcome {
                response_length: None,
                delivered_length: 0,
            },
        }
    }

    /// True if a RST should close us: from our known peer, or (before a peer is
    /// recorded, i.e. passive `Listen`) from anyone. An off-peer RST during an
    /// active open must not tear the connection down.
    fn reset_is_from_peer(&self, view: &TcpSegmentView) -> bool {
        self.remote_port == 0 || view.source_port == self.remote_port
    }

    /// Active-open `SynSent` handler: completes the three-way handshake on a
    /// SYN-ACK from our peer that acknowledges our SYN; ignores anything else.
    fn handle_syn_sent(
        &mut self,
        view: &TcpSegmentView,
        response_out: &mut [u8],
    ) -> SegmentOutcome {
        if view.source_port != self.remote_port {
            return SegmentOutcome {
                response_length: None,
                delivered_length: 0,
            };
        }
        self.complete_active_open(view, response_out)
    }

    fn complete_active_open(
        &mut self,
        view: &TcpSegmentView,
        response_out: &mut [u8],
    ) -> SegmentOutcome {
        if !self.is_acceptable_synack(view) {
            return SegmentOutcome {
                response_length: None,
                delivered_length: 0,
            };
        }
        self.receive_next = view.sequence_number.wrapping_add(1); // their SYN seq + 1
        self.send_next = self.send_next.wrapping_add(1); // our SYN consumed the ISN
        let length = self.emit(TCP_FLAG_ACK, &[], response_out);
        self.state = TcpState::Established;
        SegmentOutcome {
            response_length: Some(length),
            delivered_length: 0,
        }
    }

    fn is_acceptable_synack(&self, view: &TcpSegmentView) -> bool {
        let synack = TCP_FLAG_SYN | TCP_FLAG_ACK;
        view.flags & synack == synack
            && view.acknowledgment_number == self.send_next.wrapping_add(1)
    }

    fn handle_listen(&mut self, view: &TcpSegmentView, response_out: &mut [u8]) -> SegmentOutcome {
        if view.flags & TCP_FLAG_SYN == 0 {
            return SegmentOutcome {
                response_length: None,
                delivered_length: 0,
            };
        }
        self.remote_port = view.source_port;
        self.receive_next = view.sequence_number.wrapping_add(1); // SYN occupies one seq
        let length = self.emit(TCP_FLAG_SYN | TCP_FLAG_ACK, &[], response_out);
        // SYN consumes one of our sequence numbers.
        self.send_next = self.send_next.wrapping_add(1);
        self.state = TcpState::SynReceived;
        SegmentOutcome {
            response_length: Some(length),
            delivered_length: 0,
        }
    }

    fn handle_syn_received(&mut self, view: &TcpSegmentView) -> SegmentOutcome {
        if view.flags & TCP_FLAG_ACK != 0 {
            self.state = TcpState::Established;
        }
        SegmentOutcome {
            response_length: None,
            delivered_length: 0,
        }
    }

    fn handle_established(
        &mut self,
        view: &TcpSegmentView,
        inbound_payload: &[u8],
        response_out: &mut [u8],
        delivered_out: &mut [u8],
    ) -> SegmentOutcome {
        // Only accept in-order data at receive_next.
        let mut delivered_length = 0;
        if !inbound_payload.is_empty() && view.sequence_number == self.receive_next {
            delivered_length = inbound_payload.len().min(delivered_out.len());
            delivered_out[..delivered_length].copy_from_slice(&inbound_payload[..delivered_length]);
            self.receive_next = self.receive_next.wrapping_add(delivered_length as u32);
        }
        let mut response_length = None;
        if view.flags & TCP_FLAG_FIN != 0 {
            self.receive_next = self.receive_next.wrapping_add(1); // FIN occupies one seq
            self.state = TcpState::CloseWait;
            response_length = Some(self.emit(TCP_FLAG_ACK | TCP_FLAG_FIN, &[], response_out));
            self.send_next = self.send_next.wrapping_add(1);
        } else if !inbound_payload.is_empty() {
            // ACK every data-bearing segment with our current receive_next. For
            // accepted in-order data this advances the window; for a duplicate or
            // out-of-order segment it is a duplicate ACK that prompts the peer to
            // retransmit the byte we are actually missing (no reassembly buffer).
            response_length = Some(self.emit(TCP_FLAG_ACK, &[], response_out));
        }
        SegmentOutcome {
            response_length,
            delivered_length,
        }
    }

    /// Builds a data segment (PSH|ACK) carrying `data`, advancing our sequence.
    /// Returns the segment length. Only valid in ESTABLISHED.
    pub fn send_data(&mut self, data: &[u8], response_out: &mut [u8]) -> usize {
        let length = self.emit(TCP_FLAG_PSH | TCP_FLAG_ACK, data, response_out);
        self.send_next = self.send_next.wrapping_add(data.len() as u32);
        length
    }

    /// Builds an outgoing TCP segment with `flags` and `payload` using the
    /// current sequence/acknowledgment numbers.
    fn emit(&self, flags: u8, payload: &[u8], out: &mut [u8]) -> usize {
        build_segment(
            self.local_ipv4,
            self.remote_ipv4_or_zero(),
            self.local_port,
            self.remote_port,
            self.send_next,
            self.receive_next,
            flags,
            64240,
            payload,
            out,
        )
    }

    fn remote_ipv4_or_zero(&self) -> [u8; 4] {
        self.remote_ipv4
    }

    /// Records the peer's IPv4 address (the kernel loop sets this from the IP
    /// header before dispatching the first segment).
    pub fn set_remote_ipv4(&mut self, remote_ipv4: [u8; 4]) {
        self.remote_ipv4 = remote_ipv4;
    }
}

#[cfg(test)]
mod tests {
    use super::{TcpConnection, TcpState, SYN_RETRANSMIT_INTERVAL_TICKS, SYN_RETRANSMIT_MAXIMUM};
    use crate::net::tcp::{parse_segment, TCP_FLAG_ACK, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN};

    const LOCAL_IP: [u8; 4] = [10, 0, 2, 15];
    const REMOTE_IP: [u8; 4] = [10, 0, 2, 2];

    /// Our active-open ephemeral source port and the remote SSH port.
    const CLIENT_PORT: u16 = 0xC123;
    const SERVER_PORT: u16 = 22;
    const CLIENT_ISN: u32 = 0x0000_1000;

    fn inbound(flags: u8, seq: u32, ack: u32, payload: &[u8], buffer: &mut [u8]) -> usize {
        crate::net::tcp::build_segment(
            REMOTE_IP, LOCAL_IP, 40000, 22, seq, ack, flags, 64240, payload, buffer,
        )
    }

    /// An inbound segment from `source_port` to our `CLIENT_PORT` (active open).
    fn inbound_to_client(
        source_port: u16,
        flags: u8,
        seq: u32,
        ack: u32,
        buffer: &mut [u8],
    ) -> usize {
        crate::net::tcp::build_segment(
            REMOTE_IP,
            LOCAL_IP,
            source_port,
            CLIENT_PORT,
            seq,
            ack,
            flags,
            64240,
            &[],
            buffer,
        )
    }

    fn connecting() -> TcpConnection {
        TcpConnection::new_connecting(LOCAL_IP, CLIENT_PORT, REMOTE_IP, SERVER_PORT, CLIENT_ISN)
    }

    #[test]
    fn test_start_connect_emits_syn_at_isn() {
        let mut connection = connecting();
        let mut out = [0u8; 64];
        let length = connection.start_connect(&mut out);
        let syn = parse_segment(&out[..length]).unwrap();
        assert_eq!(syn.flags, TCP_FLAG_SYN);
        assert_eq!(syn.sequence_number, CLIENT_ISN);
        assert_eq!(syn.source_port, CLIENT_PORT);
        assert_eq!(syn.destination_port, SERVER_PORT);
        assert_eq!(connection.state(), TcpState::SynSent);
    }

    #[test]
    fn test_active_open_synack_completes_handshake() {
        let mut connection = connecting();
        let mut out = [0u8; 64];
        connection.start_connect(&mut out);
        let mut seg = [0u8; 64];
        // Server SYN-ACK: seq=S, ack=ISN+1 (acknowledges our SYN).
        let n = inbound_to_client(
            SERVER_PORT,
            TCP_FLAG_SYN | TCP_FLAG_ACK,
            9000,
            CLIENT_ISN + 1,
            &mut seg,
        );
        let view = parse_segment(&seg[..n]).unwrap();
        let mut response = [0u8; 64];
        let mut delivered = [0u8; 64];
        let outcome = connection.on_segment(&view, &[], &mut response, &mut delivered);
        assert_eq!(connection.state(), TcpState::Established);
        let ack = parse_segment(&response[..outcome.response_length.unwrap()]).unwrap();
        assert_eq!(ack.flags, TCP_FLAG_ACK);
        assert_eq!(ack.sequence_number, CLIENT_ISN + 1);
        assert_eq!(ack.acknowledgment_number, 9001);
    }

    #[test]
    fn test_active_open_rst_from_peer_refuses() {
        let mut connection = connecting();
        let mut out = [0u8; 64];
        connection.start_connect(&mut out);
        let mut seg = [0u8; 64];
        let n = inbound_to_client(SERVER_PORT, TCP_FLAG_RST, 0, CLIENT_ISN + 1, &mut seg);
        let view = parse_segment(&seg[..n]).unwrap();
        let mut response = [0u8; 64];
        let mut delivered = [0u8; 64];
        let outcome = connection.on_segment(&view, &[], &mut response, &mut delivered);
        assert_eq!(connection.state(), TcpState::Closed);
        assert!(outcome.response_length.is_none());
    }

    #[test]
    fn test_active_open_wrong_port_synack_ignored() {
        let mut connection = connecting();
        let mut out = [0u8; 64];
        connection.start_connect(&mut out);
        let mut seg = [0u8; 64];
        let n = inbound_to_client(
            2222,
            TCP_FLAG_SYN | TCP_FLAG_ACK,
            9000,
            CLIENT_ISN + 1,
            &mut seg,
        );
        let view = parse_segment(&seg[..n]).unwrap();
        let mut response = [0u8; 64];
        let mut delivered = [0u8; 64];
        let outcome = connection.on_segment(&view, &[], &mut response, &mut delivered);
        assert_eq!(connection.state(), TcpState::SynSent);
        assert!(outcome.response_length.is_none());
    }

    #[test]
    fn test_active_open_offport_rst_ignored() {
        let mut connection = connecting();
        let mut out = [0u8; 64];
        connection.start_connect(&mut out);
        let mut seg = [0u8; 64];
        let n = inbound_to_client(2222, TCP_FLAG_RST, 0, CLIENT_ISN + 1, &mut seg);
        let view = parse_segment(&seg[..n]).unwrap();
        let mut response = [0u8; 64];
        let mut delivered = [0u8; 64];
        connection.on_segment(&view, &[], &mut response, &mut delivered);
        assert_eq!(connection.state(), TcpState::SynSent);
    }

    #[test]
    fn test_active_open_synack_not_acking_our_syn_ignored() {
        let mut connection = connecting();
        let mut out = [0u8; 64];
        connection.start_connect(&mut out);
        let mut seg = [0u8; 64];
        // ack wrong (not ISN+1) -> stale/forged; ignore.
        let n = inbound_to_client(
            SERVER_PORT,
            TCP_FLAG_SYN | TCP_FLAG_ACK,
            9000,
            CLIENT_ISN + 99,
            &mut seg,
        );
        let view = parse_segment(&seg[..n]).unwrap();
        let mut response = [0u8; 64];
        let mut delivered = [0u8; 64];
        connection.on_segment(&view, &[], &mut response, &mut delivered);
        assert_eq!(connection.state(), TcpState::SynSent);
    }

    #[test]
    fn test_syn_retransmit_after_interval() {
        let mut connection = connecting();
        let mut out = [0u8; 64];
        connection.start_connect(&mut out);
        assert!(connection
            .poll_retransmit(SYN_RETRANSMIT_INTERVAL_TICKS - 1, &mut out)
            .is_none());
        let length = connection
            .poll_retransmit(SYN_RETRANSMIT_INTERVAL_TICKS, &mut out)
            .unwrap();
        let syn = parse_segment(&out[..length]).unwrap();
        assert_eq!(syn.flags, TCP_FLAG_SYN);
        assert_eq!(syn.sequence_number, CLIENT_ISN);
    }

    #[test]
    fn test_syn_retransmit_gives_up_and_closes() {
        let mut connection = connecting();
        let mut out = [0u8; 64];
        connection.start_connect(&mut out);
        let mut tick = 0u64;
        for _ in 0..SYN_RETRANSMIT_MAXIMUM {
            tick += SYN_RETRANSMIT_INTERVAL_TICKS;
            assert!(connection.poll_retransmit(tick, &mut out).is_some());
        }
        tick += SYN_RETRANSMIT_INTERVAL_TICKS;
        assert!(connection.poll_retransmit(tick, &mut out).is_none());
        assert_eq!(connection.state(), TcpState::Closed);
    }

    #[test]
    fn test_active_open_then_send_and_receive_data() {
        let mut connection = connecting();
        let mut out = [0u8; 128];
        connection.start_connect(&mut out);
        let mut seg = [0u8; 128];
        let n = inbound_to_client(
            SERVER_PORT,
            TCP_FLAG_SYN | TCP_FLAG_ACK,
            9000,
            CLIENT_ISN + 1,
            &mut seg,
        );
        let view = parse_segment(&seg[..n]).unwrap();
        let mut response = [0u8; 128];
        let mut delivered = [0u8; 128];
        connection.on_segment(&view, &[], &mut response, &mut delivered);
        // Send a byte stream out.
        let length = connection.send_data(b"SSH-2.0-X", &mut response);
        let sent = parse_segment(&response[..length]).unwrap();
        assert_eq!(sent.sequence_number, CLIENT_ISN + 1);
        assert_eq!(&response[sent.payload_offset..length], b"SSH-2.0-X");
        // Receive inbound data at receive_next (9001).
        let payload = b"hi";
        let n = inbound_to_client_data(SERVER_PORT, 9001, payload, &mut seg);
        let view = parse_segment(&seg[..n]).unwrap();
        let outcome = connection.on_segment(
            &view,
            &seg[view.payload_offset..n],
            &mut response,
            &mut delivered,
        );
        assert_eq!(outcome.delivered_length, 2);
        assert_eq!(&delivered[..2], b"hi");
    }

    fn inbound_to_client_data(
        source_port: u16,
        seq: u32,
        payload: &[u8],
        buffer: &mut [u8],
    ) -> usize {
        crate::net::tcp::build_segment(
            REMOTE_IP,
            LOCAL_IP,
            source_port,
            CLIENT_PORT,
            seq,
            CLIENT_ISN + 1,
            TCP_FLAG_PSH | TCP_FLAG_ACK,
            64240,
            payload,
            buffer,
        )
    }

    #[test]
    fn test_passive_open_and_data_echo() {
        let mut connection = TcpConnection::new_listening(LOCAL_IP, 22, 0x1000);
        connection.set_remote_ipv4(REMOTE_IP);

        // 1) Inbound SYN -> expect SYN-ACK, state SYN_RECEIVED.
        let mut seg = [0u8; 128];
        let n = inbound(TCP_FLAG_SYN, 500, 0, &[], &mut seg);
        let view = parse_segment(&seg[..n]).unwrap();
        let mut response = [0u8; 128];
        let mut delivered = [0u8; 128];
        let outcome = connection.on_segment(&view, &[], &mut response, &mut delivered);
        assert_eq!(connection.state(), TcpState::SynReceived);
        let response_view = parse_segment(&response[..outcome.response_length.unwrap()]).unwrap();
        assert_eq!(response_view.flags, TCP_FLAG_SYN | TCP_FLAG_ACK);
        assert_eq!(response_view.acknowledgment_number, 501); // peer SYN seq + 1

        // 2) Inbound ACK -> ESTABLISHED.
        let n = inbound(
            TCP_FLAG_ACK,
            501,
            response_view.sequence_number + 1,
            &[],
            &mut seg,
        );
        let view = parse_segment(&seg[..n]).unwrap();
        connection.on_segment(&view, &[], &mut response, &mut delivered);
        assert_eq!(connection.state(), TcpState::Established);

        // 3) Inbound data "hi" -> delivered, ACK emitted.
        let payload = b"hi";
        let n = inbound(
            TCP_FLAG_PSH | TCP_FLAG_ACK,
            501,
            response_view.sequence_number + 1,
            payload,
            &mut seg,
        );
        let view = parse_segment(&seg[..n]).unwrap();
        let data_payload = &seg[view.payload_offset..n];
        let outcome = connection.on_segment(&view, data_payload, &mut response, &mut delivered);
        assert_eq!(outcome.delivered_length, 2);
        assert_eq!(&delivered[..2], b"hi");
        assert!(outcome.response_length.is_some());

        // 4) Echo it back.
        let length = connection.send_data(b"hi", &mut response);
        let echoed = parse_segment(&response[..length]).unwrap();
        assert_eq!(echoed.flags, TCP_FLAG_PSH | TCP_FLAG_ACK);
        assert_eq!(&response[echoed.payload_offset..length], b"hi");
    }
}
