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

/// TCP connection state (passive open subset).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TcpState {
    Listen,
    SynReceived,
    Established,
    CloseWait,
    Closed,
}

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
        }
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
            return SegmentOutcome { response_length: None, delivered_length: 0 };
        }
        if view.flags & TCP_FLAG_RST != 0 {
            self.state = TcpState::Closed;
            return SegmentOutcome { response_length: None, delivered_length: 0 };
        }
        match self.state {
            TcpState::Listen => self.handle_listen(view, response_out),
            TcpState::SynReceived => self.handle_syn_received(view),
            TcpState::Established => {
                self.handle_established(view, inbound_payload, response_out, delivered_out)
            }
            TcpState::CloseWait | TcpState::Closed => {
                SegmentOutcome { response_length: None, delivered_length: 0 }
            }
        }
    }

    fn handle_listen(&mut self, view: &TcpSegmentView, response_out: &mut [u8]) -> SegmentOutcome {
        if view.flags & TCP_FLAG_SYN == 0 {
            return SegmentOutcome { response_length: None, delivered_length: 0 };
        }
        self.remote_port = view.source_port;
        self.receive_next = view.sequence_number.wrapping_add(1); // SYN occupies one seq
        let length = self.emit(TCP_FLAG_SYN | TCP_FLAG_ACK, &[], response_out);
        // SYN consumes one of our sequence numbers.
        self.send_next = self.send_next.wrapping_add(1);
        self.state = TcpState::SynReceived;
        SegmentOutcome { response_length: Some(length), delivered_length: 0 }
    }

    fn handle_syn_received(&mut self, view: &TcpSegmentView) -> SegmentOutcome {
        if view.flags & TCP_FLAG_ACK != 0 {
            self.state = TcpState::Established;
        }
        SegmentOutcome { response_length: None, delivered_length: 0 }
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
        } else if delivered_length > 0 {
            response_length = Some(self.emit(TCP_FLAG_ACK, &[], response_out));
        }
        SegmentOutcome { response_length, delivered_length }
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
    use super::{TcpConnection, TcpState};
    use crate::net::tcp::{parse_segment, TCP_FLAG_ACK, TCP_FLAG_PSH, TCP_FLAG_SYN};

    const LOCAL_IP: [u8; 4] = [10, 0, 2, 15];
    const REMOTE_IP: [u8; 4] = [10, 0, 2, 2];

    fn inbound(
        flags: u8,
        seq: u32,
        ack: u32,
        payload: &[u8],
        buffer: &mut [u8],
    ) -> usize {
        crate::net::tcp::build_segment(
            REMOTE_IP, LOCAL_IP, 40000, 22, seq, ack, flags, 64240, payload, buffer,
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
        let n = inbound(TCP_FLAG_ACK, 501, response_view.sequence_number + 1, &[], &mut seg);
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
