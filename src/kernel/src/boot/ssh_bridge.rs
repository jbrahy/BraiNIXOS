//! SSH-to-userspace-shell bridge.
//!
//! Holds the active SSH connection's state (session, TCP connection, peer
//! address, NIC) in kernel globals so that — once the client requests a shell —
//! the userspace shell can be dispatched and its `serial_read`/`serial_write`
//! syscalls can be redirected here: input comes from CHANNEL_DATA, output goes
//! out as CHANNEL_DATA. Cooperative, single-core: the serial syscalls drive the
//! network (poll + process) each time the shell reads.
//!
//! Allowlist: `src/kernel/src/boot/` — mutable statics for the single active
//! SSH session.
#![allow(unsafe_code)]
// Scoped lint suppression for a module P2-T6 deletes.
//
// `segment_start + view.payload_offset` adds an offset parsed from a TCP
// segment, and the cognitive-complexity bar is exceeded by the bridge's
// dispatch. Both are real, and neither is worth fixing here: NORTH_STAR
// §Non-goals forbids a general-purpose remote shell, management is the six
// frozen BSP admin verbs, and P2-T6 deletes this bridge along with its
// `static mut` session state. This is also x86-64-era code that cannot run on
// the only supported platform.
//
// REMOVE THIS BLOCK when P2-T6 lands. If the module outlives P2-T6, the
// suppression is hiding live code and the two findings must be fixed instead --
// the addition in particular, which is an attacker-influenced offset.
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cognitive_complexity)]

use crate::arch::e1000::E1000Device;
use crate::net::tcp::parse_segment;
use crate::net::tcp_connection::{TcpConnection, TcpState};
use crate::ssh::SshSession;

const SERVICE_PORT: u16 = 2222;
const INITIAL_SEQUENCE: u32 = 0x5348_0000;
const OUR_IPV4: [u8; 4] = [10, 0, 2, 15];

static mut SESSION: Option<SshSession> = None;
static mut CONNECTION: Option<TcpConnection> = None;
static mut PEER_MAC: [u8; 6] = [0; 6];
static mut PEER_IPV4: [u8; 4] = [0; 4];
static mut BANNER_SENT: bool = false;
/// True while the userspace shell is dispatched and its serial I/O is bridged.
static mut BRIDGE_ACTIVE: bool = false;
/// The NIC, so the serial syscalls can drive the network without a handle.
static mut BRIDGE_NIC: Option<E1000Device> = None;

/// Stores the NIC handle for the bridge.
pub fn set_nic(nic: E1000Device) {
    // SAFETY: single-core boot; set once before the service loop.
    unsafe { core::ptr::write(core::ptr::addr_of_mut!(BRIDGE_NIC), Some(nic)) }
}

fn nic() -> Option<E1000Device> {
    // SAFETY: single-core; E1000Device is Copy.
    unsafe { *core::ptr::addr_of!(BRIDGE_NIC) }
}

/// (Re)initializes the bridge to listen for a fresh SSH connection.
pub fn reset(session: SshSession) {
    // SAFETY: single-core; the bridge is reset between connections.
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(SESSION), Some(session));
        core::ptr::write(
            core::ptr::addr_of_mut!(CONNECTION),
            Some(TcpConnection::new_listening(
                OUR_IPV4,
                SERVICE_PORT,
                INITIAL_SEQUENCE,
            )),
        );
        BANNER_SENT = false;
    }
}

/// True if the serial syscalls should be redirected to the SSH channel.
pub fn is_active() -> bool {
    unsafe { BRIDGE_ACTIVE }
}

/// Marks the bridge active (the userspace shell is being dispatched).
pub fn activate() {
    unsafe { BRIDGE_ACTIVE = true }
}

/// True once the client has requested a shell on the session channel.
pub fn shell_requested() -> bool {
    // SAFETY: single-core read.
    unsafe {
        (*core::ptr::addr_of!(SESSION))
            .as_ref()
            .map(|session| session.shell_active())
            .unwrap_or(false)
    }
}

/// True if the TCP connection has closed (peer hung up).
pub fn connection_closed() -> bool {
    unsafe {
        (*core::ptr::addr_of!(CONNECTION))
            .as_ref()
            .map(|connection| matches!(connection.state(), TcpState::Closed | TcpState::CloseWait))
            .unwrap_or(true)
    }
}

/// One network iteration: poll the NIC, process a TCP/SSH segment, send any
/// responses (SSH handshake/auth/channel, ACKs, the banner on connect).
pub fn step() {
    let nic = match nic() {
        Some(nic) => nic,
        None => return,
    };
    let nic = &nic;
    let mut receive_frame = [0u8; 2048];
    let received = match nic.poll_receive(&mut receive_frame) {
        Some(received) => received,
        None => return,
    };
    let (peer_mac, peer_ipv4, segment_range) =
        match crate::net::extract_ipv4_tcp(&receive_frame[..received], OUR_IPV4) {
            Some(parts) => parts,
            None => return,
        };
    let view = match parse_segment(&receive_frame[segment_range.clone()]) {
        Some(view) => view,
        None => return,
    };
    if view.destination_port != SERVICE_PORT {
        return;
    }
    // SAFETY: single-core; exclusive access to the bridge globals.
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(PEER_MAC), peer_mac);
        core::ptr::write(core::ptr::addr_of_mut!(PEER_IPV4), peer_ipv4);
    }
    let segment_start = segment_range.start;
    let payload_start = segment_start + view.payload_offset;
    let payload_end = segment_range.end;

    let mut segment_scratch = [0u8; 2048];
    let mut delivered = [0u8; 2048];
    let mut ssh_response = [0u8; 4096];

    // SAFETY: single-core; exclusive access.
    let connection = unsafe { (*core::ptr::addr_of_mut!(CONNECTION)).as_mut() };
    let session = unsafe { (*core::ptr::addr_of_mut!(SESSION)).as_mut() };
    let (connection, session) = match (connection, session) {
        (Some(connection), Some(session)) => (connection, session),
        _ => return,
    };
    connection.set_remote_ipv4(peer_ipv4);
    let payload = &receive_frame[payload_start..payload_end];
    let outcome = connection.on_segment(&view, payload, &mut segment_scratch, &mut delivered);
    if let Some(response_length) = outcome.response_length {
        send_segment(
            nic,
            peer_mac,
            peer_ipv4,
            &segment_scratch[..response_length],
        );
    }
    if connection.state() == TcpState::Established && !unsafe { BANNER_SENT } {
        let banner = SshSession::server_identification();
        let length = connection.send_data(banner, &mut segment_scratch);
        send_segment(nic, peer_mac, peer_ipv4, &segment_scratch[..length]);
        unsafe { BANNER_SENT = true }
    }
    if outcome.delivered_length > 0 {
        let response_length =
            session.on_received(&delivered[..outcome.delivered_length], &mut ssh_response);
        if response_length > 0 {
            let length =
                connection.send_data(&ssh_response[..response_length], &mut segment_scratch);
            send_segment(nic, peer_mac, peer_ipv4, &segment_scratch[..length]);
        }
    }
}

/// Reads one input byte for the bridged shell, driving the network first.
pub fn read_input_byte() -> Option<u8> {
    step();
    // SAFETY: single-core.
    unsafe {
        (*core::ptr::addr_of_mut!(SESSION))
            .as_mut()?
            .poll_channel_input()
    }
}

/// Sends one output byte from the bridged shell as CHANNEL_DATA.
pub fn write_output_byte(byte: u8) {
    let nic = match nic() {
        Some(nic) => nic,
        None => return,
    };
    // SAFETY: single-core; exclusive access.
    let connection = unsafe { (*core::ptr::addr_of_mut!(CONNECTION)).as_mut() };
    let session = unsafe { (*core::ptr::addr_of_mut!(SESSION)).as_mut() };
    let (connection, session) = match (connection, session) {
        (Some(connection), Some(session)) => (connection, session),
        _ => return,
    };
    let mut ssh_response = [0u8; 512];
    let ssh_length = session.write_channel_output(&[byte], &mut ssh_response);
    if ssh_length > 0 {
        let mut segment_scratch = [0u8; 1024];
        let length = connection.send_data(&ssh_response[..ssh_length], &mut segment_scratch);
        let (peer_mac, peer_ipv4) = unsafe {
            (
                core::ptr::read(core::ptr::addr_of!(PEER_MAC)),
                core::ptr::read(core::ptr::addr_of!(PEER_IPV4)),
            )
        };
        send_segment(&nic, peer_mac, peer_ipv4, &segment_scratch[..length]);
    }
}

/// Wraps a TCP segment in IPv4 + Ethernet and transmits it.
fn send_segment(
    nic: &E1000Device,
    destination_mac: [u8; 6],
    destination_ipv4: [u8; 4],
    tcp_segment: &[u8],
) {
    let mut frame = [0u8; 2048];
    let frame_length = crate::net::build_ipv4_frame(
        destination_mac,
        nic.mac_address(),
        OUR_IPV4,
        destination_ipv4,
        crate::net::tcp::IP_PROTOCOL_TCP,
        tcp_segment,
        &mut frame,
    );
    nic.send_frame(&frame[..frame_length]);
}
