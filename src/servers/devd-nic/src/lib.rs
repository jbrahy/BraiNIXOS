#![no_std]
#![deny(unsafe_code)]

//! devd-nic: Isolated device server for the network interface controller.
//!
//! Runs as a ring-3 process with a single CapDevice scoped to the NIC's
//! MMIO range and IRQ line. No global memory authority. No cross-device
//! access. Receives CapDevice at boot via kernel-direct grant (D-01).
//!
//! Enforces INV-DEV-002: each device service receives least privilege.

/// Maximum number of descriptors in a single virtio ring buffer.
pub const VIRTIO_RING_CAPACITY: usize = 256;

/// Index of the receive virtqueue within the virtio device.
pub const VIRTIO_RECEIVE_RING_INDEX: usize = 0;

/// Index of the transmit virtqueue within the virtio device.
pub const VIRTIO_TRANSMIT_RING_INDEX: usize = 1;

/// A single descriptor entry in a virtio split virtqueue ring.
///
/// Describes one buffer in the descriptor table: its guest physical address,
/// length, flags, and next descriptor chain index.
#[derive(Copy, Clone, Debug)]
pub struct VirtioRingDescriptor {
    /// Guest physical address of the buffer described by this descriptor.
    pub physical_address: u64,
    /// Length in bytes of the buffer at physical_address.
    pub length: u32,
    /// Descriptor flags (e.g., VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE).
    pub flags: u16,
    /// Index of the next descriptor in the chain when VIRTQ_DESC_F_NEXT is set.
    pub next_descriptor_index: u16,
}

/// Reads a packet from the virtio receive ring buffer into a CapFrame page.
///
/// Copies bytes from ring_buffer_content into frame_page up to the minimum
/// of their respective lengths. Returns the number of bytes copied.
pub fn read_packet_from_receive_ring(ring_buffer_content: &[u8], frame_page: &mut [u8]) -> usize {
    let copy_length = compute_copy_length(ring_buffer_content, frame_page);
    copy_ring_bytes_into_frame_page(ring_buffer_content, frame_page, copy_length);
    copy_length
}

/// Computes the number of bytes to copy as the minimum of source and destination lengths.
fn compute_copy_length(source: &[u8], destination: &[u8]) -> usize {
    core::cmp::min(source.len(), destination.len())
}

/// Copies length bytes from source into destination.
fn copy_ring_bytes_into_frame_page(source: &[u8], destination: &mut [u8], length: usize) {
    destination[..length].copy_from_slice(&source[..length]);
}

/// Writes a packet from a CapFrame page into the virtio transmit ring buffer.
///
/// Copies packet_length bytes from frame_page into ring_buffer up to the
/// minimum of packet_length and the ring buffer capacity. Returns bytes copied.
pub fn write_packet_to_transmit_ring(
    frame_page: &[u8],
    ring_buffer: &mut [u8],
    packet_length: usize,
) -> usize {
    let transmit_length = compute_transmit_copy_length(frame_page, ring_buffer, packet_length);
    copy_frame_page_into_ring_buffer(frame_page, ring_buffer, transmit_length);
    transmit_length
}

/// Computes the number of bytes to transmit as the minimum of packet_length and buffer capacity.
fn compute_transmit_copy_length(
    frame_page: &[u8],
    ring_buffer: &[u8],
    packet_length: usize,
) -> usize {
    let available_length = core::cmp::min(frame_page.len(), ring_buffer.len());
    core::cmp::min(available_length, packet_length)
}

/// Copies transmit_length bytes from frame_page into the ring buffer.
fn copy_frame_page_into_ring_buffer(
    frame_page: &[u8],
    ring_buffer: &mut [u8],
    transmit_length: usize,
) {
    ring_buffer[..transmit_length].copy_from_slice(&frame_page[..transmit_length]);
}

/// Forwards an Ethernet frame to the link layer via IPC.
///
/// Phase 9 stub — production implementation sends frame_page bytes to linkd
/// via a capability-mediated synchronous IPC call on the registered endpoint.
pub fn forward_frame_to_link_layer() {
    // Phase 9: IPC send to linkd endpoint with CapFrame grant
}

/// Parses an IPC message received on the device server's endpoint.
///
/// Returns the message type identifier from the first data word,
/// or None if the message is empty (zero-length).
///
/// This function is the IPC boundary that fuzz testing targets.
/// Verified by: fuzz_devd_nic_ipc_boundary_cannot_reach_kernel_memory
pub fn parse_ipc_message_type(message_data: &[u8]) -> Option<u8> {
    extract_first_byte_from_message(message_data)
}

/// Extracts the first byte from a message data buffer.
///
/// Note: This function is intentionally duplicated in devd-disk. Device
/// server crates must not share code dependencies for isolation reasons —
/// a compromise of one device server's dependency must not affect another.
/// Per CODE_STANDARDS Rule 3, duplication is acceptable when the
/// alternative would create a cross-device dependency.
fn extract_first_byte_from_message(message_data: &[u8]) -> Option<u8> {
    if message_data.is_empty() {
        return None;
    }
    Some(message_data[0])
}

/// Device server main loop: receives IPC messages and dispatches to handlers.
///
/// In Phase 8 this is a stub that demonstrates capability receipt.
/// Phase 9 wires real NIC register access via the CapDevice MMIO mapping.
///
/// Enforces INV-DEV-002: device server loops only on its assigned endpoint.
pub fn device_server_main_loop() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        read_packet_from_receive_ring, write_packet_to_transmit_ring, VIRTIO_RECEIVE_RING_INDEX,
        VIRTIO_RING_CAPACITY, VIRTIO_TRANSMIT_RING_INDEX,
    };

    #[test]
    fn ring_capacity_constant_is_256() {
        assert_eq!(VIRTIO_RING_CAPACITY, 256);
    }

    #[test]
    fn receive_ring_index_constant_is_zero() {
        assert_eq!(VIRTIO_RECEIVE_RING_INDEX, 0);
    }

    #[test]
    fn transmit_ring_index_constant_is_one() {
        assert_eq!(VIRTIO_TRANSMIT_RING_INDEX, 1);
    }

    #[test]
    fn read_packet_copies_bytes_into_frame_page_and_returns_length() {
        let ring_content = [0x01u8, 0x02, 0x03, 0x04];
        let mut frame_page = [0u8; 4096];
        let copied_length = read_packet_from_receive_ring(&ring_content, &mut frame_page);
        assert_eq!(copied_length, 4);
        assert_eq!(&frame_page[..4], &ring_content);
    }

    #[test]
    fn read_packet_truncates_to_frame_page_capacity() {
        let ring_content = [0xAAu8; 8];
        let mut frame_page = [0u8; 4];
        let copied_length = read_packet_from_receive_ring(&ring_content, &mut frame_page);
        assert_eq!(copied_length, 4);
        assert_eq!(&frame_page[..4], &[0xAAu8; 4]);
    }

    #[test]
    fn write_packet_copies_frame_page_into_ring_and_returns_length() {
        let frame_page = [0xBBu8, 0xCC, 0xDD, 0xEE];
        let mut ring_buffer = [0u8; 4096];
        let written_length = write_packet_to_transmit_ring(&frame_page, &mut ring_buffer, 4);
        assert_eq!(written_length, 4);
        assert_eq!(&ring_buffer[..4], &frame_page);
    }

    #[test]
    fn write_packet_truncates_to_packet_length() {
        let frame_page = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66];
        let mut ring_buffer = [0u8; 4096];
        let written_length = write_packet_to_transmit_ring(&frame_page, &mut ring_buffer, 3);
        assert_eq!(written_length, 3);
        assert_eq!(&ring_buffer[..3], &[0x11u8, 0x22, 0x33]);
    }
}
