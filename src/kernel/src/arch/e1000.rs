//! Minimal polled Intel e1000 (82540EM) NIC driver — bring-up stage.
//!
//! The QEMU NIC is an MMIO-mapped Intel e1000, not a virtio device. This module
//! discovers it via PCI, maps its register BAR strong-uncacheable into the
//! kernel PML4, resets the device, and reads its MAC address. Descriptor-ring
//! transmit/receive (polled, no interrupts — the chosen most-secure design)
//! builds on this.
//!
//! The kernel performs NIC bring-up; per the microkernel design the packet I/O
//! path will ultimately live in a userspace network server driven through
//! capability-gated MMIO, but discovery + reset stay here.
//!
//! Allowlist: `src/kernel/src/arch/` — MMIO register access has no safe
//! interface.
#![allow(unsafe_code)]

use crate::arch::pci::{find_device, read_base_address_register};
use crate::arch::paging::kernel_page_table::{kernel_virtual_to_physical, map_mmio_region_into_kernel};
use crate::arch::paging::page_table_walk_helpers::compute_physical_address_of_bss_page;

/// True guest-physical address backing a kernel virtual address for device DMA
/// (descriptor rings, buffers). Prefers the live page-table walk; falls back to
/// the fixed image-offset helper (proven correct for the virtio-blk queue DMA)
/// if the walk can't resolve the address — never silently 0.
fn dma_physical_address(virtual_address: u64) -> u64 {
    kernel_virtual_to_physical(virtual_address)
        .unwrap_or_else(|| compute_physical_address_of_bss_page(virtual_address).as_u64())
}

/// PCI vendor:device for the QEMU Intel 82540EM e1000.
const INTEL_VENDOR_ID: u16 = 0x8086;
const E1000_82540EM_DEVICE_ID: u16 = 0x100E;

/// e1000 register MMIO window size (128 KiB = 32 pages).
const E1000_REGISTER_SPACE_PAGES: usize = 32;

// e1000 register offsets.
const REGISTER_CONTROL: u64 = 0x0000;
const REGISTER_RECEIVE_CONTROL: u64 = 0x0100;
const REGISTER_TRANSMIT_CONTROL: u64 = 0x0400;
const REGISTER_TRANSMIT_IPG: u64 = 0x0410;
const REGISTER_RX_DESCRIPTOR_BASE_LOW: u64 = 0x2800;
const REGISTER_RX_DESCRIPTOR_BASE_HIGH: u64 = 0x2804;
const REGISTER_RX_DESCRIPTOR_LENGTH: u64 = 0x2808;
const REGISTER_RX_DESCRIPTOR_HEAD: u64 = 0x2810;
const REGISTER_RX_DESCRIPTOR_TAIL: u64 = 0x2818;
const REGISTER_TX_DESCRIPTOR_BASE_LOW: u64 = 0x3800;
const REGISTER_TX_DESCRIPTOR_BASE_HIGH: u64 = 0x3804;
const REGISTER_TX_DESCRIPTOR_LENGTH: u64 = 0x3808;
const REGISTER_TX_DESCRIPTOR_HEAD: u64 = 0x3810;
const REGISTER_TX_DESCRIPTOR_TAIL: u64 = 0x3818;
const REGISTER_MULTICAST_TABLE_BASE: u64 = 0x5200;
const MULTICAST_TABLE_ENTRY_COUNT: u64 = 128;
const REGISTER_RECEIVE_ADDRESS_LOW: u64 = 0x5400;
const REGISTER_RECEIVE_ADDRESS_HIGH: u64 = 0x5404;

/// CTRL.RST — device reset (self-clearing).
const CONTROL_RESET: u32 = 1 << 26;
/// CTRL.ASDE (auto-speed detection) | CTRL.SLU (set link up) — bring the link up
/// after reset so the transmitter will process descriptors.
const CONTROL_AUTO_SPEED_DETECT: u32 = 1 << 5;
const CONTROL_SET_LINK_UP: u32 = 1 << 6;

// TCTL: EN | PSP | CT=15 | COLD=64.
const TRANSMIT_CONTROL_VALUE: u32 = (1 << 1) | (1 << 3) | (15 << 4) | (64 << 12);
// IPG values for e1000 copper (IPGT=10, IPGR1=8, IPGR2=6).
const TRANSMIT_IPG_VALUE: u32 = 10 | (8 << 10) | (6 << 20);
// RCTL: EN | BAM (accept broadcast) | SECRC (strip CRC); BSIZE 2048 (bits clear).
const RECEIVE_CONTROL_VALUE: u32 = (1 << 1) | (1 << 15) | (1 << 26);

// TX descriptor CMD bits.
const TX_CMD_END_OF_PACKET: u8 = 1 << 0;
const TX_CMD_INSERT_FCS: u8 = 1 << 1;
const TX_CMD_REPORT_STATUS: u8 = 1 << 3;
/// TX descriptor STA.DD (descriptor done).
const TX_STATUS_DESCRIPTOR_DONE: u8 = 1 << 0;
/// RX descriptor STATUS.DD.
const RX_STATUS_DESCRIPTOR_DONE: u8 = 1 << 0;

const RING_ENTRY_COUNT: usize = 8;
const RECEIVE_BUFFER_SIZE: usize = 2048;
/// Each legacy descriptor (TX and RX) is 16 bytes.
const DESCRIPTOR_SIZE: usize = 16;

#[repr(C, align(4096))]
struct DescriptorRing([u8; RING_ENTRY_COUNT * DESCRIPTOR_SIZE]);

#[repr(C, align(4096))]
struct ReceiveBuffers([[u8; RECEIVE_BUFFER_SIZE]; RING_ENTRY_COUNT]);

#[repr(C, align(2048))]
struct TransmitBuffer([u8; RECEIVE_BUFFER_SIZE]);

static mut TX_DESCRIPTOR_RING: DescriptorRing =
    DescriptorRing([0u8; RING_ENTRY_COUNT * DESCRIPTOR_SIZE]);
static mut RX_DESCRIPTOR_RING: DescriptorRing =
    DescriptorRing([0u8; RING_ENTRY_COUNT * DESCRIPTOR_SIZE]);
static mut RX_BUFFERS: ReceiveBuffers = ReceiveBuffers([[0u8; RECEIVE_BUFFER_SIZE]; RING_ENTRY_COUNT]);
static mut TX_BUFFER: TransmitBuffer = TransmitBuffer([0u8; RECEIVE_BUFFER_SIZE]);
/// Next TX descriptor index (the tail we write).
static mut TX_TAIL_INDEX: usize = 0;
/// Next RX descriptor index to inspect.
static mut RX_NEXT_INDEX: usize = 0;

/// A discovered and reset e1000 NIC.
#[derive(Copy, Clone, Debug)]
pub struct E1000Device {
    mmio_base_address: u64,
    mac_address: [u8; 6],
}

impl E1000Device {
    /// The NIC's 6-byte MAC address, read from RAL/RAH after reset.
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac_address
    }

    /// Base of the mapped register window.
    pub fn mmio_base_address(&self) -> u64 {
        self.mmio_base_address
    }

    /// Diagnostic: read a raw register by offset.
    pub fn debug_register(&self, offset: u64) -> u32 {
        read_register(self.mmio_base_address, offset)
    }

    /// Diagnostic: the upper status dword of TX descriptor 0, and the ring's
    /// computed physical address (should equal TDBAL).
    pub fn debug_tx_descriptor(&self) -> (u32, u64) {
        // SAFETY: single-core; read-only inspection of the static ring.
        unsafe {
            let descriptor = core::ptr::addr_of!(TX_DESCRIPTOR_RING) as *const u8;
            // Pack the CMD byte (offset 11) and length (offset 8) we wrote into the
            // high half so a single value reveals whether our write is visible.
            let cmd_byte = core::ptr::read_volatile(descriptor.add(11) as *const u8) as u32;
            let length = core::ptr::read_volatile(descriptor.add(8) as *const u16) as u32;
            let upper_status = core::ptr::read_volatile(descriptor.add(12) as *const u8) as u32;
            let combined = (cmd_byte << 16) | (length << 4) | upper_status;
            let ring_physical =
                dma_physical_address(core::ptr::addr_of!(TX_DESCRIPTOR_RING) as u64);
            (combined, ring_physical)
        }
    }
}

/// Diagnostic register offsets for logging TX/link state.
pub const DEBUG_REGISTER_STATUS: u64 = 0x0008;
pub const DEBUG_REGISTER_TX_HEAD: u64 = REGISTER_TX_DESCRIPTOR_HEAD;
pub const DEBUG_REGISTER_TX_TAIL: u64 = REGISTER_TX_DESCRIPTOR_TAIL;
pub const DEBUG_REGISTER_TX_BASE_LOW: u64 = REGISTER_TX_DESCRIPTOR_BASE_LOW;
pub const DEBUG_REGISTER_TX_CONTROL: u64 = REGISTER_TRANSMIT_CONTROL;

/// Discovers the e1000 via PCI, maps its register BAR, resets it, and reads the
/// MAC address. Returns `None` if the NIC is absent or its BAR is not memory-mapped.
pub fn initialize_nic() -> Option<E1000Device> {
    let location = find_device(INTEL_VENDOR_ID, E1000_82540EM_DEVICE_ID)?;
    let bar0 = read_base_address_register(location, 0);
    // Memory BAR: bit 0 clears for memory space; base masks off the low 4 flag bits.
    if bar0 & 0x1 != 0 {
        return None;
    }
    let mmio_base_address = (bar0 & 0xFFFF_FFF0) as u64;

    // SAFETY: mmio_base_address is the NIC's real BAR from PCI enumeration.
    unsafe { map_mmio_region_into_kernel(mmio_base_address, E1000_REGISTER_SPACE_PAGES).ok()? };

    reset_device(mmio_base_address);
    bring_link_up(mmio_base_address);
    let mac_address = read_mac_address(mmio_base_address);
    clear_multicast_table(mmio_base_address);
    // SAFETY: single-core boot; exclusive setup of the static rings/buffers.
    unsafe {
        setup_transmit_ring(mmio_base_address);
        setup_receive_ring(mmio_base_address);
    }
    Some(E1000Device {
        mmio_base_address,
        mac_address,
    })
}

impl E1000Device {
    /// Transmits one Ethernet frame (polled). Returns false if the frame is too
    /// large or the descriptor does not complete.
    pub fn send_frame(&self, frame: &[u8]) -> bool {
        if frame.is_empty() || frame.len() > RECEIVE_BUFFER_SIZE {
            return false;
        }
        // SAFETY: single-core; exclusive use of the static TX ring and buffer.
        unsafe { transmit_frame(self.mmio_base_address, frame) }
    }

    /// Polls the RX ring once for a received frame, copying it into `output`.
    /// Returns the number of bytes received, or `None` if nothing is ready.
    pub fn poll_receive(&self, output: &mut [u8]) -> Option<usize> {
        // SAFETY: single-core; exclusive use of the static RX ring and buffers.
        unsafe { receive_frame(self.mmio_base_address, output) }
    }
}

/// Zeroes the 128-entry multicast table so no multicast filtering is applied.
fn clear_multicast_table(mmio_base_address: u64) {
    for entry_index in 0..MULTICAST_TABLE_ENTRY_COUNT {
        write_register(
            mmio_base_address,
            REGISTER_MULTICAST_TABLE_BASE + entry_index * 4,
            0,
        );
    }
}

/// Programs the TX descriptor ring registers and enables the transmitter.
unsafe fn setup_transmit_ring(mmio_base_address: u64) {
    let ring_physical = dma_physical_address(core::ptr::addr_of!(TX_DESCRIPTOR_RING) as u64,);
    core::ptr::write(core::ptr::addr_of_mut!(TX_TAIL_INDEX), 0);
    write_register(mmio_base_address, REGISTER_TX_DESCRIPTOR_BASE_LOW, ring_physical as u32);
    write_register(
        mmio_base_address,
        REGISTER_TX_DESCRIPTOR_BASE_HIGH,
        (ring_physical >> 32) as u32,
    );
    write_register(
        mmio_base_address,
        REGISTER_TX_DESCRIPTOR_LENGTH,
        (RING_ENTRY_COUNT * DESCRIPTOR_SIZE) as u32,
    );
    write_register(mmio_base_address, REGISTER_TX_DESCRIPTOR_HEAD, 0);
    write_register(mmio_base_address, REGISTER_TX_DESCRIPTOR_TAIL, 0);
    write_register(mmio_base_address, REGISTER_TRANSMIT_IPG, TRANSMIT_IPG_VALUE);
    write_register(mmio_base_address, REGISTER_TRANSMIT_CONTROL, TRANSMIT_CONTROL_VALUE);
}

/// Programs the RX descriptor ring (each descriptor pointing at a buffer) and
/// enables the receiver with the tail at the last descriptor (all available).
unsafe fn setup_receive_ring(mmio_base_address: u64) {
    let ring_base = core::ptr::addr_of_mut!(RX_DESCRIPTOR_RING) as *mut u8;
    for descriptor_index in 0..RING_ENTRY_COUNT {
        let buffer_physical = dma_physical_address(core::ptr::addr_of!(RX_BUFFERS.0[descriptor_index]) as u64,);
        let descriptor = ring_base.add(descriptor_index * DESCRIPTOR_SIZE);
        core::ptr::write_volatile(descriptor as *mut u64, buffer_physical);
        core::ptr::write_volatile(descriptor.add(12) as *mut u8, 0); // status
    }
    core::ptr::write(core::ptr::addr_of_mut!(RX_NEXT_INDEX), 0);
    let ring_physical =
        dma_physical_address(core::ptr::addr_of!(RX_DESCRIPTOR_RING) as u64);
    write_register(mmio_base_address, REGISTER_RX_DESCRIPTOR_BASE_LOW, ring_physical as u32);
    write_register(
        mmio_base_address,
        REGISTER_RX_DESCRIPTOR_BASE_HIGH,
        (ring_physical >> 32) as u32,
    );
    write_register(
        mmio_base_address,
        REGISTER_RX_DESCRIPTOR_LENGTH,
        (RING_ENTRY_COUNT * DESCRIPTOR_SIZE) as u32,
    );
    write_register(mmio_base_address, REGISTER_RX_DESCRIPTOR_HEAD, 0);
    write_register(
        mmio_base_address,
        REGISTER_RX_DESCRIPTOR_TAIL,
        (RING_ENTRY_COUNT - 1) as u32,
    );
    write_register(mmio_base_address, REGISTER_RECEIVE_CONTROL, RECEIVE_CONTROL_VALUE);
}

/// Copies `frame` into the TX buffer, writes the descriptor, bumps the tail, and
/// polls for the descriptor-done status.
unsafe fn transmit_frame(mmio_base_address: u64, frame: &[u8]) -> bool {
    let tail_index = core::ptr::read(core::ptr::addr_of!(TX_TAIL_INDEX));
    let buffer = core::ptr::addr_of_mut!(TX_BUFFER.0) as *mut u8;
    core::ptr::copy_nonoverlapping(frame.as_ptr(), buffer, frame.len());
    let buffer_physical =
        dma_physical_address(core::ptr::addr_of!(TX_BUFFER) as u64);

    let descriptor =
        (core::ptr::addr_of_mut!(TX_DESCRIPTOR_RING) as *mut u8).add(tail_index * DESCRIPTOR_SIZE);
    core::ptr::write_volatile(descriptor as *mut u64, buffer_physical);
    core::ptr::write_volatile(descriptor.add(8) as *mut u16, frame.len() as u16);
    core::ptr::write_volatile(descriptor.add(11) as *mut u8, // CMD
        TX_CMD_END_OF_PACKET | TX_CMD_INSERT_FCS | TX_CMD_REPORT_STATUS);
    core::ptr::write_volatile(descriptor.add(12) as *mut u8, 0); // STA

    let next_tail = (tail_index + 1) % RING_ENTRY_COUNT;
    core::ptr::write(core::ptr::addr_of_mut!(TX_TAIL_INDEX), next_tail);
    write_register(mmio_base_address, REGISTER_TX_DESCRIPTOR_TAIL, next_tail as u32);

    // QEMU processes the TX ring synchronously on the TDT write (TDH advances to
    // the tail). The legacy descriptor's DD write-back is unreliable under this
    // QEMU model, so confirm transmission by polling TDH reaching the tail
    // rather than the descriptor DD bit.
    let mut attempts = 0u32;
    loop {
        if read_register(mmio_base_address, REGISTER_TX_DESCRIPTOR_HEAD) as usize == next_tail {
            return true;
        }
        if core::ptr::read_volatile(descriptor.add(12) as *const u8) & TX_STATUS_DESCRIPTOR_DONE != 0
        {
            return true;
        }
        core::hint::spin_loop();
        attempts = attempts.wrapping_add(1);
        if attempts > 2_000_000 {
            return false;
        }
    }
}

/// Inspects the next RX descriptor; if done, copies the frame out, recycles the
/// descriptor, and advances the tail. Returns the byte count or `None`.
unsafe fn receive_frame(mmio_base_address: u64, output: &mut [u8]) -> Option<usize> {
    let index = core::ptr::read(core::ptr::addr_of!(RX_NEXT_INDEX));
    let descriptor =
        (core::ptr::addr_of_mut!(RX_DESCRIPTOR_RING) as *mut u8).add(index * DESCRIPTOR_SIZE);
    let status = core::ptr::read_volatile(descriptor.add(12) as *const u8);
    if status & RX_STATUS_DESCRIPTOR_DONE == 0 {
        return None;
    }
    let length = core::ptr::read_volatile(descriptor.add(8) as *const u16) as usize;
    let copy_length = length.min(output.len()).min(RECEIVE_BUFFER_SIZE);
    let buffer = core::ptr::addr_of!(RX_BUFFERS.0[index]) as *const u8;
    core::ptr::copy_nonoverlapping(buffer, output.as_mut_ptr(), copy_length);

    // Recycle: clear status, advance tail to this descriptor, advance next index.
    core::ptr::write_volatile(descriptor.add(12) as *mut u8, 0);
    write_register(mmio_base_address, REGISTER_RX_DESCRIPTOR_TAIL, index as u32);
    core::ptr::write(
        core::ptr::addr_of_mut!(RX_NEXT_INDEX),
        (index + 1) % RING_ENTRY_COUNT,
    );
    Some(copy_length)
}

/// Resets the device via CTRL.RST and spins until the bit self-clears.
fn reset_device(mmio_base_address: u64) {
    let control = read_register(mmio_base_address, REGISTER_CONTROL);
    write_register(mmio_base_address, REGISTER_CONTROL, control | CONTROL_RESET);
    // RST self-clears once the reset completes; bound the spin so a stuck device
    // cannot hang boot.
    let mut attempts = 0u32;
    while read_register(mmio_base_address, REGISTER_CONTROL) & CONTROL_RESET != 0 {
        core::hint::spin_loop();
        attempts = attempts.wrapping_add(1);
        if attempts > 1_000_000 {
            break;
        }
    }
}

/// Sets CTRL.SLU | CTRL.ASDE so the PHY link comes up; without it the QEMU
/// e1000 leaves the link down and the transmitter never completes descriptors.
fn bring_link_up(mmio_base_address: u64) {
    let control = read_register(mmio_base_address, REGISTER_CONTROL);
    write_register(
        mmio_base_address,
        REGISTER_CONTROL,
        control | CONTROL_SET_LINK_UP | CONTROL_AUTO_SPEED_DETECT,
    );
}

/// Reads the 6-byte MAC from the Receive Address registers (RAL/RAH), which
/// QEMU pre-populates from the `-device e1000,mac=...` option.
fn read_mac_address(mmio_base_address: u64) -> [u8; 6] {
    let low = read_register(mmio_base_address, REGISTER_RECEIVE_ADDRESS_LOW);
    let high = read_register(mmio_base_address, REGISTER_RECEIVE_ADDRESS_HIGH);
    [
        (low & 0xFF) as u8,
        ((low >> 8) & 0xFF) as u8,
        ((low >> 16) & 0xFF) as u8,
        ((low >> 24) & 0xFF) as u8,
        (high & 0xFF) as u8,
        ((high >> 8) & 0xFF) as u8,
    ]
}

/// Reads a 32-bit e1000 register at `offset` from `mmio_base_address`.
fn read_register(mmio_base_address: u64, offset: u64) -> u32 {
    let pointer = mmio_base_address.wrapping_add(offset) as *const u32;
    // SAFETY: the register window was mapped strong-uncacheable; offset is in range.
    unsafe { core::ptr::read_volatile(pointer) }
}

/// Writes a 32-bit e1000 register at `offset` from `mmio_base_address`.
fn write_register(mmio_base_address: u64, offset: u64, value: u32) {
    let pointer = mmio_base_address.wrapping_add(offset) as *mut u32;
    // SAFETY: the register window was mapped strong-uncacheable; offset is in range.
    unsafe { core::ptr::write_volatile(pointer, value) }
}
