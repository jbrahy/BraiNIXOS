//! Minimal polled virtio-blk driver over the legacy PCI I/O interface.
//!
//! Scope and rationale: the kernel needs trustworthy access to a small,
//! security-critical region of disk to persist the authentication credential
//! store (the auth TCB). Rather than trust an untrusted userspace disk driver
//! for credentials, the kernel reads/writes the credential block itself. Bulk,
//! general-purpose disk I/O for userspace remains the job of the devd-disk
//! server; this driver is intentionally tiny and TCB-scoped.
//!
//! Interrupts are never used (userspace runs IF-masked under KPTI, and the
//! kernel polls): block requests complete by spinning on the used ring.
//!
//! Implements: device discovery + reset/feature handshake + the legacy split
//! virtqueue (descriptor table + available/used rings) + polled 512-byte sector
//! read and write. The queue and DMA buffers live in page-aligned kernel BSS;
//! their guest-physical addresses come from the kernel's fixed
//! virtual→physical image offset (BSS is loaded contiguously at 1 MiB), and the
//! "IOMMU absent, software-only" boot config lets the device DMA to them.
//!
//! Allowlist: `src/kernel/src/arch/` — port I/O and device DMA buffers have no
//! safe Rust interface (see UNSAFE_CODE_POLICY.md).
#![allow(unsafe_code)]

use core::sync::atomic::{fence, Ordering};

use crate::arch::paging::page_table_walk_helpers::compute_physical_address_of_bss_page;
use crate::arch::pci::{find_device, VIRTIO_PCI_VENDOR_ID};

/// PCI device ID of the transitional virtio-blk device (legacy interface).
const VIRTIO_BLK_TRANSITIONAL_DEVICE_ID: u16 = 0x1001;

// Legacy virtio PCI I/O register offsets (relative to BAR0 base, MSI-X absent).
const REGISTER_DRIVER_FEATURES: u16 = 0x04;
const REGISTER_QUEUE_ADDRESS_PFN: u16 = 0x08;
const REGISTER_QUEUE_SIZE: u16 = 0x0C;
const REGISTER_QUEUE_SELECT: u16 = 0x0E;
const REGISTER_QUEUE_NOTIFY: u16 = 0x10;
const REGISTER_DEVICE_STATUS: u16 = 0x12;
const REGISTER_BLOCK_CAPACITY_LOW: u16 = 0x14;
const REGISTER_BLOCK_CAPACITY_HIGH: u16 = 0x18;

// Device status bits (virtio spec §2.1).
const STATUS_RESET: u8 = 0x00;
const STATUS_ACKNOWLEDGE: u8 = 0x01;
const STATUS_DRIVER: u8 = 0x02;
const STATUS_DRIVER_OK: u8 = 0x04;
const STATUS_FEATURES_OK: u8 = 0x08;

// Descriptor flags.
const VIRTQ_DESC_F_NEXT: u16 = 0x01;
const VIRTQ_DESC_F_WRITE: u16 = 0x02;

// virtio-blk request types.
const VIRTIO_BLK_TYPE_READ: u32 = 0;
const VIRTIO_BLK_TYPE_WRITE: u32 = 1;

/// A virtio-blk sector is always 512 bytes.
pub const SECTOR_SIZE_IN_BYTES: usize = 512;

/// Status byte value the device writes on a successful request.
const VIRTIO_BLK_STATUS_OK: u8 = 0;

/// Bytes reserved for the virtqueue (descriptor table + avail ring + used ring).
/// Sized for the QEMU legacy queue (≤ 256 entries): 16*256 + ~6+512 rounded up
/// to a 4 KiB boundary for the used ring + ~2 KiB used ring = under 16 KiB.
const QUEUE_AREA_SIZE_IN_BYTES: usize = 16384;

/// Largest queue size this driver supports (bounds the static area).
const MAXIMUM_QUEUE_SIZE: u16 = 256;

#[repr(C, align(4096))]
struct QueueArea([u8; QUEUE_AREA_SIZE_IN_BYTES]);

/// Page-aligned backing store for the single virtqueue.
static mut VIRTQUEUE_AREA: QueueArea = QueueArea([0u8; QUEUE_AREA_SIZE_IN_BYTES]);

/// virtio-blk request header (type, reserved, starting sector).
#[repr(C)]
struct BlockRequestHeader {
    request_type: u32,
    reserved: u32,
    sector: u64,
}

static mut REQUEST_HEADER: BlockRequestHeader = BlockRequestHeader {
    request_type: 0,
    reserved: 0,
    sector: 0,
};
/// DMA buffer for the sector payload (read into / written from).
static mut SECTOR_DATA_BUFFER: [u8; SECTOR_SIZE_IN_BYTES] = [0u8; SECTOR_SIZE_IN_BYTES];
/// Device-written request status byte.
static mut REQUEST_STATUS_BYTE: u8 = 0xFF;

/// A discovered and initialized virtio-blk device.
#[derive(Copy, Clone, Debug)]
pub struct VirtioBlockDevice {
    io_base_port: u16,
    capacity_in_sectors: u64,
    queue_size: u16,
    used_ring_offset: usize,
}

impl VirtioBlockDevice {
    /// Disk capacity in 512-byte sectors.
    pub fn capacity_in_sectors(&self) -> u64 {
        self.capacity_in_sectors
    }

    /// Base I/O port of the legacy register window.
    pub fn io_base_port(&self) -> u16 {
        self.io_base_port
    }

    /// Reads one 512-byte sector into `output`. Returns false on device error.
    pub fn read_sector(&self, sector: u64, output: &mut [u8; SECTOR_SIZE_IN_BYTES]) -> bool {
        // SAFETY: single-core boot; exclusive use of the static queue/buffers.
        unsafe {
            if !self.submit_request(VIRTIO_BLK_TYPE_READ, sector, true) {
                return false;
            }
            output.copy_from_slice(&*core::ptr::addr_of!(SECTOR_DATA_BUFFER));
            true
        }
    }

    /// Writes one 512-byte sector from `input`. Returns false on device error.
    pub fn write_sector(&self, sector: u64, input: &[u8; SECTOR_SIZE_IN_BYTES]) -> bool {
        // SAFETY: single-core boot; exclusive use of the static queue/buffers.
        unsafe {
            (*core::ptr::addr_of_mut!(SECTOR_DATA_BUFFER)).copy_from_slice(input);
            self.submit_request(VIRTIO_BLK_TYPE_WRITE, sector, false)
        }
    }

    /// Builds the three-descriptor chain, publishes it on the available ring,
    /// notifies the device, and spins on the used ring until completion.
    /// `device_writes_data` is true for reads (the device fills the data buffer).
    ///
    /// # Safety
    /// Single-core, exclusive access to the static queue and DMA buffers.
    unsafe fn submit_request(
        &self,
        request_type: u32,
        sector: u64,
        device_writes_data: bool,
    ) -> bool {
        core::ptr::write(
            core::ptr::addr_of_mut!(REQUEST_HEADER),
            BlockRequestHeader {
                request_type,
                reserved: 0,
                sector,
            },
        );
        core::ptr::write(core::ptr::addr_of_mut!(REQUEST_STATUS_BYTE), 0xFF);

        let header_physical = bss_physical_address(core::ptr::addr_of!(REQUEST_HEADER) as u64);
        let data_physical = bss_physical_address(core::ptr::addr_of!(SECTOR_DATA_BUFFER) as u64);
        let status_physical = bss_physical_address(core::ptr::addr_of!(REQUEST_STATUS_BYTE) as u64);

        let data_flags = if device_writes_data {
            VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE
        } else {
            VIRTQ_DESC_F_NEXT
        };
        write_descriptor(0, header_physical, 16, VIRTQ_DESC_F_NEXT, 1);
        write_descriptor(1, data_physical, SECTOR_SIZE_IN_BYTES as u32, data_flags, 2);
        write_descriptor(2, status_physical, 1, VIRTQ_DESC_F_WRITE, 0);

        let used_index_before = read_used_index(self.used_ring_offset);
        let available_index_before = read_available_index(self.queue_size);
        set_available_ring_entry(self.queue_size, available_index_before, 0);
        fence(Ordering::SeqCst);
        write_available_index(self.queue_size, available_index_before.wrapping_add(1));
        fence(Ordering::SeqCst);

        write_port_word(self.io_base_port + REGISTER_QUEUE_NOTIFY, 0);

        while read_used_index(self.used_ring_offset) == used_index_before {
            core::hint::spin_loop();
        }
        fence(Ordering::SeqCst);
        core::ptr::read_volatile(core::ptr::addr_of!(REQUEST_STATUS_BYTE)) == VIRTIO_BLK_STATUS_OK
    }
}

/// Discovers the transitional virtio-blk device, runs the status/feature
/// handshake, reads capacity, sets up queue 0, and marks the driver ready.
/// Returns `None` if the device is absent or the queue is too large.
pub fn initialize_block_device() -> Option<VirtioBlockDevice> {
    let location = find_device(VIRTIO_PCI_VENDOR_ID, VIRTIO_BLK_TRANSITIONAL_DEVICE_ID)?;
    let bar0 = crate::arch::pci::read_base_address_register(location, 0);
    let io_base_port = (bar0 & 0xFFFC) as u16;

    write_status(io_base_port, STATUS_RESET);
    write_status(io_base_port, STATUS_ACKNOWLEDGE);
    write_status(io_base_port, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
    let _device_features = read_port_dword(io_base_port + 0x00);
    write_port_dword(io_base_port + REGISTER_DRIVER_FEATURES, 0);
    write_status(
        io_base_port,
        STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
    );

    let capacity_low = read_port_dword(io_base_port + REGISTER_BLOCK_CAPACITY_LOW) as u64;
    let capacity_high = read_port_dword(io_base_port + REGISTER_BLOCK_CAPACITY_HIGH) as u64;
    let capacity_in_sectors = capacity_low | (capacity_high << 32);

    write_port_word(io_base_port + REGISTER_QUEUE_SELECT, 0);
    let queue_size = read_port_word(io_base_port + REGISTER_QUEUE_SIZE);
    if queue_size == 0 || queue_size > MAXIMUM_QUEUE_SIZE {
        return None;
    }
    let used_ring_offset = compute_used_ring_offset(queue_size);
    if used_ring_offset + used_ring_byte_length(queue_size) > QUEUE_AREA_SIZE_IN_BYTES {
        return None;
    }

    // SAFETY: single-core boot; the static queue area is exclusively ours.
    let queue_physical =
        unsafe { bss_physical_address(core::ptr::addr_of!(VIRTQUEUE_AREA) as u64) };
    write_port_dword(
        io_base_port + REGISTER_QUEUE_ADDRESS_PFN,
        (queue_physical >> 12) as u32,
    );
    write_status(
        io_base_port,
        STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
    );

    Some(VirtioBlockDevice {
        io_base_port,
        capacity_in_sectors,
        queue_size,
        used_ring_offset,
    })
}

/// Available-ring byte length: flags(2) + idx(2) + ring[N](2N) + used_event(2).
fn available_ring_byte_length(queue_size: u16) -> usize {
    6 + 2 * (queue_size as usize)
}

/// Used-ring byte length: flags(2) + idx(2) + ring[N](8N) + avail_event(2).
fn used_ring_byte_length(queue_size: u16) -> usize {
    6 + 8 * (queue_size as usize)
}

/// Offset of the used ring within the queue area: after the descriptor table
/// (16N) and available ring, rounded up to a 4 KiB boundary (legacy qalign).
fn compute_used_ring_offset(queue_size: u16) -> usize {
    let descriptor_table_length = 16 * (queue_size as usize);
    let unaligned = descriptor_table_length + available_ring_byte_length(queue_size);
    (unaligned + 4095) & !4095
}

/// Translates a kernel BSS virtual address to its guest-physical address.
unsafe fn bss_physical_address(virtual_address: u64) -> u64 {
    compute_physical_address_of_bss_page(virtual_address).as_u64()
}

unsafe fn queue_area_base() -> *mut u8 {
    core::ptr::addr_of_mut!(VIRTQUEUE_AREA) as *mut u8
}

/// Writes descriptor `index`: addr(u64)@0, len(u32)@8, flags(u16)@12, next(u16)@14.
unsafe fn write_descriptor(index: usize, address: u64, length: u32, flags: u16, next: u16) {
    let descriptor = queue_area_base().add(index * 16);
    core::ptr::write_volatile(descriptor as *mut u64, address);
    core::ptr::write_volatile(descriptor.add(8) as *mut u32, length);
    core::ptr::write_volatile(descriptor.add(12) as *mut u16, flags);
    core::ptr::write_volatile(descriptor.add(14) as *mut u16, next);
}

/// Available ring base = end of descriptor table (16 * queue_size).
unsafe fn available_ring_base(queue_size: u16) -> *mut u8 {
    queue_area_base().add(16 * (queue_size as usize))
}

unsafe fn read_available_index(queue_size: u16) -> u16 {
    core::ptr::read_volatile(available_ring_base(queue_size).add(2) as *const u16)
}

unsafe fn write_available_index(queue_size: u16, index: u16) {
    core::ptr::write_volatile(available_ring_base(queue_size).add(2) as *mut u16, index);
}

/// Sets ring slot `available_index % queue_size` to descriptor head `head`.
unsafe fn set_available_ring_entry(queue_size: u16, available_index: u16, head: u16) {
    let slot = (available_index % queue_size) as usize;
    let entry = available_ring_base(queue_size).add(4 + slot * 2);
    core::ptr::write_volatile(entry as *mut u16, head);
}

unsafe fn read_used_index(used_ring_offset: usize) -> u16 {
    let used_index = queue_area_base().add(used_ring_offset + 2);
    core::ptr::read_volatile(used_index as *const u16)
}

fn write_status(io_base_port: u16, status: u8) {
    write_port_byte(io_base_port + REGISTER_DEVICE_STATUS, status);
}

fn write_port_byte(port_address: u16, value: u8) {
    // SAFETY: device register write via port I/O. Ring 0. Allowlist: arch/.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port_address,
            in("al") value,
            options(nomem, nostack, preserves_flags),
        );
    }
}

fn read_port_word(port_address: u16) -> u16 {
    // SAFETY: device register read via port I/O. Ring 0. Allowlist: arch/.
    let value: u16;
    unsafe {
        core::arch::asm!(
            "in ax, dx",
            in("dx") port_address,
            out("ax") value,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}

fn write_port_word(port_address: u16, value: u16) {
    // SAFETY: device register write via port I/O. Ring 0. Allowlist: arch/.
    unsafe {
        core::arch::asm!(
            "out dx, ax",
            in("dx") port_address,
            in("ax") value,
            options(nomem, nostack, preserves_flags),
        );
    }
}

fn read_port_dword(port_address: u16) -> u32 {
    // SAFETY: device register read via port I/O. Ring 0. Allowlist: arch/.
    let value: u32;
    unsafe {
        core::arch::asm!(
            "in eax, dx",
            in("dx") port_address,
            out("eax") value,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}

fn write_port_dword(port_address: u16, value: u32) {
    // SAFETY: device register write via port I/O. Ring 0. Allowlist: arch/.
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") port_address,
            in("eax") value,
            options(nomem, nostack, preserves_flags),
        );
    }
}
