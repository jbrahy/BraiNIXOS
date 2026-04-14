# BraiNIX Device Isolation Policy

## Purpose

This document defines the device isolation model for BraiNIX. It specifies the one-server-per-device principle, the CapDevice capability type, authority rules, IOMMU requirements, cross-device isolation enforcement, interrupt binding, compromise containment guarantees, and development mode configuration.

This is an authoritative specification. If code or configuration diverges from this document, the document must be updated in the same PR that introduces the change.

---

## 1. Principle

**One server process per hardware device.** No device server manages multiple unrelated devices. Each device server runs in its own address space with its own page tables, its own CSpace, and its own scheduling budget.

### Rationale

Device drivers are historically the largest source of kernel vulnerabilities in monolithic systems. By running each device server as an isolated userspace process:

- A bug in the NIC driver cannot corrupt the disk driver's state.
- A compromised device server cannot access kernel memory.
- The blast radius of a device exploit is bounded to the authority granted to that specific device.

This design upholds INV-DEV-001 (devices do not imply universal memory authority) and INV-DEV-002 (each device service receives least privilege).

---

## 2. Device Capability Type

Device servers access their hardware through a **CapDevice** capability (defined in `CAPABILITY_MODEL.md`). CapDevice is a typed capability that bounds what a device server can access.

### CapDevice Fields

| Field | Type | Description |
|-------|------|-------------|
| `device_type` | `DeviceType` enum | Identifies the hardware class (NIC, disk, serial, timer, etc.) |
| `mmio_base_address` | `u64` | Physical base address of the device's memory-mapped I/O region |
| `mmio_size` | `u32` | Size in bytes of the MMIO region (bounded; cannot exceed device's actual register space) |
| `irq_set` | `[u8; 4]` | Explicit list of IRQ numbers assigned to this device (up to 4 IRQ lines; unused entries set to `IRQ_NONE = 0xFF`) |

### DeviceType Enum

```rust
#[repr(u8)]
enum DeviceType {
    NetworkInterface = 0,
    BlockStorage = 1,
    SerialPort = 2,
    Timer = 3,
    DisplayAdapter = 4,
    InputDevice = 5,
    TpmDevice = 6,
}
```

### Bounds Enforcement

- The `mmio_base_address` and `mmio_size` fields define the exact physical memory window the device server may map into its address space. Any attempt to map memory outside this window fails with `CapabilityError::OutOfBounds`.
- The `mmio_size` field is validated at CapDevice creation time. It must match the actual hardware register space reported by firmware or PCI enumeration. Oversized MMIO ranges are rejected.
- The `irq_set` field contains only the specific IRQ lines assigned to this device. The device server cannot bind to IRQ lines not listed in its `irq_set`.

---

## 3. Authority Rules

Each device server holds **only** its specific CapDevice capability (plus minimal additional capabilities for IPC and memory allocation). The authority rules are:

### What a Device Server Holds

- One CapDevice for its assigned hardware device
- One or more CapEndpoint for IPC with adjacent services (e.g., a NIC server holds an endpoint to communicate with `linkd`)
- CapMemory for its own process address space (stack, heap, buffers)
- CapIrq for its specific IRQ line(s) (derived from CapDevice's irq_set)

### What a Device Server Does NOT Hold

- No CapDevice for any other hardware device
- No global memory authority (no capability to map arbitrary physical memory)
- No access to other devices' MMIO regions
- No global interrupt capability (no capability to bind arbitrary IRQ lines)
- No CapCNode for other processes' capability spaces
- No CapSpawn (cannot create new processes)
- No CapAuditRead (cannot read the audit log unless explicitly granted)
- No CapUntyped (cannot create new kernel objects)

### Principle of Least Authority

A device server's CSpace contains the minimum set of capabilities required to operate its assigned device and communicate with its designated service peers. Nothing more.

---

## 4. IOMMU Requirement

An IOMMU (Input/Output Memory Management Unit) is **mandatory for production deployment**.

### Purpose

The IOMMU restricts DMA (Direct Memory Access) to the memory regions explicitly assigned to each device. Without an IOMMU, a device with DMA capability could read or write arbitrary physical memory, bypassing all software isolation.

### Production Requirements

- Intel VT-d or AMD-Vi must be present and enabled in firmware.
- The kernel configures the IOMMU to create per-device DMA domains.
- Each device's DMA domain allows access only to the memory regions assigned to that device's server process.
- DMA to kernel memory, other devices' memory, or other processes' memory is blocked by the IOMMU.

### IOMMU Configuration

For each device server, the kernel programs the IOMMU with:

| Parameter | Value |
|-----------|-------|
| Device BDF (Bus:Device:Function) | PCI address of the hardware device |
| Allowed DMA range | Only the physical pages mapped into the device server's address space |
| Default action | Deny (all DMA outside the allowed range is blocked) |

### IOMMU Absence

- In production: IOMMU absence is a boot-halting condition. The kernel refuses to start device servers without IOMMU protection.
- In development (QEMU): IOMMU emulation is used (see Section 8). If IOMMU emulation is not available, the kernel prints a warning and continues, but device isolation claims are downgraded to software-only enforcement.

---

## 5. Cross-Device Isolation

No device server can access another device server's resources. This is enforced at three levels:

### Level 1: Capability Isolation

Each device server's CSpace contains only its own CapDevice. There is no capability path from one device server's CSpace to another device server's CapDevice. The kernel does not create, copy, or derive cross-device capabilities.

### Level 2: Address Space Isolation

Each device server runs in its own address space with its own page tables. The device's MMIO region is mapped only into the owning device server's address space. No other process has a mapping to that MMIO region.

### Level 3: DMA Isolation (IOMMU)

The IOMMU ensures that DMA from one device cannot reach memory assigned to another device's server. Each device's DMA domain is disjoint from every other device's DMA domain.

### Verification

Cross-device isolation is verified by:

1. **Capability audit:** Inspecting each device server's CSpace to confirm it contains no foreign CapDevice entries.
2. **Page table audit:** Walking each device server's page tables to confirm no foreign MMIO mappings.
3. **IOMMU audit:** Dumping IOMMU translation tables to confirm per-device DMA domain separation.

---

## 6. Interrupt Binding

Each device server holds a **CapIrq** for its specific IRQ line(s). No device server holds a global interrupt capability.

### Binding Process

1. At device enumeration time, the kernel determines which IRQ lines are assigned to each device (from PCI configuration, ACPI tables, or device tree).
2. The kernel creates a CapIrq for each IRQ line and places it in the corresponding device server's CSpace.
3. The device server binds the CapIrq to a CapEndpoint, creating an interrupt-to-IPC binding: when the IRQ fires, a message is delivered to the endpoint.
4. The device server receives interrupt notifications by waiting on the endpoint.

### Interrupt Isolation

- IRQ delivery goes only to the owning device server's endpoint. No other process receives the interrupt notification.
- A device server cannot acknowledge, mask, or unmask an IRQ line that is not in its CapIrq set.
- The kernel's interrupt dispatch path checks the CapIrq binding before delivering any interrupt. An unbound IRQ is masked at the interrupt controller level.

### IRQ Authority Model

| Operation | Required Capability |
|-----------|-------------------|
| Bind IRQ to endpoint | CapIrq (with Write right) for the specific IRQ line |
| Unbind IRQ from endpoint | CapIrq (with Write right) for the specific IRQ line |
| Acknowledge IRQ | CapIrq (with Write right) for the specific IRQ line |
| Query IRQ status | CapIrq (with Read right) for the specific IRQ line |

This upholds INV-DEV-003 (interrupt authority is explicit).

---

## 7. Compromise Containment

If a device server is compromised (by exploit, bug, or malicious input), the attacker gains **only** the authority of that device's CapDevice. The blast radius is bounded to the device's assigned authority.

### What a Compromised Device Server CAN Do

- Read and write the device's MMIO registers (within the bounded mmio_size)
- Trigger DMA operations on the device (bounded by IOMMU to the device server's memory)
- Send IPC messages to its designated endpoint peers (with the content and timing the attacker controls)
- Consume its allocated CPU budget and memory quota

### What a Compromised Device Server CANNOT Do

| Action | Why Not |
|--------|---------|
| Access kernel memory | No CapMemory for kernel regions; KPTI prevents user-mode kernel access; SMEP/SMAP prevent kernel execution/access of user pages |
| Access other device MMIO regions | No CapDevice for other devices; MMIO not mapped in attacker's page tables |
| Access other device IRQ lines | No CapIrq for other devices' interrupt lines |
| Escalate to kernel privilege | No syscall grants kernel privilege; capability model prevents authority amplification (INV-AUTH-003) |
| Spawn new processes | No CapSpawn in device server's CSpace |
| Read the audit log | No CapAuditRead in device server's CSpace (unless explicitly granted) |
| Modify the audit log | Audit log is append-only and hardware write-protected |
| DMA to arbitrary memory | IOMMU restricts DMA to the device server's assigned pages |
| Communicate with arbitrary processes | Only the endpoints in the device server's CSpace are reachable |

### Containment Evidence

Containment is demonstrated by:

1. **Capability space audit:** Dumping the device server's CSpace proves it contains only the expected capabilities.
2. **Page table audit:** Walking the page tables proves no unauthorized mappings exist.
3. **IOMMU audit:** IOMMU tables prove DMA is bounded.
4. **Fuzz testing:** Fuzzing the device server's IPC boundary confirms it cannot reach kernel memory or peer device servers.

---

## 8. Development Mode

Development uses QEMU with virtio devices. Each virtio device maps to a separate device server process, maintaining the one-server-per-device principle even in emulation.

### QEMU Device Configuration

```
qemu-system-x86_64 \
  -machine q35 \
  -device virtio-net-pci,netdev=net0 \
  -netdev user,id=net0 \
  -device virtio-blk-pci,drive=drive0 \
  -drive file=disk.img,id=drive0,format=raw,if=none \
  -device intel-iommu,intremap=on,device-iotlb=on
```

### IOMMU Emulation

QEMU provides IOMMU emulation via:

- **Intel IOMMU:** `-device intel-iommu,intremap=on,device-iotlb=on` (emulates Intel VT-d)
- **AMD IOMMU:** `-device amd-iommu` (emulates AMD-Vi)

The kernel uses the same IOMMU programming interface in both development and production. The only difference is that development IOMMU emulation runs in software (inside QEMU) while production IOMMU is hardware.

### Device Server Mapping in Development

| QEMU Device | Device Server Process | DeviceType |
|------------|----------------------|------------|
| virtio-net-pci | devd-nic | NetworkInterface |
| virtio-blk-pci | devd-disk | BlockStorage |
| tpm-tis (swtpm) | devd-tpm | TpmDevice |
| QEMU serial (COM1) | devd-serial | SerialPort |

Each device server receives a CapDevice scoped to its virtio device's emulated MMIO region and IRQ line, exactly as it would in production with real hardware.

### Development Mode Limitations

- QEMU device emulation does not provide hardware-level isolation. A QEMU escape vulnerability could break all device isolation.
- IOMMU emulation is a software model, not hardware enforcement. DMA isolation claims in development mode are for flow testing only.
- Development device isolation demonstrates the capability model and IPC architecture; production device isolation adds hardware enforcement via real IOMMU and physical device separation.

---

*Last updated: 2026-04-11*
*This document is the authoritative specification for BraiNIX device isolation.*
