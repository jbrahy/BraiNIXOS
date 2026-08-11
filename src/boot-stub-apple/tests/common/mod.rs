//! Synthetic ADT construction and a recording MMIO fake.
//!
//! The encoder mirrors the layout the AS-0 fact table specifies. It is written
//! here rather than shared from `src/adt/tests/` because Rust integration tests
//! are per-crate; the encoding rules are the fact table's, not either test
//! suite's, so two independent encoders agreeing is a feature.

#![allow(dead_code)]

use brainix_boot_stub_apple::uart::Mmio;
use brainix_boot_stub_apple::MmioFactory;

// ---------------------------------------------------------------------------
// ADT encoding
// ---------------------------------------------------------------------------

/// One property record: 32-byte NUL-padded name, LE length word, value, then
/// zero padding to a multiple of 4.
pub fn property(name: &str, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let name_bytes = name.as_bytes();
    assert!(name_bytes.len() < 32, "property name too long for a record");
    out.extend_from_slice(name_bytes);
    out.resize(32, 0);
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

/// A node: 8-byte header (property count, child count), properties, children.
pub fn node(properties: &[Vec<u8>], children: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(properties.len() as u32).to_le_bytes());
    out.extend_from_slice(&(children.len() as u32).to_le_bytes());
    for property in properties {
        out.extend_from_slice(property);
    }
    for child in children {
        out.extend_from_slice(child);
    }
    out
}

/// A NUL-terminated string value.
pub fn cstr(text: &str) -> Vec<u8> {
    let mut out = text.as_bytes().to_vec();
    out.push(0);
    out
}

/// A little-endian `u32` value.
pub fn u32_value(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

/// A 64-bit quantity as two cells, least-significant cell first.
pub fn two_cells(value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&((value & 0xffff_ffff) as u32).to_le_bytes());
    out.extend_from_slice(&((value >> 32) as u32).to_le_bytes());
    out
}

/// The `/arm-io` translation window used by every fixture here.
pub const ARM_IO_PARENT_BASE: u64 = 0x2_0000_0000;
/// Size of that window.
pub const ARM_IO_WINDOW_SIZE: u64 = 0x1_0000_0000;
/// Untranslated `reg` address given to the UART node.
pub const UART_CHILD_BASE: u64 = 0x7920_0000;
/// Size given to the UART node's `reg`.
pub const UART_REG_SIZE: u64 = 0x4000;
/// What [`UART_CHILD_BASE`] must translate to through the window above.
pub const UART_TRANSLATED_BASE: u64 = ARM_IO_PARENT_BASE + UART_CHILD_BASE;

/// Options for building a fixture tree.
pub struct TreeOptions {
    /// Name of the UART node placed under `/arm-io`.
    pub uart_node_name: &'static str,
    /// Value written to the UART node's `compatible`.
    pub compatible: Option<&'static str>,
    /// Whether to give the UART node a `reg` property.
    pub with_reg: bool,
    /// Whether to add a `debug-console` child under the UART node.
    pub with_debug_console_marker: bool,
    /// Whether `/arm-io` carries a `ranges` property at all.
    pub with_ranges: bool,
}

impl Default for TreeOptions {
    /// The expected shape on a machine with no `debug-console` marker:
    /// `/arm-io/uart0`, correctly compatible, translatable.
    fn default() -> Self {
        Self {
            uart_node_name: "uart0",
            compatible: Some("uart-1,samsung"),
            with_reg: true,
            with_debug_console_marker: false,
            with_ranges: true,
        }
    }
}

/// Builds a well-formed ADT containing `/arm-io/<uart_node_name>`.
pub fn tree(options: &TreeOptions) -> Vec<u8> {
    let mut uart_properties = vec![
        property("name", &cstr(options.uart_node_name)),
        property("device_type", &cstr("uart")),
    ];
    if let Some(compatible) = options.compatible {
        uart_properties.push(property("compatible", &cstr(compatible)));
    }
    if options.with_reg {
        let mut reg = two_cells(UART_CHILD_BASE);
        reg.extend_from_slice(&two_cells(UART_REG_SIZE));
        uart_properties.push(property("reg", &reg));
    }

    let uart_children = if options.with_debug_console_marker {
        vec![node(&[property("name", &cstr("debug-console"))], &[])]
    } else {
        Vec::new()
    };

    let uart = node(&uart_properties, &uart_children);

    let mut arm_io_properties = vec![
        property("name", &cstr("arm-io")),
        property("#address-cells", &u32_value(2)),
        property("#size-cells", &u32_value(2)),
    ];
    if options.with_ranges {
        let mut ranges = two_cells(0);
        ranges.extend_from_slice(&two_cells(ARM_IO_PARENT_BASE));
        ranges.extend_from_slice(&two_cells(ARM_IO_WINDOW_SIZE));
        arm_io_properties.push(property("ranges", &ranges));
    }

    let arm_io = node(&arm_io_properties, &[uart]);

    node(
        &[
            property("name", &cstr("device-tree")),
            property("#address-cells", &u32_value(2)),
            property("#size-cells", &u32_value(2)),
        ],
        &[arm_io],
    )
}

/// A tree with both `/arm-io/uart6` (carrying the marker) and `/arm-io/uart0`.
///
/// Exists so the selection algorithm's preference can be observed rather than
/// inferred: both candidates resolve, so choosing `uart6` is a real decision.
pub fn tree_with_both_uarts() -> Vec<u8> {
    let uart6 = node(
        &[
            property("name", &cstr("uart6")),
            property("device_type", &cstr("uart")),
            property("compatible", &cstr("uart-1,samsung")),
            property("reg", &{
                let mut reg = two_cells(UART_CHILD_BASE);
                reg.extend_from_slice(&two_cells(UART_REG_SIZE));
                reg
            }),
        ],
        &[node(&[property("name", &cstr("debug-console"))], &[])],
    );

    let uart0 = node(
        &[
            property("name", &cstr("uart0")),
            property("device_type", &cstr("uart")),
            property("compatible", &cstr("uart-1,samsung")),
            property("reg", &{
                // Deliberately a different address, so a test asserting which
                // node was chosen cannot pass by accident.
                let mut reg = two_cells(UART_CHILD_BASE + 0x4000);
                reg.extend_from_slice(&two_cells(UART_REG_SIZE));
                reg
            }),
        ],
        &[],
    );

    let arm_io = node(
        &[
            property("name", &cstr("arm-io")),
            property("#address-cells", &u32_value(2)),
            property("#size-cells", &u32_value(2)),
            property("ranges", &{
                let mut ranges = two_cells(0);
                ranges.extend_from_slice(&two_cells(ARM_IO_PARENT_BASE));
                ranges.extend_from_slice(&two_cells(ARM_IO_WINDOW_SIZE));
                ranges
            }),
        ],
        &[uart6, uart0],
    );

    node(
        &[
            property("name", &cstr("device-tree")),
            property("#address-cells", &u32_value(2)),
            property("#size-cells", &u32_value(2)),
        ],
        &[arm_io],
    )
}

/// A tree with no `/arm-io` at all, so neither UART candidate resolves.
pub fn tree_without_arm_io() -> Vec<u8> {
    node(
        &[
            property("name", &cstr("device-tree")),
            property("#address-cells", &u32_value(2)),
            property("#size-cells", &u32_value(2)),
        ],
        &[],
    )
}

// ---------------------------------------------------------------------------
// MMIO fake
// ---------------------------------------------------------------------------

/// One recorded MMIO access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// A read of `offset` that returned `value`.
    Read { offset: usize, value: u32 },
    /// A write of `value` to `offset`.
    Write { offset: usize, value: u32 },
}

/// A recording MMIO window whose status register is scriptable.
pub struct FakeMmio {
    /// Every access in order.
    pub accesses: Vec<Access>,
    /// Value returned for reads of the status register.
    pub status_value: u32,
    /// Number of status reads that return 0 before `status_value` is used.
    pub not_ready_reads: u32,
    /// `Mmio::read_u32` takes `&self`, so the countdown needs interior
    /// mutability. `Cell` is the cheapest thing that provides it.
    reads_so_far: core::cell::Cell<u32>,
    status_offset: usize,
}

impl FakeMmio {
    /// A window whose transmitter is ready immediately.
    pub fn ready(status_offset: usize, ready_mask: u32) -> Self {
        Self {
            accesses: Vec::new(),
            status_value: ready_mask,
            not_ready_reads: 0,
            reads_so_far: core::cell::Cell::new(0),
            status_offset,
        }
    }

    /// A window that reports not-ready for `not_ready_reads` reads first.
    pub fn ready_after(status_offset: usize, ready_mask: u32, not_ready_reads: u32) -> Self {
        Self {
            accesses: Vec::new(),
            status_value: ready_mask,
            not_ready_reads,
            reads_so_far: core::cell::Cell::new(0),
            status_offset,
        }
    }

    /// A window that never reports ready.
    pub fn never_ready(status_offset: usize) -> Self {
        Self {
            accesses: Vec::new(),
            status_value: 0,
            not_ready_reads: u32::MAX,
            reads_so_far: core::cell::Cell::new(0),
            status_offset,
        }
    }

    /// Every value written, in order, as bytes.
    pub fn written_bytes(&self) -> Vec<u8> {
        self.accesses
            .iter()
            .filter_map(|access| match access {
                Access::Write { value, .. } => Some(*value as u8),
                Access::Read { .. } => None,
            })
            .collect()
    }

    /// Everything written, decoded as UTF-8 with invalid bytes replaced.
    pub fn written_text(&self) -> String {
        String::from_utf8_lossy(&self.written_bytes()).into_owned()
    }

    /// Offsets written to, in order, deduplicated consecutively.
    pub fn write_offsets(&self) -> Vec<usize> {
        self.accesses
            .iter()
            .filter_map(|access| match access {
                Access::Write { offset, .. } => Some(*offset),
                Access::Read { .. } => None,
            })
            .collect()
    }
}

impl Mmio for FakeMmio {
    fn read_u32(&self, offset: usize) -> u32 {
        if offset != self.status_offset {
            return 0;
        }
        let seen = self.reads_so_far.get();
        self.reads_so_far.set(seen.saturating_add(1));
        if seen < self.not_ready_reads {
            0
        } else {
            self.status_value
        }
    }

    fn write_u32(&mut self, offset: usize, value: u32) {
        self.accesses.push(Access::Write { offset, value });
    }
}

/// Hands out fakes and remembers every base it was asked for.
pub struct FakeFactory {
    /// Every base requested, in order.
    pub bases: Vec<u64>,
    status_offset: usize,
    ready_mask: u32,
}

impl FakeFactory {
    /// A factory whose windows are always ready to transmit.
    pub fn new(status_offset: usize, ready_mask: u32) -> Self {
        Self {
            bases: Vec::new(),
            status_offset,
            ready_mask,
        }
    }
}

impl MmioFactory for FakeFactory {
    type Window = FakeMmio;

    fn window_at(&mut self, base: u64) -> Self::Window {
        self.bases.push(base);
        FakeMmio::ready(self.status_offset, self.ready_mask)
    }
}
