//! COM1 UART serial driver for early-boot console output.
//!
//! Allowlist: `src/kernel/src/boot/` — port I/O for COM1 UART (0x3F8–0x3FD)
//! before any safe abstraction layer exists.
#![allow(unsafe_code)]

const SERIAL_PORT_COM1_BASE_ADDRESS: u16 = 0x3F8;
const SERIAL_BAUD_RATE_DIVISOR_LOW_REGISTER: u16 = SERIAL_PORT_COM1_BASE_ADDRESS;
const SERIAL_BAUD_RATE_DIVISOR_HIGH_REGISTER: u16 = SERIAL_PORT_COM1_BASE_ADDRESS + 1;
const SERIAL_INTERRUPT_ENABLE_REGISTER: u16 = SERIAL_PORT_COM1_BASE_ADDRESS + 1;
const SERIAL_FIFO_CONTROL_REGISTER: u16 = SERIAL_PORT_COM1_BASE_ADDRESS + 2;
const SERIAL_LINE_CONTROL_REGISTER: u16 = SERIAL_PORT_COM1_BASE_ADDRESS + 3;
const SERIAL_MODEM_CONTROL_REGISTER: u16 = SERIAL_PORT_COM1_BASE_ADDRESS + 4;
const SERIAL_LINE_STATUS_REGISTER: u16 = SERIAL_PORT_COM1_BASE_ADDRESS + 5;

const SERIAL_LINE_CONTROL_DLAB_BIT: u8 = 0x80;
const SERIAL_LINE_CONTROL_8N1_FORMAT: u8 = 0x03;
const SERIAL_FIFO_ENABLED_14_BYTE_THRESHOLD: u8 = 0xC7;
const SERIAL_MODEM_CONTROL_READY: u8 = 0x0B;
const SERIAL_BAUD_115200_DIVISOR_LOW_BYTE: u8 = 0x01;
const SERIAL_BAUD_115200_DIVISOR_HIGH_BYTE: u8 = 0x00;
const SERIAL_LINE_STATUS_TRANSMIT_EMPTY_BIT: u8 = 0x20;
const SERIAL_INTERRUPT_NONE: u8 = 0x00;

/// COM1 serial output port. Initialize with [`SerialOutputPort::initialize`].
pub struct SerialOutputPort;

impl SerialOutputPort {
    /// Initialize COM1 at 115200 baud, 8N1 format.
    pub fn initialize() -> Self {
        configure_baud_rate_divisor();
        configure_line_format();
        configure_fifo_and_modem_control();
        Self
    }

    /// Write one byte to the serial port, waiting for the transmit buffer first.
    pub fn write_byte(&mut self, byte_value: u8) {
        wait_for_transmit_buffer_empty();
        write_port_byte(SERIAL_PORT_COM1_BASE_ADDRESS, byte_value);
    }
}

fn configure_baud_rate_divisor() {
    write_port_byte(SERIAL_LINE_CONTROL_REGISTER, SERIAL_LINE_CONTROL_DLAB_BIT);
    write_port_byte(
        SERIAL_BAUD_RATE_DIVISOR_LOW_REGISTER,
        SERIAL_BAUD_115200_DIVISOR_LOW_BYTE,
    );
    write_port_byte(
        SERIAL_BAUD_RATE_DIVISOR_HIGH_REGISTER,
        SERIAL_BAUD_115200_DIVISOR_HIGH_BYTE,
    );
}

fn configure_line_format() {
    write_port_byte(SERIAL_LINE_CONTROL_REGISTER, SERIAL_LINE_CONTROL_8N1_FORMAT);
    write_port_byte(SERIAL_INTERRUPT_ENABLE_REGISTER, SERIAL_INTERRUPT_NONE);
}

fn configure_fifo_and_modem_control() {
    write_port_byte(
        SERIAL_FIFO_CONTROL_REGISTER,
        SERIAL_FIFO_ENABLED_14_BYTE_THRESHOLD,
    );
    write_port_byte(SERIAL_MODEM_CONTROL_REGISTER, SERIAL_MODEM_CONTROL_READY);
}

fn wait_for_transmit_buffer_empty() {
    loop {
        let line_status = read_port_byte(SERIAL_LINE_STATUS_REGISTER);
        let transmit_buffer_is_empty = (line_status & SERIAL_LINE_STATUS_TRANSMIT_EMPTY_BIT) != 0;
        if transmit_buffer_is_empty {
            break;
        }
    }
}

fn write_port_byte(port_address: u16, byte_value: u8) {
    // SAFETY: Writes to COM1 UART registers (0x3F8–0x3FD). Port I/O accesses
    // a separate address space from RAM — no memory safety invariants are involved.
    // - Precondition: executing in ring 0 (kernel mode) with IOPL access.
    // - Invariant: INV-BOOT-001 (serial initialized before any other output).
    // - Evidence: visible serial output in QEMU integration test.
    // Allowlist: src/kernel/src/boot/ — port I/O for COM1 UART.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port_address,
            in("al") byte_value,
            options(nomem, nostack, preserves_flags),
        );
    }
}

fn read_port_byte(port_address: u16) -> u8 {
    // SAFETY: Reads COM1 line status register. Read-only status poll,
    // no side effects that affect memory safety.
    // - Precondition: executing in ring 0 with IOPL access.
    // - Invariant: INV-BOOT-001.
    // - Evidence: visible serial output in QEMU integration test.
    // Allowlist: src/kernel/src/boot/ — port I/O for COM1 UART.
    let byte_value: u8;
    unsafe {
        core::arch::asm!(
            "in al, dx",
            in("dx") port_address,
            out("al") byte_value,
            options(nomem, nostack, preserves_flags),
        );
    }
    byte_value
}

impl core::fmt::Write for SerialOutputPort {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        for byte_value in text.bytes() {
            if byte_value == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte_value);
        }
        Ok(())
    }
}
