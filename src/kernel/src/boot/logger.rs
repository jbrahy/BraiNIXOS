//! Boot-phase step logger. Writes structured `[BOOT]` lines to the serial console.

use core::fmt::Write;

use crate::boot::serial::SerialOutputPort;

/// Writes structured boot log lines to a [`SerialOutputPort`].
pub struct BootStepLogger {
    serial_output_port: SerialOutputPort,
}

impl BootStepLogger {
    /// Create a logger that owns the given serial port.
    pub fn new(serial_output_port: SerialOutputPort) -> Self {
        Self { serial_output_port }
    }

    /// Print a full-width separator line.
    pub fn separator(&mut self) {
        let _ = write!(self.serial_output_port, "================================================================================\n");
    }

    /// Print a raw line with no `[BOOT]` prefix (used for the banner).
    pub fn line(&mut self, message: &str) {
        let _ = write!(self.serial_output_port, "{}\n", message);
    }

    /// `[OK  ]` — step completed successfully.
    pub fn ok(&mut self, message: &str) {
        self.write_prefixed_line("[OK  ]", message);
    }

    /// `[STEP]` — step is starting.
    pub fn step(&mut self, message: &str) {
        self.write_prefixed_line("[STEP]", message);
    }

    /// `[INFO]` — informational detail.
    pub fn info(&mut self, message: &str) {
        self.write_prefixed_line("[INFO]", message);
    }

    /// `[WARN]` — non-fatal warning.
    pub fn warn(&mut self, message: &str) {
        self.write_prefixed_line("[WARN]", message);
    }

    /// `[FAIL]` — step failed with detail.
    pub fn fail(&mut self, message: &str, detail: &str) {
        self.write_prefixed_line("[FAIL]", message);
        self.write_prefixed_line("[FAIL]", detail);
    }

    /// `[HALT]` — kernel is halting.
    pub fn halt(&mut self, message: &str) {
        self.write_prefixed_line("[HALT]", message);
    }

    fn write_prefixed_line(&mut self, tag: &str, message: &str) {
        let _ = write!(self.serial_output_port, "[BOOT] {} {}\n", tag, message);
    }
}
