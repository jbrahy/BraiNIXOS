#!/usr/bin/env python3
"""Drive a Flipper Zero over its USB CLI — a bring-up lab instrument.

# Why this exists

Recovery-mode work on the mini means typing long `bputil` and `kmutil`
invocations by hand, with no shell history, no copy-paste, and no way to read
the result back afterwards. A mistyped path in that context costs a full
recovery trip to discover. See `docs/operations/BRINGUP_PLAN.md` §2.

The Flipper acts as a USB HID keyboard for the target. It types **one short
line**: a call to a shell script already on the target's disk. The script does
the real work and tees its output to a log we can read later from the other
volume. That is the point — not saving keystrokes, but getting a **record of
what the install actually said**, which no attempt so far has produced.

# What it is not

One-directional. The Flipper cannot read the target's screen, cannot hold the
power button for One True Recovery, and does not replace m1n1 as the feedback
loop (`BRINGUP_PLAN.md` §4, Phase 1). It removes transcription errors and
gives us a log. Nothing more.

# Safety

Whatever this types runs **as root in a recovery shell**. Every payload is
written to the Flipper's SD card and printed here before deployment so it can
be read before it is run. Keep the typed line short and have it call a script
that was reviewed on a real machine.
"""

from __future__ import annotations

import argparse
import sys
import time

try:
    import serial
except ImportError:  # pragma: no cover - environment problem, not logic
    sys.exit("pyserial is required: python3 -m pip install --user pyserial")

DEFAULT_PORT = "/dev/cu.usbmodemflip_Laffzoe1"
PROMPT = b">: "


class Flipper:
    """A Flipper Zero CLI session."""

    def __init__(self, port: str = DEFAULT_PORT, timeout: float = 3.0) -> None:
        self.serial = serial.Serial(port, 115200, timeout=timeout)
        time.sleep(0.4)
        self.serial.reset_input_buffer()
        # Sync on a prompt so the first real command's output is not mixed with
        # the banner. Every read below is prompt-terminated for the same reason.
        self._send("")

    def _send(self, line: str, settle: float = 0.15) -> str:
        self.serial.write((line + "\r\n").encode())
        time.sleep(settle)
        return self._read_to_prompt()

    def _read_to_prompt(self, limit: float = 8.0) -> str:
        deadline = time.time() + limit
        buffer = b""
        while time.time() < deadline:
            chunk = self.serial.read(self.serial.in_waiting or 1)
            if chunk:
                buffer += chunk
                if buffer.rstrip().endswith(PROMPT.strip()):
                    break
            else:
                time.sleep(0.05)
        text = buffer.decode("utf-8", "replace")
        # Drop the echoed command and the trailing prompt.
        lines = [ln for ln in text.splitlines() if ln.strip() not in ("", ">:")]
        return "\n".join(lines)

    def command(self, line: str) -> str:
        """Runs one CLI command and returns its output."""
        return self._send(line)

    def write_file(self, path: str, content: str) -> str:
        """Writes `content` to `path` on the Flipper's SD card.

        `storage write` streams until a lone Ctrl-C, which is why this cannot
        go through `command()`.
        """
        self.serial.write(f"storage remove {path}\r\n".encode())
        time.sleep(0.4)
        self.serial.reset_input_buffer()

        self.serial.write(f"storage write {path}\r\n".encode())
        time.sleep(0.6)
        self.serial.reset_input_buffer()
        for line in content.splitlines():
            self.serial.write((line + "\r\n").encode())
            time.sleep(0.05)
        self.serial.write(b"\x03")  # Ctrl-C ends the stream
        time.sleep(0.8)
        return self._read_to_prompt()

    def close(self) -> None:
        self.serial.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", default=DEFAULT_PORT)
    sub = parser.add_subparsers(dest="action", required=True)

    sub.add_parser("info", help="device identity")

    ls = sub.add_parser("ls", help="list a directory on the SD card")
    ls.add_argument("path", nargs="?", default="/ext/badusb")

    put = sub.add_parser("put", help="write a local file to the SD card")
    put.add_argument("local")
    put.add_argument("remote")

    cat = sub.add_parser("cat", help="read a file from the SD card")
    cat.add_argument("path")

    raw = sub.add_parser("cmd", help="run one raw CLI command")
    raw.add_argument("line")

    args = parser.parse_args()
    flipper = Flipper(args.port)
    try:
        if args.action == "info":
            print(flipper.command("info device"))
        elif args.action == "ls":
            print(flipper.command(f"storage list {args.path}"))
        elif args.action == "put":
            with open(args.local, "r", encoding="utf-8") as handle:
                body = handle.read()
            print(flipper.write_file(args.remote, body))
            print(flipper.command(f"storage stat {args.remote}"))
        elif args.action == "cat":
            print(flipper.command(f"storage read {args.path}"))
        elif args.action == "cmd":
            print(flipper.command(args.line))
    finally:
        flipper.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
