#!/usr/bin/env python3
"""Send command lines to `brainx_flipper_one` over BLE.

The Flipper runs the app, is plugged into the target as a USB keyboard, and
listens on its BLE serial service. This is the workstation end: it connects and
writes lines, which the Flipper types into whatever has focus on the target.

    ./bin/brainx-ble.py scan
    ./bin/brainx-ble.py send 'ls /Volumes'
    ./bin/brainx-ble.py send-file commands.txt

# Why this exists rather than a BadUSB script

The Flipper has one USB port, so a script plugged into the target is decided
before the target's state is known and cannot be corrected. Over BLE the
command is composed at the moment of use — after reading what the machine
actually did. See docs/operations/BRINGUP_PLAN.md.

# Discovery rather than remembered UUIDs

The serial service's characteristic UUIDs are found by walking the GATT table
and taking the writable one, instead of hardcoding constants from memory. A
wrong constant here would fail in exactly the ambiguous way this project has
been losing days to.

# What arming means

The app refuses to type until armed with the OK button on the Flipper itself.
That is deliberate: everything sent here lands in a root shell. If lines vanish
with no effect, check the device — `TYPING: disarmed` is the expected reason.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

try:
    from bleak import BleakClient, BleakScanner
except ImportError:  # pragma: no cover
    sys.exit("bleak is required: python3 -m pip install --user bleak")

NAME_HINTS = ("flipper", "laffzoe", "brainix")
CHUNK = 180  # under the 243-byte characteristic limit, with headroom


async def find_device(timeout: float = 12.0):
    """Returns the first advertiser that looks like the Flipper."""
    devices = await BleakScanner.discover(timeout=timeout)
    for device in devices:
        name = (device.name or "").lower()
        if any(hint in name for hint in NAME_HINTS):
            return device
    return None


async def writable_characteristic(client: BleakClient):
    """Finds the serial service's write characteristic by walking GATT.

    Prefers `write-without-response`, which is what the Flipper's serial RX
    characteristic supports and what keeps throughput sane.
    """
    best = None
    for service in client.services:
        for char in service.characteristics:
            props = set(char.properties)
            if "write-without-response" in props or "write" in props:
                # The serial service is the one that also has a notify
                # characteristic beside it; prefer that service's writable char.
                siblings = [c for c in service.characteristics if "notify" in c.properties]
                if siblings:
                    return char
                best = best or char
    return best


async def send_lines(lines: list[str], address: str | None) -> int:
    device = None
    if address:
        device = address
    else:
        print("scanning for the Flipper ...", file=sys.stderr)
        found = await find_device()
        if not found:
            print(
                "no Flipper found. Check that the app is running on the device and\n"
                "that this terminal has macOS Bluetooth permission "
                "(System Settings > Privacy & Security > Bluetooth).",
                file=sys.stderr,
            )
            return 1
        print(f"found {found.name} [{found.address}]", file=sys.stderr)
        device = found.address

    async with BleakClient(device) as client:
        char = await writable_characteristic(client)
        if char is None:
            print("connected, but no writable characteristic found", file=sys.stderr)
            return 1
        print(f"writing to {char.uuid}", file=sys.stderr)

        for line in lines:
            payload = (line.rstrip("\n") + "\n").encode()
            # Chunked because the characteristic caps at 243 bytes, and the app
            # only acts on a complete line -- a split mid-line is harmless, a
            # dropped tail is not, so the newline always rides the last chunk.
            for start in range(0, len(payload), CHUNK):
                await client.write_gatt_char(char, payload[start : start + CHUNK], response=False)
                await asyncio.sleep(0.05)
            print(f"sent: {line}", file=sys.stderr)
            # Give the Flipper time to type it. At 12 ms per key a long command
            # takes seconds, and queueing the next line early interleaves them.
            await asyncio.sleep(max(1.0, len(line) * 0.03))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--address", help="skip scanning and connect to this BLE address")
    sub = parser.add_subparsers(dest="action", required=True)

    sub.add_parser("scan", help="list nearby BLE devices")
    send = sub.add_parser("send", help="send one line")
    send.add_argument("line")
    send_file = sub.add_parser("send-file", help="send every line of a file")
    send_file.add_argument("path")

    args = parser.parse_args()

    if args.action == "scan":

        async def do_scan():
            for device in await BleakScanner.discover(timeout=12.0):
                print(f"{device.address}  {device.name}")

        asyncio.run(do_scan())
        return 0

    if args.action == "send":
        lines = [args.line]
    else:
        with open(args.path, "r", encoding="utf-8") as handle:
            lines = [ln for ln in handle.read().splitlines() if ln.strip()]

    return asyncio.run(send_lines(lines, args.address))


if __name__ == "__main__":
    raise SystemExit(main())
