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

Everything sent here lands in a root shell. The Flipper's OK button toggles
arming and it defaults to armed, so an unattended box still works; if lines
vanish with no effect, the reply will say `error: disarmed`.

# Why replies are read back

The app answers every command on its notify characteristic, including refusals.
Three wrong conclusions in this bring-up came from treating a successful write
as delivery — the write succeeding says only that CoreBluetooth queued it. Wait
for the reply, or you are guessing again.
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
    """Finds the serial service's write characteristic, and its service.

    Returns `(service, characteristic)` because the reply characteristic must be
    chosen from the *same* service; see `notify_characteristic`.

    Prefers `write-without-response`, which is what the Flipper's serial RX
    characteristic supports and what keeps throughput sane.
    """
    best = (None, None)
    for service in client.services:
        for char in service.characteristics:
            props = set(char.properties)
            if "write-without-response" in props or "write" in props:
                # The serial service is the one that also carries the reply
                # channel; prefer that service's writable characteristic.
                siblings = [
                    c
                    for c in service.characteristics
                    if "indicate" in c.properties or "notify" in c.properties
                ]
                if siblings:
                    return service, char
                if best == (None, None):
                    best = (service, char)
    return best


def notify_characteristic(service, write_char):
    """Finds the characteristic the app answers on, within one service.

    Two things this gets wrong if you are casual about it, both of which cost a
    round of "the write succeeded and nothing came back":

    * **Scope it to the serial service.** A search across all services matches
      the battery-level characteristic in 0x180F first, because that service is
      enumerated earlier. Subscribing there succeeds and delivers nothing.
    * **Accept `indicate`, not just `notify`.** The Flipper's serial TX
      characteristic is `indicate` (acknowledged); its `notify` characteristics
      in the same service are flow control and RPC status, not the reply
      channel. Filtering on "notify" picks a real characteristic that is
      simply not the one the app writes to.
    """
    for char in service.characteristics:
        if char.uuid == write_char.uuid:
            continue
        props = set(char.properties)
        if "indicate" in props:
            return char
    for char in service.characteristics:
        if char.uuid != write_char.uuid and "notify" in char.properties:
            return char
    return None


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
        service, char = await writable_characteristic(client)
        if char is None:
            print("connected, but no writable characteristic found", file=sys.stderr)
            return 1
        print(f"writing to {char.uuid}", file=sys.stderr)

        replies: asyncio.Queue[str] = asyncio.Queue()

        def on_notify(_handle, data: bytearray) -> None:
            replies.put_nowait(data.decode("utf-8", "replace").strip())

        notify = notify_characteristic(service, char)
        if notify is not None:
            print(f"reading replies from {notify.uuid}", file=sys.stderr)
            await client.start_notify(notify, on_notify)
        else:
            print("no reply characteristic; replies will not be read", file=sys.stderr)

        for line in lines:
            payload = (line.rstrip("\n") + "\n").encode()
            # Chunked because the characteristic caps at 243 bytes, and the app
            # only acts on a complete line -- a split mid-line is harmless, a
            # dropped tail is not, so the newline always rides the last chunk.
            for start in range(0, len(payload), CHUNK):
                # Acknowledged, deliberately. Write-without-response cannot
                # fail, so an encryption or permission fault on the peer is
                # invisible -- which is how `Insufficient Encryption` hid here
                # for a day. The throughput cost is irrelevant at this size.
                await client.write_gatt_char(char, payload[start : start + CHUNK], response=True)
                await asyncio.sleep(0.05)
            print(f"sent: {line}", file=sys.stderr)

            if notify is None:
                # Blind: pace by length so lines do not interleave while typing.
                await asyncio.sleep(max(1.0, len(line) * 0.03))
                continue
            # Wait for the app to answer rather than guessing how long typing
            # took. The timeout is generous because a long line is ~12 ms per
            # character; a timeout here is real information, not impatience.
            try:
                reply = await asyncio.wait_for(replies.get(), timeout=5.0 + len(line) * 0.05)
                print(f"  {reply}", file=sys.stderr)
            except asyncio.TimeoutError:
                print("  no reply -- the line was not delivered", file=sys.stderr)
                return 1

        if notify is not None:
            await client.stop_notify(notify)
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
