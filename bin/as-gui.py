#!/usr/bin/env python3
"""Drive the mini's GUI by keyboard, and refuse to press anything blind.

The recovery console (as-recovery-console.py) covers everything reachable from
a shell. This covers what is not: the startup picker, the Recovery menu, and
the macOS installer -- screens that exist only as pixels and accept only
keystrokes.

Those screens are where this project has come closest to real damage. The
runbook records that one `tab` too many lands on **Restart**, and the
installer's disk picker is one keypress from writing over the production OS.
Both were previously navigated by me photographing the screen and reading it by
eye, which is exactly the loop that produced two wrong diagnoses in one night.

So every key here is conditional on what the screen actually says:

    as-gui.py read                          # OCR the screen, print it
    as-gui.py expect 'Reinstall macOS'      # exit 0 only if that text is there
    as-gui.py key down --expect 'BraiNIX'   # press, then verify, or fail
    as-gui.py keys                          # which keys the firmware has

`--expect` is checked AFTER the key is sent; `--require` is checked BEFORE, so
a step can assert the screen it thinks it is on before touching it. A step that
cannot confirm its screen does not press the key.

OCR is tesseract over a camera photograph, so it is approximate. Matching is
therefore done on normalized text (case-folded, whitespace-collapsed) and
callers should assert on distinctive words rather than exact punctuation:
"Not Paired" survives; "(coih):" comes back as "Ccoih):".
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BLE = REPO / "bin" / "brainx-ble.py"
SHOT = REPO / "bin" / "screenshot-mini.sh"

# Every key the app has ever carried. `keys` probes which ones the FLASHED
# firmware actually answers to, because the table lives in the app and the
# source having a key proves nothing about the device in the room.
KNOWN_KEYS = [
    "enter", "tab", "esc", "space", "up", "down", "left", "right",
    "ctrl-c", "ctrl-d", "cmd-tab", "shift-cmd-t", "cmd-q", "cmd-w", "cmd-n",
]


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def capture(device: str = "0") -> Path:
    out = Path(tempfile.mkdtemp(prefix="brainx-gui-")) / "screen.jpg"
    subprocess.run([str(SHOT), device, str(out)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return out


def ocr(img: Path) -> str:
    if not shutil.which("tesseract"):
        sys.exit("tesseract is not installed; brew install tesseract")
    # psm 6: a uniform block of text. The alternative modes hunt for columns
    # and do worse on a photographed terminal.
    r = subprocess.run(["tesseract", str(img), "-", "--psm", "6"],
                       capture_output=True, text=True)
    return r.stdout


def read_screen(device: str = "0", tries: int = 2) -> str:
    """OCR the screen, retrying once: a single frame can catch a redraw."""
    best = ""
    for _ in range(tries):
        text = ocr(capture(device))
        if len(text) > len(best):
            best = text
        if best.strip():
            break
        time.sleep(1)
    return best


def ble(line: str) -> tuple[bool, str]:
    """Send one line to the Flipper. Returns (ok, reply)."""
    for _ in range(4):
        r = subprocess.run([sys.executable, str(BLE), "send", line],
                           capture_output=True, text=True, timeout=140)
        reply = (r.stdout or "").strip().splitlines()
        reply = reply[-1].strip() if reply else ""
        if "ok" in reply:
            return True, reply
        if "unknown key name" in reply:
            return False, reply          # a real answer; do not retry
        time.sleep(1)
    return False, reply


def matches(text: str, pattern: str) -> bool:
    n = norm(text)
    if norm(pattern) in n:
        return True
    try:
        return re.search(pattern, text, re.I | re.S) is not None
    except re.error:
        return False


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--device", default="0", help="camera index (0 = built-in)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("read")
    kp = sub.add_parser("keys")
    kp.add_argument("--yes-press-every-key", action="store_true",
                    help="required: probing a key means PRESSING it")
    e = sub.add_parser("expect")
    e.add_argument("pattern")
    k = sub.add_parser("key")
    k.add_argument("name")
    k.add_argument("--require", help="text that must be on screen BEFORE pressing")
    k.add_argument("--expect", help="text that must be on screen AFTER pressing")
    k.add_argument("--settle", type=float, default=2.0)
    t = sub.add_parser("type")
    t.add_argument("text")
    t.add_argument("--require")

    a = p.parse_args()

    if a.cmd == "read":
        sys.stdout.write(read_screen(a.device))
        return 0

    if a.cmd == "keys":
        # Probe the device rather than trusting the source tree. The app answers
        # "error: unknown key name" for anything not in its table, which makes
        # capability discoverable without flashing anything.
        #
        # But the firmware taps the key BEFORE it replies, so discovering that
        # `cmd-q` exists means quitting the frontmost app -- which is precisely
        # how a recovery session was stranded on 2026-08-21, with no way back to
        # the menu bar. There is no read-only form of this question with the
        # current firmware, so it is gated and must be run on a screen where
        # every key is harmless: the startup picker, not a Terminal.
        if not a.yes_press_every_key:
            print("This PRESSES every key on the list, including cmd-q and", file=sys.stderr)
            print("cmd-w. On a Terminal that closes it and strands the session.", file=sys.stderr)
            print("Run it at the startup picker, then pass", file=sys.stderr)
            print("--yes-press-every-key.", file=sys.stderr)
            return 2
        have, missing = [], []
        for name in KNOWN_KEYS:
            ok, reply = ble(f"key {name}")
            (have if ok else missing).append(name)
        print("firmware has: " + " ".join(have))
        if missing:
            print("MISSING:      " + " ".join(missing))
            print("\nThe source may carry these; the device in the room does not.")
            print("Reflash before relying on them.")
        return 0 if not missing else 1

    if a.cmd == "expect":
        text = read_screen(a.device)
        if matches(text, a.pattern):
            print(f"ok: screen shows {a.pattern!r}")
            return 0
        print(f"FAIL: screen does not show {a.pattern!r}", file=sys.stderr)
        print("--- what it does show ---", file=sys.stderr)
        print(text, file=sys.stderr)
        return 1

    if a.cmd in ("key", "type"):
        req = getattr(a, "require", None)
        if req:
            text = read_screen(a.device)
            if not matches(text, req):
                print(f"REFUSING: expected {req!r} on screen first.", file=sys.stderr)
                print("--- what it shows ---", file=sys.stderr)
                print(text, file=sys.stderr)
                return 2
            print(f"  precondition ok: {req!r}")

        line = f"key {a.name}" if a.cmd == "key" else f"type {a.text}"
        ok, reply = ble(line)
        if not ok:
            print(f"FAIL: flipper refused: {reply}", file=sys.stderr)
            return 3
        print(f"  sent: {reply}")

        exp = getattr(a, "expect", None)
        if exp:
            time.sleep(a.settle)
            text = read_screen(a.device)
            if not matches(text, exp):
                print(f"FAIL: after sending, screen does not show {exp!r}", file=sys.stderr)
                print("--- what it shows ---", file=sys.stderr)
                print(text, file=sys.stderr)
                return 4
            print(f"  confirmed: {exp!r}")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
