#!/usr/bin/env python3
"""A two-way console for a machine that has none.

recoveryOS runs no sshd, so every result from an install has had to be read off
a photograph of the monitor. That is the single reason this process has never
been automatable: a one-way keyboard can send anything and learn nothing, and
"the screen did not change" is indistinguishable from "the command did not
run" -- a confusion that cost most of 2026-08-20/21.

But the mini *does* have a network in recoveryOS once Ethernet is up, and the
laptop is the other end of it. So the return channel is a socket, not a lens.

This is the laptop half. `as-recovery-agent.sh` is the mini half: it polls for
a command, runs it, and posts back stdout, stderr and the exit status.

    ./bin/as-recovery-console.py serve                 # start the listener
    ./bin/as-recovery-console.py bootstrap             # the one line to type
    ./bin/as-recovery-console.py run 'bputil -e'       # run, wait, print

SCOPE, DELIBERATELY SMALL
-------------------------
This is an unauthenticated-by-default command channel, so it is fenced in:

  * it binds to the Internet Sharing address only (192.168.2.1), never 0.0.0.0,
    so it is reachable from the shared segment and nothing else;
  * every request carries a token minted per session and kept in the spool;
  * it exists for the duration of an install and is torn down after.

It is a bring-up instrument, not a service, and it must never be left running
or turned into one.
"""

from __future__ import annotations

import argparse
import http.server
import os
import secrets
import shutil
import sys
import time
import urllib.parse
from pathlib import Path

DEFAULT_BIND = "192.168.2.1"
DEFAULT_PORT = 8792
SPOOL = Path(os.environ.get("BRAINX_SPOOL", "/tmp/brainx-recovery-spool"))

# How long `run` waits for the agent to come back. Deliberately generous:
# kmutil configure-boot takes minutes and looks like a hang while it works.
DEFAULT_TIMEOUT = 900.0


# ----------------------------------------------------------------- spool ----
# A directory rather than an in-process queue, so `serve` and `run` can be
# separate processes and a crashed server does not lose the transcript.


def spool_init(reset: bool = False) -> str:
    if reset and SPOOL.exists():
        shutil.rmtree(SPOOL)
    (SPOOL / "pending").mkdir(parents=True, exist_ok=True)
    (SPOOL / "done").mkdir(parents=True, exist_ok=True)
    tok = SPOOL / "token"
    if not tok.exists():
        tok.write_text(secrets.token_urlsafe(18))
    return tok.read_text().strip()


def token() -> str:
    return (SPOOL / "token").read_text().strip()


def _next_id() -> int:
    seq = SPOOL / "seq"
    n = int(seq.read_text()) + 1 if seq.exists() else 1
    seq.write_text(str(n))
    return n


def enqueue(command: str) -> int:
    cid = _next_id()
    # Written to a temp name and renamed, so the server can never serve a
    # half-written command.
    tmp = SPOOL / f".{cid}.tmp"
    tmp.write_text(command)
    tmp.rename(SPOOL / "pending" / f"{cid:06d}.cmd")
    return cid


def collect(cid: int, timeout: float) -> tuple[int, str]:
    out = SPOOL / "done" / f"{cid:06d}.out"
    rc = SPOOL / "done" / f"{cid:06d}.rc"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if rc.exists():
            return int(rc.read_text().strip() or 1), out.read_text() if out.exists() else ""
        time.sleep(0.25)
    raise TimeoutError(f"no reply for command {cid} after {timeout:.0f}s")


# ---------------------------------------------------------------- server ----


class Handler(http.server.BaseHTTPRequestHandler):
    # Quiet: the transcript is the spool, not the access log.
    def log_message(self, fmt, *args):  # noqa: A003
        pass

    def _authed(self) -> str | None:
        parts = self.path.split("/")
        # /t/<token>/<verb>[?query]
        if len(parts) >= 4 and parts[1] == "t" and secrets.compare_digest(parts[2], token()):
            return parts[3].split("?")[0]
        self.send_response(404)
        self.end_headers()
        return None

    def do_GET(self):  # noqa: N802
        verb = self._authed()
        if verb is None:
            return
        if verb != "cmd":
            self.send_response(404)
            self.end_headers()
            return
        pending = sorted((SPOOL / "pending").glob("*.cmd"))
        if not pending:
            self.send_response(204)  # nothing to do; agent sleeps and retries
            self.end_headers()
            return
        job = pending[0]
        cid = int(job.stem)
        body = f"{cid}\n{job.read_text()}".encode()
        # Move out of pending before replying, so a retry cannot double-run it.
        job.rename(SPOOL / "done" / f"{cid:06d}.cmd")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        verb = self._authed()
        if verb is None:
            return
        if verb != "out":
            self.send_response(404)
            self.end_headers()
            return
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        cid = int(q.get("id", ["0"])[0])
        rc = q.get("rc", ["1"])[0]
        n = int(self.headers.get("Content-Length") or 0)
        payload = self.rfile.read(n).decode("utf-8", "replace")
        (SPOOL / "done" / f"{cid:06d}.out").write_text(payload)
        (SPOOL / "done" / f"{cid:06d}.rc").write_text(str(rc))
        self.send_response(200)
        self.end_headers()


def serve(bind: str, port: int) -> int:
    tok = spool_init()
    try:
        srv = http.server.ThreadingHTTPServer((bind, port), Handler)
    except OSError as exc:
        print(f"cannot bind {bind}:{port}: {exc}", file=sys.stderr)
        print("Is Internet Sharing on? The mini's gateway is this address.", file=sys.stderr)
        return 1
    print(f"listening on {bind}:{port}  spool={SPOOL}")
    print(f"bootstrap line for the mini:\n\n  {bootstrap_line(bind, port, tok)}\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


# ------------------------------------------------------------------- cli ----


def bootstrap_line(bind: str, port: int, tok: str) -> str:
    """The single line a human (or the Flipper) types into recoveryOS once.

    Kept under the Flipper's 191-character line cap on purpose.
    """
    base = f"http://{bind}:{port}/t/{tok}"
    return f"sh /Volumes/Data/Users/Shared/brainix-boot/as-recovery-agent.sh {base} &"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--bind", default=DEFAULT_BIND)
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("serve")
    b = sub.add_parser("bootstrap")
    b.add_argument("--reset", action="store_true", help="mint a fresh token")
    r = sub.add_parser("run")
    r.add_argument("command")
    r.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)

    a = p.parse_args()

    if a.cmd == "bootstrap":
        tok = spool_init(reset=a.reset)
        print(bootstrap_line(a.bind, a.port, tok))
        return 0

    if a.cmd == "serve":
        return serve(a.bind, a.port)

    if a.cmd == "run":
        spool_init()
        cid = enqueue(a.command)
        try:
            rc, out = collect(cid, a.timeout)
        except TimeoutError as exc:
            print(str(exc), file=sys.stderr)
            return 124
        sys.stdout.write(out)
        if out and not out.endswith("\n"):
            sys.stdout.write("\n")
        return rc

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
