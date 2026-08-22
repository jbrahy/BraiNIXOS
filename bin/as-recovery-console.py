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

SECRETS, AND WHAT IS STILL EXPOSED
----------------------------------
A job may carry the admin password kmutil demands. It is handled as follows:

  * the spool on disk holds only the placeholder @@BRAINX_ADMIN_PASS@@, and the
    real value is substituted from this process's environment at the moment the
    job is handed to the agent, so no credential is ever at rest in the queue
    or left behind in the run transcript;
  * commands are passed to `run` on stdin, not argv, because argv is readable
    by any local user through ps;
  * the spool is 0700 and its files 0600, under $XDG_STATE_HOME rather than
    /tmp, and a spool owned by anyone else is refused rather than adopted.

Two exposures remain and are accepted deliberately rather than hidden:

  * the substituted command crosses the wire as plaintext HTTP. The link is the
    point-to-point Ethernet segment between the laptop and the mini, carrying
    a password that is being typed into that same mini anyway. Adding TLS here
    would mean shipping a certificate into recoveryOS to defend a two-node
    cable against an attacker who would already be inside both machines.
  * on the mini the agent runs `sh -c "$CMD"`, so the value is briefly visible
    in that machine's own process table. In 1TR the only user is root, who
    already has the policy authority the password buys.
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

SECRET_PLACEHOLDER = "@@BRAINX_ADMIN_PASS@@"

DEFAULT_BIND = "192.168.2.1"
DEFAULT_PORT = 8792
# Not /tmp. The spool holds the session token, and a token here is authority to
# run arbitrary commands as root on the mini, so it must not be world-readable
# on a shared machine.
SPOOL = Path(
    os.environ.get("BRAINX_SPOOL")
    or Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
    / "brainx-recovery-spool"
)

# How long `run` waits for the agent to come back. Deliberately generous:
# kmutil configure-boot takes minutes and looks like a hang while it works.
DEFAULT_TIMEOUT = 900.0


# ----------------------------------------------------------------- spool ----
# A directory rather than an in-process queue, so `serve` and `run` can be
# separate processes and a crashed server does not lose the transcript.


def _write_private(path: Path, data: str) -> None:
    """Write 0600, and never widen an existing file by writing through it."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(data)


def spool_init(reset: bool = False) -> str:
    if reset and SPOOL.exists():
        shutil.rmtree(SPOOL)
    for d in (SPOOL, SPOOL / "pending", SPOOL / "done"):
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
    # Refuse a spool somebody else owns or left group/world accessible, rather
    # than silently adopting it. Reusing one is how a stolen token survives.
    st = SPOOL.stat()
    if st.st_uid != os.getuid() or (st.st_mode & 0o077):
        raise SystemExit(f"refusing to use {SPOOL}: unsafe ownership or permissions")
    tok = SPOOL / "token"
    if not tok.exists():
        _write_private(tok, secrets.token_urlsafe(18))
    return tok.read_text().strip()


def token() -> str:
    return (SPOOL / "token").read_text().strip()


def _next_id() -> int:
    seq = SPOOL / "seq"
    n = int(seq.read_text()) + 1 if seq.exists() else 1
    _write_private(seq, str(n))
    return n


def enqueue(command: str) -> int:
    cid = _next_id()
    # Written to a temp name and renamed, so the server can never serve a
    # half-written command.
    tmp = SPOOL / f".{cid}.tmp"
    _write_private(tmp, command)
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
        # The secret is substituted HERE, on the way out, and never on the way
        # in. So the spool on disk holds only the placeholder: an admin password
        # must not sit at rest in a queue directory, and `done/` is kept as the
        # transcript of the run.
        text = job.read_text()
        if SECRET_PLACEHOLDER in text:
            secret = os.environ.get("BRAINX_ADMIN_PASS")
            if not secret:
                self.send_response(503)
                self.end_headers()
                return
            text = text.replace(SECRET_PLACEHOLDER, secret)
        body = f"{cid}\n{text}".encode()
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
        _write_private(SPOOL / "done" / f"{cid:06d}.out", payload)
        _write_private(SPOOL / "done" / f"{cid:06d}.rc", str(rc))
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
    r.add_argument("command", nargs="?", help="omit and pass --stdin to keep it out of ps")
    r.add_argument("--stdin", action="store_true", help="read the command from stdin")
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
        # argv is world-readable via ps, so anything that may carry a secret
        # placeholder is handed over on stdin instead.
        command = sys.stdin.read() if a.stdin else a.command
        if command is None:
            print("run needs a command argument or --stdin", file=sys.stderr)
            return 2
        cid = enqueue(command)
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
