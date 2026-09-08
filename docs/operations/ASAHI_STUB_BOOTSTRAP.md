# Bootstrapping a paired recoveryOS via the Asahi installer

**Status: STALLED, resume from the resize step.** The 2026-08-24 session got through the
resize prompt and into `fsck_apfs`'s live verification pass, then lost the SSH session
(likely `SIGHUP`ing the installer, since it wasn't run under `screen`/`tmux`/`nohup`),
followed by a hard power cut before the actual state was confirmed. See "What actually
happened" below before resuming — the container came back unresized (no partial-resize
damage), but the OS-selection step (picking "UEFI environment only") was never reached.
BraiNIX is still exactly where it was before this session started: `Not Paired`, no
progress made toward the actual goal. Update this banner once the OS-selection step
completes and a new volume group shows Paired.

## Why this exists

`FIRST_LIGHT_RUNBOOK.md` §5 diagnosed that the hand-carved `BraiNIX` volume group (created
by adding a volume and copying a system into it) can never become `Paired`, because it has
no recoveryOS of its own — see "The real cause: the group has no recoveryOS of its own."
The documented fix was reinstalling macOS onto it via the Recovery GUI wizard, confirming
the disk picker by photograph before every keystroke. That path was never executed: no
tested keyboard recipe exists for the GUI's disk-target picker, and the 2026-08-24 session
had no working camera on the mini (Continuity Camera never activated; only the laptop's own
FaceTime camera pointed at the user, which is useless here).

**The Asahi Linux installer solves the identical problem** — third-party OSes on Apple
Silicon need the same paired-recoveryOS prerequisite — and does it non-interactively enough
to avoid the GUI disk-picker entirely. It builds a small "stub macOS" (iBoot2, firmware,
XNU, a real RecoveryOS) via `asr restore`, the same mechanism a real Reinstall performs,
just scripted and battle-tested across thousands of installs. Running it is consistent with
this project's existing "m1n1 as a lab instrument" allowance (`CLAUDE.md`): we run the
published tool as-is, we do not copy its code into BraiNIX.

The specific installer option — **"UEFI environment only (m1n1 + U-Boot + ESP)"** — creates
the paired group and chainloads m1n1, without installing an actual Linux distro. We then
replace U-Boot's target with our own kernel via the same `kmutil configure-boot` sequence
already documented in `FIRST_LIGHT_RUNBOOK.md` §5, just pointed at the new group's UUID
instead of the old broken one.

## Prerequisites confirmed working this session

- **Two-way console** (`bin/as-recovery-console.py` + `bin/as-recovery-agent.sh`) gives real
  command output from recoveryOS instead of photographing the screen. See "Setting up the
  console" below for the gotchas.
- **The mini needs its own network in macOS**, separate from the recoveryOS Internet-Sharing
  bridge used for the console. Confirmed already present via `en1`/DHCP — no bridge
  configuration needed for this step. Verify with:
  ```sh
  ssh jbrahy@<mini-host> 'curl -m 5 -so /dev/null -w "H%{http_code}\n" http://captive.apple.com'
  ```
  `H200` is real connectivity.

## Setting up the console (recoveryOS side, this session)

1. Ethernet cable from the mini to the laptop; laptop has Internet Sharing active
   (`bridge100` at `192.168.2.1` in this session — already configured from a prior session,
   see `REMOTE_HANDS.md` "Getting the mini online in recoveryOS").
2. In recoveryOS Terminal (driven via the Flipper/BLE): `ipconfig set en0 DHCP`. Confirm the
   lease via `arp -a` on the laptop or `/var/db/dhcpd_leases`.
3. On the laptop, in **your own terminal** (not relayed through an assistant, so the admin
   password never crosses a logged channel):
   ```sh
   export BRAINX_ADMIN_USER=<user>
   export BRAINX_ADMIN_PASS='<password, typed by you>'
   ./bin/as-recovery-console.py serve
   ```
   Prints `listening on <ip>:<port>` and a bootstrap line with a session token.
4. **Read the token character-by-character, don't eyeball it from a photo.** A `0` (zero)
   vs `O` (capital letter) misread in the token cost this session ~15 minutes: two agent
   processes ran fine but polled the wrong URL forever, returning 404 with no visible error
   on the agent side (`curl -s` swallows it). Verify the exact token from
   `cat ~/.local/state/brainx-recovery-spool/token`, not from what got typed.
5. Send the bootstrap line to recoveryOS via the Flipper. **Download the agent script to the
   current directory (`.`), not a full `/Volumes/Data/...` path** — writing to the full path
   under `/Volumes/Data/Users/Shared/brainix-boot/` failed with "No such file or directory"
   in this session for reasons not yet root-caused; `cd`-relative worked immediately from
   `/var/root` (1TR's default cwd).
6. Confirm the link: `./bin/as-recovery-console.py run 'echo alive'` should echo back
   immediately. If it hangs, check `lsof -iTCP:<port> -n -P` on the laptop for zero
   connections ever reaching it — that's the token-mismatch symptom, not a network problem
   (basic IP connectivity was independently proven by the successful file download).

## Flipper firmware: keys the docs claimed existed but didn't

`REMOTE_HANDS.md` and `FIRST_LIGHT_RUNBOOK.md` both stated `cmd-q`, `cmd-w`, `cmd-n` (escape
from a dead Recovery Terminal) and `shift-cmd-t` (open Terminal from the Recovery main
window) were added to `named_keys[]` on 2026-08-20/21. **They were never actually in the
source, on any branch** (`git log --all -S "cmd-q" -- tools/flipper/` returns nothing).
Fixed and redeployed this session — see `tools/flipper/brainx-flipper-one/brainx_flipper_one.c`.
If a future session finds the Flipper doesn't answer to a documented key, verify against the
source before assuming the firmware is stale; the doc has been wrong about this before.

## Running the installer

Run interactively — **do not script this blind.** It's a live TUI (resize prompt, OS-list
menu, confirmations) that repartitions the disk; guessing at prompt timing on a
disk-destructive operation is not an acceptable risk. Drive it yourself over SSH.

**Blocker: the installer refuses to run over a bare SSH session** — it checks for a locally
logged-in console user and aborts with "Could not detect logged in user" if none exists.
**Fix: connect via Screen Sharing first** (`vnc://<mini-host>`, from Finder → Go → Connect to
Server, or `open vnc://<mini-host>`), log in there with the real keyboard/mouse over VNC —
this drives the actual console session, unlike SSH — then re-run the installer over SSH. The
installer's system-info step then correctly reports `Login user: <you>` instead of
`unknown`.

```sh
ssh jbrahy@<mini-host>
curl https://alx.sh | sh
```

Reviewed `scripts/bootstrap-prod.sh` from `AsahiLinux/asahi-installer` before running it
(not blind-piped): downloads a versioned installer tarball from `cdn.asahilinux.org`,
extracts it, execs `sudo caffeinate -dis ./install.sh`. Standard, no surprises.

Prompts encountered, in order:

1. sudo password (typed directly by the operator at their own terminal, never relayed).
2. Welcome screen, Enter to continue.
3. System info dump — confirms `Login user`, lists existing OSes in the container including
   our already-broken `BraiNIX` group (shown correctly, unpaired, harmless to leave in
   place).
4. `Choose what to do: r: Resize / q: Quit` — `r`.
5. Resize warning about Time Machine snapshot overhead reducing shrinkable space. `y` to
   continue anyway — informational, not a real blocker (this session had 2.93TB actually
   available regardless).
6. **New size for the existing (macOS) partition** — note this asks how much macOS *keeps*,
   not how much the new OS gets. `7.9TB` in this session, leaving ~98.55GB for the new
   group (the UEFI-only stub needs about 2.5GB; the rest is unused headroom, harmless).
7. Confirm resize, `y`. Then `fsck_apfs` runs a full live verification pass over every
   volume in the container before actually resizing — **this is the slow part and scales
   with file/snapshot count, not with how much space is being moved.** No reliable ETA;
   this session's Data volume made it take a while. No input needed during this phase.

**Still to be run and documented once the resize completes:** OS-selection menu (confirm
exact wording, then select "UEFI environment only (m1n1 + U-Boot + ESP)"), completion,
`bputil -e` verification that the new group shows Paired, and the `kmutil configure-boot`
step chainloading `brainix-kernel-aarch64.bin` onto the new group's UUID.

## What actually happened (2026-08-24 incident chain)

Recorded in full because most of it is process failure, not a technical blocker, and the
same mistakes are cheap to repeat.

1. **Resize started ~01:36, still at 15% of the `fsck_apfs` verification pass at ~03:10.**
   No reliable ETA exists for this step (see "Running the installer" above) — this alone
   was not a problem.
2. **The SSH session died mid-fsck**, visible in scrollback as `Shared connection to
   baby-jesus.local closed` right after the 15% line. The installer was run as a plain
   foreground process in an interactive SSH session with no `screen`/`tmux`/`nohup`, so
   losing the TCP session most likely delivered `SIGHUP` to it. **Lesson: always wrap a
   long-running remote installer in `nohup ... &` or `screen`/`tmux` before starting it,**
   even when it needs to stay interactive for prompts — a detachable session survives a
   dropped connection, a bare foreground one does not.
3. **A re-run of `curl https://alx.sh | sh` went to the wrong machine.** When the SSH
   session died, the terminal window fell back to a local shell prompt on the *laptop*,
   and the re-run was typed there without noticing the prompt had changed. The installer's
   own system-info step caught it (`MacBook Pro ... M3 Pro ... This device is not supported
   yet!`) and aborted before touching any partition — no harm done, but it could have been
   worse on a supported machine. **Lesson: after any SSH drop, re-verify `hostname`/`ssh`
   prompt before re-running anything destructive, don't assume the terminal is still where
   you left it.**
4. **A hard power cut** (unplugged, not held-to-force-shutdown) was applied to the actual
   mini around 12:41, while its true state was still unknown (screen was reading solid
   black from a capture device with no HDMI signal, which turned out to be a cabling/signal
   issue, not the machine being unresponsive). This is the single highest-risk action in
   the chain — a hard cut during a live APFS container resize risks real corruption — and
   it happened because a black capture frame was read as "machine may be hung" without
   ruling out the simpler cause first.
5. **Post-recovery, the container came back at its original 8.0TB, unresized** — the
   `resizeContainer` operation did not persist any partial change. This is the good outcome
   of an otherwise risky sequence, not something to rely on happening again.
6. **A false alarm on Macintosh HD's pairing status.** `bputil -e` run over SSH from
   regular booted macOS showed `OS Pairing Status: Not Paired` for *both* volume groups,
   including Macintosh HD, which had shown `Paired` all night when checked from within
   1TR. This was read as new damage and prompted an unnecessary `bputil -f` write against
   the production volume group. **The actual cause: `OS Pairing Status` reads `Not Paired`
   by design whenever checked from a normally-booted OS — it only reads `Paired` when
   checked from within a paired recoveryOS session itself** (confirmed against Apple
   Silicon security documentation, see sources in `FIRST_LIGHT_RUNBOOK.md` §5's `bputil -e`
   section). **Lesson, now added to the runbook: never read `bputil -e`'s pairing status
   from outside 1TR — the "Not Paired" it shows there is meaningless, not evidence.** The
   resulting `bputil -f` write is expected to be harmless (it only re-personalizes the
   policy against Apple's servers, the same operation already proven safe on BraiNIX), but
   it was unnecessary, and Macintosh HD's actual pairing status remains **unverified** as
   of session end — the next 1TR entry should check it (from within 1TR) before assuming
   anything is wrong.

**Net state at session end:** Macintosh HD boots and operates normally. BraiNIX's old
volume group is untouched, still permanently `pairing (17)`. No progress was made on the
actual goal (a paired stub via the Asahi installer) — resume from "Running the installer"
above, this time under `nohup`/`screen`.

## Open questions for next session if this gets interrupted

- Exact menu key/wording for "UEFI environment only" in installer v0.9.0 — not yet observed
  live, only from published Asahi docs/wiki summaries.
- Whether m1n1's own proxy/console (once installed by this flow) can be used directly for
  chainloading BraiNIX, replacing the `kmutil configure-boot`-per-iteration cycle — this was
  the original Phase 1 plan in `BRINGUP_PLAN.md` ("m1n1... chainloading — which replaces a
  ten-minute recovery trip with a one-second command") and this installer path may deliver
  it for free.
- What to do with the old, permanently-`pairing (17)` `BraiNIX` volume group afterward —
  leave it or delete it once the new group is proven working. Not urgent; it's inert.
