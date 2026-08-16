# Apple Silicon bring-up rig — provisioning runbook

## Purpose

Turn a stock Mac mini M2 Pro (`Mac14,12`, SoC `T6020`) into a machine that can run BraiNIX payloads and
show their serial output. Until this is done, **AS-1a's exit criterion is unreachable** and every AS-1
slice after it is blocked — not on code, on this.

This runbook stops at the acceptance test. It does **not** chainload BraiNIX; that is
[`bin/as-boot.sh`](../../bin/as-boot.sh) and it comes after.

> **Read [`BRINGUP_PLAN.md`](BRINGUP_PLAN.md) first.** §5's rule — *do not chainload BraiNIX until m1n1's
> own console prints* — was ignored on 2026-08-14/15, and the result was five recovery trips, three boot
> objects, a wedged local policy, a deleted volume group, and **zero bytes of output from anything**. The
> plan document explains why the loop has to come before the code.

**Requires physical presence at the machine.** The security downgrade in §2 cannot be done over SSH,
by MDM, or by any remote path — that is Apple's design, not an inconvenience to route around.

---

## 0. What this costs, before you start

Stated up front because these are irreversible-ish and worth knowing:

- **A macOS stub install must remain on disk permanently.** "Bare metal" here means BraiNIX is the OS,
  not that Apple software is absent. The paired recoveryOS and firmware volumes stay.
- **Permissive Security is a real reduction in that volume's security posture.** It is the supported
  mechanism for third-party kernels, and it is also the thing that lets an attacker with physical access
  boot their own code. Do not do this to a machine holding anything you care about.
- **FileVault and Activation Lock still gate the downgrade.** If the machine is enrolled or locked, sort
  that out first.
- **Every macOS update that touches firmware is a potential breaking event** for the boot stub. The
  handoff ABI below iBoot is reverse-engineered and carries no compatibility promise
  ([`../ROADMAP.md`](../ROADMAP.md), *Honest risks* #3).

---

## 0a. The machine of record — measured 2026-08-14

Read off the hardware over SSH, not copied from a spec sheet. This is the baseline every later
re-qualification compares against.

| Fact | Value | Where it came from |
|---|---|---|
| Host name | `baby-jesus.local` (192.168.5.2) | Bonjour, reached over Wi-Fi on the LAN |
| Model identifier | **`Mac14,12`** | `sysctl -n hw.model` |
| SoC | Apple **M2 Pro**, 10 cores (6 performance + 4 efficiency) | `system_profiler SPHardwareDataType` |
| Memory | **32 GB** unified | as above |
| Serial | `NNPN625M0M` | as above |
| ECID | `0x4491A21D3C01E`; CHIP `0x6020`, BORD `0x2` | `bputil -d` |
| Storage | 8.0 TB internal; container `disk3`, 3.3 TB unallocated | `diskutil apfs list` |
| macOS at first contact | **15.3.1 (24D70)** | `sw_vers` |
| **Firmware at first contact** | **11881.81.4** (System Firmware = OS Loader) | `system_profiler SPHardwareDataType` |
| Boot policy at first contact | **Full Security** (`smb0` absent), SIP enabled, Kernel CTRR enabled, boot-args filtering enabled | `bputil -d` |

### THE PIN — established 2026-08-14 after the Sequoia install

**This is the version every reverse-engineered fact in this tree is derived against.** Risk 3 applies from
here: any macOS update that moves these numbers is a re-qualification event, and firmware cannot be
downgraded.

| Fact | Value |
|---|---|
| Stub install | **macOS 15.7.5, build 24G624** (`love: 24.7.624.0.0,0`) |
| **System Firmware Version** | **`mBoot-18000.161.9`** |
| **OS Loader Version** | **`11881.140.96.701.1`** |
| Host name | `brainix-mini.local` |
| BraiNIX volume group UUID | **`D2193B68-243F-444A-A38F-D46D224964E6`** — boots from `/dev/disk3s8s1` |
| Production volume group UUID | `C40FFC20-DCC8-494E-B6A2-D7FAA994557E` — `Macintosh HD`, **leave alone** |

**Note the format change.** Before the install, System Firmware and OS Loader reported the same value
(`11881.81.4`). After it they are different and the firmware string carries an `mBoot-` prefix. Record
both; a spec file stamped with only one of them is stamped ambiguously.

**This machine was, and while it dual-boots still is, in production use.** It runs `llama-server` on
`0.0.0.0:8080` serving Qwen2.5-Coder-32B Q4_K_M, a `coder_proxy.py` on 8091, plus SMB, screen sharing and
ARD. That is why the BraiNIX install is a **second volume group** rather than a takeover of the machine:
the boot policy on Apple Silicon is per-volume-group, so BraiNIX gets its own policy and the working
install keeps its own. Deleting the volume group undoes the whole thing.

### The measured bandwidth ceiling — 2026-08-14

The incumbent stack was measured on this machine before anything was changed, because it answers a
question the roadmap had been answering from a spec sheet:

- Qwen2.5-Coder-32B-Instruct Q4_K_M, **19.851 GB** of weights, Metal GPU offload on, 128-token decode.
- **7.785 tokens/second** decode (`predicted_per_second`), 11.3 tok/s prefill on an 8-token prompt.
- Implied achieved bandwidth: 7.785 × 19.851 ≈ **155 GB/s**, against the M2 Pro's 200 GB/s theoretical.

**Use 155 GB/s, not 200 GB/s, as the denominator in the ceiling arithmetic** ([`../ROADMAP.md`](../ROADMAP.md)
A14). The figure is generous to BraiNIX in two directions and should be read as an upper reference rather
than a target: it is measured *with* the GPU, which AS-4c will not have, and it includes KV-cache traffic
so it is not a weights-only bandwidth number. What it is not is a guess.

### Permissive Security — ACHIEVED 2026-08-14

The rig's blocking item. Done from **One True Recovery** on the mini, after two remote attempts proved it
could not be done any other way.

**What the machine printed back**, which is the record that matters:

| Field | Value |
|---|---|
| OS Type | `one true recoveryOS` — confirms genuine 1TR rather than a paired recovery |
| OS Pairing Status | `Paired` |
| Authorized user | `administrator` |
| Volume Group UUID (`vuid`) | `D2193B68-243F-444A-A38F-D46D224964E6` — the stub |
| OS Version (`love`) | `24.7.624.0.0,0` |
| **Security Mode** | **`Permissive` (`smb0 && smb1`): 1** |
| 3rd Party Kexts (`smb2`) | `Enabled`: 1 |
| **Kernel CTRR** (`sip2`) | **`Disabled`**: 1 |
| SIP (`sip0`) | `Enabled` — absent from policy |
| Signed System Volume (`sip1`) | `Enabled` — absent |
| **Boot Args Filtering** (`sip3`) | **`Enabled`** — absent |

The production volume group `C40FFC20-...` was not touched and remains Full Security.

**Remote attempts fail, and the reason is worth keeping.** `bputil` accepts `-u`/`-p`/`-v` and will run to
completion from a booted macOS — the Secure Enclave answers every command with 0, garbage policies are
reaped, the nonce is reset — and then the write is refused:

```
BYErrorDomain Code=401 "Failed to create local policy"
  com.apple.bootpolicy Code=11 "AP boot mode (11)"
```

`AP boot mode (11)` is *normal* boot mode. Creating a local policy requires *recovery* boot mode. It is
not a credential, a permission, or a missing flag, and a correct password produces an **authenticated
failure** that looks nothing like an auth error. Verify with `bputil -d` afterwards rather than trusting
the exit path.

#### The one thing `-n -k -c` does not give us

**Boot-args filtering is still enabled** (`sip3` absent), because that is `-a`'s job, not `-c`'s. This is
enough to boot a custom kernel via `kmutil`, which is what AS-1 needs. It is **not** enough for the
macOS-side leg of the **OQ-5** experiment — reading legacy-UART output out of XNU needs `serial=3` and
`serial-device=<uart0 phandle>` passed as boot-args, which needs `-a`, and per the published accounts also
SIP disabled. Decide that when OQ-5 is actually being run; do not pre-emptively widen the downgrade.

### Serving a model from the stub volume — 2026-08-14

Recorded because it modifies the stub, and an undocumented modification to the machine that holds the boot
policy is exactly the kind of thing that confuses a later bring-up session.

The production `llama-server` is a LaunchDaemon on `Macintosh HD`, so booting the stub takes it down. It
can be run **from the stub without rebooting**, because the production Data volume mounts at
`/Volumes/Data`:

1. `ln -sfn /Volumes/Data/opt/homebrew /opt/homebrew` — ggml `dlopen`s its Metal and CPU backends by paths
   derived from the binary's own prefix, so `DYLD_FALLBACK_LIBRARY_PATH` is **not** sufficient; the
   Homebrew prefix has to resolve. Symptom when it does not: `no backends are loaded`.
2. `sysctl -w iogpu.wired_limit_mb=28672` — without it, a 19.85 GB model on a 32 GB machine fails at
   inference time (not load time) with `kIOGPUCommandBufferCallbackErrorOutOfMemory`. The production
   volume sets this via a `com.local.iogpu-wiredlimit` LaunchDaemon; the stub has no such daemon and
   defaults to `0`.
3. Run `llama-server` with the production arguments, paths rebased onto `/Volumes/Data`.

**Neither change persists across a reboot**, and neither is part of the BraiNIX design — they exist so the
machine is not dark while bring-up proceeds. Undo by deleting the symlink; the sysctl reverts by itself.

### The bandwidth figure, measured twice — 2026-08-14

| Run | Context | decode tok/s | Implied bandwidth |
|---|---|---|---|
| 1 | Production install, `Macintosh HD` | 7.785 | ~155 GB/s |
| 2 | Stub volume, same model and flags | 7.922 | ~157 GB/s |

Two independent runs on different volume groups agreeing to within 1.5% is a stronger basis for A14's
denominator than either alone. **~155 GB/s stands as the number to divide by**, against the M2 Pro's
200 GB/s theoretical — and it remains an *upper* reference for BraiNIX, since both runs had the GPU that
AS-4c will not.

### Session record, 2026-08-14 evening — where this was left

**The BraiNIX volume group is in an unknown boot state and the machine is powered off.** Recorded in
detail because the next session cannot re-derive it.

**Sequence.** Permissive Security landed (above) and the volume booted macOS normally. Two model services
were installed on it and both ran. At **18:57 the machine went down abruptly** while `sd-server` was
generating and `llama-server` was resident. The owner reached 1TR and ran `kmutil configure-boot` for
m1n1, then rebooted. Since then: **no network, no serial output, no Thunderbolt device, black screen.** A
remote `macvdmtool reboot serial` was acknowledged (`Rebooting target into normal mode... OK`, then
`Connected`) and produced nothing over four minutes of polling.

**Known:**

- `Macintosh HD` (`C40FFC20-...`) is untouched, Full Security, and boots. All data and weights are on disk.
- Thunderbolt reporting `No device connected` on every receptacle is the tell that the mini is **off**.
  `macvdmtool nop` succeeding does **not** contradict that — it exercises the *local* HPM, and a target's
  USB-PD controller stays powered when the Mac is off. That is how DFU works, and it misled this session.

**Not known, and it is the gap that decides the fix:** whether `kmutil configure-boot` succeeded. Its
output was never captured. Installed-and-working, installed-and-not-running, and errored-out are three
different states with three different remedies, and a silent black screen is consistent with all three.

**Recovery, and it requires physical presence:** force off (hold power 10 s), hold power to reach the
startup manager, select `Macintosh HD`. From there the BraiNIX volume can be mounted and inspected —
boot object, policy, and the 18:57 panic log — and its boot object reset if needed.

**Rule earned here:** never install a custom boot object without capturing the installer's output in the
same breath. A boot object is the one change whose failure mode is a machine that cannot tell you what
went wrong.

### Installing the boot object — three rules paid for in recovery trips

**1. `bputil -n -c`. Never `-k` on this path.** §2 documents `bputil -n -k -c`, and the `-k` is wrong
here. It enables trust in a locally SEP-signed AuxiliaryKernelCache for third-party kexts — a macOS
concern with no bearing on booting our own kernel — and it requires a *paired* AuxKC that this flow never
creates. The symptom arrives later and points elsewhere: `kmutil configure-boot` runs all the way through
`wrapping boot object payload` and then fails with

```
KMErrorDomain Code=71 "Boot policy error: Error setting 3rd party kexts tag: code pairing (17)"
```

and afterwards `bputil` itself fails with `BYErrorDomain Code=401 "Failed to create local policy"`
wrapping the same `pairing (17)`. At that point the volume group's policy is wedged: both tools refuse,
and the only recoveries are reinstalling macOS on it or deleting and recreating the volume group.

**2. Install the boot object once, last.** Every `configure-boot` replaces that volume's kernelcache, which
is what puts it into "this version of macOS needs to be reinstalled" and degrades the macOS/recoveryOS
pairing the policy tools depend on. Do the security downgrade, confirm it, and only then install the boot
object — as the final action before rebooting into it.

**3. The volume group UUID changes when the volume group is recreated.** Obvious in hindsight, and a stale
`-v` UUID produces a failure that looks like a policy fault rather than a typo. Read it fresh from
`bputil -e` every time.

### AS-1a2 changes the acceptance test — 2026-08-15

**The payload no longer depends on the serial console to prove it ran.** As of `3317f78` it paints one
horizontal stripe per boot stage into the framebuffer `boot_args.video` describes, so first light is
visible on a display whether or not the s5l UART reaches this machine's SBU pins (**OQ-5**).

| Stripes | Meaning |
|---|---|
| screen unchanged | the payload never ran, or never reached `paint` |
| 1, white | executing, and `boot_args.video` parsed |
| 2, +cyan | the ADT window derived from `boot_args` |
| 3, +green | the ADT parsed and UART discovery ran |
| last stripe red | that stage denied; the count says which |

**Consequence: m1n1 is not required.** It was only ever a convenience for chainloading over serial. The
BraiNIX payload can be the Image4 boot object directly, with the same `kmutil` invocation and a different
`-c`. Staged on the machine at `/Users/Shared/brainix-boot/brainix-boot-stub-apple.bin` (8,499 bytes,
sha256 `db630c10b9476f40...`), and on `BraiNIX - Data` under `Users/Shared/brainix-serve/`.

**Install it with `--entry-point 0`, not `2048`:**

```
kmutil configure-boot -c <payload> --raw --entry-point 0 --lowest-virtual-address 0 -v /Volumes/BraiNIX
```

**This is the difference between a payload that runs and one that does not, and it was got wrong once.**
§4's m1n1 invocation uses `--entry-point 2048` because m1n1's raw image carries a 2048-byte header before
its entry, and that section says outright those values are "m1n1's own layout convention, not BraiNIX's".
The BraiNIX payload's linker script places `_start` at **offset 0** and `llvm-readobj` reports
`Entry: 0x0`. Installed at 2048, iBoot jumps 2 KB into an 8.5 KB image, lands mid-instruction, and
executes garbage — which presents as a powered machine with **no serial, no stripes, and no network**,
i.e. every output path silent at once.

**Read that failure signature the right way round:** two independent channels going quiet together is far
more likely to mean nothing ran than that both broke. Check the entry point against
`llvm-readobj --file-headers` before concluding anything about OQ-5.

The install still requires One True Recovery, and **its output must be captured** — see the session
record above for why that one missing line cost a night.

### Running two models concurrently on 32 GB — do not

The 18:57 crash happened with `llama-server` at 7.3 GB resident and `sd-server` at 11.8 GB, GPU pinned at
98% / 18 W, against `iogpu.wired_limit_mb=28672` on a 32 GB machine. The FLUX job had been *generating*
for over ten minutes without completing and never did.

Two conclusions, stated separately because they have different confidence:

- **Firm:** FLUX.1-schnell Q4_0 under `sd.cpp`'s Metal path is **not viable on this hardware at these
  settings** — over ten minutes for a 4-step 512x512 image, unfinished. If image generation is wanted
  here, `mflux` (MLX) is the tuned Apple Silicon path and should be measured before sd.cpp is kept.
- **Circumstantial:** the crash is consistent with GPU/wired-memory exhaustion from both models resident
  at once. Not proven — the panic log has not been read. Until it is, treat concurrent LLM + diffusion
  serving on this box as unsupported rather than merely slow.

### macOS serving gotchas found the hard way — 2026-08-14

Four, each of which cost a diagnostic round and none of which is visible from an interactive shell:

1. **launchd cannot read the other volume group.** A daemon whose binary and weights lived on
   `/Volumes/Data` died with SIGSEGV at model-open while the identical script ran fine over SSH. Everything
   a boot-time service needs must be on the volume that booted it.
2. **`sd-server` recursively scans its working directory** and dies on `com.apple.TCC` under launchd. Set
   an explicit `WorkingDirectory` in the plist.
3. **`curl --retry-all-errors` with `-C -` is not resume-safe.** On a retry the CDN can answer `200`
   instead of `206`, and curl then truncates and restarts. Observed taking a 6.07 GB file back to 3.09 GB
   mid-run. Use one fresh `curl -C -` per attempt from a supervising loop instead.
4. **The mini was asleep**, which killed two downloads at once. `pmset -a sleep 0 disksleep 0` — a machine
   that serves models should never sleep, and it would have dropped inference requests too.

### gemma-4 is a reasoning model

`gemma-4-12B-it` fills `reasoning_content` before `content`. At `max_tokens: 500` on a trivial prompt it
spent the entire budget thinking and returned **empty content** with `finish_reason: length` — which reads
as a broken server. Either budget 600+ tokens or pass
`"chat_template_kwargs": {"enable_thinking": false}`, which answered the same class of question in 13
tokens. Measured throughput: **18.7 tok/s**.

### The firmware pin — owner decision, 2026-08-14

The second volume group needs a macOS install, and **the oldest installer Apple still offers is Sequoia
15.7.5 (24G624)**. System firmware on Apple Silicon is **global to the machine and cannot be downgraded**;
Apple no longer signs 15.3.1. Installing anything therefore moves the machine's iBoot permanently.

**Owner chose to bump to 15.7.5 now and pin there**, on the reasoning that no hardware fact had yet been
derived from this machine — no ADT dump, no register offsets, no AGX ABI — so the re-derivation cost of a
firmware move was zero at that moment and never would be again. Sequoia was chosen over Tahoe 26.x to stay
on the same major generation as the current install and as the published reverse-engineering work.

**Once this install completes, record the resulting firmware version in the table above and treat every
later macOS update as a re-qualification event** ([`../ROADMAP.md`](../ROADMAP.md), *Honest risks* #3).

---

## 1. Parts

| Item | Notes |
|---|---|
| Mac mini M2 Pro (`Mac14,12`, `T6020`) | The deployment target. 32 GB. **Confirmed present and measured — see §0a.** |
| ~~Debug UART cable~~ **An ordinary SuperSpeed USB-C cable** | **Corrected 2026-08-14, and this row was wrong in the expensive direction — it would have sent someone shopping for a part they do not need.** No SBU-breakout debug cable is required *when the host is itself an Apple Silicon Mac*. A **USB 3.0 / SuperSpeed (or Thunderbolt) Type-C cable** plus `macvdmtool` puts both ends into serial mode over USB-PD Vendor Defined Messages. What does **not** work is a USB 2.0-only or charge-only cable: serial mode needs the SuperSpeed pins. **Verified working on this rig 2026-08-14.** |
| Host machine | **Must be an Apple Silicon Mac running macOS** for the `macvdmtool` path. This rig's host is a `Mac15,6` (14" MacBook Pro) on macOS 26.5.2, SIP **enabled** — no SIP downgrade is needed on the host. |
| `macvdmtool` | Asahi's Apple-Silicon-to-Apple-Silicon VDM utility. Build from source; **a lab instrument, never vendored** (CONTRIBUTING rule 7), so it lives outside the repository. See §3. |
| Serial terminal | `picocom`, `screen`, or `minicom` on the host, against `/dev/cu.debug-console`. |

---

## 1a. Create the BraiNIX volume group *(added 2026-08-14)*

**Do this instead of taking over the machine** when the mini is doing anything else. The boot policy on
Apple Silicon is **per volume group**, so BraiNIX gets its own policy and the working install keeps Full
Security. Deleting the volume group undoes all of it.

### 1a.1 Carve the volume — SSH is fine, non-destructive, instant

```
sudo diskutil apfs addVolume disk3 APFS BraiNIX
```

Shares free space with the container; no repartitioning. On this rig it became `disk3s7`, mounted at
`/Volumes/BraiNIX`.

### 1a.2 Fetch the installer

```
sudo softwareupdate --list-full-installers
sudo softwareupdate --fetch-full-installer --full-installer-version <oldest offered>
```

**Take the oldest version Apple still offers.** System firmware is global to the machine and cannot be
downgraded, so this choice is permanent — see §0a's firmware-pin decision. On this rig the oldest was
Sequoia 15.7.5 (24G624) against a machine running 15.3.1.

### 1a.3 Run the installer — **GUI only, and this is not a preference**

`startosinstall` **has no `--volume` flag.** Apple removed it; `--usage` on the Sequoia installer lists
`--eraseinstall`, `--newvolumename` and `--preservecontainer`, and nothing that targets an existing
volume. `--eraseinstall` does what it says. **There is no supported CLI path to install macOS onto a
second volume in the same container**, so this step needs a human at a logged-in GUI session — physically
or over Screen Sharing.

It also cannot be launched from SSH into an empty console: `launchctl asuser` fails with
`OSLaunchdErrorDomain Code=125` when no one is logged in, and `stat -f %Su /dev/console` reporting `root`
is how you tell.

1. Log in on the target at the console or over Screen Sharing.
2. Open `/Applications/Install macOS <name>.app`, Continue, agree to the license.
3. **Click "Show All Disks…" and select `BraiNIX`.**

   > **The trap.** The default destination is the *current* system volume. Clicking through without
   > "Show All Disks…" upgrades the production install instead of creating the second volume group — no
   > data loss, but the whole point of §1a is gone and the firmware moves anyway.

4. Install. The machine reboots, installs, and comes up in Setup Assistant **on the new volume**.
5. Create a **local administrator** account. §2 needs those credentials, and a compromised or absent admin
   account is why 1TR refuses the downgrade.

### 1a.4 Record the result

Update §0a's table with the firmware version the install produced. From that point Risk 3 applies and
every macOS update is a re-qualification event.

---

## 2. Downgrade the volume to Permissive Security

**Physical presence required.** Once per machine.

1. Shut the mini down fully.
2. Enter **1TR** ("One True Recovery"): press and **hold** the power button until "Loading startup
   options" appears, then choose **Options → Continue**.
   - It must be **1TR**, entered by holding power from a full shutdown. Recovery reached any other way
     will not permit the downgrade.
3. Sign in as a local administrator when prompted.
4. Open **Utilities → Terminal**.
5. **`bputil` will ask which macOS installation to act on**, because this machine has two. *(Recorded
   2026-08-14 — the original version of this section did not mention the prompt, and picking wrong here
   downgrades the production install instead of the stub.)* Identify the target by its **volume group
   UUID**, never by its position in the list:

   | Pick | UUID | What it is |
   |---|---|---|
   | BraiNIX | `D2193B68-243F-444A-A38F-D46D224964E6` | the stub — **this one** |
   | Macintosh HD | `C40FFC20-DCC8-494E-B6A2-D7FAA994557E` | production — **not this one** |

   Confirm before committing by running `bputil -d` first and checking the `vuid` line it prints back.
   The `love` field is a second check: the stub reports `24.7.624.0.0,0` (build 24G624).

6. Run:

   ```
   bputil -n -k -c
   ```

   Read what it prints and confirm the prompts. `bputil` is interactive and states exactly what it is
   about to change; if its description does not match "downgrade this volume to Permissive Security",
   stop and re-read rather than confirming.
7. Reboot into macOS.
8. Verify from macOS:

   ```
   bputil -d
   ```

   **Expected: the volume's policy reports Permissive Security.** If it does not, nothing below will
   work, and the fix is here rather than further down.

---

## 3. Wire the serial console — via `macvdmtool`

**Rewritten 2026-08-14 against a rig that works.** The previous version of this section assumed a
breakout debug cable and looked for `/dev/tty.usbmodem*`; both are wrong for the Apple-to-Apple path.

### 3.1 Build the tool

```
git clone --depth 1 https://github.com/AsahiLinux/macvdmtool.git
cd macvdmtool && make
```

Needs the Xcode command line tools and nothing else — it compiles one `main.cpp` against CoreFoundation
and IOKit. **Keep it outside this repository.** It is a lab instrument in exactly the sense CONTRIBUTING
rule 7 permits: we run it, we do not incorporate it. On this rig it lives in `~/OtherProjects/_tools/`.

Read the source before running it, as with anything that touches the platform. It opens `AppleHPM` — the
USB-PD port controller — and sends Apple-SVID Vendor Defined Messages. It executes no subprocess, writes
no file, and opens no socket.

### 3.2 The ports are not optional, and getting them wrong looks like a different failure

The VDM only works through each machine's **DFU port**:

| Machine | Port |
|---|---|
| Mac mini | The Thunderbolt port **closest to the power connector** — the first one after Ethernet, not any of the other three. |
| 14" / 16" MacBook Pro | The Thunderbolt port **adjacent to MagSafe**, left side. |
| MacBook Air, 13" MacBook Pro | The rear port. |

**The failure signature, recorded because it cost a round on this rig:** with the cable in the wrong port,
`macvdmtool nop` **succeeds** — it finds the HPM device, unlocks it, and completes a DBMa mode round-trip
with exit 0 — and then `serial` fails with `VDM failed (reply: 0x05ac8092)`. That reads like a protocol or
cable problem and is neither. The discriminator is `debugusb`, which the tool documents as working over
USB 2.0-only cables: **if `debugusb` fails identically, the cable is fine and the port is wrong.** If
`debugusb` succeeds where `serial` fails, *then* the cable lacks SuperSpeed pins.

A correct connection also shows up in `system_profiler SPThunderboltDataType` as **`Status: Device
connected`** on one receptacle. A cable in a non-DFU port reports `No device connected` with a link status
that is nonetheless not idle.

### 3.3 Enter serial mode

```
sudo ./macvdmtool serial
```

Expected, and what this rig printed on success:

```
Entering DBMa mode... Status: DBMa
Putting target into serial mode... OK
Putting local end into serial mode... OK
Exiting DBMa mode... OK
```

The console is then `/dev/cu.debug-console` on the host — the same node m1n1 wants as `M1N1DEVICE`.

```
picocom -b 115200 /dev/cu.debug-console
```

`serial` does **not** reboot the target. `reboot serial` does; use it when you need to see a boot.

**Nothing will print yet, and that is not a failure.** A mini running ordinary macOS does not write to the
debug UART, so an idle console is the expected reading. The console is proven in §5, by rebooting
something that talks. This rig confirmed serial mode came up and then read five seconds of silence from
`/dev/cu.debug-console`, exactly as predicted.

---

## 3a. What the serial console does and does not cover

**Status 2026-08-14: the console works** (§3), which retires the "no cable" blocker this section was
originally written about. What survives is the scope note.

- **AS-1a's exit criterion is reachable.** The banner is transmitted by writing s5l UART MMIO registers,
  those bytes leave the SoC on the port's SBU pins, and `macvdmtool serial` is what puts the far end of
  the cable in a state to receive them.
- **Break-glass admin enrollment depends on this path permanently.** `INV-BOOT-008` provisions the
  break-glass PSK over the serial console and over nothing else, and the ratchet's only out-of-band repair
  path is that same console ([`../THREAT_MODEL.md`](../THREAT_MODEL.md)). Note the operational consequence
  of the `macvdmtool` route: **the break-glass path requires a second Apple Silicon Mac and a SuperSpeed
  cable**, not merely a serial adapter in a drawer. That is a cheaper dependency than a debug cable and a
  more specific one; a deployment runbook must name it.
- **The threat-model rule is unchanged.** The serial console grants physical-access authority and must not
  be present in a production configuration.

### 3b. The framebuffer alternative — still proposed, no longer urgent

**Re-rated 2026-08-14.** With the console working, this stops being the thing standing between the project
and first light and becomes what it should always have been: a second, independent output path that makes
a silent machine diagnosable. Worth building, not worth blocking on.

iBoot sets up a framebuffer and describes it in the **`video` field of the `boot_args` structure** — the
same structure AS-0-T4 already parses, whose module doc records that it deliberately does not read
`video` (`src/adt/src/boot_args.rs`). Rendering a glyph into that buffer is a pure function over bytes:
host-testable, fuzzable, and exactly the discipline `INV-PARSE-001` already demands of everything else
that reads a firmware-supplied structure.

First light would then be **text on an HDMI display**, needing no cable at all, and it works identically
whether the payload is chainloaded by m1n1 or booted directly by iBoot under `kmutil`.

Stated honestly, because this changes a written exit criterion:

- It is **additive, not a replacement.** Keep the UART transmit path; add the framebuffer path; first
  light succeeds if either produces output. Two independent output paths also disambiguate a silent
  machine, which is the failure §5's rule exists to prevent.
- It is **strictly less dangerous than the UART**, not more: a framebuffer is output-only, while the
  serial console is bidirectional and carries physical-access authority.
- It does **not** retire the cable requirement. Break-glass enrollment is serial and stays serial.
- It costs a `boot_args.video` decoder and a font blitter, both host-testable, and it removes a
  sourced-hardware dependency from the critical path to first light.

Tracked as **AS-1a2** in [`../ROADMAP.md`](../ROADMAP.md) Track C.

---

## 4. Install m1n1 as the boot object

m1n1 is used as a **lab instrument and chainloader**, never as incorporated code.
[`../../CONTRIBUTING.md`](../../CONTRIBUTING.md) rule 7 permits exactly this: running it is using a tool.
No m1n1 code is copied, linked, or vendored into BraiNIX.

1. Obtain and build m1n1 on the host per its own documentation.
2. Install it as the mini's boot object from macOS on the target:

   ```
   kmutil configure-boot -c m1n1.bin --raw --entry-point 2048 --lowest-virtual-address 0 -v /Volumes/<target>
   ```

   The `--entry-point 2048` and `--lowest-virtual-address 0` values are m1n1's own layout convention, not
   BraiNIX's. Take the exact invocation from m1n1's current documentation rather than from this file if
   the two disagree — m1n1 owns that fact.
3. `kmutil` wraps the payload as an **Image4** object signed under the machine's Secure-Enclave-held
   **local policy**. iBoot verifies it against that policy at every boot. This is Apple's supported
   third-party-kernel path.
4. Reboot.

---

## 5. Acceptance test — the gate

**m1n1's own console must print over serial.**

That is the whole test. It validates §2, §3, and §4 together, with **zero BraiNIX code involved**.

- **It prints.** The rig works. Proceed.
- **It does not print.** The problem is the rig — the downgrade, the cable, the port, the baud rate, or
  the install. It is **not** BraiNIX, because none of BraiNIX has run.

> **Do not chainload a BraiNIX payload before this passes.** If you do, a silent machine has two possible
> causes instead of one, and you will spend the debugging session distinguishing them instead of fixing
> anything. This is the single most valuable rule in this document.

Record, in this file or the PR that closes AS-1a:

- the macOS build the machine is running (`sw_vers`),
- the m1n1 version installed,
- the serial device path and baud rate that worked.

The UART fact table ([`../platform-specs/apple-s5l-uart.md`](../platform-specs/apple-s5l-uart.md)) is
**not version-stamped**, and its header says so. The macOS build recorded here is what stamps it.

---

## 6. After the gate: first light

Run [`bin/as-boot.sh`](../../bin/as-boot.sh). It builds the payload, asserts the image shape, flattens it
to a raw binary, and prints the chainload command. Then:

```
export M1N1DEVICE=/dev/tty.usbmodemXXXX
chainload.py -r src/boot-stub-apple/target/aarch64-unknown-none-softfloat/release/brainix-boot-stub-apple.bin
```

### Reading the result

| Serial output | Meaning |
|---|---|
| `[..] BraiNIX: alive` then `[OK] BraiNIX: first light` | **AS-1a is done.** The delivery chain, the UART, and ADT discovery all work. |
| `[..] alive` then `[!!] adt uart discovery denied: <reason>` | The payload runs and the fallback UART base is right. The named reason says which deny path in [`../architecture/AS-1a-first-light-boot-stub.md`](../architecture/AS-1a-first-light-boot-stub.md) §5 fired. |
| Garbled or partial characters | Likely the **`UTRSTAT` transmit-ready bit** (fact table OQ-1). The driver polls a bounded number of times then transmits anyway precisely so this looks like garbage rather than a hang. Fix `TX_READY_MASK` in `registers.rs`. |
| Nothing at all | Either the fallback UART base is wrong — it is a **`T6030`** observation and this machine is a `T6020`, so it is *expected* to differ (fact table OQ-2) — or the payload never ran. Distinguish by checking whether m1n1's console still responds. |

**Nothing printing is the anticipated first result**, not a failure of the work. The fallback base is the
one value the fact table says outright it could not confirm for this SoC. Recovering from it means
reading the real base out of the ADT — which is what the payload's stage 2 exists to do, and what a
successful `[..] alive` line unlocks.

---

## 7. What this rig does not give you

- **No attestation and no sealing, permanently.** See
  [`ATTESTATION_MODEL.md`](ATTESTATION_MODEL.md) §0. Nothing in this runbook changes that.
- **No headless provisioning.** §2 needs a human at the machine, once per machine.
- **No protection from firmware updates.** Re-qualify after any macOS update that touches firmware.
