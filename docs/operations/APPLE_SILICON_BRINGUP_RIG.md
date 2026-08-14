# Apple Silicon bring-up rig — provisioning runbook

## Purpose

Turn a stock Mac mini M2 Pro (`Mac14,12`, SoC `T6020`) into a machine that can run BraiNIX payloads and
show their serial output. Until this is done, **AS-1a's exit criterion is unreachable** and every AS-1
slice after it is blocked — not on code, on this.

This runbook stops at the acceptance test. It does **not** chainload BraiNIX; that is
[`bin/as-boot.sh`](../../bin/as-boot.sh) and it comes after.

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

## 2. Downgrade the volume to Permissive Security

**Physical presence required.** Once per machine.

1. Shut the mini down fully.
2. Enter **1TR** ("One True Recovery"): press and **hold** the power button until "Loading startup
   options" appears, then choose **Options → Continue**.
   - It must be **1TR**, entered by holding power from a full shutdown. Recovery reached any other way
     will not permit the downgrade.
3. Sign in as a local administrator when prompted.
4. Open **Utilities → Terminal**.
5. Run:

   ```
   bputil -n -k -c
   ```

   Read what it prints and confirm the prompts. `bputil` is interactive and states exactly what it is
   about to change; if its description does not match "downgrade this volume to Permissive Security",
   stop and re-read rather than confirming.
6. Reboot into macOS.
7. Verify from macOS:

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
