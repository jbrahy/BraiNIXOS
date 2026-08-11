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

## 1. Parts

| Item | Notes |
|---|---|
| Mac mini M2 Pro (`Mac14,12`, `T6020`) | The deployment target. 32 GB. |
| Debug UART cable | Apple Silicon exposes the s5l debug UART over a **USB-C** port. This is not an ordinary USB-C cable — it needs a UART-capable debug cable of the kind the Asahi project documents. **Confirm the exact part and the correct port against current Asahi documentation before ordering**; this file does not assert a part number it has not verified. |
| Host machine | Runs the serial terminal and m1n1's proxy tooling. Any Mac or Linux box with USB-C. |
| Serial terminal | `picocom`, `screen`, or `minicom` on the host. |

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

## 3. Wire the serial console

1. Connect the debug UART cable between the host and the mini's UART-capable USB-C port.
2. On the host, find the device:

   ```
   ls /dev/tty.usbmodem*     # macOS
   ls /dev/ttyACM*           # Linux
   ```

3. Open a terminal against it, for example:

   ```
   picocom -b 115200 /dev/tty.usbmodemXXXX
   ```

**Nothing will print yet.** That is expected: no software on the mini is writing to this UART. The
console is proven in §5, not here.

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
