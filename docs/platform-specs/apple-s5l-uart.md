# Apple s5l UART (debug console) — platform fact table

**Sources consulted:**

*Prose documentation (facts from here are marked **P**):*

- Samsung, *S3C2410X 32-Bit RISC Microprocessor User's Manual*, Revision 1.2, document
  `21.2-S3-C2410X-052003`, <https://www.sistemasorp.es/blog/S3C2410%20-%20datasheet.pdf>, fetched
  2026-08-10. **First-party silicon vendor documentation.** Establishes the UART register block layout
  and offsets reproduced in §2.
- Asahi Linux Documentation, "Introduction to Apple Silicon",
  <https://asahilinux.org/docs/platform/introduction/>, fetched 2026-08-10. Establishes that the Apple
  Silicon serial peripheral is functionally identical to the Samsung S5L8900 block, that the same
  Samsung UART driver applies unmodified, and that **only the base address changes across Apple SoC
  generations**. Contains no register offsets and no base addresses.
- Linux kernel device-tree bindings submission, "dt-bindings: serial: samsung: Add apple,s5l-uart
  compatible", <https://lkml.iu.edu/hypermail/linux/kernel/2103.0/07980.html>, fetched 2026-08-10.
  Establishes the **Linux FDT binding** name `apple,s5l-uart`. **This is not the ADT `compatible` value**
  — see §6.
- This repository, [`apple-device-tree-format.md`](apple-device-tree-format.md) §8.6, the AS-0 fact table.
  Establishes the ADT node selection algorithm, the ADT `compatible` value, and the translation
  requirement. Facts marked `[O]` there are direct hardware observations on a `T6030` host.
- Asahi Linux Documentation, "MachO Boot Protocol",
  <https://asahilinux.org/docs/fw/macho-boot-protocol/>, fetched 2026-08-10. Establishes the entry state
  in §4.
- Asahi Linux Documentation, "m1n1 User Guide", <https://asahilinux.org/docs/sw/m1n1-user-guide/>,
  fetched 2026-08-10. Establishes the chainload delivery facts in §5.

*Source code:* **none.** No Asahi Linux source, no m1n1 source, and no Linux driver source was read to
produce this file. Every fact below comes from vendor documentation or published prose. This is a
stronger footing than [`apple-device-tree-format.md`](apple-device-tree-format.md), which was derived
partly from source and marks those facts **S**.

*Direct hardware observation:* **none.** The bring-up rig does not exist yet. Every value in §3 is
therefore unconfirmed against the target machine, and §3 is the whole of what hardware can invalidate.

**Firmware / OS version:** **not stamped.** No macOS release has been observed on the target machine, and
no firmware version has been read. Per [`README.md`](README.md), a fact table with no version recorded is
a fact table about an unknown machine. **This file must be re-qualified against the deployment machine's
actual macOS build before anything derived from §3 is trusted.**
**Machine / SoC:** Mac mini M2 Pro, `Mac14,12`, SoC `T6020` — **target, not observation host.**
**Spec author:** AS-1a design session, 2026-08-10.
**Derived:** 2026-08-10.
**Implementer restriction:** the implementer of this subsystem **may not read the sources named above**.
Work from this file only. If it is insufficient, return the question to the spec author.

> The formal two-role procedure is **mandatory for AS-4 and AS-5 work only** ([`README.md`](README.md),
> *Scope*). AS-1a is outside that mandate, so a single session authored this table and the code against
> it. The restriction line above is retained because it is the directory's format, and the no-copied-code
> rule of `CONTRIBUTING.md` rule 7 applies regardless of mandate. No code was copied.

---

## 1. What this file covers

The **transmit path only**, for a UART that is **already initialized by the stage that hands off to us**.

AS-1a is delivered by m1n1 chainload (§5), and m1n1 uses this same UART for its own console before
handing off. The payload therefore needs to *write*, not to *configure*: no baud-rate divisor, no line
control, no FIFO setup. Those registers are listed in §2 for completeness and are **not consumed by
AS-1a**.

An implementation that writes ULCON, UCON, UFCON, or UBRDIV is out of scope for AS-1a and is a defect
against this file.

## 2. Register block layout — **P**, confirmed

Offsets from the UART block base. Source: Samsung S3C2410X User's Manual rev 1.2, UART chapter.

| Offset | Name | Width | Role | Used by AS-1a |
|---|---|---|---|---|
| `0x00` | `ULCON` | 32 | Line control (word length, parity, stop bits) | no |
| `0x04` | `UCON` | 32 | Control (clock select, transmit/receive mode) | no |
| `0x08` | `UFCON` | 32 | FIFO control | no |
| `0x0C` | `UMCON` | 32 | Modem control | no |
| `0x10` | `UTRSTAT` | 32 | Transmit/receive status | **yes** |
| `0x14` | `UERSTAT` | 32 | Receive error status | no |
| `0x18` | `UFSTAT` | 32 | FIFO status | no |
| `0x1C` | `UMSTAT` | 32 | Modem status | no |
| `0x20` | `UTXH` | 32 | Transmit buffer | **yes** |
| `0x24` | `URXH` | 32 | Receive buffer | no |
| `0x28` | `UBRDIV` | 32 | Baud-rate divisor | no |

All accesses are 32-bit. `UTXH` takes the byte to transmit in its low 8 bits.

## 3. Values this file cannot confirm — **the whole of the hardware risk**

Every unconfirmed value in the subsystem is collected here, deliberately, so that the set of things
hardware can invalidate is a short list in one place rather than constants scattered through a driver.
The implementation mirrors this table one-for-one in `src/boot-stub-apple/src/registers.rs`.

| Value | Status | What is known | How it gets resolved |
|---|---|---|---|
| `UTRSTAT` transmit-ready bit position | **UNCONFIRMED** | The Samsung block exposes distinct "transmit buffer empty" and "transmitter empty" states in `UTRSTAT`. The manual's bit table was **not** successfully retrieved, so no bit index is asserted here. | Read the bit table from the cited Samsung manual, or observe `UTRSTAT` on hardware while m1n1's console is idle versus busy. **Mitigated in code:** polling is bounded and transmits anyway on timeout, so a wrong bit degrades to garbled output rather than to silence. |
| `T6020` UART MMIO base address | **UNCONFIRMED** | The AS-0 table records a **`T6030`** observation: untranslated `0x7920_0000`, translated `0x2_8920_0000`, and states plainly that *the `T6020` value will differ*. Published prose confirms only that the base changes per SoC generation. | The ADT is authoritative and its selection algorithm is fully specified (§6). The fallback constant is the `T6030` observation, used **only** to report ADT failure, and labelled as a different SoC's value. |
| Raw chainload load address | **UNCONFIRMED** | m1n1 loads payloads into its heapblock area, which begins at `boot_args.top_of_kdata` (**P**). No fixed address is published. | Made irrelevant by design: early code is position-independent (§7). |

**The UART's ADT node path is *not* in this table**, because it is not unconfirmed: the AS-0 fact table
§8.6 specifies the selection algorithm exactly. See §6.

**No value in this table may be presented anywhere in the tree as confirmed.** A log line, comment, or
doc that states the T6020 UART base as fact is a defect against `INV-BOOT-AS-001`'s discipline of not
claiming more than is known.

## 4. Entry state at handoff — **P**, confirmed

Source: Asahi "MachO Boot Protocol".

| Property | Value |
|---|---|
| MMU | **off** |
| Exception level | EL2 |
| `x0` | pointer to the `boot_args` structure |
| Interrupts | masked |
| `RVBAR` | locked by iBoot to the top of the page containing the entrypoint |

Inherited translation state is therefore **nothing**, which is the assumption AS-1a wants: the payload
establishes its own state and inherits none.

## 5. Delivery — **P**, confirmed

Source: Asahi "m1n1 User Guide".

- Chainloading uses `proxyclient/tools/chainload.py`, invoked as `chainload.py -r <file>`.
- **The `-r` flag denotes a raw binary.** Mach-O support for non-XNU payloads is deprecated. **AS-1a
  therefore needs no Mach-O wrapper and no Image4 wrapper.**
- The proxy presents two USB TTY ACM devices. The first is the proxy interface; the second carries the
  console.
- For the separate direct-`kmutil` path (not AS-1a), m1n1 itself installs with
  `kmutil configure-boot -c <payload> --raw --entry-point 2048 --lowest-virtual-address 0`. Recorded here
  because that path's entry-point convention is a fact worth not re-deriving later. **AS-1a does not use
  it.**

## 6. ADT resolution — deferred to the AS-0 fact table, not restated

**The ADT facts are owned by [`apple-device-tree-format.md`](apple-device-tree-format.md) §8.6.** They
are referenced here and deliberately **not duplicated**, because two fact tables stating the same fact
is two fact tables that can disagree, and one of them already would have:

> ⚠️ **Correction, recorded because it was nearly implemented.** An earlier draft of this file asserted
> that the ADT `compatible` value is `apple,s5l-uart`. **That is wrong.** `apple,s5l-uart` is the *Linux
> FDT binding* name — a different namespace that the Linux driver uses. The AS-0 table records, from
> direct hardware observation `[O]`, that the **ADT** value is **`uart-1,samsung`**. Matching on the
> Linux name would have found nothing on every machine, and the failure would have looked like a broken
> ADT parser rather than a wrong constant.

What §8.6 establishes, and what the implementation consumes:

| Fact | Value |
|---|---|
| Node selection | If `/arm-io/uart6/debug-console` exists, use `/arm-io/uart6`. Otherwise use `/arm-io/uart0`. If neither exists, **fail** — there is no third candidate and no default address. |
| ADT `compatible` | `uart-1,samsung` |
| `device_type` | `uart` |
| `reg` | One container. **Must be translated through `/arm-io` `ranges`.** An untranslated `/arm-io` address is a valid-looking physical address pointing at the wrong place. |

`/arm-io/uart6/debug-console` is a **child node, not a property**. Its mere existence is the signal and
its contents are never read.

The implementation resolves the UART base by following that algorithm and taking the node's **translated**
`reg` base, validating the node's `compatible` against `uart-1,samsung` as a cross-check.

The fallback constant exists for exactly one purpose: to have *some* console on which to report that ADT
resolution failed. If both the ADT lookup and the fallback constant are wrong, the payload is silent, and
that requires two independent failures rather than one.

Disagreement between the two is reported with **both values printed** and the payload halted. Neither is
silently preferred. This mirrors AS-0-T4's ADT-versus-boot-args memory-range cross-check.

## 7. Consequence: early code is position-independent

The load address is unconfirmed (§3) and no published source fixes it. Rather than guess a link base,
`_start` uses only PC-relative addressing to establish its stack, so **the link base does not have to be
correct for the payload to reach its first output.**

MMIO addresses are physical and absolute, and are unaffected by where the image was loaded. The MMU is
off at entry (§4), so a physical address is directly usable.

## 8. Open questions

- **OQ-1** The `UTRSTAT` transmit-ready bit index. Blocks nothing that compiles; blocks correct output on
  hardware.
- **OQ-2** Whether `T6020` shares a UART base with `T6000`/`T6001`. Not asserted either way here.
- **OQ-3** Whether m1n1 leaves the UART in a state where a bare `UTXH` write transmits without any
  further configuration. Assumed yes (§1) on the strength of m1n1 using the same UART for its console;
  unverified.
- **OQ-4** This file is not version-stamped. See the header.
- **OQ-5** *(raised 2026-08-14, and it outranks the rest of this list)* **Whether the s5l UART reaches the
  USB-C SBU pins at all on this machine, or whether debug serial is routed over DockChannel instead.**
  Published accounts of getting serial out of modern Apple Silicon state that these machines **default to
  DockChannel**, not the legacy UART, and that recovering legacy-UART output from macOS requires SIP off,
  boot-arg filtering off, `serial=3`, **and** `serial-device=<uart0 AAPL,phandle>` — the last because
  Apple rewrote `serial_init` in macOS 15 and deleted the `use-legacy-uart=1` argument that used to do it.
  Sources: <https://gist.github.com/dhinakg/3fcd9ad43c82c96964b4f64eb05e6a5e> and
  <https://asahilinux.org/docs/hw/soc/serial-debug/>, both fetched 2026-08-14.

  **Why this is a fact about our payload and not only about macOS.** Those boot-args configure *XNU's*
  choice of console. BraiNIX writes `UTXH` directly, so no boot-arg governs us. What is genuinely
  unresolved is the layer below: whether the SoC's debug-serial mux presents the **s5l UART** or
  **DockChannel** to the Type-C SBU pins after `macvdmtool serial`, on a `T6020`. If it is DockChannel,
  a correct `UTXH` write produces **no output at the host**, and AS-1a's exit criterion fails in a way
  indistinguishable from OQ-1 and OQ-2 being wrong.

  **Measured here, and it distinguishes nothing yet:** `macvdmtool serial` succeeds on this rig and
  `/dev/cu.debug-console` reads zero bytes across two full reboots of a stock macOS 15.3.1 mini. That is
  the *expected* reading whether the answer to this question is DockChannel **or** legacy-UART-but-macOS-
  is-silent, so it is not evidence either way. The experiment that discriminates is running code that
  writes `UTXH` — m1n1 or our own stub — after the Permissive Security downgrade.

  ### RESOLVED 2026-08-16: DockChannel. The legacy UART is not the console on this machine.

  m1n1 v1.6.1 was installed as the BraiNIX volume group's boot object and ran. Its first line settles it:

  ```
  Initialized dockchannel UART at 0x29e528000
    Model: Mac14,12   Target: J474s   Chip-ID: 0x6020
    CPU: M2 Pro Blizzard
  ```

  Full log: [`../operations/logs/m1n1-first-boot-20260816.log`](../operations/logs/m1n1-first-boot-20260816.log).

  **Consequence for AS-1a.** The boot stub writes `UTXH` on a machine whose debug serial is DockChannel.
  A *correct* implementation of everything in this document therefore emits zero bytes at the host, which
  is indistinguishable from the stub never running. That is the failure mode this question warned about,
  and it is now confirmed rather than suspected. The s5l UART work is not wrong; it is inapplicable to
  `T6020`, and a DockChannel transmitter is required before serial can be an exit criterion.

  **Where m1n1's output actually arrives**, on this rig: not `/dev/cu.debug-console`, but m1n1's own USB
  gadget over the ordinary USB-C cable, which enumerates two CDC-ACM ports on the workstation
  (`/dev/cu.usbmodem*`). The first carries the console, the second the proxy. No `macvdmtool serial` is
  needed for it.

  ### Also resolved: the framebuffer handed to a custom boot object is a dummy

  iBoot does populate `boot_args.video` — `base 0x10799a48000`, `640x1136`, `stride 0xa00`, `32bpp` — so
  the ADT/boot-args reading in `src/adt` is correct. But m1n1 reports:

  ```
  display: Dummy framebuffer found, initializing display
  dcp: dtpx-port is only supported with V13_5 OS firmware.
  display: failed to initialize DCP
  fb init: 640x1136 (32) [s=640] @0x10799a48000
  ```

  The surface exists in memory and is never scanned out; HDMI reads `No Signal` throughout. **Painting it
  cannot produce anything visible on this machine**, so the stage-stripe scheme in
  `src/boot-stub-apple/src/paint.rs` was unobservable by construction, however correct the painting code
  was. Every dark screen attributed to our code across 2026-08-14/15 has this as a sufficient cause.

  **Consequence for the plan:** this raises the value of a second, independent first-light output path
  (ROADMAP Track C row C7, framebuffer via `boot_args.video`), because it means a silent console at
  AS-1a's hardware gate has *four* candidate causes rather than three, and the framebuffer path shares
  none of them.
