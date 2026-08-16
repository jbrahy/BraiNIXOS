# Real hardware fixtures

## `mac14-12-j474s-adt.bin`

The **actual Apple Device Tree** from the deployment target, read out of the
running machine over m1n1's proxy on 2026-08-16. 491,520 bytes.

```
Model    Mac14,12        Target   J474s
Chip-ID  0x6020 (T6020)  CPU      M2 Pro "Blizzard"
iBoot    11881.140.96.701.1        mBoot    18000.161.9
```

Captured with `u.get_adt()` from `m1n1-1.6.1/proxyclient` against
`/dev/cu.usbmodem*`. See
[`../../../../docs/operations/logs/m1n1-first-boot-20260816.log`](../../../../docs/operations/logs/m1n1-first-boot-20260816.log).

### Why this is worth 480 KB in the repository

Every ADT test before this one used a fixture we wrote ourselves, which means
they tested the parser against our own beliefs about the format. This file
tests it against the machine. Two properties of it are already known to matter:

- **`/arm-io` child `reg` values are offsets, not addresses.** The ADT gives
  `dockchannel-uart` `reg` = `0x9E528000`, and m1n1 reports the same peripheral
  live at `0x2_9E528000`. The `0x2_00000000` delta comes from translating
  through the parent's ranges. A parser that returns the raw value looks
  correct in isolation and points at nothing.
- **`/arm-io/uart0` carries `boot-console`** and is nonetheless *not* the
  console on this machine; the debug serial mux presents DockChannel. Selecting
  a UART by that property is defensible, follows the ADT, and produces zero
  bytes at the host. See `docs/platform-specs/apple-s5l-uart.md` OQ-5.

Known-good values to assert against:

| path | property | value |
| --- | --- | --- |
| `/arm-io/uart0` | `reg` addr | `0x1_9B200000`, size `0x4000` |
| `/arm-io/uart0` | `uart-version` | `1` |
| `/arm-io/uart0` | `device_type` | `uart` |
| `/arm-io/dockchannel-uart` | `compatible` | `aapl,dock-channels` |
| `/arm-io/dockchannel-uart` | `reg` addr | `0x9E528000`, size `0x10004` |
| `/arm-io/dockchannel-uart` | `reg` addr | `0x9E50C000`, size `0x18` |
