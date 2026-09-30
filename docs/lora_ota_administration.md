# LoRa over-the-air updates: administrator guide

## Scope and status

This guide documents the operator-facing controls for the LoRa OTA
subsystem: the companion binary protocol, the plain-text CLI as declared in
`CommonCLI`, and the build-time switch that enables OTA. It is aimed at
people who administer MeshCore nodes and want to inspect or exercise the
feature on lab or test hardware.

**Only one of these two control surfaces actually works on a shipped
example today.** `examples/companion_radio` does not use `CommonCLI` at
all; it implements OTA control itself, over the binary `CMD_OTA_CONTROL`
serial command, and that path is fully wired and working. The plain-text
`ota ...`/`set ota.*`/`get ota.*` commands are declared as virtual callbacks
in `src/helpers/CommonCLI.h` with no-op/"unsupported" default bodies. The
only examples that use `CommonCLI` — `simple_repeater`, `simple_room_server`,
and `simple_sensor` — do not override those callbacks, so every text-CLI OTA
command below currently returns "OTA unsupported" (or fails) on every
shipped example, regardless of whether `MESHCORE_LORA_OTA` is enabled.
Someone would need to wire those callbacks in the `simple_*` examples before
the text CLI becomes functional; that work is outside `companion_radio`'s
scope.

**LoRa OTA is not production-ready either way.** The controls below let you
observe status, change policy settings, and drive protocol-level test
traffic on a companion-radio build. None of them can install a new firmware
image on a device yet: the custom bootloader needed to install a staged
image has source code and can be built, but the hand-off from the running
application to that bootloader is incomplete, and installing firmware this
way has not been proven on physical hardware. Do not rely on these commands
to manage firmware on a network you care about.

## Build-time requirement

LoRa OTA is compiled in only when `MESHCORE_LORA_OTA` is enabled for a
target. It is currently enabled on these `platformio.ini` environments:

- `variants/xiao_nrf52/platformio.ini` (XIAO nRF52840 + SX1262)
- `variants/sensecap_solar/platformio.ini` (SenseCAP Solar)
- `variants/xiao_s3_wio/platformio.ini` (XIAO ESP32-S3 + Wio SX1262)

A companion-radio node built without this flag returns "OTA unsupported"
for the binary `CMD_OTA_CONTROL` command below. `simple_repeater`,
`simple_room_server`, and `simple_sensor` return "OTA unsupported" for the
text CLI regardless of this flag, for the reason explained above.

## Companion binary protocol (working today, companion-radio builds only)

Companion apps talk to `CMD_OTA_CONTROL` (frame code `66`) and, for lab use
only, `CMD_OTA_LAB` (frame code `67`). This is the control surface to use
today; there is no working text-CLI equivalent yet.

| Sub-command | Byte value | Effect |
| --- | --- | --- |
| `OTA_CTRL_GET_STATUS` | 0 | Returns `RESP_CODE_OTA_STATUS` (29) with a status string (see example below). |
| `OTA_CTRL_SET_MODE` | 1 | Sets mode: `0`=direct, `1`=routed, `2`=fleet. |
| `OTA_CTRL_SET_DUTY` | 2 | Sets duty cycle, encoded as milli-percent (e.g. `2000` = 2.0%). |
| `OTA_CTRL_ABORT` | 3 | Aborts any in-progress OTA session and immediately reverts a direct-mode radio lease if one is active. |
| `OTA_CTRL_ROLLBACK` | 4 | Requests a rollback of a staged/candidate update, then aborts the session. |
| `OTA_CTRL_DIRECT_LEASE` | 5 | Requests a temporary, high-speed direct-mode radio lease: frequency/bandwidth in kHz-scaled integers, spreading factor, coding rate, and a 16-bit lease timeout in minutes. The node automatically reverts to its normal radio settings when the lease expires. |

`CMD_OTA_LAB` currently exposes one operation, `OTA_LAB_QUEUE_PRECEDENCE`
(`0`), which floods a synthetic OTA announcement and advert pair for
precedence testing. It exists to exercise the traffic-priority behaviour in a
lab, not as an administrative fleet-update trigger — see the
[developer guide](lora_ota_development.md) for the full protocol reference.

Example status reply:

```
mode=direct duty=2.0% used=120/72000 rx=14 bad=0 aborts=0 recv=1 coord=0 fleet=0 lease=1 rollback=0 backend=1
```

`used`/duty budget are milliseconds within the current 1-hour window (the
default budget is 72,000 ms = 2% of one hour). `backend=1` means both a
trust (signature/hash verification) provider and a staging (storage) sink
are attached to the OTA integration; `backend=0` means at least one is
missing and any transfer attempt will fail closed. This flag says nothing
about bootloader or physical-install capability, which is a separate,
unproven part of the system.

## Text CLI (declared, not currently wired to any example)

`src/helpers/CommonCLI.cpp` parses these plain-text commands the same way
it parses `advert`, `clock`, or `set` — see [CLI Commands](cli_commands.md)
for the general command mechanism. `start ota` (USB/BLE bootloader DFU) is
a separate, pre-existing feature and is not affected by any of this. As
explained above, every command in this table returns "OTA unsupported" (or
fails) on `simple_repeater`, `simple_room_server`, and `simple_sensor` as
currently shipped, and does not exist at all on `companion_radio`, which
uses the binary protocol instead. The table is included so the intended
surface is documented, not as a claim that it works today.

| Command | Intended effect |
| --- | --- |
| `ota status` | Reports mode, duty-cycle setting and usage, receive/error counters, and internal state machine values. |
| `set ota.mode <direct\|routed\|fleet>` | Selects which OTA mode the node currently participates in. |
| `get ota.mode` | Reports the current mode. |
| `set ota.dutycycle <percent>` | Sets the OTA airtime budget, from just above 0 up to 100. The default is 2% of a 1-hour window (72,000 ms) for background/fleet mode. |
| `get ota.dutycycle` | Reports the current duty-cycle setting. |
| `ota direct <freq> <bw> <sf> <cr> <timeout_mins>` | Requests a temporary, high-speed direct-mode radio lease. |
| `ota abort` | Aborts any in-progress OTA session and reverts an active direct-mode radio lease. |
| `ota rollback` | Requests a rollback of a staged/candidate update, then aborts the session. |

## Duty-cycle policy in practice

- Background/fleet mode is intended to run at a low default budget (2%
  airtime) so that campaigns spanning 24–72 hours never crowd out normal
  mesh traffic.
- Routed mode may be given a higher temporary budget for an explicitly
  scheduled maintenance window.
- Direct mode is a short, supervised session and is expected to be bounded
  by the same radio and regulatory limits as any other transmission.
- OTA traffic shares the same underlying MeshCore airtime/duty-cycle
  admission control as normal traffic (in `Dispatcher`); OTA does not bypass
  it. A dedicated per-region or per-sub-band legal airtime ceiling for OTA
  specifically is part of the design intent but is not a separate, already-
  implemented enforcement mechanism today.
- Unused OTA allowance expires at the end of its window; it does not carry
  over into a later burst.

See the [design document's duty-cycle section](lora_ota_design.md#duty-cycle-behaviour)
for the full policy model.

## What administrators can honestly rely on today

- Setting mode and duty cycle, and reading them back, works as documented
  above on any OTA-enabled **companion-radio** build, using the binary
  `CMD_OTA_CONTROL` protocol. It does not work through the text CLI on any
  currently shipped example.
- `OTA_CTRL_GET_STATUS` accurately reflects internal protocol state and is
  useful for diagnosing lab or bench sessions.
- A direct-mode radio lease correctly applies and automatically reverts
  temporary radio parameters; this has been reconfirmed on repeated lab runs
  over real RF at 907.525 MHz, 62.5 kHz bandwidth, SF7, CR5.
- A signed firmware transfer over the wire protocol does **not** currently
  work: the most recent lab run failed on a wire-descriptor byte-order bug,
  and a separate chunk-size/serial-frame mismatch also blocks a full image
  transfer. Neither is fixed yet. See the
  [developer guide](lora_ota_development.md#current-hardware-evidence) for
  specifics.
- Nothing here yet results in an installed firmware update on a real device.
  Treat any OTA activity on hardware you rely on as experimental and
  reversible only by falling back to USB/BLE re-flashing.

This feature is developed on a dedicated branch and has not been merged
into upstream `main`; nothing in this guide is available in a released
build yet.

## Hardware lab reference

If you are helping validate this feature on bench hardware, board roles,
protected devices, and recovery procedures are documented in
[Hardware lab device workflow](hardware_lab.md). Do not repurpose those
procedures for a production fleet.
