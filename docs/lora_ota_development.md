# LoRa over-the-air updates: developer guide

## Scope

This is the entry point for working on the LoRa OTA subsystem itself:
where the code lives, how to build and test it, the on-wire/binary command
surface, and the current hardware validation status. For the design
rationale and policy model, start with
[docs/lora_ota_design.md](lora_ota_design.md). For nRF52840 QSPI/bootloader
specifics, see [docs/lora_ota_nrf52840_qspi.md](lora_ota_nrf52840_qspi.md)
and `bootloader/xiao_nrf52840_ota/README.md`, both owned by the bootloader
work stream — this guide does not duplicate them.

## Source layout

```
src/ota/
  protocol/   wire types, byte-stream codec, envelope, canonical descriptor
  runtime/    chunk geometry, receipt bitmap, session identity, receiver/
              coordinator/fleet state machines, radio-profile lease,
              airtime limiter
  storage/    CRC32, redundant journal, receipt map, storage manager over
              the QSPI layout
  trust/      SHA-256 and Ed25519 (vendored orlp/ed25519), fail-closed
              descriptor verification pipeline
  boot/       BootTransaction: gates erase of the running image behind
              candidate authentication and a verified durable backup
  platform/   flash device/region abstraction and QSPI layout

src/helpers/ota/         glue between MeshCore runtime and the OTA core
examples/companion_radio/  CLI/binary command handling and lifecycle hooks
test/test_lora_ota_{protocol,runtime,storage,trust,boot,integration}/
```

`src/ota/` is header-only. It is gated everywhere by the `MESHCORE_LORA_OTA`
build flag, currently set in `variants/xiao_nrf52/platformio.ini`,
`variants/sensecap_solar/platformio.ini`, and
`variants/xiao_s3_wio/platformio.ini`.

## Building and testing

All entry points are `make` targets; do not invoke `pio` directly for OTA
work so the repo-local `.tmp` scratch directory and target lists stay
consistent.

```sh
make test-ota                # all native OTA tests
make test-ota-protocol        # one layer at a time, for fast iteration
make test-ota-runtime
make test-ota-storage
make test-ota-trust
make test-ota-boot
make test-ota-integration

make build-ota-targets        # compile the OTA-enabled firmware targets
make build-ota-baseline-targets  # same targets, OTA disabled, for size diffing
make build-non-ota-targets    # regression guard: platforms that never enable OTA

make verify-ota-software      # native tests + both build passes, in one gate
```

`verify-ota-software` is explicitly a **software-only** qualification gate.
Its own summary output says so: passing it means native tests are green and
firmware links, not that any device can be updated.

## Binary protocol (companion frame codes)

Handled in `examples/companion_radio/MyMesh.cpp::handleCmdFrame`:

- `CMD_OTA_CONTROL` (66), sub-operations in byte 1 of the frame:
  - `OTA_CTRL_GET_STATUS` (0) → `RESP_CODE_OTA_STATUS` (29)
  - `OTA_CTRL_SET_MODE` (1): byte 2 selects `0`=direct, `1`=routed, `2`=fleet
  - `OTA_CTRL_SET_DUTY` (2): bytes 2–5 are a little-endian `uint32_t`
    milli-percent value
  - `OTA_CTRL_ABORT` (3)
  - `OTA_CTRL_ROLLBACK` (4)
  - `OTA_CTRL_DIRECT_LEASE` (5): frequency (kHz-scaled `uint32_t`),
    bandwidth (kHz-scaled `uint32_t`), spreading factor, coding rate, and a
    16-bit lease timeout in minutes, validated by
    `mesh::ota::isValidOtaDirectLease` before
    `mesh::ota::requestOtaDirectLease` applies it
- `CMD_OTA_LAB` (67): currently one operation, `OTA_LAB_QUEUE_PRECEDENCE`
  (0), which builds and floods a synthetic `OtaAnnouncementPayload` plus a
  self-advert to exercise OTA-vs-normal traffic precedence. This exists for
  lab/test harnesses, not as a fleet-management primitive.

The equivalent text CLI (`ota status`, `ota abort`, `ota rollback`,
`ota direct ...`, `set ota.mode`, `set ota.dutycycle`, `get ota.mode`,
`get ota.dutycycle`) is implemented in `src/helpers/CommonCLI.cpp` and is
documented for operators in the
[administrator guide](lora_ota_administration.md).

## Hardware lab workflow

Every physical-board operation goes through `scripts/lab_device.py` and the
roles pinned in `lab/devices.ini` — never a raw `ttyACMn` path. See
[Hardware lab device workflow](hardware_lab.md) for the full rationale
(mode detection, DFU entry, power cycling, recovery). The current lab pair
is two XIAO nRF52840 + SX1262 boards, addressed as `client` and `target`.
A third board, listed under `[protected]`, belongs to an unrelated project
and must never be reset, flashed, or power-cycled by any MeshCore command.

Relevant targets:

```sh
make lab-devices                       # list attached boards and roles
make lab-doctor                        # check host tooling/power control
make build-xiao-nrf52-ota-lab          # build companion firmware, OTA enabled
make upload-xiao-nrf52-lab             # flash both client and target
make configure-xiao-nrf52-ota-lab      # apply lab radio/name configuration
make test-xiao-nrf52-ota-lab           # run the two-node RF harness (scripts/ota_rf_lab.py)
make validate-xiao-nrf52-qspi-hardware # run the on-target QSPI hardware test
```

`scripts/ota_rf_lab.py` drives both boards over serial, sends and waits for
OTA envelopes and adverts, and writes machine-readable evidence
(`serial-events.jsonl`, `summary.json`) into the run's artifact directory.
`tools/ota_qspi_hw_test.py` drives the on-device QSPI hardware test firmware
built from the `Xiao_nrf52_ota_qspi_hardware_test` PlatformIO environment and
captures its serial evidence log.

## Current hardware evidence

This reflects the most recent lab runs and should be re-checked against
`docs/lora_ota_design.md` and `docs/lora_ota_nrf52840_qspi.md` before relying
on it, since hardware qualification is ongoing.

Verified:

- **Raw QSPI backend, `target` role board (serial `3BE94917B92DC5E9`)**:
  `make validate-xiao-nrf52-qspi-hardware` passed — JEDEC ID `85:60:15`,
  2 MiB geometry, raw erase, program, readback, correct NOR 0-to-1 rejection,
  and out-of-bounds handling all confirmed against the physical P25Q16H chip.
- **Lab-only signed staging path**: the `MESHCORE_OTA_LAB_BACKEND`
  qualification backend, which owns a reserved 16 KiB candidate-test QSPI
  region and a deterministic lab Ed25519 key, staged an 8,192-byte signed
  test image in 52 chunks and confirmed readback and hash integrity
  (SHA-256 `31c395468a84b2bfc2b009ccc03a141a7372884b4803c8e73db93a17a3988fc9`).
  This backend is qualification-only: it does not install or boot the
  candidate, and its key is not a production trust anchor.
- **Two-node RF lab, baseline behaviour**: reconfirmed on both approved
  boards after reflashing companion firmware built from commit `e03926a4`.
  Adverts and OTA envelopes at the default 907.525 MHz, 62.5 kHz bandwidth,
  SF7, CR5, three-byte path IDs; a temporary direct-mode lease at 250 kHz
  bandwidth that reverted automatically; normal-traffic precedence over OTA
  traffic; fleet `STATE` progression; and rejection of a foreign session's
  abort all passed again on this repeat run.

**Failed on the same run** — a signed wire-descriptor transfer
(`recv7`) failed. The root cause identified is a byte-order (little-endian
vs. big-endian) mismatch in how a descriptor field is framed on the wire,
separate from the lab-only staging path above. A fix to the wire protocol,
session handling, and the production application bridge across all three
modes is in progress on a dedicated branch and has not landed yet. A second,
independent blocker was also found: the current chunk size (160 bytes) does
not fit the companion serial frame's existing 176-byte limit, so the chunk
geometry needs to be bounded to the frame size before a full image can move
over that transport. Neither issue is fixed as of this writing.

Not verified, and not to be represented as done in any documentation or
release notes:

- Full three-mode signed firmware transfer and install on real hardware.
  The most recent attempt to run the signed wire-descriptor path **failed**
  (`recv7`, endianness mismatch) — do not describe any mode as a complete
  end-to-end pass until this is fixed and re-run.
- Routed (directed, mesh-relayed) image delivery to an out-of-reach target
  has not been attempted yet; only direct-mode application-layer traffic and
  fleet-mode state probes have been run over real RF so far.
- The OTA airtime/duty-cycle budget has not been exercised to exhaustion on
  hardware. Lab runs to date have stopped for other reasons (protocol
  failures) well before the configured budget was used up, so duty-cycle
  enforcement itself remains unverified under sustained load.
- Any durable install handoff from the application-side QSPI backend to a
  bootloader — the custom QSPI-aware bootloader install/trial/rollback path
  is being built and tested separately and is unproven end to end.
- The anti-rollback counter is RAM-only (`src/ota/trust/MonotonicCounter.h`
  is an interface with no eFuse/UICR/NVS-backed implementation yet), so it
  does not survive a reset and cannot be relied on for real anti-downgrade
  protection.
- Fleet-state probes and raw QSPI read/write results are evidence of
  protocol and flash-driver correctness — they are **not** evidence of a
  completed firmware installation. Do not conflate the two when reporting
  status.
- SenseCAP Solar (P1 Pro) hardware qualification: not started.
- ESP32 (XIAO S3 WIO): builds with OTA enabled; no hardware validation.
- Heltec v3/v4: out of scope until the nRF52840 pattern is proven.

## Development status and branch

This work lives on the dedicated `feat/lora-ota-nrf52840` branch, built on
top of companion/repeater v1.17.1 ancestry, and has not been pushed to or
merged into upstream `main`. Do not treat anything in these guides as
released or upstream-approved until that branch merges.

If you are debugging a flash-upload failure, note that the lab's
`upload-xiao-nrf52-*` targets previously piped `lab_device.py` output
through `tee`, which could mask a non-zero exit code from a failed flash.
That has since been corrected so a failed upload fails the `make` target
instead of appearing to succeed.

## Host tooling status

`scripts/ota_rf_lab.py` and `tools/ota_qspi_hw_test.py` are lab test
scripts, not a production host uploader or client product. If you are
building a companion app or CLI feature against `CMD_OTA_CONTROL` /
`CMD_OTA_LAB`, treat these scripts as protocol examples, not as a reference
implementation to ship.

## Contributing safely

- Use `make lab-*` and `scripts/lab_device.py` for anything touching real
  hardware; never hardcode a `ttyACMn` path.
- Never target the `[protected]` board in `lab/devices.ini`.
- Keep `src/ota/` changes covered by the matching native test suite before
  touching firmware integration.
- Update `docs/lora_ota_design.md`'s hardware-evidence sections when you add
  a new verified result, and keep unproven claims explicitly marked as such.
