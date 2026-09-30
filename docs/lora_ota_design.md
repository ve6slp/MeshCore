# LoRa OTA patching design for MeshCore

This is the design and hardware-qualification record for LoRa OTA. For
audience-specific guides, see:

- [User guide](lora_ota_users.md) — what LoRa OTA is and its current
  availability status
- [Administrator guide](lora_ota_administration.md) — CLI/API controls and
  duty-cycle policy for operators
- [Developer guide](lora_ota_development.md) — source layout, build/test
  targets, and the current hardware evidence ledger

## Design intent

MeshCore already has the right transport primitives for a robust OTA design: direct delivery, zero-hop local traffic, and routed/flood traffic with transport codes. We should not build a separate radio subsystem; we should build a firmware-update control plane that rides on the existing packet layer and uses the radio only when the update session is permitted.

The design uses three operating modes:

1. Direct OTA upload
2. Routed-on-mesh OTA delivery
3. Background multicast/census/resolution update mode

The common design goals are:

- no partial update state that can brick a node
- signed manifest and signed image validation
- dual-slot bootloader with rollback
- transparent local-region and channel negotiation
- bounded airtime consumption by configurable duty cycle
- support for solar and battery-powered devices without starving real traffic

## Design tenets

### 1. Manifest-first, image-second
A node must receive a signed manifest before it starts accepting chunked data. The manifest declares:

- firmware version and variant
- target board family / hardware model
- image size and SHA-256 hash
- required bootloader version
- allowed radio modes and regions
- update mode and duty-cycle budget
- commit policy and rollback window

This prevents a node from accepting arbitrary packets as firmware.

### 2. Recoverable update with rollback
Every target must retain two complete firmware images:

- active image
- staged image

On ESP32-S3 these can be normal internal A/B application partitions. The
SenseCAP Solar cannot fit two applications in internal flash, so it uses an
external-QSPI candidate bank and rollback bank with a bootloader-controlled
copy/restore transaction. The bootloader validates the candidate before
altering the active image and retains the previous image until the new
application confirms a successful trial boot.

See [SenseCAP Solar nRF52840 QSPI staging design](lora_ota_nrf52840_qspi.md).

### 3. Duty-cycle-aware scheduling
The on-mesh update modes must respect traffic fairness. A setting such as 2%
airtime means that OTA may consume at most 2% of each rolling scheduling
interval after regulatory and normal-traffic reservations are applied. The
long 24-72 hour campaign window controls completion expectations; it must not
permit the accumulated allowance to be transmitted as one burst. Each radio
sub-band also has an independent legal airtime or dwell-time ceiling that the
OTA scheduler cannot override.

### 4. Multicast/census/resolution is the fleet mode
This is the closest analog to LoRaWAN firmware update groups. It uses a phased pattern:

- multicast manifest announcement
- census of eligible devices
- resolution into update cohorts
- block transfer in bounded windows
- commit after validation

This keeps background updates from overwhelming the mesh while still allowing broad distribution.

## OTA modes

### Direct mode
This is the fast path for a technician or installer who has direct radio reach to a node.

- Use the target’s active channel settings or a negotiated direct OTA channel.
- Use short, high-speed settings for the transfer window (e.g. SF5, CR4, higher bandwidth where allowed).
- Transfer is authenticated and chunked; each chunk is checksum-validated before it is accepted.
- The node stages the image and requests a final validation before commit.

This is best for field service, a node rescue, or first provisioning of a board family.

### Routed mesh OTA
This uses the mesh as an infrastructure transport.

- The source sends the manifest to the target using the standard mesh packet structure.
- Route selection uses the existing direct path or known mesh path if available.
- OTA data is transmitted in bounded blocks using explicit retry and acknowledgements.
- The manifest includes a target node ID or hash so the route remains unambiguous.

This enables remote software updates without physical access to the device.

### Background fleet mode
This is a scheduled, low-priority mode designed for 24-72 hour update cycles.

Phases:

1. Announcement: coordinator broadcasts manifest to an OTA multicast topic or update group.
2. Census: eligible devices reply with version, variant, region, and update readiness.
3. Resolution: coordinator groups devices by board family, channel policy, path quality, and window availability.
4. Transfer: each cohort receives data over a low-duty-cycle queue, with chunk retransmission only for missing blocks.
5. Commit: after final validation, the device installs the image and reboots into the new firmware.

The traffic budget is enforced at every transmitting node, including relays,
as a strict OTA share inside the radio's stricter regulatory budget.

## Duty-cycle behaviour

The policy has two nested limits:

- default background mode target is 2% airtime budget
- routed mode can use 5-10% if a maintenance window is explicitly scheduled
- direct mode may temporarily allow a higher rate, but should still be bounded by the current radio policy and local legal limits
- a rolling per-sub-band regulatory limiter always takes precedence
- unused OTA allowance expires instead of accumulating into a later burst
- normal MeshCore traffic is served before background OTA traffic

The current policy prototype computes:

- `computeAirtimeBudgetMs(update_window_ms, duty_cycle_percent)`
- `computeUploadWindowMs(...)`
- `isBackgroundEligible(...)`
- `buildPlan(...)`

This arithmetic is useful for planning but is not yet the production
scheduler. The production implementation must debit measured packet airtime
from both the regulatory bucket and a separate OTA bucket at every forwarding
node.

## Target hardware focus

The first hardware focus should be:

- Seeed Studio SenseCAP Solar / nRF52840 platform
- Xiao ESP32-S3R8 + Wio SX1262 platform
- Xiao nRF52840 + SX1262 platform (validated as a compatible lab target)

These are the most practical targets for the first production-grade OTA pattern. They are already represented in the repo and match the real-world deployment model we need to support.

Heltec v3/v4 support should come second as a future upgrade path after the protocol and bootloader model is proven on the initial hardware set.

The XIAO nRF52840 + SX1262 lab boards use the same nRF52840 class, P25Q16H
2 MiB QSPI device, and SX1262 radio family as the first target hardware. The
companion-radio target builds with the OTA core enabled, and two boards
exchanged adverts at 907.525 MHz, 62.5 kHz bandwidth, SF7, CR5 with three-byte
path IDs. This validates the MCU/radio/QSPI application surface, not OTA
installation: the stock Adafruit bootloader still cannot consume a QSPI-staged
image.

The reproducible two-node RF lab entry points are:

```sh
make build-xiao-nrf52-ota-lab
make upload-xiao-nrf52-lab OTA_LAB_ARTIFACT_DIR=.tmp/ota-rf-lab/<run>
make configure-xiao-nrf52-ota-lab OTA_LAB_ARTIFACT_DIR=.tmp/ota-rf-lab/<run>/configure
make monitor-xiao-nrf52-ota-lab OTA_LAB_ARTIFACT_DIR=.tmp/ota-rf-lab/<run>/monitor
make test-xiao-nrf52-ota-lab OTA_LAB_ARTIFACT_DIR=.tmp/ota-rf-lab/<run>/test
```

These targets are pinned to the two allowlisted USB by-id paths and never
select a device by a transient tty number. The hardware harness records every
serial frame and assertion in `serial-events.jsonl` plus a machine-readable
`summary.json`. It exercises bidirectional adverts and OTA envelopes, direct
radio leases, routed/flood traffic, fleet census/resolution, malformed-frame
and foreign-abort rejection, normal-traffic precedence, and the separate 2%
rolling OTA airtime budget.

`MESHCORE_OTA_LAB_BACKEND` is deliberately a qualification-only backend. It
uses the reserved 16 KiB candidate-test QSPI region and a deterministic lab
Ed25519 key so the harness can prove signed descriptor acceptance,
interrupted/resumed chunk staging, readback hashing, and staging completion.
It does not install or boot the candidate, does not make the lab key a
production trust anchor, and does not change the custom-bootloader acceptance
gate.

The XIAO nRF52840 application-side QSPI backend is commissioned through
`Nrf52FlashAdapter`: it owns nrfx QSPI directly, validates the P25Q16H JEDEC
identity, enforces device bounds and 4 KiB erase alignment, preserves byte
granularity through word-aligned EasyDMA bounce buffers, rejects NOR 0-to-1
programming, and waits for asynchronous erase/read/write completion. The
companion build intentionally no longer mounts `CustomLFS_QSPIFlash`, because
that implementation exposes and may format the complete chip; companion data
continues to use internal ExtraFS while the lab OTA backend owns only its
reserved QSPI test partition.

## Implementation status for this repository

The portable OTA core lives under `src/ota/`. Most components are header-only;
the ESP32 partition and NVS SDK boundaries have separate `.cpp` adapters:

- `src/ota/protocol/` — wire types, byte stream codec, envelope, canonical
  descriptor, message set
- `src/ota/runtime/` — chunk geometry, receipt bitmap, session identity,
  receiver/coordinator/fleet state machines, radio-profile lease, airtime
  limiter
- `src/ota/storage/` — CRC32, redundant journal, receipt map, storage manager
  over the SenseCAP QSPI layout
- `src/ota/trust/` — SHA-256 and Ed25519 (vendored orlp/ed25519, zlib) with a
  fail-closed descriptor verification pipeline
- `src/ota/boot/` — `BootTransaction`, which gates erase of the running image
  behind candidate authentication and a verified durable backup
- `src/ota/platform/` — flash device/region abstraction and the SenseCAP QSPI
  layout

Corresponding native tests live in `test/test_lora_ota_{protocol,runtime,storage,trust,boot}/`
and run via `make test`.

The earlier `src/helpers/LoraOtaPolicy.h` planning prototype and its tests have
been removed; `src/ota/runtime/` supersedes them.

### ESP32-S3 storage checkpoint

`Esp32FlashAdapter` now uses real IDF partition I/O, restricted to the
freshly selected inactive application slot in the existing 8 MiB partition
table. It rechecks running/boot selection, trial state, partition identity
and exclusive updater ownership before each operation. The compatibility
geometry-only constructor still refuses I/O. No bulk operation can address
the running image, filesystem, NVS, otadata or bootloader.

Dedicated `nvs/mesh_ota` primitives store versioned, big-endian CRC-protected
blobs using nonwrapping generations, explicit provisioning and commit plus
fresh readback. Missing commissioned security state, corrupt records,
capacity failures and ambiguous durability are explicit refusals, never
automatic NVS erasure or counter reset. Attempt records preserve the signed
descriptor, controller/session binding, partition identity, consent and
progress; resume does not erase the candidate.

Terminal records are not discarded by ordinary admission.
`Esp32AttemptStore::replaceTerminal()` explicitly retires an exact winning
Aborted or policy-qualified Staged checkpoint and persists a fresh attempt
in one journal generation. It requires a strictly newer session tuple,
different attempt digest, fresh authorization and consent, and current
inactive-slot ownership. Staged retirement defaults to denial unless the
shared policy proves no installer or trial still owns it. Replacement
never resets security/TX/RX history or erases candidate bytes, and does not
repair corrupt or uncertain metadata.

The bounded storage checkpoint passes 61 native cases and compiles for the
actual XIAO S3/Wio environment. It is **not connected to the board receiver**:
the update-ownership arbiter, commissioned security/AEAD ledger schemas and
local-consent policy must be supplied by shared integration. Unreferenced
SDK boundary objects are currently discarded by the linker. No boot
selection or mark-valid call is implemented, and stock Arduino's early
trial confirmation/watchdog behavior remains an installation blocker.
No ESP32 hardware qualification is claimed.

### What this does not yet prove

Software tests cannot qualify device behaviour. The following remain open
acceptance gates and are deliberately not claimed as done:

- the stock Adafruit bootloader cannot consume a QSPI-staged image, so the
  application-side nRF52840 adapter does not by itself qualify installation
  or rollback
- ESP32 partition/NVS primitives do not qualify receiver integration, trial
  confirmation or installation
- ESP32 security-counter and AEAD ledgers are not connected to those NVS
  primitives; boot-enforced eFuse anti-rollback is not qualified
- stock nRF RF staging and airtime fairness have hardware evidence (see
  [the lab guide](hardware_lab.md)); actual installation, trial confirmation
  and power-loss rollback remain unqualified

## Follow-up execution plan

The implementation sequence is:

1. implement and bench-validate the target-specific staging and rollback
   contract
2. add the signed OTA envelope and durable receiver state
3. implement one-hop direct transfer with a timed high-speed profile lease
4. add routed transfer with relay-side OTA airtime accounting
5. add multicast announcement, census, cohort resolution, and repair
6. validate success, interrupted transfer, corrupt image, failed trial boot,
   rollback, and traffic fairness on both target boards

The gate for each stage is a measurable hardware outcome, not completion of a
code task.
