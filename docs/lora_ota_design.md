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

MeshCore already provides identities, administrator permissions, direct
delivery and routed/flood traffic. LoRa OTA reuses those facilities; it does
not add a second identity or authorization system. Normal radio service and
recovery from local power failure take priority over update completion.

**Status:** the signed, single-candidate implementation is replacing the
earlier experimental lab path. Historical results below do not qualify the
replacement. No LoRa-delivered firmware installation, trial confirmation or
rollback has been verified on physical hardware.

The design uses three operating modes:

1. Direct OTA upload
2. Routed-on-mesh OTA delivery
3. Background multicast/census/resolution update mode

The common design goals are:

- no partial update state that can brick a node
- an administrator-signed manifest binding the complete image hash
- durable staging and recoverable installation with rollback
- transparent local-region and channel negotiation
- bounded airtime consumption by configurable duty cycle
- support for solar and battery-powered devices without starving real traffic

## Design tenets

### 1. Manifest-first, image-second
A node must receive a signed manifest before it starts accepting chunked data. The manifest declares:

- target board family, variant and firmware role
- exact image size, application address and SHA-256 hash
- monotonic update counter and required boot capabilities
- descriptor format and signature algorithm

Radio settings and airtime policy are separate controls, not additional
fields to invent in the image descriptor. A signed monotonic counter,
rather than a display version string, determines whether an image is newer.
An installed or older image is ignored without acquiring the staging slot.

The signer must already be an administrator trusted by the target through
MeshCore's policy. Ed25519 lets the administrator sign with a private key
and the target verify with a public key. HMAC is not a substitute: it
requires a shared secret and cannot be verified with a public key. The
administrator's private key is never copied to the target.

Background frames are signed as well. Their signature binds the complete
manifest identity, message type, block index, length and data. A short wire
tag is only a correlation aid; knowledge of a channel secret alone does not
make a sender an administrator.

### One candidate, one owner, explicit install

A device holds one candidate and its original administrator. Another image
or administrator receives a busy refusal, not an automatic takeover.
Relays may retransmit the owner's signed frames without becoming owners.

Invalid frames are rejected individually without discarding valid progress
or stopping normal service. A durably received block is not programmed
again. After a reboot, the receiver resumes from durable progress. Severe
loss may require an explicit reupload rather than increasingly complex
recovery machinery.

All modes use the same complete-image signature, hash, hardware, size and
version checks. Passing them leaves the device in durable `READY` state.
Neither the last block nor a census reply installs firmware. The original
owner, still authorized as an administrator, must issue a commit bound to
that image and that individual target.

Any currently trusted administrator may abort before commit and suppress
further multicast for that image until an explicit administrator-directed
restart. Once installation has begun, boot recovery completes the operation
or restores the backup; it does not depend on another radio packet.

### 2. Recoverable update with rollback
The active image stays usable throughout reception and while `READY` waits
for commit. Installation must retain a verified recovery image.

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

- signed manifest admission and multicast block transfer
- census of durable missing blocks
- selective repair and another census as needed
- full-image validation into `READY`
- explicit per-device commit

This keeps background updates from overwhelming the mesh while still allowing broad distribution.

## OTA modes

### Direct mode
This is the fast path for a technician or installer who has direct radio reach to a node.

- Use the target’s active channel settings or a negotiated direct OTA channel.
- Use the uploader's negotiated high-speed profile, such as SF5, coding
  rate 4/5 and higher bandwidth where the hardware and local rules permit.
- Transfer uses the same trusted owner and signed blocks as the on-mesh modes.
- The node stages and validates the image, then waits for explicit commit.
- The temporary radio lease restores the normal profile on completion,
  abort or timeout; losing a packet must not leave the node off-channel.

This is best for supervised field service on an OTA-capable node. It cannot
replace local recovery or provision a missing QSPI-aware bootloader.

### Routed mesh OTA
This uses the mesh as an infrastructure transport.

- The source sends the manifest to the target using the standard mesh packet structure.
- Route selection uses the existing direct path or known mesh path if available.
- OTA data is transmitted in bounded blocks using explicit retry and acknowledgements.
- Directed control messages identify the individual target. The shared
  image descriptor need not be re-signed for each fleet member.

This enables remote software updates without physical access to the device.

### Background fleet mode
This is a scheduled, low-priority mode designed for 24-72 hour update cycles.

Phases:

1. Admission: the coordinator announces a signed manifest on a known channel.
2. Multicast: eligible devices stage signed blocks at the configured airtime budget.
3. Census: devices report durable progress and missing blocks.
4. Resolution: the coordinator repairs missing blocks and repeats the census
   as needed. Each device performs the same full-image checks as a routed upload.
5. Commit: validated devices remain `READY` until the owner commits each
   target separately, allowing the administrator to sequence reboots.

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

The production path must debit measured packet airtime from the shared radio
admission policy and a separate OTA budget at every forwarding node. Planning
arithmetic alone is not enforcement. Qualification must reach the configured
quota and verify that ordinary traffic still allocates packets and reaches
its peer under sustained OTA load.

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

The role-specific lab entry points are:

```sh
make build-xiao-nrf52-ota-lab
make upload-xiao-nrf52-lab OTA_LAB_ARTIFACT_DIR=.tmp/ota-rf-lab/<run>
make monitor-xiao-nrf52-ota-lab OTA_LAB_ARTIFACT_DIR=.tmp/ota-rf-lab/<run>/monitor
```

These targets are pinned to the two allowlisted USB by-id paths and never
select a device by a transient tty number. The hardware harness records every
serial frame or repeater text line in `serial-events.jsonl` plus a
machine-readable `summary.json`. Paired configuration uses the companion's
binary protocol and the repeater's text CLI; it does not provision an
administrator, reboot or start an update. The default qualification command
still refuses before opening either device. Use the signed uploader and
per-target commit workflow only within the experimental qualification
process. Earlier runs exercised adverts, staging,
manual radio leases, fleet-control probes and the 2% rolling airtime
budget, not installation through the replacement implementation.

The earlier raw sender, deterministic signing-key fixture and companion-only
qualification routines have been retired. They are not another supported
transport or production trust source. The replacement cache is signed by
the uploader's existing MeshCore identity; receivers authorize that full
identity through their live administrator policy.

The nRF52840 flash adapter validates the P25Q16H JEDEC identity, device
bounds and 4 KiB erase alignment. Word-aligned EasyDMA buffers preserve
byte-range operations, and NOR 0-to-1 programming is refused. Candidate,
backup, boot journal and filesystem regions must remain disjoint according
to the shared geometry contract. A filesystem implementation that can
format the complete QSPI chip must not be mounted across these banks.

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

### ESP32-S3 recovery contract

Stage only in the inactive application partition, never the running image,
filesystem, NVS, otadata or bootloader. Durable metadata retains the single
candidate, owner and received blocks; ambiguous storage failures refuse the
update rather than erasing unrelated state.

Only explicit commit may call `esp_ota_set_boot_partition()`. After a
successful trial and late application health checks, confirmation uses
`esp_ota_mark_app_valid_cancel_rollback()`. Automatic rollback requires a
bootloader actually built with `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`.
An application-side setting cannot add that capability to a shipped
bootloader. The selected Arduino/IDF artifact's capability and behaviour
must be verified before claiming rollback support.

The resolved Arduino-ESP32 2.0.17 ESP32-S3 SDK enables rollback, and
inspection of its actual QIO/80 MHz bootloader ELF found the compiled
NEW-to-PENDING_VERIFY and PENDING_VERIFY-to-ABORTED transitions. However,
the same Arduino core confirms pending images during `initArduino()` by
default. OTA integration must defer that confirmation through the core's
`verifyRollbackLater()` hook and confirm only after late health checks.
Vendor bootloader support does not, by itself, make the application safe
to install.

Earlier inactive-partition and NVS tests are evidence for those primitives,
not for the replacement's receiver, explicit commit or trial recovery.
No ESP32 hardware qualification is claimed.

### What this does not yet prove

Software tests cannot qualify device behaviour. The following remain open
acceptance gates and are deliberately not claimed as done:

- the stock Adafruit bootloader cannot consume a QSPI-staged image, so the
  application-side nRF52840 adapter does not by itself qualify installation
  or rollback
- ESP32 partition/NVS primitives do not qualify receiver integration, trial
  confirmation or installation
- the selected ESP32 vendor artifact contains rollback handling, but late
  application confirmation and actual installed recovery remain unqualified
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
