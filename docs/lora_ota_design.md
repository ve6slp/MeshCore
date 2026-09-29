# LoRa OTA patching design for MeshCore

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

### 2. Dual-slot update with rollback
Every target must have at least two firmware image slots:

- active image
- staged image

The bootloader should validate the staged image before it becomes active. If validation fails, the previous image remains active. This is the same pattern used in robust embedded stacks and is essential for an OTA process that may be interrupted by radio loss or power outage.

### 3. Duty-cycle-aware scheduling
The on-mesh update modes must respect traffic fairness. A setting such as 2% airtime budget should be interpreted as: spend at most 2% of the update window transmitting OTA traffic. That means a 24-hour update cycle can support a maximum of about 28.8 minutes of OTA airtime; a 72-hour cycle allows about 86.4 minutes. This is a practical “background mode” that respects mesh traffic.

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

The traffic budget is enforced as a strict upload-share fraction of the configured update window.

## Duty-cycle behaviour

The policy model is deliberately simple and deterministic:

- default background mode target is 2% airtime budget
- routed mode can use 5-10% if a maintenance window is explicitly scheduled
- direct mode may temporarily allow a higher rate, but should still be bounded by the current radio policy and local legal limits

The implementation model for the repo encodes this as a policy object that computes:

- `computeAirtimeBudgetMs(update_window_ms, duty_cycle_percent)`
- `computeUploadWindowMs(...)`
- `isBackgroundEligible(...)`
- `buildPlan(...)`

This is the anchor logic we can unit-test in native mode without hardware.

## Target hardware focus

The first hardware focus should be:

- Seeed Studio SenseCAP Solar / nRF52840 platform
- Xiao ESP32-S3R8 + Wio SX1262 platform

These are the most practical targets for the first production-grade OTA pattern. They are already represented in the repo and match the real-world deployment model we need to support.

Heltec v3/v4 support should come second as a future upgrade path after the protocol and bootloader model is proven on the initial hardware set.

## Implementation status for this repository

This repository now includes a policy model and testable scheduling logic that captures the operational behavior described above:

- `src/helpers/LoraOtaPolicy.h`
- `test/test_lora_ota_policy/test_lora_ota_policy.cpp`

These are native-buildable and validate the airtime budgeting logic and the three-mode policy model.

This is the software-verifiable portion of the implementation. Full hardware validation is not possible in this environment because the physical devices are not attached to this session. The policy and state machine are now in place and can be ported directly onto the target boards once they are available for bench validation.

## Follow-up execution plan

After approval, the next staged execution is:

1. add a dedicated OTA packet type and control-plane definitions to the mesh packet model
2. implement a dual-slot bootloader contract for the primary target boards
3. add a board-specific LoRa packet transport adapter for the upload path
4. wire a background update scheduler that enforces duty-cycle quotas
5. validate on target hardware with a known-good image and rollback test

This is a outcome-driven plan rather than a task list, and it keeps the protocol, bootloader, and radio logic separate so that each can be verified independently.
