# LoRa over-the-air updates: user guide

## What this is

LoRa OTA is an experimental firmware-update capability in MeshCore. It
transfers an application image over the radio rather than through a USB
cable. It has three modes:

- **Direct** — a technician with a radio close to the node pushes an update
  at a short, high-speed profile.
- **Routed mesh** — an update travels to one specific, out-of-reach node over
  the existing mesh path.
- **Background fleet** — a coordinator announces an update to many nodes at
  once, and eligible devices pull it down in the background over 24–72 hours,
  using only a small, configurable share of airtime (2% by default) to leave
  capacity for normal traffic. Transfer time depends on image size, radio
  settings, relays and loss; 24–72 hours is a planning window, not a deadline.

## Current availability: not ready for production use

LoRa OTA is under active development and is **not** a supported way to update
your node's firmware today. Treat everything below as a preview of an
in-progress feature, not a how-to.

The signed, single-candidate implementation is replacing the earlier
experimental lab path. The results below belong to that earlier path and
must not be read as qualification of the replacement.

What was verified on earlier lab hardware:

- The XIAO nRF52840 + SX1262 boards can send and receive OTA protocol
  packets and adverts over the radio in both directions. A temporary
  high-speed direct-mode radio setting, automatic revert, ordinary-traffic
  priority over OTA traffic, and fleet-mode state changes have all been
  confirmed in earlier lab runs. Pressure tests also exposed a packet-pool
  failure that was fixed and passed a later run. The replacement must
  repeat those checks.
- The XIAO nRF52840's external QSPI flash chip has been read, erased, and
  written directly and correctly. A small signed test image has also been
  taken through a full radio transfer — signed descriptor, authorization,
  every data chunk, and commit — and staged correctly into flash, in a
  test run that specifically checked only this staging path (not the
  traffic-priority, direct-lease, or fleet-control behaviour above).

What has **not** been verified:

- All three modes working together end to end.
- The replacement has not been driven to its airtime limit while verifying
  ordinary service. Earlier tests reached the quota and exposed a full
  packet pool; a later run passed after a queue-capacity fix. Neither
  result qualifies the new signed receiver.
- Sending a target node an image over the mesh (routed delivery to an
  out-of-reach node) has not been tested yet.
- Actually installing a received, signed firmware image on a device. The
  radio transfer and flash-staging steps above have passed, but nothing
  yet turns a staged image into a running update on the board.
- No board has installed and booted a new firmware image delivered this way.
  The custom bootloader's boot marker and its SenseCAP flash profile are
  implemented and tested in software, and a full bootloader package now
  builds, but the hand-off from the running application to that bootloader,
  and installing/commissioning it on a physical device, have not been
  proven yet.
- No target board is qualified for production OTA installs yet.

This feature is being developed on its own branch and has not been merged
into the main MeshCore codebase or any release.

In short: a signed **test** image has been staged over the radio and
verified end to end in the lab, but a real signed firmware image install,
and all three modes working together, are not yet qualified. See the
[developer guide](lora_ota_development.md) for specifics. Continue to
update your node's firmware the way you always have — the MeshCore Flasher,
or `start ota` over USB/BLE — until this changes.

## Supported and planned hardware

| Board | LoRa OTA status |
| --- | --- |
| Seeed Studio XIAO nRF52840 + SX1262 | Lab-validated radio and raw flash behaviour; firmware install unproven |
| SenseCAP Solar (P1 Pro), nRF52840-based | Design complete; hardware qualification still pending |
| Seeed Studio XIAO ESP32-S3R8 + Wio SX1262 | SDK-backed staging and rollback implemented; physical qualification pending |
| Heltec v3/v4 | Not started |

## What an update should do

Your existing firmware keeps serving the mesh while a new image downloads.
The node accepts updates only from an administrator it already trusts, holds
one candidate at a time, and resumes durable progress after a restart.
Duplicates do not write flash again; a bad packet does not discard the
working firmware or the valid blocks already received.

After receiving and checking the entire image, the node waits in `READY`.
It does not reboot just because the last block arrived. The original
administrator must explicitly commit the update to that device, allowing
fleet upgrades to be sequenced. Any trusted administrator may abort before
commit and stop reception of that image until an explicit restart.

Once installation starts, the bootloader must recover from interruption or
restore the previous image if the trial fails. These are required behaviours;
they remain unverified end to end on physical hardware.

## Terminology you may see

- **Direct mode**: a short-lived, faster radio profile used only for the
  update session, then reverted automatically.
- **Fleet mode**: the signed-manifest admission → multicast pass →
  census → selective repair → re-census → validation → per-member commit
  sequence used for background updates across many nodes.
- **Duty cycle budget**: the percentage of airtime OTA traffic is allowed to
  use; normal MeshCore traffic must retain priority and queue capacity
  under sustained OTA load — see the
  [administrator guide](lora_ota_administration.md#duty-cycle-policy-in-practice).
- **Rollback**: if a new image fails to start up correctly, the device is
  meant to restore the previous working image automatically. This is part of
  the design and is not yet proven end-to-end on hardware.

## Where to go next

- If you administer a fleet of nodes and want to know what controls exist
  today, see the [administrator guide](lora_ota_administration.md).
- If you want to build, test, or extend LoRa OTA, see the
  [developer guide](lora_ota_development.md).
- For the full design rationale, see the
  [LoRa OTA design document](lora_ota_design.md).
