# LoRa over-the-air updates: user guide

## What this is

LoRa OTA is an experimental firmware-update capability in MeshCore. It
transfers an application image over the radio rather than through a USB
cable. It has three modes:

- **Direct** — a technician with a radio close to the node pushes an update
  using a leased off-frequency radio profile, then restores normal settings.
- **Routed mesh** — an update travels to one specific, out-of-reach node over
  the existing mesh path.
- **Background fleet** — a coordinator announces an update to many nodes at
  once, and eligible devices pull it down in the background over 24–72 hours,
  using only a small, configurable share of airtime (2% by default) to leave
  capacity for normal traffic. Transfer time depends on image size, radio
  settings, relays and loss; 24–72 hours is a planning window, not a deadline.

The approved lab baseline uses 62.5 kHz bandwidth (62500 Hz). LoRa OTA
does not replace a deployed network's normal radio settings.

## Current availability: not ready for production use

LoRa OTA is under active development and is **not** a supported way to update
your node's firmware today. Treat everything below as a preview of an
in-progress feature, not a how-to.

The current software implements signed transfer in all three modes, durable
staging, explicit per-device commit and recoverable installation. It reuses
MeshCore administrator identities rather than a separate OTA signing system.
Software tests cover repeated updates, failed-trial recovery and refusal of
competing candidates. These results are not physical acceptance.

Hardware qualification remains incomplete: no node has completed a
LoRa-delivered install, trial confirmation or rollback with this
implementation. The approved bench pair has received immutable applications,
but normal settings and radio configuration are not complete, and the target
has not received a qualified custom OTA bootloader. Its 2% airtime policy and
ordinary mesh service must still be verified together on the radio.
Routed delivery through intermediate
nodes and fleet contention also need hardware beyond the two-node bench.

Earlier lab firmware demonstrated radio transfers and external-flash
staging, but that transport has been retired. Those captures do not qualify
the current implementation. No target board is ready for production OTA
installs.

This feature is being developed on its own branch and has not been merged
into the main MeshCore codebase or any release.

See the [developer guide](lora_ota_development.md) for the dated evidence
and outstanding acceptance gates. Continue to
update your node's firmware the way you always have — the MeshCore Flasher,
or `start ota` over USB/BLE — until this changes.

## Supported and planned hardware

| Board | LoRa OTA status |
| --- | --- |
| Seeed Studio XIAO nRF52840 + SX1262 | Historical radio and raw-flash evidence only; current OTA qualification incomplete |
| SenseCAP Solar (P1 Pro), nRF52840-based | Design complete; hardware qualification still pending |
| Seeed Studio XIAO ESP32-S3R8 + Wio SX1262 | SDK-backed staging and rollback implemented; physical qualification pending |
| Heltec v3/v4 | Not started |

## What an update should do

Your existing firmware keeps serving the mesh while a new image downloads.
The node accepts updates only from an administrator it already trusts through
MeshCore's existing public-key permissions and Ed25519 signatures, not a new
OTA authority. The node holds one candidate
and its original owner at a time; a competing image or owner receives `BUSY`.
It resumes durable progress after a restart.
Duplicates do not write flash again; a bad packet does not discard the
working firmware or the valid blocks already received.

After receiving and checking the entire image, the node waits in `READY`.
It does not reboot just because the last block arrived. The original
administrator, still trusted as an administrator, must send an explicit,
target-bound commit, allowing fleet upgrades to be sequenced. Any currently
trusted administrator may abort before commit and stop reception of that
image until an explicit restart.

Once installation starts, the bootloader must recover from interruption or
restore the previous image if the trial fails. These are required behaviours;
they remain unverified end to end on physical hardware.
After the device proves that install or rollback has finished, a subsequent
authorized update can reuse the staging slot. An uncertain boot outcome
does not allow another upload to overwrite it.

## Terminology you may see

- **Direct mode**: a short-lived, faster radio profile used only for the
  update session, then reverted automatically.
- **Fleet mode**: the signed-manifest admission → multicast pass →
  census → selective repair → re-census → validation → per-member commit
  sequence on an existing MeshCore channel. Each member must pass the same
  full-image validation before READY and an explicit individual commit.
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
