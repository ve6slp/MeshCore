# LoRa over-the-air updates: user guide

## What this is

LoRa OTA is a firmware-update capability being built into MeshCore so that a
node can eventually receive a new firmware image over the radio, without a
USB cable. It is designed around three modes:

- **Direct** — a technician with a radio close to the node pushes an update
  at a short, high-speed profile.
- **Routed mesh** — an update travels to one specific, out-of-reach node over
  the existing mesh path.
- **Background fleet** — a coordinator announces an update to many nodes at
  once, and eligible devices pull it down in the background over 24–72 hours,
  using only a small, configurable share of airtime (2% by default) so it
  never competes with your normal traffic.

## Current availability: not ready for production use

LoRa OTA is under active development and is **not** a supported way to update
your node's firmware today. Treat everything below as a preview of an
in-progress feature, not a how-to.

What has been verified on lab hardware so far:

- The XIAO nRF52840 + SX1262 boards can send and receive OTA protocol
  packets and adverts over the radio in both directions, apply a temporary
  high-speed direct-mode radio setting and automatically revert it, and give
  ordinary MeshCore traffic priority over OTA traffic. Fleet-mode state
  changes have also been checked over the radio.
- The XIAO nRF52840's external QSPI flash chip has been read, erased, and
  written directly and correctly, and a small signed test image has been
  staged into a reserved lab test area of that flash.

What has **not** been verified:

- All three modes working together end to end, or the airtime budget being
  tested to its actual limit (lab runs so far have stopped early for other
  reasons, before using up the configured budget).
- Sending a target node an image over the mesh (routed delivery to an
  out-of-reach node) has not been tested yet.
- Sending a real, signed firmware image over the radio and installing it on
  a device. The most recent lab attempt did not succeed.
- No board has installed and booted a new firmware image delivered this way.
  The custom bootloader needed to do this already has source code and can be
  built, but the hand-off from the running application to that bootloader is
  not complete, and installing firmware this way has not been proven on a
  physical device yet.
- No target board is qualified for production OTA installs yet.

This feature is being developed on its own branch and has not been merged
into the main MeshCore codebase or any release.

In short: pieces of the radio and flash-handling side of LoRa OTA work in
the lab, but signed image transfer and installing a new firmware image on a
device are not yet qualified. See the
[developer guide](lora_ota_development.md) for specifics. Continue to
update your node's firmware the way you always have — the MeshCore Flasher,
or `start ota` over USB/BLE — until this changes.

## Supported and planned hardware

| Board | LoRa OTA status |
| --- | --- |
| Seeed Studio XIAO nRF52840 + SX1262 | Lab-validated radio and raw flash behaviour; firmware install unproven |
| SenseCAP Solar (P1 Pro), nRF52840-based | Design complete; hardware qualification still pending |
| Seeed Studio XIAO ESP32-S3R8 + Wio SX1262 | Build support only; no hardware validation yet |
| Heltec v3/v4 | Not started |

## Terminology you may see

- **Direct mode**: a short-lived, faster radio profile used only for the
  update session, then reverted automatically.
- **Fleet mode**: the announce → census → resolution → transfer → commit
  sequence used for background updates across many nodes.
- **Duty cycle budget**: the percentage of airtime OTA traffic is allowed to
  use; normal MeshCore traffic always takes priority.
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
