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
  packets and adverts over the radio in both directions. A temporary
  high-speed direct-mode radio setting, automatic revert, ordinary-traffic
  priority over OTA traffic, and fleet-mode state changes have all been
  confirmed in earlier lab runs, but the most recent full test run did not
  re-confirm the traffic-priority check — it stopped there, and the cause
  is unresolved, so treat this as previously verified rather than
  currently reconfirmed.
- The XIAO nRF52840's external QSPI flash chip has been read, erased, and
  written directly and correctly. A small signed test image has also been
  taken through a full radio transfer — signed descriptor, authorization,
  every data chunk, and commit — and staged correctly into flash, in a
  test run that specifically checked only this staging path (not the
  traffic-priority, direct-lease, or fleet-control behaviour above).

What has **not** been verified:

- All three modes working together end to end.
- The airtime budget has now been driven to its configured limit in a
  dedicated lab run (used 71,851 of 72,000 ms, no overshoot), but that
  same run then failed: once OTA traffic had queued up to the cap, an
  attempt to send an ordinary self-advert failed outright, because the
  shared radio-packet pool was full of queued OTA sends. So while the
  airtime quota itself was enforced correctly, this run does **not** show
  that ordinary traffic keeps working once OTA has driven the radio queue
  to its limit — that is now a known gap, being addressed in firmware.
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
| Seeed Studio XIAO ESP32-S3R8 + Wio SX1262 | Build support only; no hardware validation yet |
| Heltec v3/v4 | Not started |

## Terminology you may see

- **Direct mode**: a short-lived, faster radio profile used only for the
  update session, then reverted automatically.
- **Fleet mode**: the admission/signed-descriptor → multicast pass →
  census → cohort/selective repair → re-census → per-member commit
  sequence used for background updates across many nodes.
- **Duty cycle budget**: the percentage of airtime OTA traffic is allowed to
  use; by design, normal MeshCore traffic always takes priority (a known
  gap in enforcing this under sustained OTA load is being fixed — see the
  [administrator guide](lora_ota_administration.md#duty-cycle-policy-in-practice)).
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
