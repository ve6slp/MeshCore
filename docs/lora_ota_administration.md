# LoRa over-the-air updates: administrator guide

## Scope and status

This guide explains the update policy and experimental signed host workflow.
LoRa OTA reuses MeshCore identities and administrator permissions. There is no
separate OTA authority, signing-key registry or remote commissioning service.

**LoRa OTA is not production-ready.** Historical lab controls and build
results do not qualify the replacement. No physical node has completed a
LoRa-delivered firmware install, confirmation or rollback. Do not use these
controls to manage a deployed network.

## Update policy

The following is the required behaviour, not a hardware acceptance claim.

1. Use an identity already trusted as an administrator by each target. A
   contact or shared channel secret alone does not grant update permission.
2. Sign the image manifest with that administrator's Ed25519 private key.
   Targets verify with the public key; never distribute the private key.
3. Select direct, routed or background mode and an airtime budget. A device
   can retain only one candidate and its original owner. A competing image
   or administrator is refused; there is no automatic takeover timeout.
4. Transfer signed blocks. Duplicates do not rewrite flash. Bad or missing
   frames preserve valid progress and normal radio service. For severe loss,
   repair missing blocks or explicitly restart the upload.
5. Wait for each target's durable `READY` result after full-image validation.
   Finishing reception does not install the image or start a reboot timer.
6. Have the original owner, still trusted as an administrator, commit each
   target separately. Sequence the commits to preserve network service and
   confirm each device has returned before proceeding.

Any currently trusted administrator may abort before commit. The target
then ignores multicast for that image until an explicit restart. Abort
does not hand the staging slot to a competing uploader. Once a committed
install has begun, local boot recovery completes it or restores the previous
image; a radio abort is no longer the recovery mechanism.

After a confirmed install or completed rollback, a subsequent update can
reuse the staging slot once the device proves the previous boot transaction
has ended. A trial or uncertain outcome remains protected. A failed
reception still belongs to its original owner; failure is not permission
for another administrator to take over.

## Signed host workflow

These experimental host commands use the companion's existing MeshCore
identity. They never export its private key. Each target must already
trust that identity as an administrator through its normal MeshCore
permissions; there is no separate OTA key to commission.

For nRF52840, select a qualified raw application image and a security
counter greater than each intended target's confirmed floor. Set the
shell variables `image`, `counter` and `target_key` explicitly; the last
is the target's full 64-character public-key hex string.

```sh
make ota-lab-image XIAO_NRF52_TARGET_PACKAGE="$qualified_repeater_package" \
  OTA_UPLOAD_IMAGE="$image"
make ota-lab-manifest OTA_UPLOAD_IMAGE="$image" \
  OTA_UPLOAD_MANIFEST=.tmp/update.manifest OTA_UPLOAD_COUNTER="$counter"
make ota-lab-upload OTA_UPLOAD_IMAGE="$image" \
  OTA_UPLOAD_MANIFEST=.tmp/update.manifest OTA_UPLOAD_TARGET="$target_key" \
  OTA_UPLOAD_MODE=directed OTA_UPLOAD_DUTY_MILLI_PERCENT=2000
make ota-lab-status OTA_UPLOAD_TARGET="$target_key"
```

For nRF, `ota-lab-image` extracts the exact application BIN from an
already-qualified application-only DFU package without rebuilding or
opening a board. Set `qualified_repeater_package` to that package's path.
It refuses to overwrite an existing image. A package or extracted BIN is
not, by itself, evidence of a successful LoRa installation.

The descriptor builder defaults to the XIAO nRF52840 repeater profile.
Use `OTA_UPLOAD_BOARD=sensecap_solar_p1` for SenseCAP or
`OTA_UPLOAD_ROLE_ID=0` for a companion. It produces only the 59-byte
unsigned descriptor. Upload signs it with the attached companion, fills
and seals the companion's cache, then starts the requested campaign.
Use `OTA_UPLOAD_BOARD=xiao_s3_wio` for an ESP32-S3/Wio application.
That descriptor uses logical address `0x10000` and a maximum image size of
2,749,824 bytes; the target selects the inactive physical slot. Use the
raw application BIN, never a merged bootloader/partition-table image.
ESP build support does not establish physical installation or rollback.

`OTA_UPLOAD_MODE` selects `direct`, `directed` or `background`. Directed
and background modes use the normal mesh settings. Background accepts
several full target keys in the quoted `OTA_UPLOAD_TARGET` value and
requires `OTA_UPLOAD_CHANNEL` to identify a configured group channel.
Direct accepts one target and requires an off-frequency channel in
`OTA_UPLOAD_FREQ_KHZ` plus a bounded `OTA_UPLOAD_LEASE_MS`.
On the approved lab mesh, the direct frequency is 908525 kHz; normal
traffic remains at 907525 kHz. Both direct and directed use channel 255
as the unused group-channel value.

Upload **never commits**, including with `OTA_UPLOAD_WAIT_READY=1`.
That option waits for fresh, complete READY snapshots within
`OTA_UPLOAD_TIMEOUT`; the default returns after the campaign request
without claiming reception is complete. Long background campaigns can
be checked later. A matching complete READY permits a separate,
individually addressed commit:

```sh
make ota-lab-commit OTA_UPLOAD_TARGET="$target_key" \
  OTA_UPLOAD_MANIFEST=.tmp/update.manifest
```

The commit command waits for fresh READY before sending COMMIT. An
accepted command is not proof of installation, reboot or trial
confirmation. Confirm that node's health and normal mesh service before
committing the next one.

To abort before commit, use `make ota-lab-abort` with the target key and
original `OTA_UPLOAD_IMAGE`. Abort identifies the firmware content hash,
not its manifest hash. An explicit reupload uses
`OTA_UPLOAD_REUPLOAD=1`; changing the manifest does not bypass an abort.
Reupload is not a force-overwrite option. An active candidate must retain
the same owner, image content and cache or install purpose. Abort an
obsolete candidate explicitly before replacing it with different content.
Unavailable, denied, failed or malformed replies stop the host command
explicitly. Firmware transport and physical recovery qualification remain
incomplete; these commands must not be treated as a deployment result.

The companion also retains one local upload cache. Before using different
image content, abort that cache explicitly with the **old cached BIN**:

```sh
make ota-lab-abort-cache OTA_UPLOAD_IMAGE="$old_cached_image"
```

This uses the same signed abort operation with a zero target to select the
local cache. The companion signs with its existing identity and aborts
locally; it sends no radio abort and does not cancel any remote candidate.
Abort the remote target separately when that is intended. A denied,
mismatched or unavailable local abort is an error, not permission to
overwrite the cache.

## Build-time requirement

LoRa OTA is compiled in only when `MESHCORE_LORA_OTA` is enabled for a
target. It is currently enabled on these `platformio.ini` environments:

- `variants/xiao_nrf52/platformio.ini` (XIAO nRF52840 + SX1262)
- `variants/sensecap_solar/platformio.ini` (SenseCAP Solar)
- `variants/xiao_s3_wio/platformio.ini` (XIAO ESP32-S3 + Wio SX1262)

A build flag alone does not establish install capability. The running
application, signed receiver, durable storage and recovery-capable bootloader
must all be qualified together. An unsupported backend must refuse the
update explicitly without affecting ordinary mesh service.

## Control surface

Use the signed uploader commands above for an update. The current host ABI
is command 66, operations `0x10` to `0x18`, with versioned 86-byte replies.
It distinguishes local cache state from individually addressed target state.
The old command-66 mode/duty controls, raw fixed-key sender and binary
boot-journal cleanup are not an alternative upload workflow; their host
helpers have been removed.

The repeater's ordinary text CLI remains the way to inspect its full public
key and existing administrator ACL. An ACL read is not evidence that a
recent permission change has survived a restart: allow the normal lazy
save to complete and verify it after reboot. Do not replace the ACL or
export an administrator's private key to enable OTA.

`start ota`, the existing local firmware-update facility, is separate from
LoRa OTA. Keep using the supported local update and recovery procedure for
deployed nodes while the radio path is being qualified.
The experimental ESP OTA repeater profile disables the ordinary Wi-Fi
updater to prevent competing writes to the inactive slot. The ordinary
repeater profile is unchanged; USB recovery remains separate.

## Duty-cycle policy in practice

- Background/fleet mode defaults to a 2% airtime allowance. A 24–72-hour
  campaign is a planning window, not a completion guarantee. Ordinary
  traffic must retain scheduling priority and packet capacity even when
  the OTA allowance is exhausted.
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
- An earlier 2026-09-30 pressure run reached 71,851 of 72,000 ms without
  overshoot but failed ordinary advert allocation with `ERR_TABLE_FULL`.
  A later full run at 12:26:14 UTC reached 71,822 ms and delivered an
  ordinary advert in 0.983 s without increasing OTA usage. This is
  historical evidence for the queue-capacity fix, not qualification of
  the replacement. A numerical quota pass alone is insufficient.

See the [design document's duty-cycle section](lora_ota_design.md#duty-cycle-behaviour)
for the full policy model.

## Earlier hardware evidence, not replacement qualification

- Earlier **companion-radio** lab builds supported setting mode and duty
  cycle, reading them back, and inspecting status through `CMD_OTA_CONTROL`.
  Those checks must be repeated against the replacement.
- A direct-mode radio lease correctly applies and automatically reverts
  temporary radio parameters; this was confirmed on repeated lab runs over
  real RF at 907.525 MHz, 62.5 kHz bandwidth, SF7, CR5. Earlier harness
  runs also encountered traffic-priority failures. Those
  results and later fixes are recorded in the
  [developer guide](lora_ota_development.md#current-hardware-evidence).
  None qualifies the replacement's direct-mode path.
- A historical 2026-09-30 run staged a small signed test image through the
  earlier wire protocol. Its final message completed staging; it was not
  the replacement's explicit installation COMMIT. The test image was not
  bootable firmware, and the old staging command has been removed. See the
  [developer guide](lora_ota_development.md#current-hardware-evidence) for
  specifics and dates.
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
