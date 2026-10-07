# Experimental LoRa firmware updates

This optional feature is **off in ordinary builds**. It is being soaked in a
public fork; no upstream pull request or production-readiness claim is implied.
Direct nRF52840 updates have succeeded on hardware, including normal-radio
restoration. ESP32-S3 and SenseCAP Solar hardware updates, routed delivery and
fleet/background deployments have **not yet been tested on hardware**.

OTA preserves existing Ed25519 MeshCore administrator authorization. A contact
or channel secret alone does not grant permission. Receivers reject mismatched
board/role/image descriptors and counters at or below their confirmed floor.
The host never automatically takes over, aborts another candidate or treats a
queued COMMIT as an installation.

## Install and build

The current host tools target Linux (`/dev/serial/by-id`, sysfs and `flock`).
Install PlatformIO plus the host requirements in your normal Python environment:

```sh
python3 -m pip install -r requirements-ota.txt
make build ENV=Xiao_nrf52_companion_radio_usb       # ordinary, OTA disabled
make build ENV=Xiao_nrf52_companion_radio_ota_usb   # explicitly OTA enabled
```

Opt-in companion/repeater environments are `Xiao_nrf52_companion_radio_ota_usb`,
`Xiao_nrf52_repeater_ota_usb`, `SenseCap_Solar_companion_radio_ota_usb`,
`SenseCap_Solar_repeater_ota_usb`, `Xiao_S3_WIO_companion_radio_ota_usb` and
`Xiao_S3_WIO_repeater_ota_usb`. Role ID is **0 for companion, 1 for repeater**.
`make upload ENV=...` uses the normal PlatformIO upload flow. It is not the
paired nRF bootstrap procedure.

Intentional opt-in profile differences:

* All three OTA repeater profiles enable the USB interface.
* `Xiao_S3_WIO_repeater_ota_usb` disables the independent Wi-Fi HTTP OTA service:
  no `MeshCore-OTA` soft AP, `/update` or `/log` handlers; `startOTAUpdate` reports
  unsupported. This prevents an independent HTTP flash writer bypassing the OTA
  owner lease. It is not a global Wi-Fi/BLE disable; the ordinary ESP repeater and
  USB companion profiles already have no BLE transport.
* `Xiao_nrf52_companion_radio_ota_usb` replaces the external-QSPI secondary
  filesystem with internal ExtraFS, reserving QSPI for OTA. Existing QSPI contacts,
  channels and advertisement blobs are **not automatically imported**. Export and
  save them before the first profile conversion; reimport/reprovision afterward.
  This migration caveat is separate from userdata preservation during OTA between
  compatible layouts.

Before updating, install the appropriate platform backend on the receiver:

* **nRF52840:** bootstrap the matching primary/installer pair; see the
  [paired bootloader recipe](../bootloader/xiao_nrf52840_ota/README.md). Ordinary
  stock bootloaders do not install this LoRa OTA format. External QSPI is reserved
  for candidate, backup and durable transaction state.
* **ESP32-S3:** flash the OTA environment's partition table, matching application
  and a vendor bootloader with application rollback enabled. Two adequate app
  slots, OTA data and durable staging/state partitions are required. Merely
  flashing an app onto an incompatible existing partition table is insufficient.
  Trial confirmation and rollback depend on the actual bootloader, not just
  application compile flags.

Keep known-good ordinary application recovery files. Add the intended sender's
contact on the receiver and explicitly grant its OTA-administrator permission.
Admission and COMMIT both check that permission and the owner's Ed25519 signature.
Local OTA-enabled companion contact permissions can also be set explicitly:

```sh
python3 scripts/ota_uploader.py --client-port "$RECEIVER_PORT" --client-dtr \
  admin --target "$SENDER_PUBLIC_KEY" --enabled 1
```

## Inspect USB without changing settings

Choose the exact `/dev/serial/by-id/...` endpoint; no inventory or auto-discovery
is used. Inspection prints public identity, name, board and firmware version,
never GPS, PIN, channel secrets or OTA-capability guesses.

```sh
make ota-device-inspect OTA_DEVICE_PORT="$CLIENT_PORT"
# nRF TinyUSB requires DTR; ESP defaults to DTR/RTS false:
make ota-device-inspect OTA_DEVICE_PORT="$CLIENT_PORT" OTA_DEVICE_DTR=1
```

Ports are exclusively locked and opened at 115200, with RTS false and DTR selected
**before** opening. These tools never use a 1200-baud reset.

## Deploy through an OTA-enabled companion

Use a raw application `.bin`, not ZIP/UF2, bootloader, partition-table or merged
flash images. Board names are `xiao_nrf52840`, `xiao_nrf52840_sense`,
`sensecap_solar_p1` or `xiao_s3_wio`. Supply the full 64-digit receiver public key
and an explicit counter above its confirmed floor.

```sh
make ota-deploy \
  OTA_DEPLOY_CLIENT_PORT="$CLIENT_PORT" OTA_DEPLOY_CLIENT_DTR=1 \
  OTA_UPLOAD_IMAGE="$APP_BIN" OTA_UPLOAD_BOARD=xiao_nrf52840_sense \
  OTA_UPLOAD_ROLE_ID=0 OTA_UPLOAD_COUNTER="$NEXT_COUNTER" \
  OTA_UPLOAD_TARGET="$TARGET_PUBLIC_KEY" \
  OTA_UPLOAD_MODE=direct OTA_UPLOAD_FREQ_KHZ="$OFF_NORMAL_FREQ_KHZ"
```

Omit `OTA_DEPLOY_CLIENT_DTR=1` for ESP. Choose legal radio settings yourself;
there is no private RF profile, key or device-path default. Native `directed`
uses the normal mesh; `background` requires `OTA_UPLOAD_CHANNEL` set to an
existing multicast channel. Those transports are software-tested only.
`OTA_UPLOAD_DUTY_MILLI_PERCENT` controls normal-channel airtime share (2000 means
2%); it does not override local spectrum rules.

The host builds the shared canonical descriptor in memory, asks the companion
to Ed25519-sign it, stages the image, waits for fresh complete READY, sends one
signed COMMIT and waits for matching native Installed status. A supplied
`OTA_UPLOAD_MANIFEST` must match the chosen board, role, image and counter exactly.
Refusal, FAILED, ABORTED, inconsistent status, timeout or loss of transport is
an explicit failure, not success. Deadlines are `OTA_UPLOAD_TIMEOUT` and
`OTA_DEPLOY_INSTALL_TIMEOUT`.

An unsigned descriptor can also be prepared with
`bootloader/xiao_nrf52840_ota/tools/build_manifest.py`; the native/stock host
still signs its exact 59 bytes through the companion. `make sign-xiao-ota-image`
is a separate offline nRF command-record utility: it requires an explicit
private key, exact active APP, candidate, board/role/counter and output directory.
It does not grant receiver administrator permission or perform a deployment.

## Deploy through an unchanged stock companion

`OTA_DEPLOY_TRANSPORT=stock` uses ordinary MeshCore **1.17.1** USB signing and raw
packet commands. It does not require the native OTA USB command and supports
only zero-hop direct delivery to an OTA-enabled receiver.

Create your own owned mode-0600 JSON binding. Replace every angle-bracket field;
`normal_profile` is the **receiver's actual normal radio configuration**, not
an assumed sender profile. `floor` is its current confirmed anti-rollback floor.

```text
{
  "schema": 1,
  "serial": "<sender USB serial>",
  "sender_public_key": "<full sender key>",
  "target_public_key": "<full receiver key>",
  "floor": <confirmed counter>,
  "min_generation": 1,
  "normal_profile": [<frequency_khz>, <bandwidth_hz>, <sf>, <cr>]
}
```

No approval ledger, capsule provenance or lab inventory is needed. Optional
`image_sha256` and `manifest_hash` bind a reusable configuration to one exact
candidate. Duplicate USB serials require an explicit unique physical
`--by-path` anchor and corresponding `by_path`, `id_path`, `usb_vid`, `usb_pid`
binding fields; pass these additional arguments using `OTA_STOCK_ARGS`.

```sh
make ota-deploy OTA_DEPLOY_TRANSPORT=stock OTA_UPLOAD_MODE=direct \
  OTA_DEPLOY_CLIENT_PORT="$CLIENT_PORT" \
  OTA_DEPLOY_CLIENT_DTR=1 \
  OTA_STOCK_SERIAL="$CLIENT_SERIAL" OTA_STOCK_SENDER_KEY="$SENDER_PUBLIC_KEY" \
  OTA_STOCK_BINDING="$BINDING_JSON" OTA_ARTIFACT_DIR="$NEW_RUN_DIRECTORY" \
  OTA_UPLOAD_IMAGE="$APP_BIN" OTA_UPLOAD_BOARD=xiao_nrf52840_sense \
  OTA_UPLOAD_ROLE_ID=0 OTA_UPLOAD_COUNTER="$NEXT_COUNTER" \
  OTA_UPLOAD_TARGET="$TARGET_PUBLIC_KEY" OTA_UPLOAD_FREQ_KHZ="$OFF_NORMAL_FREQ_KHZ"
```

Stock captures the sender's exact original radio/repeat settings and TX power,
persists `original-radio.json` before changing radio, accounts for physical TX
completion, verifies signed direct-lease acknowledgments, and restores and reads
back the original settings on success or failure. The receiver's bounded lease
also returns it to normal radio. The unchanged stock host never changes TX power.

**Status limitation:** RF lifecycle reports are currently unsigned. Stock
success means fresh matching native Installed was reported with the candidate's
new floor; it explicitly reports `status_authenticated: false` and
`installation_confirmed: false`. Native USB reflects the companion's observed
receiver state too. Neither is independent cryptographic attestation of running
firmware. Inspect the receiver and ordinary mesh service after deployment.

## Recovery

Do not increase counters or retry COMMIT blindly after an uncertain result.
Inspect candidate generation, hash, counter and receiver state first. Explicit
native `status`, `abort`, `abort-cache`, `cache`, `upload` and `commit` subcommands
are available via `python3 scripts/ota_uploader.py --help`. ABORT requires a fresh
generation and durable ABORTED readback. Prepared ABORTED candidates require an
explicit reupload; stock additionally requires `allow_reupload: true` in its
binding. No host command silently clears receiver state.

If stock restoration failed, retain the run directory and restore explicitly:

```sh
python3 scripts/ota_stock_companion.py restore --serial "$CLIENT_SERIAL" \
  --by-id "$CLIENT_PORT" --client-dtr --sender-key "$SENDER_PUBLIC_KEY" \
  --target "$TARGET_PUBLIC_KEY" --binding "$BINDING_JSON" --artifacts "$RUN_DIRECTORY"
```

A restore error remains an error; outstanding unconfirmed physical TX blocks
retuning. Use ordinary USB/DFU recovery with a known-good app if the receiver
cannot return to service. Preserve filesystem/identity data; mass erase and
bootloader UF2 self-update are not routine OTA recovery.

Omit stock `OTA_DEPLOY_CLIENT_DTR=1` / `--client-dtr` for an ESP sender.
