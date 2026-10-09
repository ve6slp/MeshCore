# Experimental LoRa firmware updates

This optional feature is **off in ordinary builds**. It is being soaked in a
public fork; no upstream pull request or production-readiness claim is implied.
Direct nRF52840 updates have succeeded on hardware, including normal-radio
restoration. A full one-hop stock-sender routed nRF52840 installation has also
succeeded, including selective loss repair, durable counter advancement and
post-reboot RF observations (see below).
ESP32-S3 and SenseCAP Solar hardware updates and fleet/background deployments
have **not yet been verified on hardware**.

OTA uses existing Ed25519 MeshCore identities plus a separate, private
OTA-administrator permission on the receiver. It is independent of the ordinary
remote-CLI contact permission: granting or revoking one never changes the other.
A contact or channel secret alone does not grant permission. Receivers reject mismatched
board/role/image descriptors and counters at or below their confirmed floor.
The host never automatically takes over, aborts another candidate or treats a
queued COMMIT as an installation.

### Version 3 compatibility

This release uses OTA wire version 3. Update **all** OTA receivers, OTA-enabled
companions and host checkouts (`scripts/ota_uploader.py`,
`scripts/ota_stock_companion.py`) together; there is no mixed-version fallback
and no unbound legacy COMMIT.

- The native host first reads the companion's local status. It refuses a
  companion that does not report OTA USB ABI 3 before signing or staging anything.
- A receiver running an earlier OTA build never sends a version-3 census
  report. An updated OTA companion does not start the block transfer without
  one. The stock host refuses the first legacy report before negotiating a
  lease or sending any block.
- Earlier hosts cannot drive updated firmware. Native status replies are now
  107 bytes, and COMMIT and direct-lease signatures use new domains.

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

### Bench USB provisioning versus field OTA

Treat a full conversion to this firmware on the bench as fresh provisioning.
Use the simplest supported vendor USB flashing flow for the selected
bootloader/installer/APP combination. A clean slate is acceptable: users can
reconfigure keys, contacts, channels and other settings afterward. Preserving
the previous identity, layout or OTA transaction state is not a prerequisite
for this conversion. Export settings first only if you want to reuse them.
Any destructive provisioning must explicitly select the intended physical
device; it is not an automatic recovery fallback. SWD is for stuck-device
recovery, not the normal bench workflow.

For the paired XIAO nRF52840 installer, use
`make build-xiao-ota-usb-app` and the guarded
`make commission-xiao-ota-usb` phases in the
[USB bench recipe](../bootloader/xiao_nrf52840_ota/README.md).
Select the matching board, installer role and exact physical USB endpoint.
The physical USB bench path resets identity, configuration, filesystems
and the OTA floor; entering that mode alone does not erase them. The uploader
checks the selected pair against the actual APP build context before transferring.
Choose the APP's intended radio defaults before building; fresh provisioning
does not restore the old profile.

The new paired primary uses the `serial-usb-cdc-fresh-v2` profile. With USB
attached, one physical reset selects vendor CDC recovery; if the BOOT endpoint
is already present, use it directly. Fresh admission comes from the actual
configured USB transport, not a retained RAM marker or a reset/power sequence.
Local physical USB is trusted; the host's explicit fresh-provisioning consent
does not add an authentication bit to the vendor protocol. Normal boot, BLE and
field OTA keep their protections. This simplified profile is software-verified
but **not yet hardware-qualified**.

An older experimental paired bootloader may lock its own BOOT region even in
USB recovery mode. Host options and a factory reset cannot remove that installed
restriction. Such a device needs one-time stuck-device recovery before it can
use the new USB bench path; ordinary vendor bootloaders use the USB recipe
directly. Earlier physical-double-reset bench builds also have different entry
rules; selecting the new host profile does not change an installed older BOOT.

Regular **field OTA** updates are different: retain identity, configuration,
filesystem data and confirmed rollback floors, and keep signed admission,
trial confirmation and rollback safety. A fresh bench setup must not weaken
those checks or turn a failed field update into a factory reset. After bench
flashing, configure the normal radio and explicitly grant OTA administrator
permission before admitting an update.

Intentional opt-in profile differences:

* All three OTA repeater profiles enable the USB interface.
* `Xiao_S3_WIO_repeater_ota_usb` disables the independent Wi-Fi HTTP OTA service:
  no `MeshCore-OTA` soft AP, `/update` or `/log` handlers; `startOTAUpdate` reports
  unsupported. This prevents an independent HTTP flash writer bypassing the OTA
  owner lease. It is not a global Wi-Fi/BLE disable; the ordinary ESP repeater and
  USB companion profiles already have no BLE transport.
* `Xiao_nrf52_companion_radio_ota_usb` replaces the external-QSPI secondary
  filesystem with internal ExtraFS, reserving QSPI for OTA. Existing QSPI contacts,
  channels and advertisement blobs are **not automatically imported**. If you
  want to retain them, export before the first conversion and reimport afterward;
  otherwise configure the fresh device.
  This migration caveat is separate from userdata preservation during OTA between
  compatible layouts.

During bench provisioning, install the appropriate platform backend:

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
On an OTA-enabled companion receiver, grant (`--enabled 1`) or revoke
(`--enabled 0`) it over USB; success means the setting was durably saved:

```sh
python3 scripts/ota_uploader.py --client-port "$RECEIVER_PORT" --client-dtr \
  admin --target "$SENDER_PUBLIC_KEY" --enabled 1
```

The OTA-administrator permission is stored privately per contact. Ordinary
contact edits (the app's add/update contact command, including the remote-CLI
flag) never grant, revoke or clear it.

### Permission migration from earlier OTA builds

Earlier OTA builds reused contact flag `0x10`, which ordinary firmware also uses
for remote-CLI access. On first load, an updated OTA receiver migrates each saved
contact fail-closed:

| Saved contact record | Remote CLI (`0x10`) after update | OTA administrator after update |
|---|---|---|
| Ordinary/unmarked record | Preserved exactly | Not granted |
| Earlier OTA-build record (ambiguous `0x10`) | Cleared; other flags preserved | Not granted |
| New-format record | Preserved | As saved |
| Unrecognized format marker | Preserved | Not granted |

After upgrading a receiver that used an earlier OTA build, explicitly regrant
OTA administration with the `admin` command above, and re-enable remote CLI for
contacts that should keep it through your normal contact-permission workflow.
Nothing is escalated automatically. Ordinary (OTA-disabled) builds keep the
private permission byte unchanged when they load and save contacts.

### Receiver identity and storage provisioning

A freshly converted receiver initializes its filesystem and identity only after a
positively proven Normal boot. On every boot the receiver first only mounts its
filesystem. It formats only after that mount fails, and only on a proven Normal
boot with a healthy radio. It generates a new identity only when all of these
hold:

- a proven Normal boot;
- a successful radio initialization and probe;
- every required filesystem is mounted;
- the identity file is reported absent (not merely unreadable).

A companion checks both its current and its legacy identity location before
and after migrating stored data.

During a trial boot, an unknown boot state or a pending rollback, the receiver
never formats storage, generates an identity or rewrites provisioning data. It
also never does so after a short read or other storage I/O error. Reprovision
after the device reports Normal operation. A runtime factory reset never grants
OTA permission; regrant it explicitly.

These startup safeguards protect field updates and uncertain boots; they do
not require preservation-heavy migration for an explicitly selected fresh
bench USB conversion.

A fresh qualified installer has floor 0 and no previously signed OTA image.
Its transaction status can therefore report an unknown image or boot state
while local preflight reports `writes=allowed marker=qualified` and the normal
radio is usable. Do not treat that as an authenticated Installed report or
require another provisioning cycle merely to manufacture prior OTA history.

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

### Passive repeater radio-fault readback

On an OTA-enabled repeater's physical USB CLI, run `ota radio`. Both local USB
provenance and a zero sender timestamp are required; remote and Ethernet requests
return `Err - local USB only`. An unavailable radio or unsupported diagnostic also
returns an explicit `Err`.

The `retained` reply is passive history, **not a fresh chip-state measurement**.
It only copies the driver's retained diagnostic and reads software state flags:
no active probe, SPI/status read, reset, queue change, retune, fault clearing,
settings change or write-gate change. A successful recovery can give `h=1 f=1`:
the last failure remains recorded until the driver object is recreated.

Compact labels: `h` healthy, `f` hasFailure, `n` faultCount, `l` lastFaultCount;
`o` last origin (0 unknown, 1 startReceive, 2 readData, 3 receiveRearm,
4 startTransmit, 5 activeProbe); `ds` driverStatus, `pr` probeReasons,
`em` expectedMode, `sb` statusByte, `de` deviceErrors, `irq` irqFlags,
`es` deviceErrorsStatus, `is` irqFlagsStatus, `ss` statusReadStatus,
`sw` softwareStateBefore/After. Counts and `pr/em/sb/de/irq/sw` are hexadecimal
without `0x`; origin and signed statuses are decimal. Boolean `r/t/d/p` mean
software receive mode, send in progress, direct active and direct pending.
Replies fit the existing 160-byte buffer including NUL and the optional CLI prefix.

### Passive repeater service readback

The same physical USB CLI offers `ota service`, with the same zero-timestamp
and local-USB provenance gate. The `ram` reply observes dispatcher/pool/budget
state and peeks at a **due-now** outbound control reply without consuming or
releasing it. It never probes the radio, reads RSSI, updates budgets, ticks the
integration, changes queues/settings or alters boot, trust, ownership or write gates.
A missing packet manager returns an explicit `Err`.

Labels: `free` free packet count, `q` total outbound queue count,
`to` TX timeout count, `af` OTA airtime-accounting failure count,
`tx` remaining dispatcher TX budget in milliseconds, `ota` remaining OTA
airtime budget in milliseconds; `n` ready normal traffic, `d/p` direct
active/pending, `c` control reply due now, `len/kind` its byte length and first
byte. `to/af/tx/ota/kind` are hexadecimal without `0x`; other values are decimal.
`c=0 len=0 kind=00` means no control reply is due now, not necessarily that none
is scheduled for later. The OTA budget is the stored on-mesh share, not the
remaining direct-lease duration. Airtime estimation and `canTransmit` are
deliberately omitted to keep this snapshot strictly RAM-only.

For example: `ram free=32 q=2 to=4 af=1 tx=3E8 ota=11940 n=1 d=0 p=1 c=1 len=123 kind=0B`.
The maximum formatted reply is 117 characters on ROLE1 (133 with 64-bit
`unsigned long` budgets), plus optional 3-character CLI prefix and NUL.

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
(the default `OTA_UPLOAD_MODE`) uses the normal mesh; `background` requires
`OTA_UPLOAD_CHANNEL` set to an existing multicast channel. Those native-host
transports are software-tested only.

Directed and background delivery always use reliable attempt-diverse framing,
so a retried packet can pass relays that already saw a lost copy instead of
stalling the transfer. This is the default for `make ota-deploy` and
`scripts/ota_uploader.py`; `--routed-retry` is accepted but redundant. The legacy
unframed on-mesh path is no longer offered: `OTA_DEPLOY_ROUTED_RETRY=0` (or
`--no-routed-retry`) is refused for directed/background and has no effect on
zero-hop `direct` mode, which never uses relays. Receivers must run an OTA build
that understands the framing.
`OTA_UPLOAD_DUTY_MILLI_PERCENT` controls normal-channel airtime share (2000 means
2%); it does not override local spectrum rules.

The host builds the shared canonical descriptor in memory, asks the companion
to Ed25519-sign it, stages the image, waits for fresh complete READY, sends one
signed COMMIT and waits for matching native Installed status.

Every fresh BEGIN, including a reupload of an identical image after ABORT, gets a
random 16-byte BEGIN nonce. The receiver stores it with the candidate and
reports it with READY. COMMIT is signed over the target, descriptor hash, counter,
generation and that nonce, so it installs only the exact attempt the host saw
READY. Repeating COMMIT for the same attempt is harmless, for example after a
lost acknowledgment or a host or receiver restart. A COMMIT captured from an
earlier attempt is denied. The host never commits a READY that has no nonce.

Direct mode leases the off-normal frequency with a single-use receiver challenge.
The challenge comes from the receiver's latest census report and is redrawn at
boot, at BEGIN and as soon as a lease request is accepted. Replayed, stale or
identical retried requests get no acknowledgment and do not retune the receiver.
After a lost acknowledgment, the sender waits out the possible lease, polls the
census for the new challenge and asks again. A supplied
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
packet commands. It does not require the native OTA USB command. It supports
zero-hop off-channel `direct` delivery, normal-channel `directed` delivery
through **one explicitly selected relay**, and `background` collection by
**exactly two receivers sharing one block flood**. Two-target stock background
delivery is software-tested; its hardware experiment is still pending.

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

A separate stock `upload` writes a schema-2 READY receipt. The receipt includes
the receiver's generation and `begin_nonce`. `commit --ready-receipt` refuses a
schema-1 receipt, and also refuses one whose nonce no longer matches the
receiver's fresh READY (for example after ABORT and reupload). Run `upload` again
to get a current receipt. `deploy` handles this internally.
For separate `upload`/`commit` to a repeater, pass the same explicit `--board`,
`--role-id 1` and `--counter` alongside its canonical manifest; omission retains
the legacy ROLE0-only manifest checks.

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

For a stock Heltec → nRF relay → nRF repeater target on the existing normal
radio profile, select the relay's **full public key**, the repeater role and
the request path hash width explicitly:

```sh
make ota-deploy OTA_DEPLOY_TRANSPORT=stock OTA_UPLOAD_MODE=directed \
  OTA_DEPLOY_CLIENT_PORT="$CLIENT_PORT" \
  OTA_STOCK_SERIAL="$CLIENT_SERIAL" OTA_STOCK_SENDER_KEY="$SENDER_PUBLIC_KEY" \
  OTA_STOCK_BINDING="$BINDING_JSON" OTA_ARTIFACT_DIR="$NEW_RUN_DIRECTORY" \
  OTA_STOCK_RELAY_KEY="$RELAY_PUBLIC_KEY" OTA_STOCK_PATH_HASH_BYTES=1 \
  OTA_UPLOAD_CHANNEL=255 OTA_UPLOAD_FREQ_KHZ=0 \
  OTA_UPLOAD_DUTY_MILLI_PERCENT=2000 OTA_UPLOAD_TIMEOUT=172800 \
  OTA_UPLOAD_IMAGE="$APP_BIN" OTA_UPLOAD_BOARD=xiao_nrf52840_sense \
  OTA_UPLOAD_ROLE_ID=1 OTA_UPLOAD_COUNTER="$NEXT_COUNTER" \
  OTA_UPLOAD_TARGET="$TARGET_PUBLIC_KEY"
```

Omit DTR for the Heltec/ESP sender. Keep any required physical USB anchor/name
guards in `OTA_STOCK_ARGS`; directed mode does not override the binding.
All three devices must already share `normal_profile`, and the selected relay
must have OTA-aware forwarding enabled. A dedicated repeater or relay-only
repeater can forward these packets without an installer. A companion can also
serve as the relay if its existing firmware forwards OTA traffic and repeat mode
is enabled; no role change is implied. The host verifies the sender's frequency,
bandwidth, SF and CR against
the binding before any signing or RF operation, preserves its repeat setting
and TX power, and never writes radio configuration in directed mode. A mismatch
or later profile drift is an error, not an invitation to retune.

Stock CLI equivalents are `--mode directed --relay-key "$RELAY_PUBLIC_KEY"
--path-hash-bytes 1 --channel 255 --frequency-khz 0 --lease-ms 0
--normal-duty-percent 2 --timeout 172800`.
The CLI still defaults to off-channel `direct`; omitted frequency/lease in
explicit directed mode mean zero. Widths **1, 2 and 3** use the existing
MeshCore encoded path byte `((width - 1) << 6) | count` and public-key prefixes,
not SHA-256 hashes. Every request has exactly one hop. The largest wrapped
authorization fits the stock 176-byte command only with at most three path
bytes; this adapter therefore does not offer multi-relay paths.

Directed requests use existing OTA `0x11`/`0x12` BE32 attempt wrappers around the
unchanged signed frames (repair blocks use `0x12`). Attempts are fresh on every
transmission, including repeated polls and repairs; sequence exhaustion fails
without wrapping or unframed fallback. `--routed-retry` is redundant in directed
mode; `--no-routed-retry` / `OTA_DEPLOY_ROUTED_RETRY=0` are refused there.
No signed direct lease is requested and no off-channel burst is used.
`OTA_UPLOAD_DUTY_MILLI_PERCENT` / `--normal-duty-percent` apply to every packet,
including retry and path overhead. CMD65 requests use normal OTA low priority;
queue acceptance is still insufficient without measured physical TX completion.
Large applications at a small normal-channel duty share can exceed the default
four-hour campaign timeout. Select an adequate `OTA_UPLOAD_TIMEOUT` explicitly;
on-channel deployment never substitutes the faster off-channel burst profile.

**Return-route contract:** current receiver firmware sends normal-channel
census/status replies as **floods**, with width-1 relay hashes appended; it does
not provide a directed reverse-path API. The stock host requires the reply to
echo the latest request attempt and contain exactly the selected relay's
one-byte prefix. A zero-hop copy heard directly from the target, a direct reply,
an unwrapped/old attempt, or another relay trail cannot advance the campaign.
`rf_tx_request`, `rf_rx` and `rf_reply_route` JSON events expose request paths,
reply trails and attempt matching without logging packet bodies. Directed READY
receipts also bind the selected relay/path; separate COMMIT cannot switch paths.
These are **unsigned path observations**, not cryptographic hop attestation;
the selected relay's one-byte prefix must be distinct from sender/target, and
operators must rule out other relay prefix collisions. An older relay must
actually forward these OTA wrappers and v3 census floods; a protocol/version
label alone does not establish that. Qualify both directions on hardware before
a real install. Failure never retries with a zero-hop path or changes firmware.

The public `inspect` command remains USB-only and read-only by default; it
does not perform RF probes or claim that the selected topology is ready.

### Two-target shared-flood background collection

Both receivers must already be qualified installers for the same board, role
and APP image and must authorize the stock sender's OTA administrator identity.
Choose a common counter above the maximum of their freshly measured confirmed
floors. A relay-only APP does not qualify a second installer, and signing two
different role descriptors cannot make them share one signed block stream.

Provide two distinct full target keys and two owned mode-0600 bindings. Each
binding has its own target, floor and generation guards; both must agree on the
stock sender, physical USB endpoint, candidate and normal radio profile. If
physical USB anchoring is required, include the same `--by-path` and matching
binding metadata for both targets.

```sh
make ota-deploy OTA_DEPLOY_TRANSPORT=stock OTA_UPLOAD_MODE=background \
  OTA_DEPLOY_CLIENT_PORT="$CLIENT_PORT" \
  OTA_STOCK_SERIAL="$CLIENT_SERIAL" OTA_STOCK_SENDER_KEY="$SENDER_PUBLIC_KEY" \
  OTA_STOCK_BINDING="$TARGET1_BINDING_JSON" OTA_ARTIFACT_DIR="$NEW_RUN_DIRECTORY" \
  OTA_UPLOAD_TARGET="$TARGET1_PUBLIC_KEY" \
  OTA_UPLOAD_IMAGE="$COMMON_APP_BIN" OTA_UPLOAD_BOARD=xiao_nrf52840_sense \
  OTA_UPLOAD_ROLE_ID=1 OTA_UPLOAD_COUNTER="$NEXT_COMMON_COUNTER" \
  OTA_UPLOAD_CHANNEL=255 OTA_UPLOAD_FREQ_KHZ=0 OTA_UPLOAD_LEASE_MS=0 \
  OTA_UPLOAD_DUTY_MILLI_PERCENT=2000 OTA_UPLOAD_TIMEOUT=172800 \
  OTA_STOCK_ARGS="--second-target $TARGET2_PUBLIC_KEY --second-binding $TARGET2_BINDING_JSON"
```

Omit DTR for Heltec/ESP, and retain any required USB anchor/name guards in
`OTA_STOCK_ARGS`. Unlike native-host encrypted multicast-channel delivery,
stock background uses **channel 255: a public, unscoped OTA RAW flood**. It
does not require an encrypted multicast channel, select a mandatory relay,
retune radios or obtain a direct lease.

The host admits the two targets independently, sends each initial image block
once for both receivers to hear, then repairs the union of their missing
bitmaps with shared block transmissions. Each target's fresh READY and signed
COMMIT remain bound to its own generation and BEGIN nonce. Admission,
repair and installation failures remain per-target facts and cannot become
aggregate success merely because the other receiver succeeds.

The new artifact directory holds `original-radio.json`, final
`radio-unchanged.json`, schema-3 `attempt-FULL_TARGET_KEY.json` receipts and a
schema-1 aggregate `result.json`. For `make ota-deploy`,
`shared-native-installed-reported-unsigned` with `operation_complete:true`
means both matching unsigned Installed reports and counter floors were observed.
It does **not** authenticate installation: `status_authenticated` and
`installation_confirmed` remain false. Partial failure records
`shared-campaign-incomplete`, individual outcomes/errors and
`operation_complete:false`, then exits nonzero.

The stock CLI also supports two-target `upload` and separate
`commit --ready-receipt`; their aggregate outcomes are
`shared-ready-observed-unsigned` and
`shared-signed-commits-not-install-confirmed`, respectively. Neither means
installation was confirmed.

Resume an interrupted shared transfer with **both** original owned schema-3
attempt receipts. Set `OTA_STOCK_RESUME_RECEIPT` to target 1's receipt and add
`--second-resume-receipt` for target 2 in `OTA_STOCK_ARGS`, retaining the same
targets, bindings, image, board, role, counter, physical sender, normal profile,
TX power and duty budget. Select a new artifact directory; do not overwrite the
original run. Append the second receipt argument to the original
`OTA_STOCK_ARGS`; preserve its second-target/binding and any physical anchor or
sender-name arguments.

Both receipts and fresh attempt-bound censuses must match each receiver's
existing generation and BEGIN nonce. Resume supports Receiving or READY
candidates, not committed, installing or Installed continuation. Missing,
unpaired or stale receipts fail closed. It sends no BEGIN, ABORT, REUPLOAD or
initial full-image pass: independent fresh bitmaps determine the union of
missing blocks, then each target retains its own READY and signed COMMIT.
The directed resume procedure below is separate.

SIGINT/SIGTERM stops further OTA signing, transmissions and target processing,
records `shared-campaign-cancelled` with `operation_complete:false`, and unwinds
through profile readback and UART cleanup. Already-issued COMMITs remain
recorded; cancellation cannot withdraw them.

### Resume an interrupted directed attempt without a new BEGIN

Directed `upload`/`deploy` now persist an owned mode-0600
`attempt-receipt.json` after the first fresh validated census. This schema-3
receipt is **unsigned attempt/progress evidence**, not READY or installation
confirmation. It freezes full sender/target identities, image SHA-256 and size,
manifest hash, counter, generation, BEGIN nonce, floor/generation guards,
normal and sender radio profiles, TX power, physical USB binding, selected
relay/path, original duty and first-window progress.

Stop the old host gracefully and wait for its endpoint lock to be released;
do **not** ABORT the receiver. Resume using the same image, manifest, binding,
board/role/counter and route, an explicit original receipt, and a **new**
artifact directory. Add these arguments to the directed Make example:

```sh
OTA_STOCK_RESUME_RECEIPT="$ORIGINAL_ATTEMPT_RECEIPT" \
OTA_ARTIFACT_DIR="$NEW_RESUME_DIRECTORY" \
OTA_UPLOAD_DUTY_MILLI_PERCENT=80000
```

The stock CLI equivalents are `--resume-receipt "$ORIGINAL_ATTEMPT_RECEIPT"
--artifacts "$NEW_RESUME_DIRECTORY" --normal-duty-percent 80`.
**80% is an explicit caller-authorized test setting, not the product default
or a throughput guarantee.** The default stays 2%; relay/receiver airtime
settings are not changed by the host, and spectrum rules still apply.

Resume sends census polls first, never Authorization/BEGIN or REUPLOAD.
Fresh route/attempt-matched reports must retain the receipt's exact generation,
nonzero BEGIN nonce, manifest, counter and floor, and cannot regress its recorded
received count or first-window bitmap. Only then may it send missing image
blocks, observe fresh READY, and (for `deploy`) send one nonce-bound COMMIT and
wait for matching unsigned Installed. Timeout, missing route, ABORTED/FAILED,
or any identity/profile/attempt mismatch is a failure with no admission,
counter change, nonce substitution, direct fallback or retune.

The new directory preserves `resume-source.json` with the original receipt,
its source path and canonical-JSON SHA-256, plus a newly observed
`attempt-receipt.json`. Old artifacts are never overwritten; the new receipt
records the newly selected sender duty. Normal radio/repeat settings remain
unchanged and are read back on exit.

Older running hosts did not emit schema-3 receipts. If only their original
`original-radio.json` survives, a caller-owned bounded helper can capture the
current attempt **after stopping the old host**, without Authorization/BEGIN
or REUPLOAD. Construct a fresh directed `Sender` with the exact immutable image,
manifest, binding and current `stock.identify()` profile, then call
`capture_resume(private_read(original_radio_path), expected_generation,
min_received=known_received_lower_bound)`. This performs one route/attempt-matched
census and requires current Receiving, the explicit generation, matching
manifest/counter/floor and non-regressed known progress. The original radio
artifact must exactly match sender identity, physical binding, profile and TX
power. Save the returned schema-3 receipt privately in a new capture directory.

The captured nonzero BEGIN nonce is explicitly a **fresh unsigned observation
of the existing attempt**, not verification against an unavailable historical
nonce; no nonce is generated, substituted or sent to the receiver. The subsequent
resume pins that captured nonce and refuses changes. Capture never accepts
ABORTED/READY/Installed as Receiving, silently re-admits, or retries with a
direct path. Preserve the original radio evidence and capture provenance
alongside the new receipt; do not invent missing historical session metadata.
Capture records the helper's selected duty, not an unavailable historical
sender duty.

### Hardware milestone: routed installation and reboot persistence verified

As of **2026-10-09**, a stock Heltec sender → dedicated nRF repeater relay →
nRF repeater installer target has passed a bounded, non-activating RF check on
907.525 MHz / BW250 kHz / SF7 / CR5, TX2 and 2% OTA duty. The relay's isolated
profile and enabled forwarding persisted across reboot. With relay forwarding
disabled, the poll timed out after 25 seconds with no accepted route; enabled,
**5/5** baseline census replies echoed the current request attempt and carried
exactly the selected relay trail. Directly overheard target replies were rejected.
The v3 reports described the existing generation-1, floor-1 image; the probe did
not authorize or replace a candidate, retune radios or use a direct fallback.
These remain unsigned RF/path observations.

The subsequent 506,524-byte counter-2 campaign began on the same normal profile,
2% duty and a 172,800-second budget. Its early generation-2 Receiving observations
established progress, not installation.

The explicitly authorized accelerated run gracefully paused that host and
captured the existing generation-2 Receiving state at 129/6,031 blocks. It
resumed the same image and nonce with an 80% sender budget, a private 80% relay
cap and mesh duty, and the receiver's transient native `ota duty 80` setting.
TX2 and the normal radio profile stayed unchanged. A six-second relay outage
left a four-block batch missing; selective retries of blocks 2056-2059 restored
that window's census bitmap count from eight to twelve. No ABORT, new BEGIN,
REUPLOAD or direct fallback was used.

The resumed campaign completed **6,031/6,031 blocks** and reported counter-2
Installed through the selected relay at 5,538.121 seconds on the resumed clock.
The RF report remains unsigned. Separately, the receiver's local USB CLI showed
confirmed/installed, counter and floor 2, verified image SHA-256
`d96a0d8b940dddb9ab85ccffd77cf145b6f994b9bca7275fc847b1ef88f95397`,
506,524-byte extent, floor sequence 3 and qualified writes. An explicit
same-firmware reboot preserved those values, identity, normal radio and TX2.
After reboot, **25/25** accepted census samples reported the same Installed
generation and floor through the mandatory relay, rejecting bare direct copies;
one sample needed a census retry. These observations do not authenticate RF status.

The stock sender's final radio/repeat/TX2 readbacks were unchanged, and only its
temporary receiver authorization was revoked; the original administrator entry
was preserved. This completed campaign used one installer and one relay.

The subsequent two-installer background campaign admitted both Sense targets
against the same 506,524-byte image, counter 3 and 6,031-block descriptor. Its
first host run failed with a USB response-backlog overflow after 187 common
block transmissions; neither receiver was committed. After the host fix, strict
paired resume used both original schema-3 receipts. Fresh censuses matched the
original independent generations and BEGIN nonces and reported 159/6,031
received blocks on each target. The resume sends only union-bitmap repairs,
without a new BEGIN or receiver reset. Shared-flood completion, both durable
installations and post-reboot qualification remain outstanding; these
admission and resume observations are not installation proof.

The stock companion keeps sending its ordinary notifications (adverts, path
updates, message tickles, ordinary received-packet logs and similar) during a
long transfer. The uploader discards only well-formed notifications of the
known MeshCore 1.17.1 kinds it never uses. Its RF-log demultiplexer also validates
the payload shape of echoed OTA traffic, including signed blocks and retry
envelopes, then counts and removes non-consumed echoes from the USB response
queue. It does not suppress those packets on air or claim their signatures
were authenticated. Census replies and lease/profile acknowledgments remain
pending, as do command replies, errors and requested signatures.

Unknown or malformed OTA shapes are not discarded by this demultiplexer;
normal freshness and protocol checks still apply. Malformed recognized ordinary
notifications and invalid USB frame lengths fail explicitly. The bounds remain
176 bytes per frame and 256 pending responses. Diagnostic events contain
bounded metadata and exact final counters, not plaintext payloads.

Direct stock captures the sender's exact original radio/repeat settings and TX power,
persists `original-radio.json` before changing radio, accounts for physical TX
completion, verifies signed direct-lease acknowledgments, and restores and reads
back the original settings on success or failure. The receiver's bounded lease
also returns it to normal radio. The unchanged stock host never changes TX power.
Directed stock persists the original settings too and writes
`radio-unchanged.json` only after an unchanged final readback, rather than
claiming to have restored settings it never modified.

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

Candidate state is fail-closed. If the receiver cannot read it, or finds
metadata it cannot positively explain, status reports result `UNAVAILABLE` (5)
with no snapshot, never Idle or "no candidate". The receiver never falls back to
an older candidate state or approval. BEGIN, ABORT, COMMIT and erase are all
refused. Causes include:

- a power cut while a candidate record was being written (torn record);
- an interrupted metadata erase;
- a damaged committed record;
- unreadable flash.

Power-cycle once to rule out a transient read failure. If `UNAVAILABLE` persists,
OTA stays unavailable on that receiver. This availability cost is deliberate: it
guarantees an ABORT or revoked approval can never come back. Ordinary USB/DFU
application restoration may restore ordinary service, but it does not establish
persistent OTA metadata recovery. On nRF, the external-QSPI candidate records are
not cleared by an ordinary APP ZIP DFU or a filesystem erase. No supported
metadata-repair procedure is currently provided for unknown, torn-record or
tombstoned ESP cases. Do not mass-erase or wipe user data in an attempt to clear
it.

A power cut while a fresh signed BEGIN or reupload is clearing the previous
candidate normally leaves the receiver empty (no candidate), never an earlier
READY. Upload again. If the cut came at the very start of that clearing step,
status is `UNAVAILABLE` as above. On ESP32-S3, OTA stays disabled after any such
interrupted clear, with no supported metadata repair.

A power cut while the receiver only marks a completed record has a narrower
effect. An interrupted ABORT, failure or retirement still takes effect. An
interrupted forward step (receiving, verifying, READY, commit) reverts to the
previous state of the same attempt.

On ESP32-S3, a power cut during the first write of a new BEGIN can leave a
partial candidate record. OTA stays available only if that record verifies
exactly: it is signed by its owner for this board and role, and all the
remaining candidate metadata reads back erased. The next fresh signed BEGIN then
erases it. Anything else disables OTA on that receiver
(`OTA_DISABLED: ESP candidate metadata damaged` or `... unreadable`) instead of
being treated as empty.

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
