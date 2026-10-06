# Hardware lab device workflow

Every operation against a physical board goes through one tool,
`scripts/lab_device.py`, wrapped by `make lab-*` targets. No target, script, or
ad-hoc command names a `ttyACM` number or a literal USB serial.

## Host dependencies

The lab scripts need Python packages beyond the base toolchain. If a command
reports missing packages, install the declared dependencies:

```sh
python3 -m pip install -r requirements-ota.txt
```

This declares `cryptography>=43.0` and `pyserial>=3.5`.

`make test-ota-lab-host` runs the host-side unit tests in `scripts/tests/`,
including the signed uploader and the protected-power-domain behaviour
described below. It exercises
the actual wire/USB-protection logic against mocked device topology, not a
placeholder or infrastructure-only check. It is part of `make test`/`make
test-ota` and does not require a board attached.

## Roles, not ports

Boards are addressed by **role**. `lab/devices.ini` pins each role to a USB
serial:

```ini
[roles]
client = 4186AE911D94CDB1
target = 77CD44653A967172

[protected]
pine = 49C5BAF21EEF44A1

[recovery]
target = 3BE94917B92DC5E9
```

The replacement `77CD44653A967172` is the active radio target. The failed
former target remains separately bound in `[recovery]`; it is not an active
OTA role. SWD's explicit `--role target` still selects only that original
failed device, not whichever board is now the radio target.

Initial replacement discovery found `239a:810b`, manufacturer Seeed Studio,
product `XIAO-BOOT`, with CDC interfaces. That is public USB evidence, not
proof of application mode, board variant, SoftDevice or a compatible recovery
loader. Do not infer mode from the high PID bit or bypass USB/profile guards
to flash it. Its firmware baseline must be established first.

After the user's replacement-only physical double-reset on Oct. 3, 2026 UTC,
the same serial enumerated as `2886:0045`, XIAO nRF52840 Sense, with its own
MSC interface. The ancestry-matched, read-only `XIAO-SENSE` volume reported
Board-ID `Seeed_XIAO_nRF52840_Sense`, stock UF2 loader `0.6.1` and S140 `7.3.0`.
This is compatible vendor metadata, not cryptographic installed-byte proof or
custom-loader qualification. No software reset, serial open or firmware write
was made to establish that baseline.

The user identifies the replacement as a fresh factory board that has never
run MeshCore. Its first application must therefore be the ordinary
`Xiao_nrf52_repeater` profile, with separately qualified bench radio defaults.
Ordinary healthy first boot generates and saves its own MeshCore identity.
Only after capturing that new identity/settings and verifying persistence
should it be upgraded application-only to the OTA repeater profile.
The OTA profile intentionally refuses fresh identity creation and blank-storage
formatting; do not bypass those guards or clone the failed target's identity.
Keep stock recovery intact during these application and ordinary-radio checks.

**Actual replacement commissioning, Oct. 3, 2026 UTC:** application-only stock
DFU of the qualified ordinary bench image returned to APP USB. Its 389,768-byte
application SHA256 is
`54ad8251ce53610b0195ba018895020fbe1e264209a82c4ae290d401497b8713`;
ZIP SHA256 is `b71a5e90c410b28ed5d5069740575f31ef003dfd2a9b0ebcb820d31678ad0fae`.
Compiled initial/preference defaults were independently qualified as
907.525 MHz / BW250 kHz / SF7 / CR5; inherited TX power remained 22 dBm.
The ordinary profile's existing append/unflag mechanism selected those defaults:

```sh
PLATFORMIO_BUILD_FLAGS='-D LORA_FREQ=907.525 -D LORA_BW=250 -D LORA_SF=7 -D LORA_CR=5' \
PLATFORMIO_BUILD_UNFLAGS='-D LORA_FREQ=869.618 -D LORA_BW=62.5 -D LORA_SF=8' \
make build-xiao-nrf52-lab XIAO_NRF52_LAB_ENVS=Xiao_nrf52_repeater
```

It generated its own public identity `11e41e0d...ad3bd507`, retained after an
ordinary reboot. Explicit bench name/radio/path settings and normal companion
ADMIN permission were then saved and independently retained after another
ordinary reboot, including the complete ACL. The `03:47:08Z` zero-hop advert
probe received that exact target at the client: native companion acceptance and
host Ed25519 verification of the raw advert were both observed, RSSI -24 dBm /
SNR 11.75 dB. All captured settings and the complete ACL were unchanged.

**Blocking migration finding:** APP-only migration to the qualified `73da40aa`
OTA repeater preserved identity and complete ACL, but reset visible target
preferences to the compiled defaults: name `Xiao_nrf52 Repeater`, BW62.5 kHz
and path-hash mode 0 instead of the saved bench name/BW250 kHz/mode 2.
Stock proof was healthy, size 538328, CRC `0000/E87C`, marker blank, CACHE_ONLY.
No settings were replayed to hide this failure. Restoring the exact ordinary
APP recovered every original captured setting and the complete ACL without
setters; the tested migration did not erase those stored preferences.
Further OTA migration was held for a causally verified preference-read/startup
correction. The correction selects an existing OTA `/repeater_prefs.json`
first; if absent, it reuses the ordinary `/prefs.json`. That one selected path
is used for load, save and storage-health probes. It does not copy, rename,
create another preference store or write during startup, and does not fall
back from a present unreadable/malformed OTA file to stale ordinary data.
Other profiles keep their existing paths and serialization.
The replacement was returned to its ordinary bench APP with stock
recovery intact. The `03:55:01Z` probe again observed a host-verified signed
target advert; native companion acceptance was not observed in that final
probe. Neither probe qualifies bidirectional, routed, multicast or OTA delivery.
No custom loader, SoftDevice, MBR or UICR update, power cut, OTA START or COMMIT
was requested; Pine and the failed recovery target were not opened.
Source-bound first-provision and regression evidence is retained privately in
`review-candidates/replacement-77-stock-first-provision-evidence/`.

**Corrected migration qualified on the replacement:** source fix `5c41f3a9`
passed the scoped Opus 5.5 review, causal native tests and product builds.
ROOT's exact `04705d6a` build contains a 538,360-byte APP, SHA256
`69c961ff66602c865a3cf8b3855478a8191cfc605ed4d811e70a7cdcc9f18fd2`;
ZIP SHA256 is `60dd1f636fc7788d2be8fb9d1fb0a41a4dd82d84cf003f22dc961ee629f11d95`.
Its only byte differences from the owner's reviewed APP are three ASCII
`__TIME__` bytes; code and all other image bytes agree. The APP-only retry
returned to USB with healthy stock proof, size 538360, CRC `0000/B968`,
marker blank and CACHE_ONLY. Before/after/reboot captures preserved both
identities, every captured public setting and the complete ADMIN ACL, without
replaying any setter or grant. The target kept its saved bench name, BW250 kHz
and path-hash mode 2.

The `04:36:38Z` probe received a host-verified signed advert from that exact
target; native companion acceptance was not observed in this probe. Final
driver-applied observations were the normal bench tuple with healthy radios,
zero reported faults/apply failures/timeouts/accounting failures, zero OTA
airtime, and 242 ms target all-TX time. These are not physical PHY-register or
duty-window proof. The companion's original ABI2 cache remains ABORTED
generation 6 / 6,403 blocks. No OTA START or COMMIT, custom-loader/SoftDevice/
MBR/UICR update or protected-device operation was requested.

The replacement now runs the corrected OTA APP but remains **CACHE_ONLY**:
stock recovery is intact, and receiver/install authority and a confirmed
version floor are not qualified. Full radio image staging/installation,
trial confirmation, rollback and duty acceptance remain gated on separately
proven recoverable commissioning; do not bypass the current refusal.
Corrected source/artifacts and actual migration evidence are retained privately
in `review-candidates/replacement-77-prefs-migration-04705d6a/`.

**User-authorized vendor OTAFIX sequence completed, Oct. 3:** replacement
`77CD44653A967172` now has the official XIAO nRF52840 **Sense** OTAFIX
`0.9.2-OTAFIX2.3-BP1.4`, followed by the qualified ordinary MeshCore
389,768-byte bench APP and then the corrected 538,360-byte OTA APP above.
The SenseCAP Solar P1 and ThinkNode M6 files in Downloads were not used:
their board identities are different, and a UF2 board rejection can happen
after scratch writes have started.

The digest-verified Sense NOSD UF2 supplied the boot bytes; its sparse erased
gap was corroborated against the official combined ZIP's bootloader slice.
The private, reviewed Make workflow generated a **bootloader-only serial**
package, not a UF2 copy or combined SoftDevice update. Its 39,168-byte BIN
SHA256 is `0cff4f0a0e95c017def050bc03a6898b6970316c0c5934ce36e4de949b34aa9e`;
ZIP SHA256 is `54307f53efb36390ff4bb6b5c8e8d56466d8a0f2198040826c2f12a680a8ea24`.
This route stages/erases APP bank0 through `0x31000` and writes the loader
through `0xFD900`, page-rounded to `0xFE000`. ExtraFS and InternalFS are
outside those ranges. Normal MBR-parameter/SDK-setting mutations are expected;
no MBR, UICR or SoftDevice image was sent. Source inspection, 13 causal offline
tests and scoped Opus 5.5 review closed before the single physical attempt.

After transport acknowledgement, the user double-reset only 77 to select
USB recovery: OTAFIX defaults to BLE DFU when the APP is invalid, so USB
absence at that point alone is not a failed-loader diagnosis. Bounded,
ancestry-matched read-only INFO then reported OTAFIX 2.3,
`nRF52840-SeeedXiaoSense-v1` and S140 `7.3.0`. This is vendor metadata,
not cryptographic installed-loader readback. Ordinary and corrected OTA
APP-only restores returned to USB and preserved every captured public setting,
both identities and the complete ADMIN ACL without setters or grants.

A final physical single RESET retained application service, all settings/ACL,
healthy stock proof `0000/B968`, and the same live boot/parameter addresses
`0xF4000` / `0xFE000`. The `11:24:04Z` ordinary peer probe received a
host-verified signed target advert (RSSI -18 dBm, SNR 12.25 dB); native
companion acceptance and emission freshness were not established. Final
driver-reported health had no faults, timeouts or accounting failures and
zero OTA airtime. The unchanged client cache remained ABORTED generation 6
with all 6,403 blocks.

The target remains **CACHE_ONLY** with no confirmed version floor. Vendor
OTAFIX improves USB/BLE DFU; it does not supply our LoRa install/rollback
authority. Full three-mode image delivery, installation, trial/rollback and
duty qualification remain incomplete. Pine and the failed 3BE were not
operated. Reviewed helpers, vendor inputs, restoration packages and actual
evidence are retained privately in
`review-candidates/replacement-77-vendor-otafix-2.3-evidence/`.

An inventory listing can override a role for one run without editing the file:

```sh
MESHCORE_LAB_TARGET_SERIAL=ABC123 make lab-devices
```

Operational commands still require the exact approved client/replacement pair;
an inventory override does not authorize a different device.

Serials in `[protected]` cannot be assigned to a lab role, including through
an environment override. This prevents the Pine project board from being
reset, flashed, or power-cycled by a MeshCore lab command.

`ttyACM` numbering changes whenever a board re-enumerates — a DFU entry alone
moves it. Resolving a role to the current `/dev/serial/by-id` path at the moment
of use makes that a non-event.

## Commands

| Command | Purpose |
| --- | --- |
| `make lab-devices` | List attached boards, their roles, mode, and hub port |
| `make lab-doctor` | Check sudo, uhubctl, pyserial, and per-role power control |
| `make lab-reset-<role>` | Restart the application firmware |
| `make lab-bootloader-<role>` | Enter the serial DFU bootloader |
| `make lab-bootloader-uf2-target` | Request vendor UF2 mode from the target's bench USB application |
| `make lab-inspect-stock-bootloader-target` | Read public stock Sense boot metadata from its already-mounted read-only MSC volume |
| `make inspect-xiao-nrf52-channels` | Read the approved companion's configured channel names and indices, without logging keys |
| `make inspect-xiao-nrf52-ota-measurements` | Read the approved pair's driver-applied radio and completed airtime observations |
| `make inspect-xiao-nrf52-ota-client-measurements` | Read those observations from the approved companion only |
| `make lab-power-cycle-<role>` | Cut and restore USB port power |
| `make lab-wait-<role>` | Block until the board enumerates |
| `make upload-xiao-nrf52-<role>` | Build and flash the role's application |
| `make flash-xiao-nrf52-<role>` | Flash the role's existing package without rebuilding |

`lab-inspect-stock-bootloader-target` never enters a bootloader, opens serial,
mounts a volume or writes firmware. After target-only physical UF2 entry and
host read-only mounting, it requires the approved replacement's stable USB
identity, exact Sense USB/Board-ID, its own MSC interface, one ancestry-matched
read-only whole-volume mount, and bounded stock `0.6.1` / S140 `7.3.0` INFO.
Its JSON explicitly distinguishes vendor metadata from installed-byte proof
and custom-loader qualification. Missing or mismatched evidence is a refusal,
not permission to retry a flash.

That inspector deliberately remains **0.6.1-only**. It must refuse the current
replacement's newer OTAFIX metadata; do not loosen the old commissioning gate
or relabel newer observations as passing it. The separately reviewed vendor
operation retained its own bounded read-only post-update INFO evidence.

The client uses `Xiao_nrf52_companion_radio_usb`; the remotely upgraded
target uses `Xiao_nrf52_repeater_ota_usb` (`simple_repeater`). Override
`XIAO_NRF52_CLIENT_ENV` or `XIAO_NRF52_TARGET_ENV` only for an intentional
profile change. The default lab build includes both roles.

For an immutable application snapshot, pass each role's package explicitly:

```sh
make flash-xiao-nrf52-lab \
  XIAO_NRF52_CLIENT_PACKAGE=/absolute/path/to/client/firmware.zip \
  XIAO_NRF52_TARGET_PACKAGE=/absolute/path/to/repeater/firmware.zip \
  OTA_LAB_ARTIFACT_DIR=.tmp/ota-rf-lab/snapshot-flash
```

Use an application-only DFU package. The helper checks the manifest,
application bounds and required payloads before entering DFU. Bootloader,
SoftDevice and combined packages are refused; custom bootloader
commissioning uses the separate guarded installer. This flashes only the
configured client and target without rebuilding concurrently edited source.
The package check does not identify a firmware role: select each role's
qualified package explicitly.

Before selecting a background campaign's channel, inventory the uploader's
existing table:

```sh
make inspect-xiao-nrf52-channels \
  OTA_LAB_ARTIFACT_DIR="$PWD/.tmp/ota-rf-lab/channels-$(date -u +%Y%m%dT%H%M%SZ)"
```

Use a new evidence directory. This client-only inspection reads the
advertised capacity and public names, excludes empty slots from
`configured_indices`, and redacts channel keys before logging even a
malformed reply. It never opens the target, changes a channel or grants
permissions. The repeater has no corresponding channel-index table:
the chosen sender slot scopes signed OTA flooding, not verified receiver
membership. An empty table leaves no selectable background channel;
do not assume index 0 exists.

Extract that package's validated raw application for the signed uploader:

```sh
make ota-lab-image \
  XIAO_NRF52_TARGET_PACKAGE=/path/to/repeater/firmware.zip \
  OTA_UPLOAD_IMAGE=/path/to/new/candidate.bin
```

This neither rebuilds nor opens a board, and it refuses to overwrite an
existing image.

The legacy `XIAO_NRF52_LAB_PACKAGE` override still deliberately selects
the same package for both roles. Do not use it for companion-to-repeater
qualification. The RF harness now monitors the binary companion client
and the repeater's text CLI separately.

`make configure-xiao-nrf52-ota-lab` uses each role's actual protocol to
configure the pair for 907.525 MHz, **62.5 kHz bandwidth by default**, SF7,
CR5 and three-byte path hashes. For the separately authorized higher-bandwidth
bench configuration, use `OTA_LAB_BANDWIDTH_HZ=250000` with that Make target
(the helper accepts `--configure-only --bandwidth-hz 250000`). Only bandwidth
changes: both setters, readback checks and evidence use the selected profile.
Supported integer-Hz overrides are 7800, 10400, 15600, 20800, 31250, 41700,
62500, 125000, 250000 and 500000; unsupported values are refused before
opening ports. The option is configure-only, not monitor or grant, and does
not set duty cycle. It checks both roles and full public keys before
making changes, then requires unchanged identities and complete
administrator ACL readbacks. It does not grant administrator permissions,
transfer an image, commit an update or reboot either board. Client-only
configuration remains available.

Read the actual stock-boot refusal before retrying a blocked setter:

```sh
make inspect-xiao-nrf52-ota-preflight \
  OTA_LAB_ARTIFACT_DIR="$PWD/.tmp/ota-rf-lab/stock-preflight-$(date -u +%Y%m%dT%H%M%SZ)"
```

Use a new evidence directory. This opt-in inspection reads both approved
roles, identities, the captured early proof, the actual latched write
permission and later cache capability. It never changes settings,
permissions, candidates or journals, and never resets a board. A recognized
blocked diagnostic is a valid observation, not permission to proceed.
The helper rejects lifecycle-only, missing or malformed readbacks.
These diagnostics require the corrected application: `bda99d13` ignores
the companion selector and cannot report the captured early refusal.

### One-client application and local-cache validation

The user has authorized MAIN to validate the working client and flash only
a qualified immutable companion application ZIP through standard stock
application DFU. All serial/hardware operations remain MAIN-only. This does
not authorize target/SWD recovery, bootloader/SoftDevice/MBR/UICR writes,
raw code-region writes or a radio campaign.

When only companion `4186AE911D94CDB1` is available, these routes never
resolve or open active target `77CD44653A967172`, failed recovery target
`3BE94917B92DC5E9` or protected Pine `49C5BAF21EEF44A1`.
Use a **new artifact directory for every inspection and cache invocation**;
existing directories are refused before any port opens.

```sh
make inspect-xiao-nrf52-ota-client-configuration \
  OTA_LAB_ARTIFACT_DIR=/private/evidence/client-before
make inspect-xiao-nrf52-ota-client-preflight \
  OTA_LAB_ARTIFACT_DIR=/private/evidence/client-preflight
```

The first command invokes `ota_rf_lab.py --client-only --inspect-configuration`
and records the actual public key, name, radio preferences and path-hash mode.
It sends only ordinary companion identity/settings reads. The second invokes
`--client-only --inspect-ota-preflight`, reading identity and diagnostic
selectors `42 00 01` / `42 00 02`. A valid blocked diagnostic is an observation,
not authorization to change settings. `summary.json` explicitly records
`scope: client_only`, `target_inspected: false` and no qualification claim.
Configuration inspection also records `acl_complete: false`,
`target_acl_inspected: false` and `reboot_persistence_verified: false`;
there is no target ACL or receiver-floor proof.

Only the authorized hardware operator may then use the existing
`flash-xiao-nrf52-client` route with an explicitly selected, immutable,
qualified **companion application-only ZIP**:

```sh
make flash-xiao-nrf52-client \
  XIAO_NRF52_CLIENT_PACKAGE=/private/qualified-companion/firmware.zip \
  OTA_LAB_ARTIFACT_DIR=/private/evidence/client-app-flash
make inspect-xiao-nrf52-ota-client-configuration \
  OTA_LAB_ARTIFACT_DIR=/private/evidence/client-after
make inspect-xiao-nrf52-ota-client-preflight \
  OTA_LAB_ARTIFACT_DIR=/private/evidence/client-after-preflight
```

The flash helper validates application package geometry before entering
standard application DFU. Do not use a receiver-role package for this flash,
rebuild mutable source, convert roles, or write bootloader, SoftDevice, MBR
or UICR. Compare the complete public configuration before/after; separate
readbacks do not automatically qualify persistence. The original public-key
baseline was not captured: a new baseline cannot prove original-image recovery.

To exercise only QSPI storage/signing, supply an immutable raw **receiver-role1**
candidate and its canonical unsigned 59-byte manifest to the existing uploader:

```sh
make ota-lab-cache \
  OTA_UPLOAD_IMAGE=/private/candidate/receiver.bin \
  OTA_UPLOAD_MANIFEST=/private/candidate/manifest-unsigned59.bin \
  OTA_LAB_ARTIFACT_DIR=/private/evidence/client-cache
make ota-lab-status OTA_UPLOAD_TARGET= \
  OTA_LAB_ARTIFACT_DIR=/private/evidence/client-cache-status
```

`ota_uploader.py cache --image ... --manifest ... [--reupload]` validates
size/hash before opening the approved client, uses its actual application
public key and existing signing service, durably uploads 84-byte fragments,
then requires fresh, manifest/counter-bound **local CACHE_SEALED** with every
expected block present. No private key is exported. It sends no ADD_TARGET,
START, remote STATUS, COMMIT, ABORT, administrative or radio-setting request.
The empty `OTA_UPLOAD_TARGET=` override keeps status local even if a previous
campaign exported a remote target. The result's `hash` is the canonical
manifest hash; that manifest binds the validated raw image SHA256.

An interrupted upload can resume the same receiving candidate without
`--reupload`; durable duplicate blocks are accepted without rewriting them.
If BEGIN reports **VERIFYING**, the host waits for a fresh matching local
CACHE_SEALED instead of attempting writes into the frozen verification stage.
Ctrl-C records an explicit failed/interrupted invocation and closes the port
without sending ABORT, SEAL or START; retained candidate progress is not cleared.

Repeat `ota-lab-cache` in a new evidence directory to test duplicate handling.
After the hardware operator explicitly performs an ordinary application
reboot, use fresh client configuration/preflight and local status readbacks,
then repeat the same image/manifest to observe cache persistence and duplicate
acceptance. Compare full hash/counter/block counts; command acknowledgement
alone is not proof. `OTA_UPLOAD_REUPLOAD=1` is explicit and does not authorize
replacement of another owner/content/purpose. A conflict fails without
automatic cleanup. Only when separately intended, clear this image explicitly:

```sh
make ota-lab-abort-cache OTA_UPLOAD_IMAGE=/private/candidate/receiver.bin \
  OTA_LAB_ARTIFACT_DIR=/private/evidence/client-cache-abort
make ota-lab-status OTA_UPLOAD_TARGET= \
  OTA_LAB_ARTIFACT_DIR=/private/evidence/client-cache-after-abort
```

Never use trial COMMIT or a recovery bootloader experiment as a cache-refusal
test.

Stock capability must remain **CACHE_ONLY**. Storing a receiver image on the
companion does not install it there. One working radio cannot qualify radio
OTA, remote READY/install, rollback, duty-cycle accounting or multi-peer
delivery; those outcomes remain blocked until the approved target is available.

**Actual working-client validation, Oct. 2, 2026:** application-only stock DFU
completed with the exact `Device programmed.` acknowledgement and application
USB re-enumeration. The immutable companion ZIP SHA256 is
`13bbf70d41d3966a7f43510543a5a21be43db52d019c18b79f8364b5546da629`;
its validated application is 547,828 bytes. Fresh before/after inspection
preserved the public key, name, 907525 kHz / 250000 Hz / SF7 / CR5 preferences
and path-hash mode 2. Early proof remained healthy with SDK size 547828,
CRC `0000/9815`, allowed writes and **CACHE_ONLY**. This is not independent
bootloader-byte readback or installation qualification.

At `19:58:57Z`, the client's existing identity signed and sealed the full
537,816-byte receiver candidate: counter 1, 6,403/6,403 durable blocks,
canonical manifest hash
`8eeecabdcd7bf8a42b955e32bde9c62476a32b3cc75a368fd5deb71c10e9e741`.
An ordinary application reboot retained the same sealed snapshot at
`20:00:40Z`, with unchanged captured settings and healthy stock proof.

The initial duplicate attempt exposed a host bug: accepted sealed BEGIN
was followed by PUT, which the device correctly refused without losing the
cache. The host-only correction in `10a31cca` retains signing and BEGIN,
then requires fresh matching local STATUS instead of writing a sealed image.
The corrected hardware retry passed at `20:07:24Z`; its transcript contains
no PUT or SEAL. Explicit image-bound local ABORT then returned **ABORTED**,
confirmed independently at `20:07:47Z`. The retained block counts describe
an aborted snapshot, not physical erasure or an installed image.

Final readbacks at `20:08:21Z` showed unchanged captured settings, healthy
allowed writes / CACHE_ONLY, zero reported radio faults or apply failures,
and zero reported OTA airtime/TX/timeouts/accounting failures. No START,
ADD_TARGET, COMMIT or administrative request was sent. No bootloader,
SoftDevice, MBR or UICR update was requested, and neither Pine nor the failed
target was opened. Full serial evidence is retained privately under
`review-candidates/working-client-app83-final-evidence/`; the radio,
installation, rollback and full-window duty outcomes above remain unverified.

**Refined application validation, Oct. 3, 2026 UTC (Oct. 2 local):** MAIN
application-only flashed the immutable `18ca2dcc` companion build from
`971830d0` onto the same approved client. ZIP SHA256:
`fc384ba78a9667c97f76068350045987d81d58c4901e12d5ceaaa54cfab55db4`.
The application is 548,276 bytes, SHA256
`82569bad34e793c7eb50b986e3d068ebf499ea8f4047f3d11f00117c88b961e5`.
Stock DFU again acknowledged `Device programmed.` and returned to APP USB.
Fresh public configuration before/after, after an ordinary application reboot,
and at the final check matched every captured field above. Stock proof remained
healthy with allowed writes, blank marker, SDK size 548276, CRC `0000/2769`
and **CACHE_ONLY**.

An explicit local reupload of the same image-bound aborted candidate sealed
all 6,403 blocks at `2026-10-03T00:42:45Z`. Fresh local STATUS after the
ordinary reboot retained that exact sealed image/counter/count at `00:44:26Z`.
Both sealed-cache retries sent signing/BEGIN/STATUS, with no PUT or SEAL.
Image-bound local ABORT was independently confirmed at `00:45:05Z`; this is
not an erasure claim. Final `00:45:11Z` diagnostics reported the normal tuple,
healthy radio and zero radio faults/apply failures, OTA airtime, all-TX time,
timeouts or accounting failures. All 18 recorded serial opens were the
approved client. No ADD_TARGET, START, COMMIT, administrator or radio-setting
request was made; Pine and the failed target remained untouched. This extends
actual application/local-cache evidence to the refined tree, **not** remote
OTA, installation, rollback, physical RF-register readback or duty acceptance.

That physical firmware and its recorded uploader used ABI1. The current
generation-bound cancellation protocol uses ABI2/90-byte replies. The new host
refuses ABI1; do not bypass its version guard or relabel earlier cache evidence
as ABI2 acceptance.

**ABI2 application/local-cache validation, Oct. 3, 2026 UTC:** an application-only stock DFU of
the qualified `6d73c110` / `73da40aa` companion package returned to APP USB.
The ZIP SHA256 is `f5129bc90c1134b79b5348d5250d31bdea24456788622950c489192cb636de41`;
the 548,772-byte application SHA256 is
`a0bc5bd9e59166678dffa9d3433d6495bcd21e949f67c2e3e206e2049cea58cd`.
Fresh `03:10:20Z` configuration matched the pre-flash capture. Stock proof
remained healthy, writes allowed, blank marker, SDK size 548772 and CRC
`0000/45B7`, still CACHE_ONLY. Actual 90-byte ABI2 local STATUS at `03:10:25Z`
reported the retained aborted candidate, generation 4, counter 1 and all
6,403 blocks with canonical hash `8eeecabd...`.

Explicit reupload of the same 537,816-byte signed candidate sealed all 6,403
blocks at `03:13:55Z`, generation 5. An ordinary application reboot retained
the exact sealed candidate/generation at `03:17:52Z`. Both sealed retries sent
signing/BEGIN/STATUS, with zero PUT or SEAL. Actual 70-byte local ABORT bound to
generation 5 produced durable ABORTED generation 6 at `03:19:22Z`, independently
confirmed at `03:19:24Z`. An explicit retry using generation 6 remained at 6:
it did not advance the generation again.

Final `03:20:27–32Z` readbacks matched every captured public setting and retained
healthy stock proof / CACHE_ONLY / CRC `0000/45B7`. Driver-reported radio faults,
apply failures, OTA airtime, all-TX time, timeouts and accounting failures were
zero. ROOT's recorded-evidence audit verified all three normal-identity manifest
signatures, byte-exact 6,403-block transfer, 6,419 valid local 90-byte ABI2 replies
and all 17 recorded serial opens against the approved client. The separate
application flash and ordinary reboot logs also identify only that client.
No ADD_TARGET, START, COMMIT, administrator or radio-setting request was sent;
no bootloader, SoftDevice, MBR or UICR update was requested. Private source-bound
evidence is retained in `review-candidates/working-client-abi2-final-evidence/`.
This qualifies the actual ABI2 application/local-cache cancellation outcome,
**not** remote radio delivery, installation, rollback, physical PHY readback
or full-window duty acceptance. Retained ABORTED block counts are not erasure
proof.

**Partial signed-cache reboot/resume, Oct. 4, 2026 UTC:** ROOT reused that
immutable 537,816-byte candidate and canonical hash `8eeecabd...` on approved41.
Explicit reupload of its matching ABORTED generation6 was stopped by the
intended 15-second host deadline. A fresh local STATUS at `07:18:07Z` reported
RECEIVING, 632/6,403 blocks, counter1 and generation7. After an ordinary
companion-protocol reboot of41 only, fresh `07:18:24Z` STATUS retained the
exact phase, partial count, hash, counter and generation. The unacknowledged
last PUT completed before the first STATUS; the timeout log's last
acknowledged count of631 is not the reboot baseline.

Resume used `reupload=0`, replayed the retained prefix and reached VERIFYING,
then CACHE_SEALED with 6,403/6,403 blocks and the same generation7 at
`07:20:36Z`. Final identity, name, path-hash mode and
907.525 MHz / BW250 / SF7 / CR5 matched the pre-write capture; SDK
548772 / CRC `0000/45B7` remained healthy and CACHE_ONLY. Private evidence is
retained under `uploader41-partial-persistence-20261004T071859Z/`.
This qualifies actual partial local-cache data/journal persistence and host
resume, not receiver recovery, installation, rollback, duplicate-write counts,
radio delivery or duty fairness. No primary, SoftDevice, MBR, UICR, shared-power
or Pine operation was performed;77 remained in USB recovery.

**Current companion APP on41, Oct. 4, 2026 UTC:** ROOT installed the
548,132-byte role0/XN40 application through ordinary APP-only serial DFU.
Its BIN SHA256 is
`dd3b3af2fdbbfeaf6cb0da3fb2e82cf619bf1c82f018cd248995295656240d2d`;
the package SHA256 is
`554e1902f0bbcc6b59b21caa23d939bae1910e8279a7e06da8376b9fd46e80cd`.
APP USB returned, and fresh `07:41:37Z` diagnostics reported healthy SDK
extent548132 / CRC `0000/C3EC`, blank marker and CACHE_ONLY. Fresh
`07:41:39Z` cache STATUS retained CACHE_SEALED, 6,403/6,403 blocks,
counter1, generation7 and canonical hash `8eeecabd...`.

Complete pre-/post-update companion protocol snapshots matched all four
contact records, including administrator flags, all40 advertised channel
records, identity, complete self-info/radio and exposed device settings.
The channel protocol exposes128 PSK bits, not any hidden upper bits; the
comparison does not claim a filesystem or private-key dump. Raw snapshots
remain in private0600 evidence. No settings, permissions or identity were
changed, and the stock primary was not updated.

Subsequent bounded BOOT discovery measured41's actual Sense USB profile
`2886:0045`; its generic APP product had not established that BSP. The
1200-baud entry exposed serial DFU only, with no MSC interface, so no UF2 INFO
or mounted-volume proof was inferred. ROOT restored the same verified current
APP through ordinary APP-only DFU. Fresh `07:50:26Z` diagnostics again showed
548132 / CRC `0000/C3EC`, healthy stock boot and CACHE_ONLY; `07:51:19Z`
STATUS retained the sealed 6,403-block generation7 cache. The complete
userdata comparison still matched after this return to APP.

Actual Sense role0 packaging, UF2 metadata and a separately verified
commissioning write set are still prerequisites to any41 paired-primary work;
a base-role0 build is not that qualification. Companion command `0x13` is
CMD_REBOOT, not a text CLI; the current `"reboot"` prefix handler performs an
ordinary restart and does not provide a `"reboot-uf2"` transition.

**Explicit UF2-entry APP on41, Oct. 4, 2026 UTC:** ROOT subsequently installed
the reviewed 550,308-byte role0 companion APP using ordinary APP-only DFU.
BIN SHA256 is
`9f7f013ad118f501118aea8e7c234e5d989625443e93b5aa3349043588449733`;
ZIP SHA256 is
`4b9813fd43489232eaa158f4cda21546bb42e37f17c85595b5e1972f32d8d0d9`.
Fresh `08:54:36Z` preflight reported healthy stock boot, blank marker,
SDK550308 / CRC `0000/A69D` and CACHE_ONLY. All four complete contact records,
all40 channels, identity, self-info and exposed settings matched the private
pre-update snapshot. Fresh `08:54:38Z` STATUS retained the same sealed
6,403-block counter1/generation7 cache.

The new maintenance request is exactly companion payload
`13 72 65 62 6f 6f 74 20 75 66 32` (`0x13` + `"reboot uf2"` without a NUL).
Only genuine USB reception in the supported USB-only nRF lab profile can
schedule it. Standard OK acknowledges deferred acceptance, not MSC entry.
The existing readiness checks, including refusal of CACHE_SEALED, remain;
ROOT must explicitly abort the local cache before requesting entry.
The reviewed source and independent exact-tree build alone do not establish
UF2/MSC entry, INFO metadata or paired installation capability.

**Actual stock UF2 metadata on41, Oct. 4, 2026 UTC:** ROOT explicitly aborted
the local cache at `09:02:49Z`, producing ABORTED generation8 while retaining
the manifest hash, counter1 and 6,403-block reported count. The one-shot UF2
request then produced fresh OK, an observed USB serial disconnect and new
exact41 Sense BOOT with CDC/data/MSC. ROOT mounted only41's ancestry-matched
whole `/dev/sde` at `/run/media/slepp/XIAO-SENSE1`, with vfat mount and
superblock both read-only. It was not77's volume.

Bounded INFO read at `09:03:32Z` reported
`Board-ID: Seeed_XIAO_nRF52840_Sense`, bootloader0.6.1, S1407.3.0 and build
date Nov. 12, 2021. INFO SHA256 is
`78d580460bbea1a33ac78ba3ff0858cf57eb01e858db490b44bec3127e4bd191`.
This establishes the actual Sense metadata/BSP selection for future role0
qualification; it does not cryptographically verify the installed primary.

ROOT returned41 to the same verified APP through ordinary APP-only serial
DFU. Fresh SDK diagnostics again showed healthy550308 / CRC `0000/A69D`,
blank marker and CACHE_ONLY. Complete protocol-visible userdata still matched;
`09:05:45Z` cache STATUS retained the intentionally ABORTED generation8,
counter1, hash and reported6,403 blocks. Reported retained counts are not data
erasure or resealing proof. No primary, installer, SD, UICR, filesystem,
shared-power or Pine write was requested.

Source qualification boundary: the reviewed UF2 delta passed the focused
native cases and actual nRF USB/ESP USB builds. Initial standard nRF BLE
GNU++11 builds failed on both the saved pre-UF2 baseline and the new source,
with OTA-only imports and an excluded ed25519 dependency. The compatibility
repair gates those imports and restores the original bundled library without
changing the BLE language standard, identity implementation or key formats.
ROOT's combined prospective tree passed the focused93 native cases,140 host
cases and actual BLE411160/USB550308 builds. The USB payload matches the
selected physical550308 image except four RadioLib diagnostic clock digits;
the selected `9f7f013a...` BIN/`4b9813fd...` ZIP is not replaced. These build
results do not claim physical BLE qualification.

**Actual read-only41 precommission baseline, `09:45:55Z` Oct. 4, 2026:**
ROOT captured only the full installer slot, primary and SDK page through the
exact41 whole-volume read-only mount. Mapping was derived from live stage-only
FIBMAP and matching CURRENT/raw UF2 anchors; every requested record's address,
header, family and padding was checked. No filesystem, QSPI, UICR, MBRparams
or APP payload was read.

| Range | Bytes | Observed SHA256 |
| --- | ---: | --- |
| Installer C4000..D4000 | 65536, all FF | `71189f7fb6aed638640078fba3a35fda6c39c8962e74dcc75935aac948da9063` |
| Primary F4000..FE000 | 40960 | `894f2e6df7663fcc5c398e210db7f2e7f21d3da53036e0a11576909c849f78fb` |
| SDK FF000..100000 | 4096 | `5c9132fa5a602338c77e0565cfabb48e2823c13237b53be3ef11ae8de25beda8` |

The actual45056-byte C9000..D4000 tail was also all FF, SHA256
`266a016d62778776d2a2b6750fb8a661b33c2104dc0816760667500cf2900216`.
SDK fields showed bank0 VALID_APP, size550308, stored CRC0000, bank1 FF,
zero SD/APP/BOOT update sizes, SDstart0 and an FF tail after28 bytes. These
are observed fields, not an image-validity or pending-finalization inference;
the primary hash does not establish its source lineage.

ROOT promptly returned41 to the SAME selected ordinary APP. Complete
protocol-visible userdata matched, SDK diagnostics were healthy550308/A69D
with blank marker/CACHE_ONLY, and `09:48:29Z` STATUS retained ABORTED
generation8, counter1, hash and reported6403 blocks. The measured raw64KiB
baseline and typed provenance receipt are retained privately with0700/0600
permissions. No primary or installer write occurred during this capture.

**Actual41 compound/ordinary restoration and full readback, `18:40:01Z`
Oct. 4, 2026:** ROOT used the reviewed host03 Sense ROLE0 pair/source release
`e3af600c2946be76e4ae614c6f81d37a0aa6f3ec9118a1897d8e66d087a0d5ef`.
Compound659548 and SAME ordinary550308 transfers completed, followed by
fresh healthy550308/A69D SDK diagnostics and complete matching userdata.
An initial userdata request timed out; a fresh read-only preflight and complete
snapshot passed without another firmware transfer. `18:38:12Z` STATUS retained
ABORTED generation8, counter1, manifest hash and reported6403 blocks.

After explicit UF2 entry, the mount guard initially refused before any mount
action because the MSC block was not yet ready. Exact current41 ancestry then
exposed one whole block; ROOT mounted that block once, read-only, without a
reset or unmount/remount. Bounded O_DIRECT reads validated every touched UF2
record and compared every659548 compound byte plus all65536 installer bytes.
The complete compound matched SHA256
`5b40e31e1f7165f9b7a1a75770cd07847ac701a2652da42d884d39dbbba12f91`.
Full-slot SHA256 was
`91c62360655a7e05410be2438753602cb9a949c69ff89759f389bfca8bc5432d`:
stage16476 matched `aa078fbc...`, padding throughC9000 was FF, and the measured
C9000..D4000 baseline tail was unchanged. Thus the installed Seeed fork
actually preserved this installer through the ordinary APP restoration;
this is no longer only an upstream erase-range model.

The exclusive0600 receipt binds the actual USB/block/mount, package/BIN/stage/
baseline digests and all2768 validated record mappings. No raw APP dump,
filesystem/QSPI/UICR/MBRparams read or primary transfer occurred in this
qualification. Primary activation, full installed-primary hash, factoryfloor0
and INSTALL_CAPABLE remain separate physical gates.

**Actual41 primary bytes verified, APP health still incomplete:** ROOT made
one matched BOOT-only transfer after a fresh complete compound/slot comparison.
The operator confirmed one pin reset. Read-only capture at `18:52:59Z`
Oct. 4, 2026 verified every40960 primary byte against
`fff496269455f4e323779cffcaf3523b5557892fcecb29dd68f6906cf8d92eef`
and the complete installer slot against `91c62360655a7e...`. Parsed CF2,
ROLE0 XOBI, stage ABI and the primary's stage tuple also matched. INFO matched
the compiled0.9.2-OTAFIX2.3-BP1.4 Sense/May21 2026/S1407.3.0 text.
SDK then showed bank0/bank1 FF, zero sizes/start and an FF settings tail:
no pending tuple was observed, but no valid APP or durable floor was inferred.

The mandatory SAME550308/A69D APP transport subsequently completed and its
normal USB identity appeared. It did **not** establish a working APP:
independent APP_START and local STATUS requests timed out. A separate
operator-confirmed single cold-start reset did not restore STATUS responses;
the reviewed1200-bps/DTR diagnostic also failed to enter BOOT. No primary
retry, shared-power operation or journal erase was performed.

Selected-ELF startup analysis identifies a4136-byte live proof/hash call chain
against the4096-byte loop task allocation, before command registration.
That path is activated by the paired marker and was bypassed on stock BOOT.
This is a compiled stack-budget defect; the actual fault PC is unmeasured.
The APP-only fix must preserve full-window proof semantics and demonstrate
bounded compiled stack use plus actual responsive hardware, not just
enumeration. The verified primary remains intact. Final APP health,
post-restoration SDK/factoryfloor0 and full userdata/cache preservation are
still unqualified; this commissioning outcome is not complete.

**Physical recovery and post-restoration SDK on41:** the verified Sense
primary's existing double-reset entry uses retained RAM marker `005A1AD5`
at `20007F7C`, recognized before stage2/APP startup. Two quick pin resets in
its500ms detection window select persistent USB CDC+MSC. The operator performed
that separate recovery gesture after the stalled APP could not service1200-bps
entry; ROOT observed exact41 BOOT+MSC, then made a new guarded read-only capture
at `19:50:59Z` Oct. 4, 2026. No SWD, power operation or primary rewrite was used.

The entire primary and installer slot still matched `fff496...` and
`91c623...`. The actual post-APP SDK showed bank0 VALID_APP, size550308,
stored CRC A69D, bank1 FF, zero pending sizes/start and an FF tail; page SHA256
was `fd7345dd22e9450ca17ab35c167c0422b00153c6ca9762c9bd04415a6c50cd31`.
Thus ordinary APP publication and independent physical recovery are measured,
not inferred from enumeration. APP command-loop health and the durable
floor/transaction/cache state remain separate, unmeasured outcomes.

The existing factory-genesis record is unbound sequence1/counter0/extent0/hash0,
not a record binding the original9f7 image. With that exact seed and blank
transaction windows, fresh healthy SDK evidence can admit an ordinary APP-only
replacement without refreshing the floor, erasing journals or rewriting BOOT.
Cache ABORTED generation8 alone does not prove those journal conditions.
Any non-genesis floor or nonterminal transaction evidence must stop the
ordinary replacement rather than being silently reset.

**Actual41 responsive paired APP checkpoint, Oct. 4, 2026 UTC:** one ordinary
APP-only DFU installed the reviewed550580-byte stack repair (CRC5406, BIN
`f955de00ded89c71c71372aea9b9a1b785d47ff5e566c94d9821468ed64478f3`).
Its early-proof chain is3048 bytes, instead of4136, with unchanged4096-byte
task allocation and proof semantics. The exact frozen source passed ROOT's
focused native gate before this single APP transfer; BOOT was not rewritten.

At `20:31:22Z`, actual APP_START returned SelfInfo and framed diagnostics
reported `writes=allowed marker=qualified proof=qualified-state` and
`INSTALL_CAPABLE`, with floor present, sequence1/counter0/extent0/hash0 and
`io=ok`. At `20:31:54Z`, the real90-byte local STATUS returned OK and retained
ABORTED cache generation8, counter1, hash `8eeecabd...` and6403/6403 chunks.
The full private before/after protocol snapshots matched identity, settings,
SelfInfo, all4 contacts including their ACL flags, and all40 channel slots.

This establishes responsive paired BOOT+APP operation and actual unbound
genesis admission, superseding the unmeasured APP/floor/preservation outcomes
above. It supports the stack-overflow explanation; the live fault PC was not
captured. This initial repair does not fix every recovery caller's stack
budget. Signed installation remains gated on the final recovery-chain repair;
no signed install, confirmation, automatic rollback or on-air success is
claimed by this checkpoint.

Fresh APP_START and diagnostics at `20:58:59Z` still reported the same qualified
state and INSTALL_CAPABLE floor0, without another flash or reset.
INSTALL_CAPABLE is not receiver READY: the existing USB begin/put/seal commands
stage an explicitly noninstallable uploader cache, local COMMIT refuses that
purpose, and RF START rejects the self identity. No USB self-install path was
added or assumed. Real signed installation, confirmation and failed-trial
rollback therefore require a second working authorized RF peer, in addition
to the recovery-chain repair. The existing ROLE1 receiver and nonconfirming
candidate profiles provide that test path once77 is repaired through SWD.
No compatible SWD probe was observed in the current USB inventory.

**Final recovery-stack repair physically running on41:** ROOT made one
APP-only transfer of the reviewed552756-byte/CRC4181 image, BIN
`dbcac4fcec4f90b9423c1c477c5f49cda327685e4f9a69067cbc263e8c265dd7`.
At `21:24:45Z`, actual APP_START and diagnostics again reported qualified
writes and INSTALL_CAPABLE with the same unbound sequence1/counter0 floor.
Real local STATUS at `21:24:47Z` retained ABORTED generation8/counter1,
hash `8eeecabd...` and6403/6403 chunks. Complete before/after private snapshots
matched identity, settings, SelfInfo, all4 contacts/ACL flags and40 channels.
BOOT, installer, geometry, preferences and the4096-byte task allocation did
not change.

The final repair releases outer packet/control frames before proof calls and
uses independent, guarded workspaces rather than nested stack buffers. Every
read and hash remains fresh; no proof result is cached between epochs.
These entry points run synchronously in the main loop task; the workspace
guards are not a general multithread synchronization primitive. The actual
ARM ELF's conservative maximum is3032 bytes including104 bytes for exception
overhead, with6760 additional BSS bytes. This supersedes the initial repair's
remaining recovery-stack gate, but still does not prove RF delivery, signed
installation, confirmation or rollback. Receiver builds must use this repair,
not the preserved pre-fix cached image.

**Repaired receiver images and actual uploader cache restart, Oct. 4, 2026:**
three distinct ROLE1 APP-only packages were built from the same final repaired
source tree `8c79d1f3ab83b0efe610386e084411333a4bed87`:

| Label | BIN bytes | BIN SHA256 | CRC16 |
| --- | ---: | --- | --- |
| `ota-base02` | 537800 | `c594a61d8a73b337285bbe9ce7a7d010fc0bec93e05cae616b814792cb153528` | `521B` |
| `ota-confirm02` | 537816 | `0d2199821968260e3aea076bf582b0f79ed28697f8adaac919e7a2708512cf98` | `3497` |
| `ota-rollback02` | 537752 | `7508cf2a3ad11deae01262883d6065a0feb50bb0009fae3844975b200e195261` | `A13A` |

Their packages contain no SoftDevice or BOOT segment and stay below the
C4000 installer boundary. Subsequent Opus5.5 review checked all three actual
ROLE1 ELFs rather than assuming the ROLE0 bound applies. No static OTA stack
overrun was found: the conservative largest root bound is3948 bytes including
104 bytes of exception allowance, against the4096-byte task allocation.
Some indirect flash and radio callbacks are bounded by implementation family.
These are static executable bounds, not physical stack high-water measurements.

ROOT intentionally replaced41's obsolete ABORTED generation8 cache with the
new `ota-confirm02` image using the existing signed, explicit-reupload cache
operation. At `21:51:56Z`, actual local STATUS reported CACHE_SEALED, OK,
generation9, counter1,6403/6403 chunks and manifest hash
`48c9eebe3e723495527291e5b667f4feb3ead91f4c01c7fe91dbf9439f003a1c`.
An ordinary application reboot through `make lab-reset-client` observed
disconnect and return of the exact41 APP. Fresh APP_START/diagnostics at
`21:52:51Z` again reported qualified writes and INSTALL_CAPABLE with unchanged
sequence1/counter0/extent0/hash0. At `21:52:53Z`, fresh local STATUS returned
the same complete CACHE_SEALED generation9 tuple. Complete private protocol
snapshots matched identity, settings, SelfInfo, all4 contacts including ACL
flags, and all40 channel slots.

The canonical counter1 is preparation metadata, not a measurement of77's
confirmed floor. No RF START or COMMIT was sent. This is a durable uploader
cache, explicitly noninstallable locally; it is not receiver READY, signed
installation, confirmation or rollback. Existing private generation8 records
remain as historical evidence.77 still requires recovery of the defective
installed modified loader before its ROLE1 receiver flow can proceed.

**Alternative receiver41 with an unchanged stock USB companion:** the actual
`companion-v1.17.1` source supports USB signing commands33-35, raw-packet TX
command65 and raw RX notifications88 hex, emitted before payload dispatch.
These permit a PC-managed OTA sender without flashing the stock companion.
The existing firmware-cache uploader uses command66 and is not that adapter.
The stock176-byte USB limit requires the existing compact kind01 signed
84-byte block format, not the183-byte full-owner block format. A zero-hop
171-byte direct ACK exactly fits its176-byte raw RX notification.

The user supplied an additional stock companion, now identified read-only as
`lab-stock`, Heltec V3, public key
`0f7cc3e7f6fe812ca754a8dcc563757ab15a87e2ce762143898077539d9a6783`.
At `22:43:24Z`, its version was `v1.17.1-d929643`; the suffix matches the
actual `companion-v1.17.1` release commit. Its original settings read back as
907.525MHz,250kHz bandwidth,SF7, coding rate4/5 (wire value5),2dBm, repeater
disabled and path-hash mode2. No firmware, radio settings, signatures or RF
transfers were changed/requested during identification.

Its CP2102 USB serial is `0001`, but another attached, unauthorized CP2102
has the same serial. The shared by-id link currently resolves to ttyUSB1:
`/dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0`.
It is not a unique device binding. ROOT instead pins the authorized USB path
`/dev/serial/by-path/pci-0000:0d:00.0-usb-0:4.2.4:1.0-port0`, its serial/USB
ancestry, and the verified full public key. The other CP2102 on path4.1 is not
authorized and must not be opened. APP_START first after ordinary UART settling,
then DEVICE_QUERY, obtained the public identity/version; BLE PIN and GPS fields
were neither displayed nor recorded in the public baseline.

**Actual normal radio link,22:54Z:** a single19-byte ordinary raw datagram from
the unchanged stock companion reached41 with the exact generated payload,
RSSI-40dBm and SNR12dB.41's actual saved normal profile also read907.525MHz,
250kHz,SF7,CR5, not the62.5kHz source default. The complete original stock
SelfInfo and DeviceInfo frames matched again after the normal radio operation.
Its firmware and2dBm setting were unchanged. This establishes the physical
stock-to41 radio link, not OTA authorization, image delivery or installation.

The host adapter and distinct, matching ROLE0 companion candidates for41
are being prepared. ROLE1 images above cannot be
installed on41's ROLE0 loader. Only an explicit lab-only nonconfirming ROLE0
candidate may be used for the later genuine trial-deadline rollback outcome.
No stock-companion firmware/BOOT transfer, USB self-stage workaround or
additional primary commissioning is part of this route.

At `22:14:23Z`, fresh read-only41 APP_START/diagnostics still reported qualified
writes and INSTALL_CAPABLE with sequence1/counter0/extent0/hash0 and `io=ok`.
At `22:14:25Z`, actual STATUS retained the complete sealed generation9 tuple.
The new complete private protocol snapshot matched the preceding preserved
identity, settings, SelfInfo,4 contacts/ACLs and40 channels. This is preparation,
not on-air transfer evidence. The new sender must be explicitly identified and
authorized, its original radio settings retained/restored, and the signed
uploader cache deliberately retired before receiver admission if required.

The receiver41 preparation exposed a concrete lifecycle gate: local ABORT
alone cannot currently retire an uploader cache into a new RF receiver session.
Both `prepareReupload` and the RF REUPLOAD handler exclude local-cache purpose,
including ABORTED caches. The required fix is limited to an explicitly aborted
cache, a fresh fully signed/admin-authorized and policy-qualified receiver
descriptor, then the existing target/generation-bound signed RF REUPLOAD.
The new receiver session must have a new generation and empty received bitmap;
old cached bytes must never be promoted to READY or installation. Sealed caches,
bare authorization, unauthorized signers and stale generations remain blocked.
The reviewed fix retains these guards and makes prepared receiver census
replies visible without changing stored cache purpose. Queries for the cached
hash remain silent; a different prepared descriptor hash is required for the
automatic RF flow. ROOT independently passed all252 integration cases on the
exact combined source tree `7c68821f530d339fcfb9b09ec9c136193aa9144c`, including
the nine added retirement cases. Opus5.5 actual patch/profile review found no
blockers. The guarded ROLE0 profiles reuse the existing health callback and
45000ms deadline, changing only lab-negative loop readiness.

These are source results. The three integrated baseline/confirm/nonconfirm
ELFs and actual receiver41/RF qualification remain separate gates. No new USB
STAGE/reset API or boot-journal erase is introduced.

The three integrated ROLE0 APP-only artifacts are now frozen from the same
qualified tree, with no SoftDevice/BOOT payload:

| Label | BIN bytes | CRC16 | BIN SHA256 |
| --- | ---: | --- | --- |
| `ota-41-base01` | 552740 | `A974` | `484da15d649dd1f60eb61bf88567fcb8c76217ff89ab5dae64e223add4903323` |
| `ota-41-confirm01` | 552756 | `A967` | `f51bb6c59d1e4d6053058ca1a267f00255b9730b098252cfcc27526aacb05fce` |
| `ota-41-rollback01` | 552676 | `9F11` | `6d681fb3f500248418cec3259317fd3db2642f3ac9d527671c6c9c9c90c5849f` |

An expanded actual ELF root analysis covers18 OTA-facing ancestor/callee
chains, including informational signed direct requests omitted from the
earlier13-path figure. All three bound at3264 bytes including104 bytes of
exception allowance, with832 bytes of headroom in the unchanged4096-byte
task. This refines the earlier3032 selected-path bound; it is not a new stack
allocation or proof weakening. Final independent actual-ELF review found no
blockers.

**Actual receiver41 baseline,23:06Z:** ROOT installed only the reviewed
`ota-41-base01` application through ordinary USB DFU. Runtime DeviceInfo
confirmed that exact label. The bootloader/SoftDevice/installer were not
updated. Actual early proof remained qualified and INSTALL_CAPABLE, with
unchanged floor sequence1/counter0/extent0/hash0 and successful floor I/O.
The sealed generation9 cache survived, and complete private snapshots matched
identity, settings, SelfInfo, all4 contacts including ACLs, and all40 channels.
This is receiver preparation, not an OTA installation.

At `23:09:54Z`, ROOT deliberately aborted that old local cache through the
existing image-bound local API. STATUS reported ABORTED, generation10,
counter1, the same manifest hash and6403/6403 old cached chunks. Subsequent
preflight still showed the unchanged qualified floor0. Those cached bytes
were not promoted into a receiver image; the fresh signed RF descriptor,
generation-bound REUPLOAD and complete retransmission remain required.
Actual signed RF confirmation/automatic rollback are still unqualified.

**Actual restart and stock transport,23:15-23:18Z:** an ordinary41 application
reboot retained ABORTED generation10 and the unchanged qualified floor0.
Normal stock-to41 RF still worked afterward; complete identity/settings/all4
contact ACLs/all40 channels remained unchanged.

The unchanged stock companion then signed the exact59-byte ROLE0 confirming
descriptor through commands33/34/35. Independent Ed25519 verification passed
against its actual authorized public key. Ordinary RAW_CUSTOM nonce traffic
also physically exercised command65 at175 USB bytes, with171 payload bytes,
and the return packet arrived through stock notification0x88 at the full176
USB-byte ceiling without truncation. Stock SelfInfo/DeviceInfo were unchanged
afterward, and41's full private userdata still matched. These are actual
signing and transport-boundary results, not delivery of an OTA image.

**Actual fast PHY,23:39Z:** both41 and the unchanged stock companion accepted
908.525MHz/250kHz/SF5/CR5 through their normal radio APIs. Full-size ordinary
command65 traffic and the176-byte raw return notification worked in both
directions, with forward RSSI-44dBm/SNR7.25dB. Both original normal profiles
and complete SelfInfo/DeviceInfo were restored;41's full identity/settings,
all4 contact ACLs and all40 channels matched afterward. Stock remains2dBm;
41's actual original TX setting is22dBm and was preserved, not changed to
the sender's setting. This proves the high-speed PHY, not a signed temporary
lease, OTA image delivery or installation.

**Actual durable stock authority,23:49-23:50Z:** ROOT added only the exact
authorized lab-stock contact and used the existing dedicated SET_ADMIN API,
which returned durable OK. Complete five-contact readback showed all four
original contacts/ACL bytes unchanged; only the new stock contact gained
the0x10 admin flag and current-time lastmod. All40 channels, identity,
SelfInfo and settings matched. An ordinary application reboot retained the
complete five-contact snapshot and qualified INSTALL_CAPABLE floor0.
The aborted generation10 cache was unchanged.

The first private preparation attempt exposed a contact-protocol trap:
including an explicit optional lastmod0 in the148-byte add request hides
that contact from GET_CONTACTS, whose START still reports the total count.
ROOT measured the exact new contact through GET_CONTACT_BY_KEY, verified all
original contact/channel bytes and a nonzero RTC, then used SET_ADMIN rather
than retrying ADD. SET_ADMIN assigned a positive lastmod and restored complete
contact iteration. New add requests should omit that optional timestamp.
Actual OTA image delivery/confirmation/automatic rollback remain unqualified;
the following actual upload attempts supersede the earlier host-handoff gate.

**Stock host integration and real RF attempts,Oct.5,00:05-00:41Z:** ROOT
integrated `scripts/ota_stock_companion.py`, its focused suite and the two
Make entry points. The first attempt stopped before activation because the
host accepted direct replies but rejected the normal-channel flood census.
Stock restoration was measured;41 retained its old ABORTED generation10
cache, qualified floor0 and complete five-contact/40-channel userdata.
The corrected decoder accepts version0/type0x0C direct or flood packets,
validates and skips their path hashes, and retains identity/manifest/
counter/generation checks. ROOT's focused75 cases and existing75 uploader
cases passed before the second real attempt.

That second attempt also ended without an admitted census or receiver
activation. The stock companion's exact original907525/250000/SF7/CR5/
repeater-off profile,2dBm and `v1.17.1-d929643` were independently read back.
41 remained ABORTED generation10 with the old local-cache manifest; no
RF data blocks or COMMIT had been accepted.

ROOT then sent **one different, read-only census window**, first128,
without another authorization, retirement or lease request.41 emitted its
actual USB OTA event: accepted kind0x0A, direct route, one-byte path hash,
rxFrames3 and badFrames0. The unchanged stock received and correctly
decoded a107-byte flood notification containing the fresh confirming
manifest, counter1, floor0, generation10, lifecycle ABORTED, zero received
and6581 total blocks. This proves that the signed authorization had
prepared the new receiver descriptor and that the corrected flood decoder
works. It is not receiver activation or image delivery.

The concrete failure in those attempts was mesh-level duplicate suppression:
`Packet::calculatePacketHash` hashes payload type plus payload, and
`SimpleMeshTables` retains160 hashes without expiry. `Mesh::onRecvPacket`
discards identical OTA packets before the receiver sees them. The first
attempt's identical first0 poll therefore prevented later retries from
regenerating its discarded reply. A final READY sweep followed by a
separate COMMIT sweep would encounter the same issue. The correction must
allow idempotent local OTA retries while preserving duplicate suppression
for forwarding and ordinary traffic. Resetting the device or filling/
clearing the packet cache is not the fix. The then-installed baseline still
contained this defect; corrected application artifacts and real full-image
delivery/confirmation/automatic rollback remain separate gates.

After both failed attempts and the distinct-window probe, ROOT again matched
41's complete private identity/settings/five-contact ACL/40-channel snapshot
against the pre-RF baseline. At `00:59:28Z`, actual preflight still reported
qualified INSTALL_CAPABLE, sequence1/counter0/extent0/hash0 and `io=ok`.
The diagnostic-only host revision10 is now integrated byte-exact and passed
81 focused plus75 existing uploader cases. It adds flushed public-only
phase, progress and RF metadata events, without changing wire requests,
retry counts, budgets or authority/restore guards. The subsequent physical
transfer below uses this revision.

The guarded receiver correction is now published as `d4f95013`, canonical
tree `b27ec216f967e24899acc85945a205843c3bebde`. It locally redelivers
already-seen OTA packets only when their path hash count is zero, then
releases them without forwarding or remarking the hash. Count-one-or-more
relayed copies and own-flood echoes remain filtered; ordinary delivery and
routed next-hop forwarding are unchanged. Nine real-Mesh/SimpleMeshTables
cases cover lost census replies, repeated READY/COMMIT polling, failed-write
block retry, duplicate block/COMMIT no-write behaviour, uploader observation
refresh, echo suppression and unchanged FIFO/ordinary/routed filtering.
ROOT independently passed all261 integration cases on the exact immutable
combined tree; bounded Opus5.5 delta review found no blockers.

Three same-source ROLE0 applications (`ota-41-base02`, `ota-41-confirm02`,
`ota-41-rollback02`) were frozen from that qualified tree. All three fresh
ELF root bounds remain3264 bytes including104 IRQ allowance, with832 bytes
headroom in4096; the Mesh caller remains40 bytes. These are static bounds,
not physical stack high-water measurements.
This is a one-hop correction, not reliable multihop retransmission: relays
still retain identical forwarded packets in their160-entry duplicate FIFO.
A protocol-level attempt discriminator and physical routed/fleet repair
remain required. Neither cache flushing nor a host nonce workaround is used.

**Corrected baseline and first signed RF data,Oct.5:** ROOT installed
`ota-41-base02` once through ordinary APP-only USB DFU. Its552804-byte BIN
SHA256 is `a76288ea84dc2ce0c4dc8f64106db0b7afc650a662b4dd83e8f9eaceadbfe19d`.
Actual preflight at `01:33:35Z` remained qualified INSTALL_CAPABLE,
sequence1/counter0/extent0/hash0 and `io=ok`. The complete private
identity/settings/SelfInfo/five-contact ACL/40-channel snapshots matched.
BOOT, SoftDevice and installer were not changed.

Host revision10's third real campaign obtained the pending census and
physically retired the old local cache through signed RF REUPLOAD.
The receiver entered Receiving generation11, counter1, with the new
`ota-41-confirm02` manifest
`894553fbb4886341d8b6a2847b977757980f7d313f1b0e1e5e470c0b202df1ec`,
zero received and6582 total blocks. The stock companion verified the target's
full signed direct ACK and switched to the negotiated SF5 profile, but leased
census timed out before any block was sent. Both radios returned to normal;
stock firmware and its original profile/TX2 were independently read back.
There was no READY receipt or COMMIT.

A bounded probe resumed that same generation without another retirement,
ABORT or reset while ROOT continuously drained receiver USB diagnostics.
Normal and leased census then returned promptly. Receiver driver-applied
measurements showed908525 kHz/BW250000 Hz/SF5/CR5 with a healthy driver.
ROOT sent one genuine compact signed kind01 block over the stock radio;
the receiver accepted it and a fresh matching RF census reported bit0 set
and1 of6582 received. The lease expired normally and the receiver's measured
profile returned to907525/BW250000/SF7/CR5. This proves signed RF data
reception, not full-image validation or installation.

**Unattended USB blocker:** these observations strongly isolate diagnostic
backpressure: `ArduinoSerialInterface` reports connected and not busy, while
`MyMesh::onOtaDataRecv` writes an unsolicited14-byte0x91 event through its
blocking frame writer. Unread USB can therefore stall the radio loop.
A continuously drained USB observer is bench instrumentation, not the
production fix or unattended acceptance. The core diagnostic path must become
nonblocking without dropping ordinary command responses or truncating frames.
The fourth campaign delivered all6582 blocks of that exact candidate in
115minutes with that explicit observer; it does not qualify reader-free
operation. A complete52-window normal-channel RF census reported READY,
generation11/counter1/manifest`894553fb...`; the private receipt explicitly
says installation is not confirmed, and the unchanged stock companion
restored its normal profile. The full pre-install snapshot still matched
allfive contact ACLs, all40 channels, identity and settings. ROOT then set
only41 TX power from22 to the user-authorized2dBm; independently validated
full snapshots proved only the SelfInfo TX byte2 changed. The initial
one-shot helper checked the adjacent maximum-power byte3 and failed its
post-write guard; no setter retry was used. The TX2 snapshot is the new
preservation reference.

**First complete physical LoRa installation:** the separate command
completed its fresh52-window normal-channel READY sweep and sent the
signed COMMIT. 41 autonomously disconnected/re-enumerated USB; ROOT did
not reset or reflash it. Actual DeviceQuery reports `ota-41-confirm02`.
Independent readback reports healthy qualified state1/phase6, allowed
writes and INSTALL_CAPABLE floorsequence2/counter1/extent552820/SHA256
`947f06073473bdfed7d44d8a33582c116f3020214e66ed56767bd03b95040713`,
with IO OK. The full pre-peer snapshot matched identity, settings,
allfive contact ACLs and all40 channels against the TX2 reference.
Ordinary direct zero-hop RF advertisements in both directions matched
the exact peer keys and verified Ed25519 signatures; pre/post normal
radio and TX2 guards passed. Stock reported a native contact notification.
41 did not report that notification, but its subsequent contact readback
stored the exact host-verified stock advertisement timestamp. Only that
contact's advertisement timestamp and lastmod changed; allremaining
contact bytes, including ACLs, and allsettings/channels were preserved.
Autonomous failed-trial rollback and reader-free operation remain open.

The source correction now uses explicit best-effort output for both the OTA
event and raw RX logging, which ran before packet dispatch and could also
block reception. nRF TinyUSB reserves space for the whole framed diagnostic
and checks DTR without waiting; other Arduino streams retain a complete frame
in a179-byte member buffer and drain only available capacity per loop tick.
Partial tails cannot overwrite or interleave with ordinary responses.
The existing nonblocking BLE, WiFi and Ethernet queues explicitly opt in, so
their raw RX logs remain available, including in non-OTA builds. Unsupported
optional transports skip diagnostics rather than invoke a blocking fallback.
Ordinary command-response methods retain their existing behaviour.

ROOT independently passed276 integration cases on exact prospective tree
`0dd5a999634177cc610a119eda2f6ecf92705ead`; bounded Opus5.5 follow-up found
no blockers. The ten reviewed files are integrated byte-exact. Matching
`ota-41-base03`/`ota-41-confirm03`/`ota-41-rollback03` firmware is frozen
from that exact source: real nRF RAM174244 (+184), all18 entry-root bounds
3264/4096 including IRQ104, and actual nRF USB/BLE and ESP BLE/WiFi builds
passed. An actual ESP native-USB build exposed a partial-tail/session issue;
the follow-up source passed294 integration cases but review found a C3
atomic compile assertion and a mode0 DTR-only diagnostic regression.
The subsequent SDK04 correction removed both blockers and passed bounded
Opus review. It is integrated together with signed250/500kHz profile
negotiation and opt-in bounded host bursts/less polling. ROOT independently
passed306 integration and78 uploader cases on exact combined tree
`d3031860b5ec508863a68e150b2eb3ab1feaacbf`. Matching base04/confirm04/
rollback04 ROLE0 images and allseven actual compatibility builds are now
frozen. Confirm04 is554372 bytes, SHA256
`417a6228926fdd531d8a388c516c7bbc8255352b97132aaa3ea26ddd6d09be56`.
RAM is174260 (+16 versus03). The18 measured roots bound3256 including
IRQ104; an additional real TX-signing root bounds3340/4096, leaving756
bytes. The older3264 figure was not a universal task bound. Published
commit`3dbd03e4` differs from the exact d303 build source only by the
Arduino header's final newline; the immutable build provenance is retained.

ROOT remeasured confirmed floor1 and completed the LoRa-only counter2
confirm04 campaign, canonical59 SHA256
`eb2cee5e26ab8db26c86b9f20b9644f75fceeedd02bdfe787a775599c274d41a`.
Real RF reported all6600 blocks READY at generation12. The exact private
receipt was followed by a separate fresh52-window READY sweep and signed
COMMIT. Actual readback independently reports `ota-41-confirm04`, healthy
qualified state1/phase6, allowed writes and confirmed floorsequence3/
counter2/extent554372/hash417a... with IO OK. No host reset or APP reflash
was used. The full pre-peer snapshot preserved identity, settings, allfive
contacts including ACLs and all40 channels. One capture during USB
re-enumeration failed before opening the receiver; the later read-only
capture passed without setters. Ordinary zero-hop RF advertisements in both
directions again matched the exact peer keys and Ed25519 signatures, with
normal-profile/TX2 guards before and after. Stock reported a native contact
event;41 did not, so native acceptance is not claimed for both directions.
The transfer used legacy250 because the previous confirm02 could not
negotiate500. Its old-firmware USB observer exited on the autonomous serial
disconnect and is released. Both radios remain2dBm. The full post-peer
snapshot was also classified: only the existing stock contact's bytes132,
144 and145 changed, within its advertisement timestamp and lastmod. The
stored advertisement timestamp1715770360 matches the verified RF summary;
allACLs, other contact bytes, order, settings, identity and channels remain
unchanged. This does not add native acceptance or emission-freshness proof.

**First actual500kHz reader-free progress:** ROOT assigned counter3 against
the independently measured floor2 for exact frozen rollback04 ROLE0 BIN
`6d81f857a882f7be844a3bbae4d6b7de8608d78a4c0d580c5cf463b7691316a7`
(554308 bytes,6599 blocks), canonical59 SHA256
`694fb604b083d527245b6aded840ab64bdc7e4136521e39012f8a8a2999f4966`.
The unchanged stock companion received the target-signed500kHz/SF5/CR5
profile ACK at908525kHz. Actual RF census reported partial Receiving at
generation13,195/6599 blocks at144.372 seconds, without any receiver USB
reader. This is receiver-reported progress, not a claim based on sender TX
counts. ROOT gracefully paused the sender for the Receiving restart
boundary; the stock restoration receipt passed and both ports released.
Subsequent read-only diagnostics showed actual driver-applied normal
907525kHz/BW250000/SF7/CR5, no active lease, healthy driver and no profile
apply failures. Complete500kHz READY/installation, measured full-image
throughput and autonomous failed-trial rollback remain separate physical
acceptance gates. No REUPLOAD or
journal clearing was used.

**Actual partial Receiving restart/resume:** after pausing the same campaign,
ROOT captured all52 RF bitmap windows with a fixed883/6599 received blocks,
generation13/counter3 and the exact manifest above. Fresh target-signed profile
ACKs established functional native owner admission, bracketed by local session
readbacks; generation itself is not signed by that ACK. Exactly one explicitly
armed ordinary application reboot was written, guarded by a fixed exclusive
attempt marker. The subsequent native uptime drop and complete identical bitmap
proved an observed application restart with session persistence. Confirmed
floorsequence3/counter2/extent554372/hash417a..., `ota-41-confirm04`, healthy
sampled driver-applied normal PHY and owner admission were preserved.
Complete before/after userdata matched identity, settings, SelfInfo, allfive
contacts including ACLs and all40 channels, aggregate SHA256
`3590661d1dc0a60400f838a7bd53b9e27683fd940bfb9d57fde110dbed0019d6`.
The same MissingOnly500kHz transfer resumed without REUPLOAD or a receiver USB
reader; RF census reported1094/6599 at142.966 seconds into that resumed run.

This qualifies restart/session durability, not continuous radio reliability.
The before capture's lifetime driver-fault count increased86 to139; after the
observed reboot it increased0 to53. Each complete capture therefore observed53
recovered faults despite every sampled current health/profile/apply guard and
final normal restoration passing. Ordered counts and deltas remain in the
private receipts; positive growth is explicit degradation and
`continuous_fault_free_radio_verified=false`. No fault cause is inferred.
Counter decreases within either capture are refused; only the observed reboot
permits a reset between captures. Unsigned RF census freshness is not
authenticated. At this restart boundary, full reader-free delivery,
autonomous failed-trial rollback and independent qualification of radio fault
origin/recovery impact were still open.

**Complete500kHz reader-free READY and separate COMMIT:** the same immutable
counter3/generation13 rollback04 campaign completed without a receiver USB
reader, replacement counter, REUPLOAD or journal clearing. It started this
resumed segment at883 persisted blocks. RF first reported Ready5 at4268.692
seconds; the final complete52-window normal-channel sweep reported all6599
blocks, including the71-bit tail, and completed READY at4900.233 seconds
(81.7 minutes). The approved500kHz/908525kHz profile was activated52 times.
Sender logs contain6957 block transmission events covering5716 distinct
indices:5716 first attempts and1241 second attempts. These are sender-side
repair counts, not per-block durable-write or RF-delivery proof; complete
receiver-reported READY supplies the progress evidence. Timing includes
signing, repairs, lease returns and normal census, but excludes earlier
transfer segments and restart qualification. It does not prove complete-from-
empty throughput or a speedup over250kHz.

The sender exited successfully, stock restoration passed, and both authorized
UARTs were released. A separate signed COMMIT then followed a fresh complete
52-window normal READY sweep, again with stock restoration. The native witness
started0.307 seconds after the production COMMIT invocation returned, but its
initial USB readback timed out. Its receipt is explicitly **incomplete**:
no trial, post-trial USB disconnect/reconnect, healthy returned baseline or
userdata/normal-peer preservation was observed. Aggregate COMMIT TX is not
installation or rollback proof; neither the failure reason nor the lack of
samples proves a radio fault or a failed boot. No second COMMIT, host reset,
reflash or reboot was used to manufacture a result. The last independently
confirmed baseline remains confirm04/floorsequence3/counter2/hash417a...;
the immediate witness did not establish post-COMMIT state.

**Late read-only current-state diagnosis:** a separate, once-only bounded
capture subsequently read all eight native responses from exact unit41 in
0.164 seconds, with no timeout, RF transmission, reset or repeated COMMIT.
The first historical timeout was the one-second driver-applied radio request
`42 00 03`, issued before identity/version; its hardware or transport cause
remains unproved. The late capture found `ota-41-confirm04`, qualified state1/
phase8/decision0 with writes allowed, and the unchanged confirmed floor:
sequence3/counter2/extent554372/hash
`417a6228926fdd531d8a388c516c7bbc8255352b97132aaa3ea26ddd6d09be56`.
The exact counter3/generation13/manifest candidate reported Failed10 with all
6599 blocks retained; native lifecycle still reported `verified=0 image=unknown`.
Normal907525kHz/BW250000/SF7/CR5/TX2, current driver health, valid profile and
zero apply failures were observed. The current boot reported1088 seconds
uptime, zero error flags and zero lifetime driver faults; this does not erase
the earlier boot's recovered fault growth or prove continuous radio health.

The returned baseline and failed candidate are now observed current state,
not reconstructed trial history. This sequential snapshot cannot supply the
missing trial/disconnect/reconnect evidence, qualify autonomous rollback, or
authorize the phase8 rollback peer gate. The original incomplete witness and
its authority remain unchanged; future observation must tolerate explicit
bounded transient read gaps without promoting missing evidence.

Full reader-free reception is now qualified for this bench campaign.
Autonomous failed-trial rollback, uninterrupted installation observation and continuous
fault-free radio operation remain unqualified. The original restart evidence's
recovered fault growth remains degradation, not a resolved fault cause.

**Diagnostic candidate READY; installation attempt unsuccessful:** the next
healthy diagnostic image, `ota-41-diag-conf05`, completed a reader-free
500kHz upload through the unchanged stock companion. The receiver reported
all6618 blocks READY, counter4 and freshly measured generation14. The
555876-byte image SHA256 is
`7a58300659aeec6ccde7f7808e9407a2312e4a1100def28993ea8c50f2efe226`;
its canonical manifest SHA256 is
`adfff97d0ea018f9796619f4a56059417ac44a4db1290cfe08dc615796e27f30`.
The uploader exited0 and restored the stock radio. This is unsigned READY
evidence, not authenticated census or installation.

A separate, once-only COMMIT process started with a750-second USB observer
already armed. The stock process exited1 after535.401 seconds; restoration
was proved, but no successful COMMIT result or seal was produced. The observer
completed its fixed window with147 READY samples, no observed trial,
installation, USB disconnect or response gap. Its final sample still showed
`ota-41-confirm04`, the unchanged sequence3/counter2 confirmed floor, and the
exact counter4/generation14 candidate READY with all6618 blocks. Sampled normal
907525kHz/BW250000/SF7/CR5/TX2 and current driver health passed; the lifetime
fault counter nevertheless increased791 to837. That growth has no established
cause.

The COMMIT wrapper discarded the child's public progress and error output.
Consequently, the exact stock-process failure and whether a COMMIT transmission
was attempted cannot be reconstructed. A535-second exit does not prove a
timeout. The nominal292.062-second pacing calculation for52 census queries
omits host/completion overhead and retries and is not an upper bound. No
repeated COMMIT, reset, reflash, ABORT or late fabricated seal was used.
Post-install diagnostic collection and private userdata comparison were not
admitted by that failed attempt; the later independently confirmed installation
and separately admitted readbacks are documented below.
The preparation snapshot covers only protocol-visible userdata; it does not
establish complete persistent storage or private-key preservation.

**Healthy diagnostic installation independently confirmed (2026-10-05):**
ROOT admitted one separately observed signed COMMIT retry of the unchanged
counter4/generation14 candidate. This preserved its native transaction,
owner and manifest; it did not AUTH, reupload, replace the candidate or reset
the receiver. The production sender completed all52 fresh READY census
windows under the unchanged2% normal-channel policy. Its owned process
exited0 after610.392 seconds, with request, aggregate transmission and result
events retained, independently verified stock-radio restoration and a genuine
COMMIT interval seal.

The prearmed observer nevertheless exited2 after613.810 seconds, well before
its fixed2010-second deadline. Its generic contract-refusal receipt does not
identify the exact exception. The last retained sample before the seal still
showed confirm04, floorsequence3/counter2 and all6618 blocks READY. There were
no recorded trial, disconnect or read-gap events. Recovered radio faults grew
837 to886 during observation; their cause remains unknown.

ONE separate late read-only capture then found exact41 running
`ota-41-diag-conf05`, with qualified state1/phase6/decision0, writes allowed,
confirmed/installed lifecycle, verified running hash and confirmed
floorsequence4/counter4/extent555876/hash7a583... . The independent current-state
receipt SHA256 is
`b428ce66d848256785320fc7e37896569c17a4878e4e71a02f426b564ac1acd9`.
Native ABI2 reported
Installed8 for the exact manifest/generation14/all6618 blocks, with age0 and
retry0. Core error flags were0, uptime132 seconds and normal
907525kHz/BW250000/SF7/CR5/TX2 operation was healthy. The new application
reported radio fault count0 in this late sample; that does not erase the
previous application's fault growth or prove continuous fault-free operation.

This is the third independently established healthy signed RF installation on41.
No additional COMMIT, host reset or reflash was performed. The original
observer receipt remains failed: the late image-bound confirmation proves
current installation, not an uninterrupted trial/reset history or autonomous
rollback. Full private-key/storage preservation remains outside the exposed
snapshot.

**Diagnostic post-install userdata and ordinary RF recovery (2026-10-05):**
ROOT separately collected passive selector5 diagnostics and compared a complete
protocol-visible snapshot with the actual campaign06 pre-upload snapshot. All
six checks matched: identity, self-info, raw self-info, exposed device settings,
contact digest and channel digest. Both snapshots contained five contacts and
40 channel slots. Fresh image-bound confirmation was required before each
collection session. Selector5 reported healthy operation, no retained failure,
and zero lifetime/origin counts in both reads; no active probe was requested.
The successful readback receipt SHA256 is
`ac6c96bb2bbc3cc58915af10912c5fcda06a089a4730714f9f83984f992f7624`.

Only after that pre-peer comparison, ROOT admitted one standardCMD7 ordinary
zero-hop advert request per transmitter. The unchanged stock companion and41
each received the other full public key's Ed25519-verified ordinary advert on
907525kHz/BW250000/SF7/CR5 at2dBm. Both native acceptance events were observed.
Stock-to41 reception measured RSSI-35dBm/SNR12dB;41-to-stock measured
RSSI-38dBm/SNR13dB. Fresh reads before and after still qualified the exact
diag-conf05 image, floorsequence4/counter4, native Installed8, healthy normal
profile and zero apply failures. The successful ordinary-peer receipt SHA256 is
`6edcc0cffd6a53c4aa9dc34d6d2f7137f3a25ab9fd17a3be34b50d81359a59f2`.
No OTA control, settings write, additional COMMIT, reset or reflash was performed.
Ordinary contact-timestamp updates were expressly admitted after the snapshot.

These are signed post-command RF receptions, not cryptographic proof of fresh
emission or command causation. Native events did not independently correlate
the signed packet's timestamp. The receiver's sampled lifetime fault count
increased0 to1 across the peer exchange despite healthy current radio state.
Its origin/cause is not established by those radio reads; recovery is proved,
continuous fault-free operation is not. The original failed observer and its
unlogged exception remain unchanged and historically unrecoverable. Exposed
userdata equality does not prove hidden storage, private keys, hidden PSK
halves, atomicity, uninterrupted boot history or autonomous rollback.

**Passive post-peer fault classification (2026-10-05):**
ONE separately admitted read-only collection freshly qualified the same installed
diag-conf05 image and floorsequence4/counter4 before reading retained selector5
details. Both reads reported healthy radio state, lifetime count1 and one
`ActiveProbe` origin; every other origin count was0. The retained failure reason
was0x20 (chip-mode mismatch): software expected transmit mode2, while status0x2c
decoded to STDBY_RC. IRQ flags were0x0001 (TX_DONE), device errors were0, and all
three checked SPI reads reported success. The passive receipt SHA256 is
`751f074f2e0705f57d03b458b7cefdb4bfcb75a89c67ce3dd143e01054eba5e8`.

This identifies the retained fault as a checked mode disagreement, not a failed
SPI read or a retained device-error bit. A latched TX_DONE flag does not establish
fresh completion, the command that caused it, or whether software serviced that
completion before the probe. Both sequential reads retained count1; the
collection requested no active probe, RF transmission, settings write, reset or
OTA action. It does not establish a shared MCU boot epoch with the prior peer
session, continuous health, CMD7 causation, or the earlier837-to886 faults'
cause. The qualified installed source showed a possible transmit-completion/probe
ordering race compatible with this diagnostic, not proof of its historical cause.
The strict health classifier has not been weakened.

**Transmit-completion source milestone (2026-10-05):**
Both companion and repeater trial-health paths now service an owned, unexpired
send through the dispatcher's ordinary exactly-once completion/accounting path.
RadioLib cleanup rearms receive. The SX1262 probe handles an ISR arriving during
its reads with at most one completion service and fresh probe, retaining original
SPI/device failures. No extra send is scheduled by the health probe; stale IRQs,
unowned/expired completions and persistent standby remain unhealthy. The focused
native boundary passed32 cases (20 completion product cases plus12 existing
fault-attribution cases).

Compile/link passed for XIAO nRF, Solar and Wio OTA companion/repeater firmware
and XIAO nRF BLE non-OTA firmware. XIAO nRF OTA companion RAM/flash are
174332/560068 bytes; Solar companion131156/557264; Wio companion168740/723077.
These are compile results, not installed images or new physical reliability
evidence. Unit41 remains on `ota-41-diag-conf05` with its existing floor4.

The separate private exact floor4 diagnostic rollback profile passed16 combined
offline profile/observer cases using synthetic USB, including genuine ordered
trial/return requirements, missing-trial refusal, unhealthy/changed-floor return
refusal, fixed deadlines and once-only approval binding. Production signature
verification rejects the synthetic invalid signature; tests do not sign or
authorize a campaign. The profile SHA256 is
`3cf6193bb05ef7e5c48ea40c7bbb3d2a9e798a49add33850aa10a14820cb296d`;
its scoped observer bridge SHA256 is
`aec55e3dadaaa879af4c15b5fe1384fe8c992fdbfedc370291555ed699a36c23`.
The bridge requires private owned single-link files and safe-path Python.
This resolves the source-profile blocker only. A new legitimate ROOT authority
must bind the actual floor4 baseline, qualified nonconfirming image, signed
descriptor/counter, measured READY generation and native nonce before any new
hardware campaign. No COMMIT, signing, upload, reset, reflash or observer rerun
was performed for this milestone; all historical failed receipts stay unchanged.

**Transmit-fixed healthy APP candidate (2026-10-05, source/build only):**
A distinct `ota-41-tx-conf06` artifact was built from the exact published
`17df6089571f310c75db45c5f97aae8993bf9860` tree, not the dirty worktree or
inherited index. It retains the routed-retry integration and strict classifier,
uses the enrolled Sense-family target0x584E3430/ROLE0, and runs the ordinary
10-second healthy confirmation policy with a45-second deadline. It does not
force health, withhold confirmation or contain a bootloader/SoftDevice image.
The raw APP is560084 bytes, SHA256
`1c58ed5e99e863a4313e1d7dede6c3381dff5265fbcdb40ae48335a44f8cf5dd`;
the APP-only ZIP SHA256 is
`afda9a1865113f70f9b2d27a84c673a4c265d2f610c76497b1d1d46f5aa27502`.
Its load range0x27000..0xafbd4 is below installer0xc4000, with82988 bytes of
APP-slot slack and174332 bytes of static RAM. Raw/ZIP/ELF/HEX image bytes match.
The ZIP's Nordic compatibility metadata is not an RF campaign signature or
counter; target/role/version and geometry were checked separately.

The new completion callback's initially partial1552-byte chain was closed
against actual compiled targets, frames and indirect calls: its conservative
bound is1848 bytes including the inherited104-byte IRQ allowance. The selected
OTA-root maximum remains3348/4096, with748 bytes of headroom. The separate
closure receipt SHA256 is
`facc171e64b4324731c87b376e3abc8670ef12dae8ca735cd085625373fca340`.
This is static selected-root analysis, not runtime stack high-water or whole-loop
filesystem/UI/sensor certification. The original partial report remains
unchanged; the new closure records the resolved edges explicitly.

An exact private APP06 healthy-installation observer profile is now qualified
in source. Its first focused boundary exposed the frozen observer's static
diag-conf05 version decoder, which overwrote the caller's APP06 recognition.
A separate source view replaces only the decoder binding at line291 with the
exact caller-supplied decoder; the frozen classifier, evidence implementation,
files and globals remain unchanged. The final focused Make boundary passed
seven product groups using26 synthetic public USB fixtures. The original failed
run remains preserved. The exact profile SHA256 is
`a3845199cd5b1c9971da62aa215bd23b999724b35dd866a81019f50af7a669e0`;
the successful product receipt SHA256 is
`089a9f2a06177687ecc83cc8e74886ada7409945c83dd6f9640a34e5422106bd`.

This is source qualification, not hardware admission. The profile still denies
deployment without genuine completed counter5 trial/gap/unchanged-floor return
and sealed COMMIT/restoration receipts, an independently reviewed fresh ROOT
approval, the actual new signed descriptor/counter>5/measured generation/native
nonce, current physical/floor/core/normal-radio checks and a real prearm before
separate bounded COMMIT. Healthy confirmation requires the exact new image
and floor with native Installed8. A short healthy trial may remain explicitly
unobserved only under ROOT's separate policy; it is never fabricated.
The subsequent live rollback trial exposed a second incompatibility shared by
the frozen rollback and healthy classifiers: they require a deferred trial
floor, while the actual diagnostic firmware exposes the exact existing floor
as present, `STAGING_ONLY` and write-blocked. The synthetic APP06 qualification
above remains recorded, but does not cover that actual trial ABI. The profile
is not admitted for deployment; prospective source correction is required.
The new artifact is still unsigned, without an assigned counter/generation,
and not installed on41. Separately, a new counter5 campaign using the older qualified
nonconfirming `ota-41-diag-roll05` image was prepared and USB-signed through the
unchanged stock companion. Its once-only reader-free500kHz RF upload completed:
the exact counter5 manifest
`315f0ecf6d852f87e202c9017a895015a11083e2e347bd65bd838b4a8cccf600`
reached complete READY with native measured generation15, and the stock
companion restored its radio. Generation was not assigned by the host; this
unsigned RF READY result is staging evidence, not installation evidence.
Fresh pre-upload readbacks established the existing diag-conf05/floor4
baseline and captured five contacts/40 channels privately.

A new ROOT-reviewed launch was started once, with a fresh READY sample and
observer arm before the separately supervised signed COMMIT. The unchanged
stock child exited0 after bounded request/sent/result and aggregate transmission
evidence; its exact counter5/generation15 result and radio restoration were
independently read and sealed. The campaign still ended incomplete: the observer
reopened unit41 in a real native trial, then refused that sample and stopped.
Its official receipt contains no accepted trial or post-trial return history.

The journal's rejected sample shows `ota-41-diag-roll05`, native Trial7 for the
exact counter5/generation15 candidate, write-blocked phase5, core0/uptime5,
normal PHY/TX2 and healthy sampled radio. Its floor is present and matches the
existing sequence4/counter4/extent555876/hash7a583... exactly, with successful
I/O and `STAGING_ONLY`/blocked writes. The frozen trial classifier instead
requires `floor=deferred`; this is the concrete refusal condition. The captured
sample is not promoted into the failed observer's accepted history. That
observer also counted49 newly observed radio faults before the trial and eight
concrete disconnects; neither establishes a reset cause or the radio fault's
triggering command. The failed campaign receipt SHA256 is
`2518170d7510b6e60872a64202fa4a3a13f53a0db16821ad6a07a72d35ca8c4b`;
the failed future-observer receipt SHA256 is
`61c6cf65569b17811020b96a2926a434acf1678b3c7d570d1529fe5a038b598c`.

One separately admitted read-only postattempt capture subsequently found
`ota-41-diag-conf05`, the exact original floor4, write-allowed failed phase8 and
native Failed10 for that counter5/generation15 candidate. Core0, normal TX2 and
healthy sampled radio with lifetime count0 were observed. Both approved UARTs
were released. Its receipt SHA256 is
`84a33cc56502bf77771c3deca7d714b7221039cc67158b1c0dc0331ba62af6a7`.
This establishes a later correct return state, not the missing uninterrupted
trial/post-trial-gap/autonomous-return observation. No second COMMIT, host reset
or reflash was performed; old receipts and consumed markers remain unchanged.
Any new rollback campaign needs its own prospective strict available-floor
trial profile and fresh ROOT authority, not a replay of this attempt.
A separate source-only
post-return recovery capsule requires genuine
ordered trial/return receipts before strict exposed-userdata comparison and
independently admitted ordinary RF checks; its delivery grants no hardware
permission.

**Corrected observer and fresh counter6 rollback campaign (2026-10-05):**
A new prospective profile accepts either the legacy deferred trial floor or
the available floor actually exposed by the diagnostic firmware. The latter
must have successful I/O, `STAGING_ONLY` capability, blocked writes and the
exact baseline sequence4/counter4/extent555876/image hash. All existing native
candidate/session bindings, core0, normal PHY/TX2, trial decision/proof and
uptime-before45-second-deadline requirements remain enforced. It neither
coerces the floor to deferred nor grants writes. The frozen evidence and
ordered observer implementations remain unchanged; the source-view bridge
qualifies the precise trial-floor refusal before applying this alternative.

The focused Make boundary passed27 source product cases, including the
captured trial-floor ABI and synthetic ordered trial/gap/return/seal coverage.
These are not live rollback evidence. The new profile SHA256 is
`b6628e71ff5f1fee2e1a33c9a298dd6b9e9e49c84ce6106f23307d3e1b657ae5`;
the staged coordinator SHA256 is
`55d66ea9049e31281a3556b6c04395c5ac8b722f27d8fcd074ec825ea516dec9`;
the source handoff SHA256 is
`2ee0be1a7fad981f60446cf6539330fb8338e6ffabc9770ac224d7006c1d9c61`.
ROOT reviewed the full new sources and qualification before distinct admission.
The failed counter5 campaign, receipts and consumed markers remain unchanged.

Fresh readbacks for the new campaign established diag-conf05, the exact floor4,
failed counter5/generation15, core0, normal PHY/TX2 and sampled healthy radio.
The private protocol-visible snapshot again contained five contacts and40
channel slots. Its public comparison hash
`a98461062125d68b01f5784de581af2a7fc71f857f27a9a0884d20bd6b4bf80f`
matches the actual counter5 pre-upload snapshot; this does not prove hidden
storage or private-key preservation. The new prepare receipt SHA256 is
`213fdfda40f971361f053c1a4d5095c6ee2aaaa5ea28e98d8ccd98711f2a3546`.

ROOT explicitly selected counter6, not an automatically assigned floor+1.
The same qualified nonconfirming `ota-41-diag-roll05` image was bound into a
new59-byte canonical descriptor, manifest SHA256
`6eef4e82422af2b84b596142dd38671c2ab528d46c15aa939123566205d0dd61`.
Separately admitted USB signing through the unchanged stock1.17.1 companion
completed with real Ed25519 verification; the signed descriptor SHA256 is
`15dd09298c24abee2087dbece38bb176fe7eb0a544194cc37e5452347e5ddd4a`.
A separately admitted once-only reader-free RF upload completed using
908525kHz/BW500000/SF5/CR5 and the unchanged2% airtime policy, with a14400-second
production deadline. Unit41 had no concurrent USB reader. The exact counter6
manifest reached complete READY with native measured generation16, not a
host-assigned generation, and the stock companion restored its radio. Its result
is explicitly unsigned RF READY, not installation confirmation. The upload
handoff SHA256 is
`c5fa3e9ee25a33ae683370cbe7df320de23ec9a2cf7cf6ad4ee549a61b2eb478`;
the stock result SHA256 is
`fffe7784e735102c97eae94dd183413bd1a2bcfc110417a85428e25c88ca425e`.

After the target lease-expiry wait, ROOT separately reviewed and admitted the
new launch with exact counter6/generation16, native owner/manifest/generation
nonce `eab6f0eccb242d0e` and all three known prior nonce exclusions. The new
approval SHA256 is
`1b37afc69e5a509a28f581c92fd308a2a1cec53c7efcc621f2203cb0cf5e213a`.
A fresh physical USB READY sample established core0, normal radio before and
afterward, and TX2. The real observer armed before the separately bounded
signed COMMIT invocation, retaining the original2010-second parent deadline.
The authority SHA256 is
`b20d83472e9f9ecf959affa3d5afeb8801844b93db747e863f3045139dae3ef0`;
the actual armed receipt SHA256 is
`7e0a9145ce4690c6b0e2dae3ee9351944b7a6e537d5226335abd4235ebbd1ce3`.
The stock COMMIT subsequently exited0 with actual request/sent/result and
aggregate transmission evidence for the exact counter6/generation16 candidate,
restored its radio and completed the bounded seal. The seal SHA256 is
`74a756de749aecb3bb9edeb4dc65c0b1fefa7a6b2963984da1e7adc49d70cb87`.
The whole campaign still exited2/incomplete: the corrected observer accepted
eight genuine trial samples at uptime2,7,13,18,24,30,35 and41 seconds, then failed
before observing the post-trial USB gap or healthy return. Those accepted
samples establish the available-floor classifier's live compatibility: exact
native Trial7/counter6/generation16/full6617, core0, normal PHY/TX2 and the exact
present, write-blocked floor4. They do not establish a verified running trial
image hash or complete autonomous rollback.

The terminal journal event failed at the next identity-stage physical check,
before any reply or decoded field. The open-UART binding guard refused an
unequal selection, device number or character-device condition; it did not
retain which comparison changed. The journal does not therefore prove a
kernel USB re-enumeration or reset cause. Its eight concrete disconnects were
all before the accepted trial, and no post-trial disconnect/reopen/return was
accepted. The observer also counted47 newly observed radio faults before the
trial despite healthy sampled trial radio; this does not identify their cause.
The failed campaign receipt SHA256 is
`068b2d513525629c2af906ffb5adc90f58bb0ad175e773591136fc689d535180`;
the failed observer receipt SHA256 is
`2e3bafcc6064dc7d2b052402ebacc66003eaa9c94db4e982fd0cdeabf47f64c1`.
Both children were reaped. No retry, host reset or reflash was performed.

One separately admitted read-only current-state capture later established
diag-conf05, the exact original floor4 with successful I/O and allowed writes,
failed phase8 and native Failed10 for counter6/generation16. Core0, normal TX2
and healthy sampled radio with lifetime count0 were observed; both approved
UARTs were released. The new capture receipt SHA256 is
`37f0cf75b110260d54eb3d9050808ae991bfcdf19946417405d8142972d05e3b`.
This is a later correct return state, not the missing ordered post-trial
gap/return history, userdata comparison or ordinary RF recovery. The original
failed receipts and consumed markers remain unchanged.

Genuine ordered trial, post-trial gap and exact floor4 return, followed by fresh
userdata and ordinary two-way RF recovery, remain required. The transmit-fixed
healthy APP remains unsigned and uninstalled.

**Post-return recovery and corrected healthy deployment (2026-10-05, source only):**
Three new private capsules now wire the genuine counter6 campaign's future
lineage into post-return recovery, the exact APP06 observer and staged healthy
deployment. Their focused Make boundary passed12 cases using30 MODEL fixtures;
these exercise the real scoped observer, recovery and coordinator against
synthetic USB/RF/history and independent approval inputs, not actual campaign
success or ROOT authority. The first failed qualification remains preserved.
The final handoff SHA256 is
`dfb5f6a34e0eb0e5dc5e3eb83a294aacf715191f99711419f0a958e03c9edc01`;
the final product receipt and independent rerun SHA256 is
`0cbddb5f26f80dfb0fba71fc0ed4bd0113a3939072789f2b3bce204c8f85d8e4`.

Recovery requires the actual new source-bound preparation/signing/session
receipts, genuine ordered trial/gap/unchanged-floor return and bounded signed
COMMIT transmission/result/restoration seal under the original parent deadline.
Only then can separate ROOT admission permit full protocol-visible userdata
comparison and one ordinary signed, native-accepted advert in each direction
at normal2dBm. Any permitted contact-timestamp change requires its own exact
ROOT diff review; missing fields do not fall back to counts. Current healthy
radio and unchanged observed fault counts are required, without erasing
historical faults or requiring lifetime zero.

The healthy observer retains the exact APP06 image/floor/native Installed8
requirements and corrects only its trial-floor predicate, accepting the strict
available baseline floor or legacy deferred floor. Deployment still requires
genuine counter6 recovery, an independently selected higher counter, actually
measured higher READY generation and native nonce excluding all prior sessions.
No counter or generation is assigned by this source delivery. Separate
prepare/descriptor/sign/upload/launch admission, actual fresh READY, real
prearm before bounded COMMIT and sealed radio restoration remain mandatory.
There is no permanent source-only refusal once genuine prerequisites are
supplied, but absent prerequisites deny all live execution.

The counter6 upload and separately prearmed COMMIT subsequently completed with
measured generation16 and sealed stock-radio restoration, but the failed
observer history above cannot satisfy these capsules' genuine-success gate.
They remain default-denied for live deployment. No hardware operation was
performed by the source qualification itself; the radio fix remains unsigned
and uninstalled.

**Prospective USB-epoch continuity (2026-10-05, source only):**
Four distinct new capsules now wire a future rollback campaign, its post-return
recovery and corrected healthy observation/deployment. Their focused Make
product boundary passed21 cases using47 MODEL fixtures; an independent rerun
produced the same receipt hash. These are source-operation inputs, not physical
rollback history or hardware authority. The final handoff SHA256 is
`7d2f9052abea501fb3f3b67fcd2c8ecb7ef430e0b2e4b9a708067fc0018b0cfe`;
the qualified product receipt and independent rerun SHA256 is
`9ac292ef1ba37c7f70d288caba258cabf0e3fa90eba9fdde4c1ae476f040051c`.

The prospective observer requires the exact same serial, VID/PID, physical
USB path and full public identity, a changed kernel USB device number and owner
token, and old-handle/new-device discontinuity. It closes the old handle before
reopening the exact board exclusively and obtaining completely fresh coherent
native samples. Old-handle identity uses the stable device/inode/device-number
tuple and character type, not inode ctime, which Linux changes on unlink.
Receipt replay validates the actually recorded old-handle token and type;
a timestamp-only change cannot establish a new device. Identity, ownership,
ambiguous epoch and protocol failures
remain fatal; arbitrary errors, tty changes or no-response are not boot or reset
proof. Samples are bracketed, not atomic, and no reset cause is claimed.

Recovery admits only a genuine new source-bound ordered trial, qualified
post-trial kernel USB epoch change and exact floor4 return, with the separately
bounded signed COMMIT transmission/result/restoration seal. The later counter6
snapshot cannot satisfy that chain. Full userdata and independent ordinary RF
recovery retain their separate ROOT gates, as does any exact contact-timestamp
diff review. Healthy deployment retains exact APP06/native Installed8/new-floor
requirements and independently higher actual counter/generation/nonce lineage;
an unobserved short healthy trial requires an explicit ROOT boolean.

The future rollback counter must be explicitly ROOT-selected above6, and READY
generation actually measured above16; neither is assigned by this source work.
Fresh preparation must remeasure the failed counter6/generation16 floor4
baseline and full userdata. All five stage admissions, true prearm, original
deadlines and physical restrictions remain mandatory. The source delivery
itself supplied no live authority or hardware result. The radio fix remains
unsigned and uninstalled, and the old failed history remains irrecoverable.

**Counter7 rollback attempt (2026-10-06, sealed COMMIT but incomplete history):**
After separate ROOT source acceptance, ROOT explicitly selected counter7 for a
distinct campaign using the same older nonconfirming diag-roll05 image, not
the transmit-fixed APP. Fresh admitted preparation remeasured diag-conf05,
the exact original floor4, failed counter6/generation16, core0 and healthy
sampled normal TX2. The new full protocol-visible five-contact/40-channel
userdata inventory matches the actual counter6 pre-upload comparison hashes;
this does not establish hidden-key or full-storage preservation. The preparation
receipt SHA256 is
`b4d98b7ab8e90db27ceda6af712d10392f1dcbe6593c56912a07e1da12cb9d3b`.

Separate descriptor and signing admissions produced a new canonical59 manifest
`6da16c8a571d15be24e03c285af7e8e5082db07642180349be79331fbd72fff6`
and a real, verified USB signature through the unchanged stock companion on
physical USB4.2.4. The signed descriptor SHA256 is
`05ab1e38bac6b3b8b3b672374f1a2544856d0c80e6a985fc4fb5c173d20e61c9`.
A distinct once-only AUTH/upload admission then started the reader-free500kHz
LoRa transfer under the unchanged2% airtime policy and14400-second production
timeout. Its approval SHA256 is
`b71846ee73380297781de0128f821ac223f00e7854e46e3fa6a03d2a48432678`.
The transfer completed with exact counter7 READY, native measured generation17
and stock-radio restoration. Generation17 was measured, not assigned, and this
unsigned READY result is staging evidence, not installation confirmation.
The upload handoff SHA256 is
`77c32c7719ee29c9db3f967f87ae43901d32d3e32c5ee8f3194215b36849766d`;
the actual stock result SHA256 is
`761b3fbdb1585655b4e96fcc7cfc19b083e6b3f60a51c613bc9b49b1f6d88adf`.

After the lease-expiry wait and independent ROOT session review, a new launch
approval bound actual generation17, native nonce `2f631fab5e00e987` and all four
prior nonce exclusions. Its SHA256 is
`1a87d3e76725e4c7a6a9d1d637883bfb29fe86f945e542dce0cf2e6b2fbd8514`.
A fresh physical USB READY sample established full6617, core0, the unchanged
floor4 and healthy sampled normal TX2. Its historical lifetime radio-fault
count was796 before and afterward; this is not erased or attributed to a cause,
and sampled health does not establish continuous radio reliability.
The real observer armed before the separately bounded signed COMMIT invocation,
retaining the original2010-second parent deadline. The authority SHA256 is
`0c803cba4d5d4d59ece2b0018024e4b58f7ab30c7dcaa395927268dd730805b1`;
the actual armed receipt SHA256 is
`0a9c624a1a5512bef5263ddeb546d596603458871f8a5bf251040f991c7c2408`.
The unchanged stock COMMIT completed with exit0, request/result transmission
evidence for the exact counter7/generation17 session and stock-radio restoration.
Its result SHA256 is
`65647cd7e1507ce6d983c1227e7d51af0c88dfc8c308eaecc1050d2202bdaf5d`;
the transmission/result/restoration seal SHA256 is
`442a4fabbef64443bc114547e5a5eea16e62e6e33346cad0a716e51f3eea2a4b`.
The campaign nevertheless completed with exit2 and all children reaped. The
observer accepted no trial, qualified kernel USB gap, new epoch or floor4 return.
Its next physical-resolution callback failed on an absent serial anchor
(`ENOENT`) before the new kernel guard captured removal evidence. Missing-anchor
failure alone does not establish kernel removal, a reset or any trial transition.
The last accepted sample was still READY/core0/normal TX2, with lifetime
radio-fault count847 versus796 initially:51 observed additional faults, without
an established cause or continuous-health claim.
The immutable failed campaign SHA256 is
`a700e7c3a9a1dab848167c15e61dfc9cc092cb6c858c9095db33f9d98db0e6b0`;
its observer SHA256 is
`05b2e6b7f1207ce7fcca655d8511ddbf0b74e7f581655ba4cacc75475519a382`;
its journal SHA256 is
`866172f9b1c281de53d31f58d314e7668cfaf5678ef938050bb2dea9840b3d54`.

A distinctly ROOT-admitted read-only capture later found diag-conf05, the exact
original floor4, native Failed10 at counter7/generation17, core0 and healthy
sampled normal TX2. Its actual lifetime fault count was0 before and afterward,
not a host-forced zero; this does not explain the earlier faults or establish
continuous reliability. The reader released ownership. The current-state
receipt SHA256 is
`b35a63cd13837fdbb5310b3d53e4bbdfad3197fb109ed56663828327f4c145f6`.
This later return cannot recover the missing ordered trial/removal/return
history or prove autonomous rollback. No retry, host reset or reflash was
performed. This read-only capture did not compare userdata or exercise RF.

The current campaign's recovery and healthy-deployment gates remain blocked.
A distinct source-only correction is now independently qualified for proved
removal of the previously owned kernel USB epoch before resolving an absent
anchor, across physical, framed-command, serial I/O and reopen paths.
It probes the saved kernel owner independently, closes the old handle before
reopening and bounds absence to120 seconds within the original2010-second
deadline. Startup absence, missing removal proof, wrong identity, permissions
and ambiguous metadata remain fatal. A pre-trial removal can permit observing
a genuine trial but cannot replace the required distinct post-trial
gap/new-epoch return. Actual stable fault counts, including0, are accepted
without host mutation; changing counts still refuse admission.
The focused Make product boundary passed25 cases with64 MODEL fixtures, with
an independent parent rerun producing the same receipt. These are synthetic
inputs through the real scoped product paths, not hardware history or ROOT
authority. The final source handoff SHA256 is
`bd46e3f3c106602d59fc6c75f279c6edfb6f5edc2f68aeb8e396e2849856a557`;
the qualified product and parent rerun SHA256 is
`c2fd086bbda74b0e2260eb5a1d4bf68d85f33fe3da4f4a60624a7c126121adf0`.
All four new rollback/recovery/healthy-observation/deployment capsules retain
their separate admission and genuine-history gates. The source delivery supplies
no hardware authority or result.
A future campaign requires fresh ROOT review of the current failed
counter7/generation17 baseline, an explicitly selected counter above7 and
actually measured READY generation above17, with all five prior nonce
exclusions. Nothing defaults to counter8 or generation18. New ordered rollback,
independent full userdata and ordinary two-way RF recovery, transmit-fix
installation and physical reliability remain open. All old sources, claims
and failed receipts remain frozen; later snapshots do not promote them.

**Fresh counter8 campaign (2026-10-06, rollback/userdata passed; RF recovery refused):**
After independent ROOT source acceptance, ROOT explicitly selected counter8,
above the actual failed counter7; no READY generation was assigned. A distinct
read-only preparation freshly remeasured diag-conf05, the exact original floor4,
failed counter7/generation17, core0 and normal TX2. All four radio readings
retained their actual stable lifetime fault count0. The full new
five-contact/40-channel protocol-visible userdata comparison hashes match the
prior ROOT inventories; hidden keys and full persistent storage remain outside
that proof. The preparation receipt SHA256 is
`dccf39e9d25c69066ce0f9fff8b128c59d1c891bdc25f01ee3e42b8d3db2065a`.

Separate descriptor and unchanged-stock USB signing admissions produced the new
counter8 manifest
`31beac38b69ad96ec2189d6be2b234336c9c59712893e48e0b369906af245de7`
for the same older nonconfirming diag-roll05 image, not the transmit-fixed APP.
Independent review verified its actual59-byte canonical descriptor and64-byte
Ed25519 signature against the exact stock owner. The signed descriptor SHA256 is
`a6362801506ef34e786566ea294f6aa17d90b4ade7083e2b3219734c7ffa91c2`.
A further distinct once-only AUTH/upload approval, SHA256
`0ef989f7fb038936435fca759001cd67af0467ebb7c1446aa81e08d417cb4756`,
started the reader-free500kHz LoRa upload under the unchanged2% airtime policy.
The attached upload completed with exit0 on the authorized physical USB4.2.4
path. Its actual READY generation18 was measured, not assigned; all6617 blocks
were present and stock-radio restoration was true. The upload handoff SHA256 is
`a883dd68ab7db2012fbc09468e675ba20a3a353b0c89a5c47aa36fc183e4029d`;
the production result SHA256 is
`45e58ebb7caad16a88d8a5b0b9d796040379eae745b4687c361d4ca8bb90a0d2`.
Independent native owner/manifest/generation binding review derived attempt1
nonce `47ea9339f9b20a5c`, excluding all five prior nonces.

After the65-second fast-lease expiry wait and completed receipt review, a
distinct fresh ROOT launch approval, SHA256
`5f0159b233de1bfa52ab8e68d86076ce80a65739630433cb8c3e4a7c1391172f`,
started the attached observed campaign. Its actual fresh local USB READY sample
confirmed counter8/generation18, diag-conf05, the exact floor4, core0 and normal
TX2. Both radio readings retained actual stable lifetime fault count796,
not forced zero; the cause and continuous fault-free operation remain unknown.
The genuine prearm receipt SHA256 is
`f0a0de230b5626431076c0bc0166c91159336384abc659031888286c5dfb8346`.
Only after this real ARM did the separate bounded signed-COMMIT production child
start on USB4.2.4, within the original2010-second campaign budget.
The attached campaign subsequently completed with exit0; both its observer and
stock production child were reaped. Actual COMMIT request/sent/result events,
exit0 and stock-radio restoration were sealed within the original deadline.
The campaign receipt SHA256 is
`7d4572b76446e0e2c56ed76a2ca47a820b279607c6e3a660246eaed20252d6a7`;
the independent observer receipt SHA256 is
`855d2fa6e77d968aa3c4df0566fe023d48b6cefe56953ebbb885988871e1a12b`.
Its154-row journal, SHA256
`7a2fff1231a344e6fe3a56bcc88b627c596e46209bfb8f8315e7734a74538779`,
contains23 genuine native trial samples and four independently qualified
owned-kernel removal/new-enumeration intervals. The exact board progressed
through kernel device numbers86->87->88->89->90, with each old handle closed
before exclusive reopening and each return inside120 seconds.

The first observed diag-roll05 trial had counter8/generation18, core0/uptime1,
and the unchanged PRESENT floor4 with qualified blocked STAGING_ONLY writes.
A distinct post-trial removal preceded the final new-epoch diag-conf05 return:
native Failed10 for the same counter8/generation18/manifest, core0/uptime9,
exact original floor4 and sampled healthy normal TX2 with actual stable count0.
Independent ROOT review of all29 pinned receipts passed the unchanged strict
completed-history validator. No host reset, reflash, new AUTH, retry, deadline
extension or old failed-receipt promotion was used. This establishes the new
ordered failed-trial return, not exact reset cause, running-image hash,
atomic samples or continuous fault-free operation. The observer recorded49
additional recovered radio faults before the trial; their cause remains unknown.

Initially, independent post-return recovery stopped at source admission before
creating authority or accessing hardware:
the accepted qualification receipt and independent parent rerun have identical
SHA256 `c2fd086bbda74b0e2260eb5a1d4bf68d85f33fe3da4f4a60624a7c126121adf0`,
but the frozen lookup requires exactly one matching file. Both archived files
remain intact; no source edit, receipt deletion/rename or gate bypass was made.
A separately admitted source-only recovery/deployment correction is now
independently qualified. It accepts one or more byte-identical copies of the
explicitly pinned valid qualification while retaining exact source, schema,
content and default-denial gates; different bytes, wrong hashes and invalid
sources remain refused. Frozen capsules and both archived receipts are unchanged.
The focused Make product boundary passed13 cases with28 MODEL fixtures; the
agent's two final runs and independent parent rerun produced identical SHA256
`773d73f7867f1b6014dc44fcc9c2f17ed3fc10a8bf66e3b9a46f5eb78225e073`.
The parent-verified source/schema/custody handoff SHA256 is
`41e6969d6506c75c6ff5b4999c56d2dfa04bd39795b6cc5c4293c2e50d24fc38`.
The new recovery05 and healthy observation/deployment10 scopes retain the
actual successful campaign04 history, not a new rollback trial or promoted old
history. No recovery authority or hardware result comes from this qualification.
Full exposed-userdata readbacks, independent ordinary RF and any exact
contact-timestamp review retain their separate ROOT admissions.

Distinct ROOT readbacks subsequently completed with exit0 and an exact full
protocol-visible comparison against the genuine campaign04 preupload inventory:
all five contacts, all40 channels, settings/ACL and self-info matched. The
normalized userdata SHA256 remained
`a98461062125d68b01f5784de581af2a7fc71f857f27a9a0884d20bd6b4bf80f`;
the readbacks receipt SHA256 is
`93db23689b575331eab8b0b578e8b332f8f1c37e87f7fa339e0e2b4ccf0742ac`.
The bounded30-second stage finished in approximately2 seconds with exact
diag-conf05/floor4, failed counter8/generation18, core0 and sampled normal TX2.
All four radio readings retained actual count0; no host zeroing, RF or settings
write was performed. Hidden keys, unexposed storage and atomicity are not proven.

A further distinct ROOT admission executed the once-each ordinary RF commands.
Both directions had observed signature verification and native acceptance on
the guarded normal2dBm profile, but the overall recovery stage failed with exit2:
the receiver's same-session radio fault count increased0->1. Its later samples
were healthy and stable at1; that does not cancel the new observed fault.
The immutable failed peer receipt SHA256 is
`15bae4ddf895bc1321e088978ba9437b411c0c52671a36f39aaf2adf0fe2b330`.
The post-RF inventory recorded only the stock contact's last-advert and lastmod
timestamp changes; channels and all other exposed fields were unchanged.
No metadata-acceptance stage was admitted after the failed radio gate.
Observed signed traffic is not cryptographic proof of fresh command causation,
and neither the fault's cause nor continuous reliability is established.
The consumed failed stage is not retried or promoted. Recovery and healthy
deployment remain blocked; the transmit fix is still unsigned and uninstalled.

A distinct degraded-radio bootstrap source is now independently accepted:
recovery06 collectors, deployment11 coordinator/materializer and owned
observer11 are wired through the production paths, not just a MODEL API.
Agent qualification and the independent parent Make run produced identical
product SHA256
`0cc6cc9ddf55df26a5fda0f39912efbe4dd65aea1515caec427996408c01ad3f`.
The boundary passed13 production-path MODEL cases and21 API cases, including
real Ed25519/native-frame verification on synthetic fixtures; port, kernel,
process, clock and history leaves were simulated, not hardware evidence.
The independently verified source/schema/custody handoff SHA256 is
`0600b12b26b1d2cd78cca9a1c86384fb700aa7b63f4ccdd301afdc9eb92ffa70`.
All14 new source/Make bindings, shared dependencies,10 known frozen-source
pins and archived qualifications matched. Frozen04/05/09/10 sources and the
failed RF05 stage remain unchanged.

This path requires a separate explicit ROOT policy with budget0 or1 newly
observed preinstall ordinary-RF fault; absent, unlimited or exhausted budgets
are refused. It does not claim strict recovery, fault-free operation or RF
causation. Current health, core0, stable within-read counts, exact physical and
cryptographic identity, native session and floor remain mandatory. Fresh full
userdata and any exact changed-timestamp baseline review precede new RF;
an independent exact post-RF timestamp review follows it. Durable once-only
consumption precedes side effects, and failure cannot be replayed as authority.
The exact APP06 still needs separate preparation, signing, upload and launch
admissions, device-measured READY, trueARM and bounded COMMIT/restoration.
Native Installed8 and a new floor must then be followed by separate strict
full-userdata and both-way native RF checks with zero new faults. No actual
bootstrap authority, hardware operation or fix installation comes from source
acceptance; the fix remains unsigned and uninstalled.

**Live bootstrap remains blocked:** subsequent accessor review found that
strict genuine-history preparation populates the history namespace, while
policy materialization and recovery admission use a separate earlier copy.
The validated original-userdata summary is not propagated between them.
MODEL setup had supplied that field, masking the actual transition gap; the
passing source-only receipt does not qualify this genuine-history boundary.
No actual policy, admission, stage consumption or hardware operation followed.
A new recovery07/deployment12/observer12 source-only correction is underway;
accepted06/11 sources and all previous evidence remain frozen. The correction
must exercise strict preparation from an unprimed namespace before any live
bootstrap can be admitted.

**Routed retry software milestone:** the opt-in per-attempt wrapper preserves
the signed inner authority and native same-attempt deduplication. Attempts
advance only after send/queue acceptance, not during budget or queue refusal;
exhaustion stops the uploader explicitly. All14 owned paths are integrated
byte-exact. The final focused gate passed27 cases, reusing the prior672 native
and548 host cases rather than rerunning them.
Actual XIAO nRF and Solar companion/repeater, XIAO nRF non-OTA and Wio
companion/repeater compile/link cells passed. The Wio repeater's initially
missing declared library was restored through PlatformIO without changing
source, dependency declarations, SDKs or toolchains. Actual nRF ROLE0 RAM
is174276 (+16 versus04); Wio ROLE1 RAM is56764, with no matching baseline
delta claimed. Analyzed ARM roots, including IRQ104, bound3348/3456 for
XIAO ROLE0/ROLE1 and3332/3464 for Solar ROLE0/ROLE1, all within4096.
These are static analyzed OTA-root and compile results, not runtime stack
certification, installed routed firmware or physical multihop qualification.
Those routed changes were not included in the confirm04 RF image or prior
frozen04 artifacts. The installed diagnostic image uses the separately qualified
passive-diagnostics patch, not the routed-retry changes.

**Supervised client41 paired commissioning:** only the explicit Sense ROLE0
profile admits the selected550308 APP/ZIP above. The original Sense ROLE1/77
helpers and ordinary APP643072 ceiling remain unchanged. Do not use77 commands
with swapped serials or roles. Build, test and package into new directories:

```sh
make build-xiao-ota-client41-bootloader-pair \
  test-xiao-ota-client41-bootloader-pair \
  package-xiao-ota-client41-bootloader-pair
make verify-xiao-ota-client41-bootloader-pair-packages
```

ROOT must first retain actual41 primary/SDK evidence and the raw65536-byte
installer-slot baseline C4000..D4000, associated with the captured device and
unchanged read-only USB ancestry. For an already-frozen qualified pair, pass
explicit `XIAO_OTA_CLIENT41_PAIR_DIR` and `XIAO_OTA_CLIENT41_PACKAGE_DIR` to
the preload/primary aliases; their defaults do not select ROOT's host03 freeze.
Before primary transfer, arrange ONE
physical pin reset or an independently qualified target-only reset mechanism.
The reviewed GP_A8 activation path can remain in unlimited BLE DFU with no
USB endpoint; 1200-baud/DTR requires an enumerated APP and cannot rescue that
state. Do not start primary merely because firmware writes are authorized.
The commands below describe ROOT's reviewed write sequence, not authorization
for an agent to operate hardware:

```sh
make commission-xiao-nrf52-client41-preload
# ROOT: the existing one-shot companion USB request 0x13 + "reboot uf2".
# Require actual exact41 BOOT2886:0045 with CDC+MSC; ACK alone is insufficient.
make lab-mount-xiao-nrf52-client41-commission-uf2
make commission-xiao-nrf52-client41-primary \
  XIAO_OTA_CLIENT41_BASELINE_SLOT="$actual_precommission_raw_64KiB_slot"
# ROOT: the coordinated pin reset if GP_A8 remains in BLE; observe actual USB.
# Restore the SAME selected ordinary APP; do not retry the primary transfer.
make flash-xiao-nrf52-client \
  XIAO_NRF52_CLIENT_PACKAGE="$PWD/.tmp/live-app-contract/companion41-uf2-01/app-build/Xiao_nrf52_companion_radio_usb/firmware.zip"
```

Preload validates both packages before any touch, transfers compound then
waits for APP, transfers the SAME ordinary550308 APP then waits for APP.
Do not omit that second transfer: compound659548 makes the SDK extent exceed
643072 and correctly blocks runtime UF2 readiness. No runtime exception is
introduced. Explicit local-cache ABORT remains a separate prerequisite where
the existing request requires it.

The primary command validates the exact matched40KiB BOOT-only package,
stock Sense0.6.1/S1407.3.0/Nov12 2021 INFO and stable whole-volume read-only
mount. Before sending, it reads all compound659548 bytes and all slot65536
bytes: stage16476, FF throughC9000, captured C9000..D4000 unchanged.
This actual comparison is required because upstream ordinary-erase modelling
does not establish the installed Seeed fork's behavior. Failed readback stops
before primary; there are no automatic retries, resets, power-cycles or
unmount/remount operations. Transport completion does not verify primary SHA
or activation. Low APP27000..31000 staging means final ordinary APP restoration
and full userdata comparison remain ROOT's explicit responsibilities.

Administrator setup is a separate, explicit **normal MeshCore** operation:

```sh
make grant-xiao-nrf52-ota-client-admin \
  OTA_LAB_ARTIFACT_DIR="$PWD/.tmp/ota-rf-lab/client-admin-$(date -u +%Y%m%dT%H%M%SZ)"
```

Use a new evidence path for each invocation; the Make wrapper refuses any
already-existing artifact directory. It invokes
`scripts/ota_rf_lab.py --artifact-dir "$OTA_LAB_ARTIFACT_DIR" --grant-client-admin`
and only opens approved client
`4186AE911D94CDB1` and target `77CD44653A967172`, never Pine
`49C5BAF21EEF44A1`. After checking actual companion/repeater roles, distinct
normal full public keys and the complete ACL, it sends exactly
`setperm <64-hex-normal-companion-pk> 3` through the existing repeater text CLI
and requires exact `OK`. A complete ACL readback must show permission `03`
and preserve every unrelated entry; an already-admin client needs no write.
It does not change identities, name/radio/path settings, OTA authority,
candidates, journals or floors, and never reboots. After an acknowledged
mutation it waits six seconds for the ordinary lazy-save opportunity:
dirty contacts save 5000 ms after the latest contact update, and the
destructive-write gate can defer saving. Neither timing nor live ACL readback
proves durable persistence; a normal reboot does **not** flush the ACL.
MAIN must separately authorize a later normal restart and check the complete
ACL afterwards. Configure-only stays non-provisioning, monitoring stays
read-only, and the signed runner never grants permissions. This setup command
and its mocked tests make no hardware-success claim.

After the separately authorized normal restart, capture settings and the
complete ACL without repeating setters or an administrator grant:

```sh
make inspect-xiao-nrf52-ota-configuration \
  OTA_LAB_ARTIFACT_DIR="$PWD/.tmp/ota-rf-lab/configuration-after-reboot-$(date -u +%Y%m%dT%H%M%SZ)"
```

This read-only inspection records both identities, names, radio preferences,
path settings and the full target ACL. Compare them with the commissioning
capture. A settings readback is still not proof of on-air peer reception.

Repeater radio readbacks describe configured preferences, not the live radio
profile; applying them requires a separate reboot. Neither role's
configuration readback proves reboot persistence or peer reception.
Integer-kHz frequencies also accept their float32 MHz storage value truncated
to seven decimal places by the normal CLI, not a broad frequency tolerance.
The radio setter must return exactly `OK - reboot to apply`; name and path
hash setters return `OK`. Readbacks use the `> ` value prefix inside the
text reply. These formats match `CommonCLI.cpp`, not the older mock-only
assumptions. `make test-xiao-nrf52-ota-lab` continues to refuse
qualification before opening either port: paired configuration and mocked
host tests are not an end-to-end OTA result.

### Ordinary peer reception

After configuration and normal reboot, request a fresh ordinary radio advert
without starting an OTA campaign:

```sh
make qualify-xiao-nrf52-normal-peer \
  OTA_LAB_ARTIFACT_DIR="$PWD/.tmp/ota-rf-lab/normal-peer-$(date -u +%Y%m%dT%H%M%SZ)"
```

This explicitly transmits the target's normal zero-hop advert. It requires
matching approved radio preferences, the client's three-byte path setting
and the existing administrator ACL, then records radio arrival after the
request, bound to the target's full public key. It prefers native companion
advert notifications. A raw receive is accepted only after decoding the
ordinary advert and verifying its existing MeshCore Ed25519 signature.
Evidence distinguishes host verification from observed companion acceptance;
it does not establish fresh emission or replay resistance. A stale contact,
transmit ACK, unsigned raw key or unrelated peer is not success.
The probe rereads settings and the full
ACL without correcting them and records whether target path preferences were
exposed by the readback. It works before custom-loader commissioning and
never starts an image operation, grants permission or resets a board. Its result is only
target-to-client ordinary reception, not bidirectional, routed or OTA proof.
It requests at most three adverts, at least two seconds apart after each ACK,
within the same deadline. Normal packet/radio counters are diagnostic only,
never peer proof. Use a new evidence directory; the whole probe has a
30-second bound.

### Signed full-image qualification

`qualify-xiao-nrf52-signed-stage` and
`qualify-xiao-nrf52-signed-commit` exercise the signed production workflow,
not the retired raw sender. They require reviewed role-specific artifacts,
completed commissioning and the companion's existing administrator
permission on the target. They do not install a bootloader, grant
permissions, reset a board or bypass a conflicting candidate.

The OTA candidate must differ from the currently running bootstrap image.
A matching post-install hash is not replacement proof if those bytes were
already installed. Build a labelled bench candidate through the dedicated
profile, which inherits the existing role-1 OTA configuration and appends
only the guarded firmware-version definition:

```sh
make build-xiao-nrf52-ota-candidate XIAO_OTA_LAB_VERSION=ota-direct-001 \
  PLATFORMIO_BUILD_DIR="$PWD/.tmp/ota-direct-001"
```

Labels must start with a letter or digit and contain only 1 to 19 ASCII
letters, digits, dots, underscores or hyphens. Normal firmware defaults
remain unchanged. Preserve the resulting role-specific `firmware.zip`,
then extract that candidate package explicitly to a new image path:

```sh
make ota-lab-image \
  XIAO_NRF52_TARGET_PACKAGE="$PWD/.tmp/ota-direct-001/Xiao_nrf52_repeater_ota_usb_candidate/firmware.zip" \
  OTA_UPLOAD_IMAGE="$PWD/.tmp/ota-direct-001/candidate.bin"
```

Without the package override, the extraction target defaults to the
bootstrap profile, not the candidate. Compare the extracted SHA-256 with
the retained bootstrap image before creating the manifest. Record the
exact source tree and label with the immutable artifact inventory.
Do not replace inherited flags with `PLATFORMIO_BUILD_FLAGS`.

Select the expected BIN hash from the immutable artifact inventory and a
planned counter above the observed floor. Each invocation needs a new
artifact directory. For example, with the shell variables below set to
actual reviewed artifacts and completed evidence:

```sh
make qualify-xiao-nrf52-signed-stage \
  OTA_UPLOAD_IMAGE="$image" OTA_UPLOAD_MANIFEST="$manifest" \
  OTA_SIGNED_LAB_IMAGE_SHA256="$reviewed_image_hash" \
  OTA_SIGNED_LAB_COUNTER="$counter" \
  OTA_SIGNED_LAB_PROVENANCE="$artifact_inventory" \
  OTA_SIGNED_LAB_COMMISSIONING="$commissioning_capture" \
  OTA_SIGNED_LAB_MODE=directed OTA_LAB_ARTIFACT_DIR="$stage_dir"
```

The evidence references are recorded strings, not authenticated receipts
or a new commissioning authority. They cannot substitute for actual board
observations. The runner independently reads current identity, settings,
ACL and floor. It captures `baseline.json` before candidate installation
and writes `ready.json` only after fresh, complete READY. Stage never
commits. The original public-key baseline was not captured; these
readbacks do not prove recovery of the lost original application.

Commit is deliberately separate:

```sh
make qualify-xiao-nrf52-signed-commit \
  OTA_UPLOAD_IMAGE="$image" OTA_UPLOAD_MANIFEST="$manifest" \
  OTA_SIGNED_LAB_IMAGE_SHA256="$reviewed_image_hash" \
  OTA_SIGNED_LAB_COUNTER="$counter" \
  OTA_SIGNED_LAB_PROVENANCE="$artifact_inventory" \
  OTA_SIGNED_LAB_COMMISSIONING="$commissioning_capture" \
  OTA_SIGNED_LAB_READY_RECORD="$stage_dir/ready.json" \
  OTA_LAB_ARTIFACT_DIR="$commit_dir"
```

Use identical candidate and evidence inputs. The runner requires fresh
READY, observes a firmware-initiated disconnect and re-enumeration, then
checks candidate-bound remote Trial and Installed, the verified running
hash, counter and confirmed floor, and preserved identity, settings and
ACL. Missing remote reboot is a blocked outcome, not repaired by a USB
reset. Denied or uncertain COMMIT is not installation success.

Remote Trial observation is a stricter lab criterion than normal COMMIT.
A short trial can be missed at 2% airtime; that leaves lifecycle
observation incomplete, rather than proving installation failed. The
runner never fabricates or forces a trial.
It still collects Installed, hash, floor and preservation evidence in
`installed.json`, then reports `remote_trial_not_observed` with
`remote_install_qualified` false. A failed qualification is not permission
to commit the already-installed candidate again.

Select `OTA_SIGNED_LAB_MODE=direct` for 908525 kHz and 60-second leases;
firmware restores the normal profile on expiry, then uses a fresh
authenticated handshake to resume the durable bitmap. This is not
indefinite lease renewal. Background requires an existing
configured channel through `OTA_SIGNED_LAB_CHANNEL`. The default share
is 2%, with a 72-hour host timeout, not a completion guarantee. A
supervised full-image smoke run requires
`OTA_SIGNED_LAB_DUTY=95000` (95%) or `100000` (100%), together with
`OTA_SIGNED_LAB_EXTRA=--supervised-full-image-smoke`; it is not 2%
acceptance. Both peers may use the separately verified 250 kHz bench
profile; the default remains 62.5 kHz. Use the same mode, duty share and
supervision settings for stage and commit. To resume the same candidate, pass
`OTA_SIGNED_LAB_EXTRA='--baseline-record /path/to/prior/baseline.json'`.
Different local-cache content still requires an independent, explicit
abort, not force-overwrite.
After that abort, stage requires fresh local ABORTED evidence consistent
with the companion's lifecycle before and after baseline capture. Only
then does it explicitly restart the cache. An active conflicting cache,
missing evidence or a changed snapshot remains a refusal.

Stage records baseline, periodic, READY and end/restoration measurements
between existing STATUS exchanges. Use
`OTA_SIGNED_LAB_EXTRA='--measurement-interval 5'` for the default five-second
sampling interval; the accepted range is 0.1 through 5 seconds. Combine it
with `--supervised-full-image-smoke` for the separately authorized high-duty
run. Nonzero driver faults, failed radio applications, TX timeouts or lost
airtime records prevent measurement qualification.

Ordinary peer reception must be bracketed by fresh RECEIVING progress,
not inferred from transmission totals. Sampled 2% software-budget evidence
requires a full-window observation, consistent accounting and new completed
OTA charges as well as independent ordinary service. A short smoke run or
missing coverage does not pass that gate. The runner does not establish a
continuous PHY duty guarantee, physical multihop, fleet contention or
power-cut recovery. Tests and recipes alone are not a hardware result.

The new USB-enabled nRF52 lab firmware exposes `ota radio` and `ota budget`
on the repeater, and companion selectors `42 00 03` and `42 00 04`.
These report checked driver-applied radio settings and completed software
TX timing, not independently measured chip registers or RF airtime.
The [developer contract](lora_ota_development.md#read-only-radio-and-airtime-evidence)
defines the fields and failure counters. Hardware acceptance still requires
fresh RF progress, normal service during on-mesh transfer and observations
through direct expiry, restoration and a second applied interval. Do not
substitute stored radio preferences for those observations.
The current STATUS ABI exposes durable counts, not bitmap bits or the
fresh handshake token/ACK. Direct interval and progress observations
therefore remain distinct from a separate wire-handshake witness; the
runner does not invent missing handshake evidence.

The repeater transport also reads `get acl`, whose output has no closing
marker. It waits for the echoed reply to a following `get role` command
instead of treating a quiet serial port as a complete ACL. An in-memory
ACL entry does not prove that `setperm` has saved it: qualification must
allow the lazy-save opportunity and verify the complete ACL after a separately
authorized restart; restarting does not itself flush dirty contacts.

## Why these mechanisms

**Mode detection uses the USB product ID, not product strings.** The Adafruit
nRF52 core sets bit 15 of the PID in the application and clears it in the
bootloader (`0x8044` vs `0x0045`). Product strings differ between board
variants and between modes, so matching on them is unreliable.

**Bootloader entry opens the port at 1200 baud and drops DTR.** The core
triggers on the DTR high-to-low edge at that line rate. Re-rating an
already-open port with `termios` works on some boards and silently does nothing
on others.

**Discovery waits for the by-id symlink.** A board appears in sysfs before udev
applies permissions and creates the stable symlink. Acting on the raw
`/dev/ttyACMn` node in that window fails with `EACCES`.

**Flashing drives `adafruit-nrfutil` directly.** PlatformIO's uploader always
issues its own 1200-baud touch and then rediscovers the port by scanning, which
fails when the board is already in DFU or when numbering shifts mid-upload.
Pointing `adafruit-nrfutil` at an already-resolved DFU port is deterministic.

**Power cycling uses `uhubctl -f`, never the sysfs `authorized` toggle.** The
`authorized` toggle looks like a reasonable fallback but leaves the
nRF52840 USB stack wedged (`can't set config #1, error -32`), recoverable
only by a real power cut or a physical reset. It cost the lab one board
before this was understood.

## Protected power domains

The bench hubs report ganged power switching: forcing a port off/on with
`uhubctl -f` can affect every device sharing that hub, not just the port
you asked for. `scripts/lab_device.py` therefore refuses to run `uhubctl`
against **any** hub that also carries a device listed under `[protected]`
in `lab/devices.ini`, even with `-f`, even for a role that isn't itself
protected.

Hub paths change when boards are reattached. The tool checks the actual
power domain at the time of the request, using the protected serial
inventory rather than an old bus number. A refusal means a physical reset
or replug is required; do not bypass it with a direct `uhubctl` command.
`make lab-doctor` reports protected shared domains as
`physical reset required`.

## What this lab has verified for LoRa OTA

This bench pair is used to qualify LoRa OTA. Earlier firmware demonstrated
application-level radio behaviour and raw/staged flash correctness, but
that transport has been retired. Those captures do not qualify the
replacement's signed companion-to-repeater transfer or installation.
The custom bootloader has separate artifact and simulated-recovery evidence;
installed recovery remains unproven. See the
[LoRa OTA developer guide](lora_ota_development.md#current-hardware-evidence)
for the current, dated evidence ledger and its explicit gaps before quoting
any hardware result from this lab elsewhere.

On 2026-10-01, the existing read-only diagnostic on each approved board
returned its full internal-flash and QSPI contents for comparison with its
authenticated encrypted archive. Both comparisons matched byte for byte.
That comparison issued no flash, reset, power cycle or install command, and
the protected board was not opened. This establishes preservation of the
captured media, not a mesh connection or a working OTA installation.

The eight-profile firmware gate passed for `bda99d13`, and its immutable,
role-specific applications were flashed to both approved boards.
The first companion NAME setter (`0x08`, `OTA-LAB-CLIENT`) returned
`0104 BAD_STATE` before mutation, blocking normal commissioning at that
revision.

The reviewed `7e3066b9` diagnostic applications subsequently passed the
six affected OTA profile builds and were flashed to the same pair.
Read-only inspection identified the refusal on both boards: valid bank 0,
blank custom-loader marker and stored SDK CRC `0000`, with nonzero calculated
image CRCs. The stock Adafruit bootloader intentionally uses zero to mean
that its optional CRC check is disabled; normal serial DFU writes that
sentinel. This finding did not authorize changing the qualified loader's
integrity checks.

On 2026-10-02, reviewed and gated `6e0b63be` applications corrected that
stock-only compatibility issue on both boards. Actual preflight readbacks
reported healthy stock boot, ordinary writes allowed and cache-only OTA.
Both accepted `OTA-LAB-CLIENT`/`OTA-LAB-TARGET`, 907.525 MHz, 250 kHz,
SF7, CR5 and three-byte path preferences without changing their public keys.
The separate normal administrator grant added only client permission 3.
After the six-second save opportunity and normal protocol reboots of both
boards, read-only inspection at `06:25:47Z` confirmed the same identities,
names, radio preferences, client path mode and complete target ACL.
It issued no setters or replacement grant. This establishes persistence
across those reboots, not by itself on-air peer reception or OTA installation.
At `07:27:09Z`, the bounded ordinary-advert probe passed on the same
profile after two requests: the companion produced the target's native
advert notification in 4.194 seconds, and host verification independently
validated the received advert's existing MeshCore signature. Both identities,
names, radio/path preferences and the complete target ACL were unchanged
afterward. This proves target-to-client ordinary reception only. The two
earlier probe timeouts remain failed runs, not retrospectively passed
qualifications.
The reviewed recovery corrections in `e62cf33b` subsequently passed the
immutable software gate: fresh application fixtures, all four production-C
boot drivers and the C++ consumer of their actual rollback outputs, under
both original SDK CRC policies. Cache cut-and-retry coverage, 345 host tests
and all six OTA firmware profile builds also passed.
The newly preserved, role-specific applications were flashed to both approved
boards. Read-only inspection at `09:15:35Z` confirmed their existing identities,
names, radio/path preferences and complete target ACL without reconfiguration.
Both still reported healthy stock boot, ordinary writes allowed and cache-only.
The target-only loader installer then passed artifact validation but refused
the vendor's actual stable boot-port product name before writing. Its
identity check now reuses the shared lab device resolver rather than a
product-name template, retaining the approved serial, Seeed vendor,
bootloader mode and stable by-id requirements. Read-only inspection in the
mode requested by the 1200-baud helper found CDC but no mass-storage
interface or mounted UF2 volume. Vendor and Arduino source inspection
then established why: that helper deliberately selects serial-only DFU,
which hides mass storage. The vendor has a separate UF2-entry API and a
physical double-reset path. Their existence does not establish today's
boot configuration or board compatibility. The volume and Board-ID guards
have not been bypassed.
No qualified target-loader installation, replacement-protocol radio OTA
transfer, READY, COMMIT, installation or rollback has been performed.

The uploader must remain on the stock bootloader, with only cache staging
available after its preflight succeeds. The ordinary settings-write
refusal is not permission to install a custom uploader loader.
Torn and partially erased cache metadata now has native cut-and-retry
coverage. Physical power-failure recovery remains unqualified. This is not
production qualification.

The archives contain the diagnostic applications, not the lost original
502,300-byte application artifact. The original public-key baseline is also
absent. New captures can preserve evidence going forward, not restore the
lost original identity. Preserve newly qualified, role-specific recovery
packages before commissioning. Destructive power-cut qualification is
deferred because the target shares a protected power domain; do not bypass
that protection or describe power-failure recovery as physically qualified.

The **historical 2026-09-30T12:26:14Z stock-only integration run passed**:
the signed 320-byte RF-to-QSPI fixture completed, and ordinary advert
allocation and expected-peer reception succeeded under 2% OTA pressure.
Usage stayed at 71,822/72,000 ms; the ordinary advert arrived in 0.983 s
without consuming that OTA budget. Paired post-run reads confirmed that
all eight boot-journal sectors remained blank. Evidence is in
`.tmp/ota-rf-lab/stock-policy-allocation-fixed-qualification/` and
`.tmp/ota-boot-preflight/stock-policy-allocation-fixed-after-qualification/`.
This supersedes the failing `stock-floor-gated-*` artifact, whose missing
descriptor-format policy and raw-injection allocation reserve were fixed.
It proves stock-only staging and that revision's two-board fairness witness,
not the current receiver, a firmware installation, reboot resume or completed
multicast repair. The earlier stage, airtime and boot-journal commands have
been removed; preserved captures remain historical evidence only.

## Bootloader commissioning

The obsolete binary boot-journal reader and historical floor-erasure helper
have been removed. They were written for a different companion-only lab
protocol, not the current text repeater or durable candidate records.
Never clear confirmed-floor or transaction sectors to make an update pass.
An erased journal does not identify the installed bootloader or qualify it.

Before commissioning, preserve identity, configuration and a validated
recovery package. Use only the guarded installer for a package whose board,
role, complete flash load and boot-info marker have been checked. Follow the
[nRF52840 QSPI and bootloader guide](lora_ota_nrf52840_qspi.md) for geometry
and physical acceptance requirements. Artifact verification alone is not
installed recovery qualification.

UF2 identity inspection requires a real mass-storage interface and exactly
one mounted UF2 volume belonging to the approved target's USB serial.
Its `INFO_UF2.TXT` Board-ID must match the supported board. A CDC-only
serial DFU port does not provide that volume, regardless of its product
name. The 1200-baud application-flash helper selects serial-only DFU, not
UF2 mode. Do not fabricate a mount or bypass the Board-ID check.

With the matching bench application, first capture the target's current
MBR and UICR address words through the read-only preflight:

```sh
make inspect-xiao-nrf52-ota-preflight OTA_LAB_REQUIRE_BOOT_ADDRESSES=1 \
  OTA_LAB_ARTIFACT_DIR="$PWD/.tmp/ota-rf-lab/boot-addresses-$(date -u +%Y%m%dT%H%M%SZ)"
```

The inspection requests only public boot metadata, never a memory dump,
reset or repair. It derives the effective boot and parameter addresses
from the flash words, falling back to UICR only when a flash word is
`FFFFFFFF`. It requires `000F4000` and `000FE000`, matching reported
derived values and allowed early and later ordinary-write diagnostics.
Missing or malformed tuples, and zero, erased or incompatible effective
addresses, fail explicitly.
This establishes address compatibility only: current UF2 Board-ID, CF2,
artifact and installed-loader checks remain separate requirements.

Then request the vendor's separate UF2 mode through that application's
local USB CLI:

```sh
make lab-bootloader-uf2-target
```

This target-only helper requires the approved application-mode serial and
stable by-id identity, an acknowledgement for the current command,
observed USB disappearance and bootloader re-enumeration with a real
mass-storage interface under the target's USB ancestry. It has no
1200-baud fallback and refuses an already-running serial DFU bootloader.
The firmware refuses non-USB requests and active OTA transactions or
unresolved boot verification, and rechecks those guards before entry.
The helper neither mounts a volume nor writes firmware. Mount the
serial-matched volume separately, then read its current `INFO_UF2.TXT`
and complete the board and artifact checks. Do not copy a bootloader
update to this volume. Successful UF2 entry alone proves neither package compatibility
nor an installed recovery loader.

The approved target passed this address and UF2-entry sequence on
Oct. 2, 2026, using the reviewed `47b40e59` bench application. Its current
volume reports Board-ID `Seeed_XIAO_nRF52840_Sense` and USB identity
`2886:0045`, not the base package's CF2 identity `2886:0044`.
The virtual `CURRENT.UF2` does not expose the bootloader region, so it
cannot establish the current CF2 contents. Keep that distinction:
current public identity can qualify a matching vendor board profile,
but an old archive cannot serve as a fresh CF2 readback.

**Latest physical commissioning result, Oct. 2, 2026:** the immutable
`47b40e59` application was restored through stock serial DFU. Fresh
address and configuration readbacks at `13:24:51Z` preserved the identities,
radio/path preferences and complete target ACL. Read-only, address-selected
application bytes from `CURRENT.UF2` independently matched its full
536,152-byte SHA-256 at `13:32:40Z`. Only application bytes were retained;
this did not read or qualify the bootloader or CF2.

The reviewed `0.11.0` Sense bootloader-only serial package subsequently
passed the actual stock identity, package and fresh-address guards.
Vendor transport reported completion, but the target disconnected at
`13:46:21Z` and did not return on USB, including after one target-only
physical reset. The cause remains unproven. No application restoration,
bootloader retry or filesystem erase followed. Installed-loader,
genesis-floor and radio-installation acceptance therefore remain
**blocked**, not passed. Do not repeat commissioning or bypass its guards
to recover an inaccessible board.

The [incident analysis and SWD arrival notes](lora_ota_bootloader_failure_notes.md)
separate transfer acknowledgement from activation, record the exact failed
artifact and recovery input, and describe how the first capture will
guide triage of startup stalls, faults and MBR/loader-selection problems.

## Non-erasing SWD diagnosis

**Target recovery and physical SWD diagnosis remain paused.**
Target `3BE94917B92DC5E9` is still inaccessible
after the `13:46:21Z` vendor bootloader-only DFU transport acknowledgement;
reset and power reconnect did not restore USB. Actual cause is **unknown**.
That acknowledgement is not installed-loader proof. The `13:24:51Z` address
evidence is expired and must not be reused or re-stamped. For this SWD
workflow, leave the healthy client `4186AE911D94CDB1` and protected Pine
`49C5BAF21EEF44A1` untouched. The separate user-authorized client-only
application/local-cache validation above is not paused by this target failure.
The Raspberry Pi Debug Probe **SC0889** (CMSIS-DAP), XIAO Expansion Board
**103030356**, and spare **102010469** are being ordered. No diagnosis has
been acquired with this helper.

After equipment arrives, the user must identify the physical approved target
and the exact probe UID and authorize this physical workflow. Published
connector mapping is documented below; actual fixture revision, seating and
contact continuity remain unverified. Power the target normally from USB; connect only
**common GND, SWDIO and SWCLK**, with **3.3 V target logic**. Leave probe power
outputs and target reset disconnected: no probe-powered target or reset wire.
Do not attach to another board to try the procedure.

**One-time manufacturer pinout qualification, Oct. 2, 2026:** this is a
conditional wiring reference, not permission to connect. Use the SC0889
**D / DEBUG** connector, not **U / UART**. Its numbered DEBUG interface is
pin 1 SWCLK, pin 2 GND, pin 3 SWDIO, with nominal 3.3 V I/O and no VTREF
or target-power pin. The manufacturer's cable drawing locates the pin-1
mark on the underside; do not infer socket left/right or trust cable colours.

| SC0889 D / DEBUG | Expansion Board 103030356 J7 |
|---|---|
| Pin 1, SC / SWCLK | Pin 1, SWCLK |
| Pin 2, GND | Pin 4 or 5, GND |
| Pin 3, SD / SWDIO | Pin 2, SWDIO |

J7 is **not a standard 10-pin ARM debug header**. Seeed's v1.0 board drawing,
viewed from the top/component side with the XIAO socket to the left, gives:

```text
1 SWCLK       8 RX
2 SWDIO       7 TX
3 SYS_3V3     6 VBOOST_5V
4 GND         5 GND
```

**J7.3 is not ground; J7.6 is boosted 5 V.** Leave both power pins and
the UART pins unused. Use the explicit GND connection for the common signal
reference. Do not add another fixture power source or drive an unpowered
target from a powered probe.

The published non-Plus nRF52840 **Sense V1.1** design maps the expansion
contacts U2.17 to TP3/SWDCLK, U2.18 to TP5/SWDIO, U2.16 to TP1/GND, and
U2.15 to TP2/RESET. Header-aligned nominal contact centres fall within the
published Sense lands. This supports the planar electrical mapping, not
verified fit to the inaccessible target's revision, pogo stroke, tip clearance
or header seating. Check the received revisions and contact continuity before
any probe connection; do not substitute SAMD/ESP compatibility marketing.

**Reset caveat:** the stock base already connects its RESET pogo to onboard
button K2. Leaving out an external reset wire does not physically isolate that
contact. Do not press K2. The unmodified fixture does not meet a literal
reset-disconnected setup; resolve this explicitly with the user before use,
without silently changing the setup or modifying the fixture.

Primary references: Raspberry Pi's
[connector specification](https://pip-assets.raspberrypi.com/categories/885-raspberry-pi-debug-probe/documents/RP-008189-DS-1-debug-connector-specification.pdf),
[DEBUG cable drawing](https://pip-assets.raspberrypi.com/categories/885-raspberry-pi-debug-probe/documents/RP-008190-DS-1-debug-swd-cable-specification.pdf)
and [product brief](https://pip-assets.raspberrypi.com/categories/885-raspberry-pi-debug-probe/documents/RP-008193-DS-1-raspberry-pi-debug-probe-product-brief.pdf);
Seeed's [Expansion Board v1.0 Eagle design](https://files.seeedstudio.com/wiki/Seeeduino-XIAO-Expansion-Board/document/Seeeduino%20XIAO%20Expansion%20board_v1.0_200824.brd)
and [Sense V1.1 KiCad design](https://files.seeedstudio.com/wiki/XIAO-BLE/Seeed-Studio-XIAO-nRF52840V1.1-KiCad-Project-260105.zip).

`scripts/swd_diagnose.py` is independent of USB application/serial discovery.
It requires the explicit full probe UID and approved target serial/role in
`lab/devices.ini`'s authoritative `[recovery] target`, not the replacement
radio `[roles] target`. A present malformed/missing recovery target is refused;
it never falls back to the active radio target. Legacy inventories without a
recovery section still require the original hard-approved failed serial.
The helper ignores role environment overrides and has no first-probe
fallback. CMSIS-DAP discovery occurs **only** in the physical `diagnose`
command; native tests never import pyOCD or open probes.

The qualified optional dependency/API is **pyOCD 0.43.1**. It is not needed for
help or native tests. If physical invocation reports it missing, install
that version in a private repo-local virtualenv, not shared/global Python:

```sh
make tmpdir
TMPDIR="$PWD/.tmp" python3 -m venv .tmp/swd-venv
TMPDIR="$PWD/.tmp" PIP_CACHE_DIR="$PWD/.tmp/pip-cache" \
  .tmp/swd-venv/bin/python -m pip install 'pyocd==0.43.1'
```

Then use:

```sh
make test-xiao-nrf52-swd-diagnosis
# PHYSICAL TARGET/SWD — do NOT run while target recovery is paused:
make diagnose-xiao-nrf52-target-swd \
  SWD_DIAGNOSE_PYTHON="$PWD/.tmp/swd-venv/bin/python" \
  SWD_PROBE_UID='<complete UID of the user-identified SC0889>' \
  SWD_TARGET_SERIAL=3BE94917B92DC5E9 > approved-target-swd.json
```

Use `SWD_DIAGNOSE_PYTHON=/path/to/python` for a separate dependency environment.
In the current lab, `.tmp/swd-venv` is not present. The already retained
`.tmp/swd-pyocd` prefix was imported offline successfully as pyOCD 0.43.1 with
the builtin NRF52840 target, without probe enumeration or a Session.
It needs no reinstall: use `PYTHONPATH="$PWD/.tmp/swd-pyocd"` on the Make
invocation and `SWD_DIAGNOSE_PYTHON=python3` instead. This dependency check is
not physical probe/target qualification; all arrival and authorization gates
above still apply.
`make test-ota-lab-host` also discovers the product safety tests.
The JSON and process exit must both be checked: `ok: false`, acquisition or
state-restoration/teardown errors, or a nonzero exit are **not** a completed
readout. Failed/missing/protected debug access means **stop**; never
automatically retry, unlock, recover, mass erase, flash, or reset.

**One-time offline API/init qualification, Oct. 2, 2026:** the installed
pyOCD 0.43.1 safety-critical sources were inspected and 15 source files matched
the public version tag, without connecting to hardware. There is no recurring
pyOCD/Make infrastructure qualification target. Physical invocation checks the
qualified API version, built-in NRF52840 class and effective safety options
before attach; unsupported/unsafe configurations fail explicitly, without an
automatic dependency download, upgrade or retry.

The supported `no_config=True` option suppresses default/cwd and probe-specific
configuration. It does **not** suppress the separate Python user-script loader:
the diagnostic Session subclass makes `_load_user_script` a no-op. Only this
helper's restricted init delegate is installed. Exact full UID equality is
checked **before constructing the Session**, not through ConnectHelper's
substring selection. Before `session.open()`, the helper checks the actual
built-in NRF52840 class and every effective safety option, including disabled
pack/cbuild-run overrides. Offline product tests exercise these guards and the
script suppression without importing an installed pyOCD or opening any probe.

The reviewed public sources are:

- [NRF52 security/init](https://github.com/pyocd/pyOCD/blob/v0.43.1/pyocd/target/family/target_nRF52.py):
  default `auto_unlock` can mass erase and `persist_unlock` can write UICR.
  This helper explicitly sets `auto_unlock=False`, replaces the security task
  with a read-only CTRL-AP APPROTECT refusal, and removes both unlock tasks.
- [CoreSight attach](https://github.com/pyocd/pyOCD/blob/v0.43.1/pyocd/coresight/coresight_target.py)
  and [Cortex-M](https://github.com/pyocd/pyOCD/blob/v0.43.1/pyocd/coresight/cortex_m.py):
  `connect_mode=attach` skips reset and halt; this helper also suppresses core
  init's DHCSR rewrite (C_HALT can be unknown when C_DEBUGEN is clear).
  `resume_on_disconnect=False` plus explicit non-resuming teardown
  prevents detach from resuming a preexisting halted CPU. The helper only
  resumes a CPU it temporarily halted from an initially running or sleeping
  state. Original DHCSR.C_DEBUGEN is measured before halt and verified again
  during cleanup. After successful normal resume, originally disabled halting
  debug is restored by the single direct volatile write `DHCSR=0xA05F0000`.
  Originally enabled debug is preserved. Failed/no-op resume never triggers
  that clear as a forced-resume workaround. DEMCR/TRCENA are never rewritten.
- [Session](https://github.com/pyocd/pyOCD/blob/v0.43.1/pyocd/core/session.py),
  [discovery](https://github.com/pyocd/pyOCD/blob/v0.43.1/pyocd/coresight/discovery.py)
  and [CMSIS-DAP transport](https://github.com/pyocd/pyOCD/blob/v0.43.1/pyocd/probe/pydapaccess/dap_access_cmsis_dap.py):
  config/pack overrides and separate user scripts are disabled; flash object
  creation and non-core FPB/DWT initialization are removed. Connect/disconnect
  use debug transport operations, not target reset or flash programming.

The security gate precedes system-memory discovery. The full public FICR
DEVICEID and chip part are verified **before core creation or any halt/resume**,
not inferred from an application serial. The pinned vendor
[`usb_desc_init`](https://github.com/adafruit/Adafruit_nRF52_Bootloader/blob/c67f0bcf0fa8e841426335b1bbde91cda6ca1f50/src/usb/usb_desc.c)
constructs its TinyUSB serial from the eight little-endian FICR DEVICEID bytes:
`DEVICEID[1]` then `DEVICEID[0]`, each eight uppercase hexadecimal digits.
Its pinned TinyUSB `9775e76910d569ec73b8dd946f3fa5fe5414acdb`
[`GET_DESCRIPTOR` path](https://github.com/hathach/tinyusb/blob/9775e76910d569ec73b8dd946f3fa5fe5414acdb/src/device/usbd.c)
uses the vendor string callback, not a different chip-ID construction.
Another chip/serial, APPROTECT, missing core, or uncertain CPU state refuses
without reset, erase, unlock or a fallback.

Only individual whitelisted public words are acquired: FICR identity,
flash `0xFF8/0xFFC`, UICR `0x10001014/0x10001018`, two words at the effective
page-aligned boot vector **within `0xF4000..0xFD000` only**, the SDK header
`[0xFF000,0xFF01C)` (exactly 28 bytes/seven words), the first 16 bytes of the
known OTA marker at `0xFDC00`, DHCSR `0xE000EDF0`,
SCB fault/status words, CPU PC/SP/LR/xPSR/MSP/PSP, public WDT
RUNSTATUS/CONFIG/CRV, RESETREAS/GPREGRET and the single reserved
double-reset RAM word described below. pyOCD additionally reads
DP/AP and CoreSight discovery/debug metadata; it does not dump ROM, flash,
RAM, filesystems or QSPI. InternalFS `0xED000..0xF4000`, ExtraFS
`0xD4000..0xED000`, keys/configuration and OTA journal sectors are never read
or written. An untrusted effective boot pointer is recorded but never chased
into those regions. The pinned `nrf_mbr.h:71` defines `MBR_BOOTLOADER_ADDR`
as **`0xFF8`**, not the NMI vector at `0x8`. Previous address evidence remains
expired; correcting this source-derived address does not re-stamp old data.
A boot-vector policy refusal records `boot_vector: null` and a `boot_vector`
error with the rejected address, then continues SDK/SCB/WDT metadata and CPU
capture subject to identity/watchdog guards. Its JSON remains failed and exit
is nonzero. Actual read/transport failures on legal words remain fatal.

The pinned Nordic `lib/nrfx/mdk/nrf52840.h` register definitions establish
WDT RUNSTATUS `0x40010400`, CONFIG `0x4001050C`, CRV `0x40010504`,
POWER RESETREAS `0x40000400` and GPREGRET `0x4000051C`. These status reads
neither clear reset reasons nor feed/reconfigure the watchdog. The pinned
`nrf52840_bitfields.h` defines CONFIG.HALT at **bit 3**: clear means pause
while debugger-halted, set means keep running. This is interpreted only from
fresh readback, not the retained trial loader's settings. An active watchdog
configured to run during halt, or an unrecognized RUNSTATUS, blocks a new
halt/snapshot of an initially running or sleeping CPU; its public
status and other completed reads remain in the explicit failure JSON.
The pinned vendor [`main.c`](https://github.com/adafruit/Adafruit_nRF52_Bootloader/blob/c67f0bcf0fa8e841426335b1bbde91cda6ca1f50/src/main.c)
and [`linker/nrf52840.ld`](https://github.com/adafruit/Adafruit_nRF52_Bootloader/blob/c67f0bcf0fa8e841426335b1bbde91cda6ca1f50/linker/nrf52840.ld)
agree on `DFU_DBL_RESET_MEM`/`DBL_RESET`: **one 32-bit word at `0x20007F7C`**.
Both retained OTA linker variants reserve the same address. Only that word
is read; adjacent NOINIT bond-sharing memory at `0x20007F80` and every other
RAM data address remain outside the whitelist. A magic value is reference
boot metadata, not installed-loader proof.

The **expected**, not currently measured, canonical values are MBR boot/params
`FFFFFFFF/FFFFFFFF`, UICR boot/params `000F4000/000FE000`, and effective
boot/params `000F4000/000FE000`. Fresh results separate these expectations from
actual reads and timestamp all acquisitions/errors. SDK/image metadata may be
malformed; raw public words are
reported, never silently repaired or treated as a validated image.
Halt/resume and enabling debug affect **volatile state and timing**, and resume
clears volatile debug cause bits; SCB fault/status is sampled beforehand.
Running and sleeping are both runnable states; either may be observed after
resume (including a wake from sleep). CPU-state and C_DEBUGEN restoration
flags are separate, and any read/write/verification error fails the workflow.
The helper never resumes a preexisting halted CPU. Firmware can still act during ordinary execution;
this workflow is not a proof against firmware-originated writes or hardware
faults. Installed image identity, USB recovery, counter floor and radio
acceptance remain blocked. Any later comparison or symbolication using a
retained supplied ELF (e.g. `63d1ccf9…`) or raw image (`abb02642…`) is
**reference-only**, never proof that those bytes are installed.

**UF2 self-update is blocked for this layout.** The retained upstream
0.6.1 and pinned vendor sources stage the bootloader update at
`0xE0000..0xEA000`, inside protected ExtraFS, before copying it to the
bootloader slot. Checking only the UF2 destination addresses misses that
indirect write. This is a source-derived preservation conflict, not an
attestation of the installed Seeed binary's exact lineage.

Commissioning must instead use the ordinary vendor serial bootloader-only
workflow with the exact reviewed Sense boot span and proven MBR/UICR
addresses. That workflow deliberately overwrites application staging but
does not overlap either filesystem in the verified SINGLEBANK source.
Restore the immutable qualified application separately, then recheck
healthy boot, identities, configuration and the complete ACL before
accepting a genesis floor. A DFU acknowledgement or process exit status
alone is not installation proof.

The reviewed factory-initialization loader can create the initial durable
floor only with verified flash, healthy vendor boot evidence and all eight
journal sectors erased. It does not erase existing history. After the first
normal boot, commissioning must establish a **present, valid** counter-0
floor with zero extent and zero image hash, followed by install-capable
application status. A default counter getter returning zero is not that
proof. If initialization did not complete, leave installation unavailable;
do not clear a damaged or historical floor to make commissioning pass.
The original application remains unconfirmed until an authorized candidate
completes the normal install and confirmation lifecycle.

With the matching application and reviewed loader installed, require that
actual first-boot record through the existing read-only inspection:

```sh
make inspect-xiao-nrf52-ota-preflight OTA_LAB_REQUIRE_GENESIS_FLOOR=1 \
  OTA_LAB_ARTIFACT_DIR="$PWD/.tmp/ota-rf-lab/genesis-readback-$(date -u +%Y%m%dT%H%M%SZ)"
```

The target must report install capability, ordinary writes allowed and
`floor=present seq=00000001 ctr=00000000 ext=00000000`, an all-zero
64-digit image hash and `io=ok`. Missing, blank, damaged or unreadable
fields fail this gate; no values are supplied by default. The uploader
remains stock and is not expected to have a floor. This command observes
the record and cannot create, repair or erase it.

`make validate-xiao-nrf52-client-archive` and
`make validate-xiao-nrf52-target-archive` authenticate an existing encrypted
full-media capture without opening either board. Set `OTA_LAB_ARCHIVE_KEY`
and `OTA_LAB_ARCHIVE_FILE` explicitly. This is an offline evidence check,
not a live comparison or a firmware recovery package; installing the
read-only diagnostic replaces the application it is meant to inspect.

Build the genuine Sense no-SWD profile for offline qualification:

```sh
make package-xiao-ota-bootloader-noswd \
  XIAO_OTA_BOARD=xiao_nrf52840_sense XIAO_OTA_ROLE_ID=1
```

This selects the vendor's real `xiao_nrf52840_ble_sense` BSP and must fit
the 38,912-byte bootloader code slot, including the `.data` load image.
Its UF2 is an artifact-inspection format, not permission to copy it to
mass storage. `make install-xiao-nrf52-target-ota-bootloader` and
`make flash-xiao-nrf52-target-ota-bootloader` currently refuse the unsafe
UF2 write route.

Generate the standard vendor bootloader-only serial package offline:

```sh
make package-xiao-ota-bootloader-serial \
  XIAO_OTA_BOARD=xiao_nrf52840_sense XIAO_OTA_ROLE_ID=1 \
  XIAO_OTA_SERIAL_PACKAGE_DIR="$PWD/.tmp/sense-role1-serial-new"
```

The output directory must be new. The packager proves byte equality among
the HEX, UF2 and ELF load image, then emits exactly 40,192 bytes for the
half-open span `F4000..FDD00`. Its legacy ZIP contains only bootloader
data, not an application, SoftDevice, MBR or UICR image. The ELF binds the
compiled vendor version to the pinned release, 0.11.0 (`0x00000B00`);
a hash-only version of zero is not an acceptable replacement for stock
0.6.1. ARM fit includes the initialized `.data` load image, not just the
nominal text size.

Physical commissioning uses the separate, explicit
`flash-xiao-nrf52-target-ota-bootloader-serial` target only after source,
product tests, ARM artifacts, package and workflow review are closed.
Set `XIAO_OTA_ARTIFACTS` and `XIAO_OTA_SERIAL_PACKAGE_DIR` to the immutable
reviewed files, and `XIAO_OTA_BOOT_ADDRESS_EVIDENCE` to the actual ROOT
address observation JSON. `XIAO_OTA_SERIAL_INSTALL_FLAGS=--dry-run` checks
inputs and reports the command without invoking DFU. This is one guarded
installer around the existing vendor tool, not a second update protocol.

Standard serial bootloader-only DFU intentionally invalidates bank0 and
can erase application pages `27000..31000` before later checks fail.
It avoids the verified UF2 staging overlap with ExtraFS, but is not an
application-preserving operation. Separately restoring the immutable
qualified application is mandatory; uncertain DFU first requires ROOT
inspection of enumeration, version and boot evidence, not blind retries
or automatic restoration. Require positive vendor completion as well as
a successful process exit. Neither proves installation or a genesis floor.
After restoration, read back identity, settings, complete ACL, install
capability, ordinary-write permission and the actual floor described above.

The address reference is an observation, not a new authorization registry.
Its timestamp must be the real acquisition time, within the installer's
two-hour limit. If it expires while the board is in UF2 mode, return the
approved target to its application through an approved reset or recovery
procedure and read the addresses again. Never re-stamp old evidence.
The actual installed Seeed stock-source lineage and physical power-failure
behaviour remain unverified; offline package generation is not installation
approval.

## Recovering an unresponsive board

`make lab-reset-client` sends the companion's framed binary `reboot`
command; `make lab-reset-target` sends the repeater's text `reboot` command.
Both require USB disconnection followed by application re-enumeration.
For an intentional role change, select `OTA_LAB_CLIENT_PROTOCOL` or
`OTA_LAB_TARGET_PROTOCOL` (`companion` or `repeater`) to match the installed
application. Direct use of `lab_device.py reset` requires an explicit
`--protocol`; the tool does not guess from USB enumeration.

DTR/RTS toggling alone does not reset these boards. Firmware without the
selected reboot command, including the QSPI diagnostic image, needs DFU
entry or a physical reset instead.

```sh
make lab-devices           # is it present at all?
make lab-power-cycle-target
make upload-xiao-nrf52-target
```

`lab-power-cycle` locates the board in sysfs by serial rather than by role
resolution, so it still works on a board that exposes no serial port.

If `lab-power-cycle-target` refuses because a protected board shares its
power domain, physically reset or replug `target` instead, then continue
with `make upload-xiao-nrf52-target`.

If `make lab-doctor` reports `physical reset required` for a role, that port has
no software power control (or shares a hub with a
protected device), and the board's reset button or a manual replug is the
only recovery.
