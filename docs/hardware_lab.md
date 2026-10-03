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
target = 3BE94917B92DC5E9

[protected]
pine = 49C5BAF21EEF44A1
```

Override a role for one run without editing the file:

```sh
MESHCORE_LAB_TARGET_SERIAL=ABC123 make lab-devices
```

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
| `make inspect-xiao-nrf52-channels` | Read the approved companion's configured channel names and indices, without logging keys |
| `make inspect-xiao-nrf52-ota-measurements` | Read the approved pair's driver-applied radio and completed airtime observations |
| `make inspect-xiao-nrf52-ota-client-measurements` | Read those observations from the approved companion only |
| `make lab-power-cycle-<role>` | Cut and restore USB port power |
| `make lab-wait-<role>` | Block until the board enumerates |
| `make upload-xiao-nrf52-<role>` | Build and flash the role's application |
| `make flash-xiao-nrf52-<role>` | Flash the role's existing package without rebuilding |

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
resolve or open target `3BE94917B92DC5E9` or protected Pine `49C5BAF21EEF44A1`.
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
generation-bound cancellation protocol uses ABI2/90-byte replies and has not
been qualified on this client. The new host refuses ABI1; do not bypass its
version guard or relabel the earlier cache evidence as ABI2 acceptance.

Administrator setup is a separate, explicit **normal MeshCore** operation:

```sh
make grant-xiao-nrf52-ota-client-admin \
  OTA_LAB_ARTIFACT_DIR="$PWD/.tmp/ota-rf-lab/client-admin-$(date -u +%Y%m%dT%H%M%SZ)"
```

Use a new evidence path for each invocation; the Make wrapper refuses any
already-existing artifact directory. It invokes
`scripts/ota_rf_lab.py --artifact-dir "$OTA_LAB_ARTIFACT_DIR" --grant-client-admin`
and only opens approved client
`4186AE911D94CDB1` and target `3BE94917B92DC5E9`, never Pine
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
`lab/devices.ini`, ignores role environment overrides, and has no first-probe
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
