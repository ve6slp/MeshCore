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
configure the pair for 907.525 MHz, 62.5 kHz bandwidth, SF7, CR5 and
three-byte path hashes. It checks both roles and full public keys before
making changes, then requires unchanged identities and complete
administrator ACL readbacks. It does not grant administrator permissions,
transfer an image, commit an update or reboot either board. Client-only
configuration remains available.

Repeater radio readbacks describe configured preferences, not the live radio
profile; applying them requires a separate reboot. Neither role's
configuration readback proves reboot persistence or peer reception.
The radio setter must return exactly `OK - reboot to apply`; name and path
hash setters return `OK`. Readbacks use the `> ` value prefix inside the
text reply. These formats match `CommonCLI.cpp`, not the older mock-only
assumptions. `make test-xiao-nrf52-ota-lab` continues to refuse
qualification before opening either port: paired configuration and mocked
host tests are not an end-to-end OTA result.

### Signed full-image qualification

`qualify-xiao-nrf52-signed-stage` and
`qualify-xiao-nrf52-signed-commit` exercise the signed production workflow,
not the retired raw sender. They require reviewed role-specific artifacts,
completed commissioning and the companion's existing administrator
permission on the target. They do not install a bootloader, grant
permissions, reset a board or bypass a conflicting candidate.

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

Select `OTA_SIGNED_LAB_MODE=direct` for 908525 kHz and 60-second leases;
firmware owns restoration and renewal. Background requires an existing
configured channel through `OTA_SIGNED_LAB_CHANNEL`. The default share
is 2%, with a 72-hour host timeout, not a completion guarantee. A
supervised full-image smoke run requires both
`OTA_SIGNED_LAB_DUTY=100000` and
`OTA_SIGNED_LAB_EXTRA=--supervised-full-image-smoke`; it is not 2%
acceptance. To resume the same candidate, pass
`OTA_SIGNED_LAB_EXTRA='--baseline-record /path/to/prior/baseline.json'`.
Different local-cache content still requires an independent, explicit
abort, not force-overwrite.

The runner does not establish measured airtime, physical multihop, fleet
contention or power-cut recovery. Its tests and recipes do not close the
firmware recovery or remote-reboot review gates, or constitute a hardware
result.

The repeater transport also reads `get acl`, whose output has no closing
marker. It waits for the echoed reply to a following `get role` command
instead of treating a quiet serial port as a complete ACL. An in-memory
ACL entry does not prove that `setperm` has saved it: qualification must
allow the lazy write to finish and verify the permission after a restart.

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
No flash, reset, power cycle or install command was issued, and the
protected board was not opened. This establishes preservation of the
captured media, not a mesh connection or a working OTA installation.
The boards still require qualified companion and repeater applications.

The archives contain the diagnostic applications, not the lost original
application artifact. Preserve newly qualified, role-specific recovery
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

`make validate-xiao-nrf52-client-archive` and
`make validate-xiao-nrf52-target-archive` authenticate an existing encrypted
full-media capture without opening either board. Set `OTA_LAB_ARCHIVE_KEY`
and `OTA_LAB_ARCHIVE_FILE` explicitly. This is an offline evidence check,
not a live comparison or a firmware recovery package; installing the
read-only diagnostic replaces the application it is meant to inspect.

`make install-xiao-nrf52-target-ota-bootloader` builds the no-SWD package
for the authorized XIAO repeater, defaulting to firmware role 1. It refuses
a companion-role or non-XIAO package. Run it only from the frozen,
qualified source tree after completing the preservation checks above;
the target rebuilds its package.

For an immutable, already-qualified bootloader package, use:

```sh
make flash-xiao-nrf52-target-ota-bootloader \
  XIAO_NRF52_TARGET_OTA_BOOTLOADER_PACKAGE=/absolute/path/to/repeater/bootloader.uf2
```

This target does not rebuild source or enter DFU. Put the authorized target
in bootloader mode first. Board and repeater-role guards run before the
artifact-only validation; the package must pass that validation before
the Make workflow resolves the target's serial port. The physical
installer checks the package again, validates the approved serial and
mounted volume, then copies it. Passing these checks does not establish
installed recovery.

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
