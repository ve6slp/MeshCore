# LoRa over-the-air updates: developer guide

## Scope

This is the entry point for working on the LoRa OTA subsystem itself:
where the code lives, how to build and test it, the on-wire/binary command
surface, and the current hardware validation status. For the design
rationale and policy model, start with
[docs/lora_ota_design.md](lora_ota_design.md). For nRF52840 QSPI/bootloader
specifics, see [docs/lora_ota_nrf52840_qspi.md](lora_ota_nrf52840_qspi.md)
and `bootloader/xiao_nrf52840_ota/README.md`.

## Source layout

```
src/ota/
  protocol/   wire types, byte-stream codec, envelope, canonical descriptor
  runtime/    chunk geometry, receipt bitmap, session identity, receiver/
              coordinator/fleet state machines, radio-profile lease,
              airtime limiter
  storage/    CRC32, redundant journal, receipt map, storage manager over
              the QSPI layout
  trust/      SHA-256 and Ed25519 (vendored orlp/ed25519), fail-closed
              descriptor verification pipeline
  boot/       BootTransaction: gates erase of the running image behind
              candidate authentication and a verified durable backup
  platform/   flash device/region abstraction and QSPI layout

src/helpers/ota/         glue between MeshCore runtime and the OTA core
examples/companion_radio/  CLI/binary command handling and lifecycle hooks
test/test_lora_ota_{protocol,runtime,storage,trust,boot,integration}/
```

The portable OTA core is mostly header-only. Board backends provide the
Nordic and ESP32 SDK boundaries. It is gated by the `MESHCORE_LORA_OTA`
build flag, currently set in `variants/xiao_nrf52/platformio.ini`,
`variants/sensecap_solar/platformio.ini`, and
`variants/xiao_s3_wio/platformio.ini`.

The lean migration uses MeshCore identities and existing administrator
permissions, not a separate commissioning authority or transport-key ledger.
Firmware manifests and background frames use Ed25519 signatures; a sender's
public key is accepted only through the device's administrator policy.

Each device retains one candidate image and its original administrator.
Duplicate durable blocks do not write flash again. Invalid frames preserve
valid progress, and installed or older versions do not acquire the candidate
slot. A competing image or administrator receives a busy refusal. Any trusted
administrator may abort reception and suppress that image's multicast until
an explicit restart.

All three transfer modes converge on the same image validation. Complete
reception leaves durable `READY` state, not an install command. Only an
explicit per-device commit for the validated image publishes the bootloader
handoff. The current image remains operational during reception and while
waiting for commit. These are migration requirements, not hardware results.

## Building and testing

All entry points are `make` targets; do not invoke `pio` directly for OTA
work so the repo-local `.tmp` scratch directory and target lists stay
consistent.

```sh
make test-ota                # all native OTA and host tests
make test-ota-native          # native tests only; supports OTA_TEST_FILTER
make test-ota-protocol        # one layer at a time, for fast iteration
make test-ota-runtime
make test-ota-storage
make test-ota-trust
make test-ota-boot
make test-ota-integration
make test-ota-lab-host        # host-side unittest suite for lab scripts (below)
make test-ota-lab-host OTA_LAB_HOST_TEST_PATTERN=test_lab_device.py

make build-ota-targets        # compile the OTA-enabled firmware targets
make build-ota-nrf52-targets  # XIAO/SenseCAP, companion and repeater roles
make build-ota-esp32-targets  # XIAO S3/Wio, companion and repeater roles
make build-ota-baseline-targets  # same targets, OTA disabled, for size diffing
make build-non-ota-targets    # regression guard: platforms that never enable OTA

make verify-ota-software      # full tests + six OTA and ordinary profile builds
```

`verify-ota-software` is explicitly a **software-only** qualification gate.
Its own summary output says so: passing it means native tests are green and
firmware links, not that any device can be updated.
It builds all four nRF profiles, both ESP profiles and the representative
ordinary non-OTA profiles. The default Arduino source filter excludes OTA;
only the six OTA application profiles add its sources and C++17 explicitly.

`build-ota-nrf52-targets` builds all four nRF52840 USB application profiles.
It does not substitute the ESP32-S3 profile for the XIAO nRF52840 companion
or qualify custom-loader installation.

`build-ota-esp32-targets` builds `Xiao_S3_WIO_companion_radio_usb` and
`Xiao_S3_WIO_repeater_ota_usb`. The new repeater profile inherits the
ordinary repeater's configuration and dependencies, adding the OTA flag,
source filters and C++17. The existing `Xiao_S3_WIO_repeater` profile
remains unchanged. Building either role does not qualify installation or
rollback on physical ESP32 hardware.

The ESP OTA profiles bind `XIAO_S3_OTA_COMPILED_ROLE_ID` to companion 0 or
repeater 1. The experimental OTA repeater also disables the ordinary Wi-Fi
updater with `DISABLE_WIFI_OTA`, preventing two updaters from owning the same
inactive slot. The ordinary repeater profile retains its existing updater.

### nRF52840 bootloader qualification

`make qualify-xiao-ota-bootloader` builds and packages both nRF board
profiles for companion role 0 and repeater role 1, then runs each native
gate with matching boot-process identity. Its metadata harness must run
against that board/role's actual prepared source; a missing tree fails
qualification rather than silently skipping. This remains an offline
gate, not an installation result. Package validation must include every
file-backed flash load segment, including initialized `.data`, and preserve
the fixed configuration and boot-info addresses.

Independent qualification of all four current no-SWD packages found
37,812 bytes of code, unwind metadata and initialized data within the
38,912-byte load slot. The final file-backed load ends at `0xFD3B4`,
leaving 1,100 bytes before configuration at `0xFD800`. Each package
retains its ELF and section report alongside HEX, UF2 and linker map.
These are build-artifact and simulated-recovery results, not physical
installation or power-cut results.

The running app checks the manifest signer against its administrator policy
before committing. Its install record snapshots that accepted public key
and signed manifest; the bootloader independently verifies the signature,
image hash, hardware, size and installed version floor. This is a
local-failure trust boundary, not a physical-attacker secure-boot claim.

Boot reliability qualification covers durable backup before internal erase,
invalid-bank publication before copying, valid settings publication last,
exact original SDK settings restoration, and trial confirmation or rollback.
Reception and staging tests must exercise the production integration path,
including reboot resume, harmless duplicates, bad-frame refusal, busy
ownership, abort suppression and `READY` without an install command.

### ESP32-S3 vendor recovery inspection

The 2026-10-01 build of `Xiao_S3_WIO_companion_radio_usb` linked with the
resolved Arduino-ESP32 2.0.17 package. Its SDK enables
`CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`, and disassembly of the actual
QIO/80 MHz bootloader found both pending-image abort transitions and
the new-image-to-pending transition. The generated `bootloader.bin`
SHA-256 was
`1776e4dd896a69d0a5c2e79957b0e2a88aa4129b1381d6478683515a1f6af343`.
This identifies that inspected build; it is not a compiled trust anchor
or a guarantee about an unknown bootloader already on a device.

`make inspect-xiao-s3-ota-bootloader` records the existing ELF, SDK config
and generated binary hashes and prints the boot-selection disassembly.
Run it as a manual release inspection after building the profile; it
does not upload anything and is not a recurring infrastructure test.
Override the `ESP32_OTA_*` paths if PlatformIO's packages live elsewhere.
Select `ESP32_OTA_ENV=Xiao_S3_WIO_repeater_ota_usb` to inspect that
profile's generated bootloader instead of the companion's.
`ESP32_OTA_BUILD_DIR` defaults to `PLATFORMIO_BUILD_DIR` when supplied,
otherwise `.pio/build`, so isolated firmware builds can be inspected too.

The actual core's `esp32-hal-misc.c` also defines the weak
`verifyRollbackLater()` hook to return false and confirms pending images
inside `initArduino()`. The LoRa OTA integration must defer that default
confirmation until filesystem, radio and main-loop health are established.
The board backend supplies explicit installation, vendor image validation,
late confirmation and an independent RTC watchdog. The raw flash adapter
alone does not expose installation. Its product tests and linked symbols
are software evidence; receiver-to-installation and physical rollback
remain unqualified on ESP32 hardware.

The shared unsigned descriptor builder supports `xiao_s3_wio`: family
`0x4553`, variant `0x5333`, role 0 or 1, logical application address
`0x10000`, capabilities 1 and at most 2,749,824 image bytes. The capacity
is bounded by the durable bitmap and 84-byte blocks, not the Nordic
application region. The SDK chooses the inactive physical slot; the
descriptor never names a raw flash destination. The offline nRF
install-command signer still accepts only nRF board profiles.

`make test-ota-index` archives the prospective Git index under `.tmp/`.
Unstaged work is excluded and the output identifies the exact source tree.
Builds and library dependencies stay inside that snapshot, preserving
board scripts that resolve libraries relative to their project directory.

Combine native suite selectors in one invocation when working across
layers, for example:

```sh
make test-ota-native OTA_TEST_FILTER='test_lora_ota_trust test_lora_ota_runtime'
```

`test-ota-lab-host` runs `python3 -m unittest discover -s scripts/tests` —
real unit tests for the lab tooling itself (for example, the protected-
power-domain refusal logic in `scripts/lab_device.py`), not a proxy for
hardware or firmware qualification. It is now a dependency of both `make
test` and `make test-ota`. If a command reports missing Python packages,
install the lab's declared dependencies:

```sh
python3 -m pip install -r requirements-ota.txt   # cryptography>=43.0, pyserial>=3.5
```

## Signed companion USB ABI

`src/helpers/ota/OtaUsbProtocol.h` is the authoritative contract.
Companion requests use `<`, a little-endian 16-bit payload length, then
command 66 and an operation byte. Replies use `>` and the same outer
length encoding. Multi-byte fields inside the OTA payload are big-endian.

| Operation | Value | Body after command and operation |
| --- | --- | --- |
| CacheBegin | `0x10` | flags1, canonical59, signature64 |
| CachePut | `0x11` | blockIndex16, exactLength8, data1..84 |
| CacheSeal | `0x12` | none |
| AddTarget | `0x13` | full target PK32 |
| Start | `0x14` | mode8, channel8, frequencyKHz32, leaseMs16, dutyMilliPercent32 |
| Commit | `0x15` | target PK32, manifestHash32, counter32 |
| Abort | `0x16` | target PK32, imageHash32 |
| Status | `0x17` | target PK32; all zero selects the local cache |
| SetContactAdmin | `0x18` | target PK32, enabled8 |

CacheBegin flag 1 means explicit reupload. Its signer is the companion's
existing local identity; no additional owner key is supplied in the USB
request. A local cache must not become an install command for the uploader.
CacheSeal validates it for transmission; target admission separately checks
that same signer against the target's live administrator policy.

Start modes are direct 0, directed 1 and background 2. Direct requires one
target, channel 255 and a frequency with a 250..60,000 ms lease. Directed
requires one target and channel 255; background requires a configured group
channel and accepts up to 32 targets. On-mesh frequency and lease are zero.
Positive airtime shares are 1..100,000 milli-percent; 2,000 means 2%.

Every reply is exactly 86 bytes: response code 31, ABI version 1, echoed
operation, result, phase, flags, target PK32, hash32, received16, total16,
counter32, statusAgeMs32 and retryAfterMs32. Flags are snapshot-valid 1 and
remote 2. A reply without a snapshot has unknown phase, zero hash, counts
and counter, and age `0xFFFFFFFF`. It still reports the actual operation
result and requested target. Unknown versions, flags or enum values are
errors, not successful defaults.

Local cache operations and Start echo a zero target; individually addressed
operations echo the full supplied target. CacheSealed is a local uploader
state; Ready is the target's validated candidate awaiting explicit Commit.
Pending is not final success. The host honours retryAfterMs and retries an
identical block when backpressure requires it.

An old cached READY cannot authorize a new commit wait. Snapshot age must
establish a remote observation made after the wait began, with the expected
manifest, counter, scope and complete nonzero block counts. A status query
may honestly report FAILED; a fresh failure for the current candidate ends
a mutating wait. COMMIT acceptance does not prove a reboot or confirmation.

The old raw sender, fixed-key fixture, command-66 mode/duty helpers and
binary journal cleanup have been removed from the host workflow. Existing
MeshCore local-update commands remain separate from this signed upload ABI.

## Hardware lab workflow

Every physical-board operation goes through `scripts/lab_device.py` and the
roles pinned in `lab/devices.ini` — never a raw `ttyACMn` path. See
[Hardware lab device workflow](hardware_lab.md) for the full rationale
(mode detection, DFU entry, power cycling, recovery). The current lab pair
is two XIAO nRF52840 + SX1262 boards, addressed as `client` and `target`.
The client is a USB companion; the target must run `simple_repeater`.
A third board, listed under `[protected]`, belongs to an unrelated project
and must never be reset, flashed, or power-cycled by any MeshCore command.

Relevant targets:

```sh
make lab-devices                       # list attached boards and roles
make lab-doctor                        # check host tooling/power control
make build-xiao-nrf52-ota-lab          # build companion client and repeater target
make upload-xiao-nrf52-lab             # flash both client and target
make monitor-xiao-nrf52-ota-lab        # capture binary client and text repeater output
make configure-xiao-nrf52-ota-client   # client-only radio/name configuration
make configure-xiao-nrf52-ota-lab      # role-correct paired configuration, no reboot
make test-xiao-nrf52-ota-lab           # refuses until end-to-end qualification is implemented
make validate-xiao-nrf52-qspi-hardware # run the on-target QSPI hardware test
make test-xiao-ota-bootloader-tools    # host tests for installer and artifact tooling
make verify-xiao-ota-boot-info-artifacts # check actual HEX/UF2 markers and UF2 admissibility
                                        # (XIAO_OTA_BOARD=xiao_nrf52840 default, or
                                        # XIAO_OTA_BOARD=sensecap_solar_p1)
```

The serial transport distinguishes the binary companion client from the
repeater's echoed text CLI. Monitoring and configuration support both
roles. Paired configuration checks the roles and full identities before
mutation, sets ordinary MeshCore names, radio preferences and path hashes,
then requires unchanged identities and complete administrator ACL
readbacks. It neither provisions an administrator nor reboots a board.
Client-only configuration remains available.

Repeater readbacks are preferences; applying the radio profile requires a
separate reboot. Readback does not prove reboot persistence or reception on
the configured mesh. The source-confirmed radio setter reply is exactly
`OK - reboot to apply`; name and path setters return `OK`. Value readbacks
start with `> `. The default qualification operation
continues to refuse before device access rather than run the retired raw
sender.

Configuration does not send historical command-66 mode or duty
subcommands. Campaign mode and airtime belong to the signed uploader's
START request; configuration does not claim an OTA status or installation
capability.

The replacement host signing helper uses the companion's existing signing
commands (33, 34 and 35) for the canonical 59-byte manifest. It verifies
the returned Ed25519 signature against the companion's public identity
before accepting it; it does not export or substitute a private lab key.
This helper and the delimited repeater ACL reader are host-side building
blocks, not evidence of an implemented upload or bootloader handoff.

### Signed uploader host

`scripts/ota_uploader.py` implements the replacement host side of
`src/helpers/ota/OtaUsbProtocol.h`: command 66, operations `0x10` to
`0x18`, with versioned 86-byte replies. It matches the operation and full
target identity, rejects unavailable or malformed replies, and uses
snapshot age rather than reply arrival time when waiting for READY.
An old failure snapshot does not invalidate a newer candidate; a fresh
failure or abort ends the wait explicitly. Companion signing shares the
upload deadline, rather than starting a separate timeout for each command.
ABORT supplies the image-content SHA-256; COMMIT supplies the canonical
manifest SHA-256 and counter. These hashes are not interchangeable.

`make ota-lab-manifest` builds the unsigned descriptor from a raw nRF52840
application image. Set `OTA_UPLOAD_IMAGE`, `OTA_UPLOAD_MANIFEST` and an
explicit `OTA_UPLOAD_COUNTER` greater than the target's confirmed floor.
`OTA_UPLOAD_BOARD` defaults to `xiao_nrf52840`; select
`sensecap_solar_p1` for that board profile. `OTA_UPLOAD_ROLE_ID` defaults
to repeater role 1; use 0 for a companion. The shared descriptor builder
also serves the offline signing tool and validates geometry, alignment,
role and counter before writing. It emits exactly 59 bytes, with no
signature, private key or boot command. Select `xiao_s3_wio` for the
ESP32 descriptor policy described above.

The other Make entry points are `ota-lab-upload`, `ota-lab-status`,
`ota-lab-commit`, `ota-lab-abort` and `ota-lab-admin`. Supply a raw image
with `OTA_UPLOAD_IMAGE`, its exact canonical 59-byte descriptor with
`OTA_UPLOAD_MANIFEST`, and the full target public key with
`OTA_UPLOAD_TARGET`. Upload signs the descriptor using the companion,
fills and seals its cache, then requests a campaign. It never commits.
Set `OTA_UPLOAD_WAIT_READY=1` to wait for fresh, complete target snapshots;
the default returns the campaign request result without claiming target
completion. `OTA_UPLOAD_DUTY_MILLI_PERCENT=2000` selects 2% airtime; the
host also accepts lower positive shares.

**Implementation boundary:** host commands and native tests are not a
hardware qualification result. The firmware implements autonomous
three-mode transfer, remote status and target-bound commit. Native tests
exercise durable admission, repair, image validation, commit retry and
byte-exact full-image transfer across multiple direct leases. Fresh boot
evidence, not a COMMIT acknowledgement, must establish installation.
Physical qualification still requires reviewed applications and recovery
packages, real radio transfers, installation and late trial confirmation.

The boot signing utility now emits only the version-3, 220-byte install
record containing the application-admitted signer key. Its Make wrapper
no longer passes the removed `--command-version` argument or selects a
private key implicitly. `sign-xiao-ota-image` requires a deliberately supplied
`XIAO_OTA_PRIVATE_KEY` and is only an offline fixture workflow, not production
MeshCore authorization. `generate-xiao-ota-fixture-key` creates or reuses a
local test keypair without changing any compiled header. Artifact verification
checks board, role, layout, capabilities and record integrity, not a compiled
signer key: the bootloader verifies each command with its admitted public key.
Fixture keys always live in the project-root `.tmp/xiao-ota-keys` directory;
overriding `TMPDIR` changes build scratch, not that fixture location. No
fixture key is selected automatically.

The retired `test-xiao-nrf52-ota-airtime` scope exercised only the
airtime/duty-cycle budget against already-flashed firmware, without
building or flashing first. Its default timeout was 420 seconds.
That helper, its raw fixed-key sender and the binary floor-cleanup workflow
have been removed rather than maintained alongside the signed uploader.
The latest historical full RF
harness passed on 2026-09-30T12:26:14Z: usage reached
71,822 of 72,000 ms, and an ordinary advert allocated and reached the
expected peer in 0.983 s without changing OTA usage. This supersedes
earlier pressure runs that enforced the quota but failed ordinary advert
allocation with `ERR_TABLE_FULL`. A numerical quota pass alone is still
not a passing background-service result.

`scripts/ota_rf_lab.py` writes serial observations and machine-readable
evidence (`serial-events.jsonl`, `summary.json`) into the run's artifact
directory. Its earlier two-companion qualification routines sent and
observed OTA envelopes and adverts; they are not the new signed sender.
`tools/ota_qspi_hw_test.py` drives the on-device QSPI hardware test firmware
built from the `Xiao_nrf52_ota_qspi_hardware_test` PlatformIO environment and
captures its serial evidence log.

### Read-only evidence capture

`make build-xiao-nrf52-archive` builds a separate USB diagnostic application
without normal MeshCore startup or radio operation. Its protocol exposes
raw reads, not formatting, programming, erasing, or restoration. Building
does not flash either board; installation must use a separately qualified,
immutable application package through the lab-device workflow.

After that diagnostic is installed, use explicit private, persistent key
and archive paths outside `.tmp`, which is disposable build scratch:

```sh
archive_dir="$HOME/.local/state/meshcore-ota-lab/capture-001"
install -d -m 700 "$archive_dir"
make generate-ota-lab-archive-key OTA_LAB_ARCHIVE_KEY="$archive_dir/archive.key"
make archive-xiao-nrf52-client OTA_LAB_ARCHIVE_KEY="$archive_dir/archive.key" \
  OTA_LAB_ARCHIVE_FILE="$archive_dir/client-media.archive"
make verify-xiao-nrf52-client-archive OTA_LAB_ARCHIVE_KEY="$archive_dir/archive.key" \
  OTA_LAB_ARCHIVE_FILE="$archive_dir/client-media.archive"
```

Build scratch is shared across qualification owners. `make clean-tmp`
refuses whole-directory deletion; cleanup must target only individually
named paths owned by the operation, never `.tmp` itself or wildcards.

The corresponding target-board commands are `archive-xiao-nrf52-target`
and `verify-xiao-nrf52-target-archive`. A complete capture requires all
1 MiB of internal flash and 2 MiB of QSPI, encrypted locally; neither
plaintext media nor the encryption key belongs in logs or Git.
`make test-ota-lab-archive` exercises the archive protocol and failure
paths without hardware.

To authenticate a preserved capture without discovering or opening a board,
use `make validate-xiao-nrf52-client-archive` or
`make validate-xiao-nrf52-target-archive` with the same key and archive
variables. These commands check full-media integrity and the configured
role, serial and device UID. They do not compare the running device with
the capture or establish a recovery image.

The diagnostic replaces the running application, so its internal-flash
capture contains the diagnostic application and its SDK settings, not the
previous stock application. Preserve the original immutable application
artifact separately. These archives are evidence only: they do not
authorize restoring old counters, floors, identity, or firmware, and
capturing them does not qualify OTA installation or rollback.

The original 502,300-byte lab application artifact was lost after the
historical captures. The diagnostic images cannot reconstruct it. Before
further commissioning, preserve a newly qualified, immutable recovery
application and verify identity and configuration across the role change.

## Current hardware evidence

This reflects the most recent lab runs and should be re-checked against
`docs/lora_ota_design.md` and `docs/lora_ota_nrf52840_qspi.md` before relying
on it, since hardware qualification is ongoing.

### Current preservation evidence

On 2026-10-01, both approved boards passed the existing Make targets for
live, read-only comparison with their authenticated encrypted archives.
Each comparison covered all 1 MiB of internal flash and 2 MiB of QSPI,
with an exact byte-for-byte match. The boards still run the diagnostic
applications; neither result establishes production mesh service.
No flash, reset, power cycle or installation was performed, and the
protected board was not opened.

Destructive power cuts are deferred while the target shares the protected
power domain. Simulated recovery and offline artifact qualification do
not close that physical acceptance gap.

### Historical radio and flash evidence

The paths below identify earlier run directories, not artifacts guaranteed
to exist in the current qualification tree. These records describe the
retired transport and do not qualify the replacement.

Previously verified:

- **2026-09-30T12:26:14Z -- full stock-only RF harness**:
  `.tmp/ota-rf-lab/stock-policy-allocation-fixed-qualification/summary.json`
  records signed 320-byte RF-to-QSPI staging, queue precedence, manual
  radio-lease/reversion and fleet-control probes, plus 2% budget pressure
  with successful ordinary advert allocation and expected-peer reception.
  The staged SHA-256 is
  `9b5b15f57a4b1e4ead22796bc4fd085a636322fa0aae00291f79b7c3d7e907da`.
  Both boards ran the frozen 502,300-byte application whose BIN SHA-256 is
  `80fd9ebd972ae06c5e54634332be8332708b7e0375db928a00f81bc2721de118`.
  Paired full-sector reads afterward found all eight boot-journal sectors
  blank; no install command, confirmation or floor was written. This
  fixture is not a bootable firmware update, and manual lease/probe
  results do not establish autonomous three-mode operation.
- **Raw QSPI backend, `target` role board (serial `3BE94917B92DC5E9`)**:
  `make validate-xiao-nrf52-qspi-hardware` passed — JEDEC ID `85:60:15`,
  2 MiB geometry, raw erase, program, readback, correct NOR 0-to-1 rejection,
  and out-of-bounds handling all confirmed against the physical P25Q16H chip.
- **Lab-only signed staging path**: the `MESHCORE_OTA_LAB_BACKEND`
  qualification backend, which owns a reserved 16 KiB candidate-test QSPI
  region and a deterministic lab Ed25519 key, staged an 8,192-byte signed
  test image in 52 chunks and confirmed readback and hash integrity
  (SHA-256 `31c395468a84b2bfc2b009ccc03a141a7372884b4803c8e73db93a17a3988fc9`).
  This backend is qualification-only: it does not install or boot the
  candidate, and its key is not a production trust anchor.
- **Two-node RF lab, baseline behaviour**: reconfirmed on both approved
  boards after reflashing companion firmware. Adverts at the default
  907.525 MHz, 62.5 kHz bandwidth, SF7, CR5, three-byte path IDs (the raw
  advert packet header byte was observed as `128` on the wire in both
  directions, which decodes to the 3-byte path-hash mode, not just a
  settings-getter return value).
- **2026-09-30T08:03:15Z — signed staging path passed in full, isolated
  run**: `make test-xiao-nrf52-ota-stage` passed against evidence file
  `.tmp/ota-rf-lab/qualified-be128-stage/summary.json`. The earlier
  `recv7` byte-order failure (below) is fixed: the canonical signed image
  descriptor is a fixed 59-byte, big-endian field layout
  (`src/ota/protocol/OtaDescriptor.h`) used consistently by both ends of
  the link. On `target`, descriptor → Ed25519 signature acceptance →
  authorization → 128+128+64-byte chunks → commit all passed, ending in
  receiver state 6 (staging complete), for a 320-byte test image (SHA-256
  `9b5b15f57a4b1e4ead22796bc4fd085a636322fa0aae00291f79b7c3d7e907da`). A
  repeated (duplicate) first chunk was not reprocessed by the OTA receiver,
  but the test explicitly does **not** treat that as proof of the
  receiver's own duplicate-chunk handling: MeshCore's general raw-packet
  seen-hash cache drops the duplicate before it reaches the OTA layer at
  all (the raw receive is logged, the OTA event callback is not invoked a
  second time). This is radio-level deduplication, not a resume-after-
  interruption capability, and no reboot-persisted session resume exists.
  Evidence also carries explicit `install_or_boot_claim: false` and
  `reboot_resume_claim: false` flags — this pass is staging into QSPI
  only, not an install.
  **This was an isolated run and must not be read as a full RF baseline
  pass.** `test-xiao-nrf52-ota-stage` deliberately skips the
  normal-traffic-precedence probe, the direct-mode radio lease, the
  fleet-control-state probes, and the duty-cycle/airtime test — none of
  those were exercised in this run. The full harness
  (`make test-xiao-nrf52-ota-lab`), which does exercise them,
  failed its `normal-traffic-precedence` check in that qualification period
  **nondeterministically**: the command that queues the synthetic
  advert-then-OTA-announcement flood returned success, but no advert event
  was observed on the receiving side within the check's window. Identical
  same-second adverts are legitimately deduplicated, so the host fixture
  now uses fresh advert bytes and requires enqueue success. These host
  corrections were not themselves a hardware pass. The later
  2026-09-30T12:26:14Z full-harness result above supplies that clean rerun.
- **Bootloader packaging/offline tooling gate** (`make
  test-xiao-ota-bootloader-tools`, `make verify-xiao-ota-boot-info-artifacts`,
  both `XIAO_OTA_BOARD=xiao_nrf52840` default and
  `XIAO_OTA_BOARD=sensecap_solar_p1`): cached HEX/UF2 marker and key
  checks, and full no-SWD UF2 family/address admissibility, have passed.
  These are offline artifact checks — they do **not** exercise a custom
  bootloader install on physical hardware, and no such install has
  happened. Do not describe this gate as bootloader-install evidence.
- Those historical transfers used 128-byte chunks. The signed receiver
  uses at most 84 data bytes per block, preserving Nordic four-byte
  alignment. Packet sizing must include the actual outer transport and
  signature, not an assumed envelope from the retired implementation.
  The separate ChaCha20-Poly1305 envelope and sequence ledger are removed.
  Earlier airtime estimates do not establish current campaign duration;
  repairs, relays, census and lease transitions all add overhead.

**Fixed, previously failed** — a signed wire-descriptor transfer (`recv7`)
failed in an earlier run. The root cause was a byte-order (little-endian
vs. big-endian) mismatch in how the descriptor was framed on the wire. As
described above, the descriptor format is now defined and used as a single
59-byte big-endian layout end to end, and the fix is exercised by both a
new native C++ test in `test/test_lora_ota_protocol/` and the RF lab
harness. The historical command-version-2 bootloader record carrying this
descriptor is 188 bytes; it is not a companion wire frame. The signed
application-to-bootloader command retains the app-authorized signer public
key with the signed manifest. The current boot contract is
version 3 and 220 bytes, with the admitted key at offset 79, signature at
111, CRC at 212 over bytes `[0,212)`, and commit marker at 216. The
application writer and recovery packages remain qualification gates.

Receiving group chunks grants no install permission. The original
administrator must issue an explicit per-device commit for the fully
validated, ready image. A trusted administrator can abort before commit;
after committed installation begins, the bootloader completes or rolls back.

**nRF boot-trial and confirmation acceptance criteria — physical
qualification pending.** The contract for deciding whether a staged
install becomes "Installed/Confirmed" is:
health is only considered continuously good after 10 uninterrupted
seconds following an actual readiness/image check (not a stub); any gap
between health-loop iterations longer than 1 second restarts that
10-second timer from zero. CRC/SHA verification during the loop is
bounded and incremental — the ordinary health loop does not recompute a
full image hash on every pass. The boot trial runs under a 60-second
watchdog using reload-request register 0 (RR0), which the trial application
must not feed. The application has a 45-second confirmation deadline.
Confirmation requires writing and verifying the body before separately
writing and verifying the final commit marker, followed by exactly one
controlled reboot. The bootloader then persists and verifies the floor
before the CONFIRMED state, recovering that transaction idempotently after
interruption. Only once the floor, the state record, and the
running image hash all subsequently match is an attempt considered
Installed/Confirmed. None of this sequence has been exercised on
hardware yet — these are acceptance criteria, not a physical result.
ESP32 uses vendor slot states, an independent RTC watchdog and late
confirmation rather than the Nordic register and copy/restore sequence.

Not verified, and not to be represented as done in any documentation or
release notes:
- Full three-mode signed firmware transfer and install on real hardware.
  Signed staging and the full stock-only RF harness have passed, but
  neither transfers and installs a bootable firmware through all three
  autonomous modes. No actual device install has passed.
- Routed (directed, mesh-relayed) image delivery to an out-of-reach target
  has not been attempted yet; only direct-mode application-layer traffic and
  fleet-mode state probes have been run over real RF so far.
- Sustained multi-node and multihop fairness during a real background
  campaign remains unverified. The latest two-board pressure run does
  pass both the quota and ordinary-service witness, but it does not model
  fleet contention, autonomous byte repair or a 24-72-hour campaign.
- Turning a staged image into a running update is not proven end to end,
  but the pieces are at different stages, not all "not started":
  - The bootloader's boot marker (at flash offset `0xFDC00`) and a
    distinct SenseCAP flash profile **are implemented and covered by
    native tests**. Packaged HEX and UF2 build artifacts with marker
    verification now build separately for both the XIAO and SenseCAP
    profiles, in their own board/role-specific output directories. All
    four current no-SWD packages use 37,812 of 38,912 bytes, leaving
    1,100 bytes free. Historical footprints do not describe this build.
  - The candidate and backup regions each hold at most 708,608 bytes,
    preserving the extra-filesystem range `0xD4000`–`0xED000`.
    The 811,008-byte staging stride includes receiver metadata; it is
    not image capacity. A fresh, live read of `BANK_VALID`, the app
    flag, size and CRC16 is required before destructive installation.
    A stale floor value or a guessed extent is not sufficient.
  - The application-to-bootloader hand-off, and commissioning/installing
    that bootloader on physical hardware, are **not qualified** — no
    device has gone through commissioning, a real install, or a confirmed
    boot from an image delivered this way. Native tests exercise all three
    transfer modes, but no mode has completed a firmware installation on
    physical hardware with the replacement.
  Do not describe the marker or SenseCAP profile as "not implemented" —
  they exist and are tested; the gap is specifically the hand-off and
  physical hardware qualification.
- Anti-rollback has durable implementations: Nordic uses confirmed A/B
  floor records, and ESP32 stores its confirmed numeric floor in NVS.
  Neither has been qualified through a real install/confirmation cycle.
  The approved lab pair currently runs read-only diagnostics, not the
  retired RAM-counter backend or the new production receiver.
- Fleet-state probes and raw QSPI read/write results are evidence of
  protocol and flash-driver correctness — they are **not** evidence of a
  completed firmware installation. Do not conflate the two when reporting
  status.
- SenseCAP Solar (P1 Pro) hardware qualification: not started.
- ESP32 (XIAO S3 WIO): builds with OTA enabled; no hardware validation.
- Heltec v3/v4: out of scope until the nRF52840 pattern is proven.

## Development status and branch

This work lives on the dedicated `feat/lora-ota-lean` branch, built on
top of companion/repeater v1.17.1 ancestry, and has not been pushed to or
merged into upstream `main`. Do not treat anything in these guides as
released or upstream-approved until that branch merges.

If you are debugging a flash-upload failure, note that the lab's
`upload-xiao-nrf52-*` targets previously piped `lab_device.py` output
through `tee`, which could mask a non-zero exit code from a failed flash.
That has since been corrected so a failed upload fails the `make` target
instead of appearing to succeed.

## Host tooling status

`scripts/ota_rf_lab.py` and `tools/ota_qspi_hw_test.py` provide lab
configuration, monitoring and flash diagnostics, not a production client
product. The old raw sender and `CMD_OTA_LAB` workflow have been retired.
`scripts/ota_uploader.py` implements the signed host lifecycle against
`OtaUsbProtocol.h`; its mocked-host coverage does not qualify firmware
transport or physical recovery. Use the versioned ABI above when building
a companion app or CLI, not the removed lab controls.

## Contributing safely

- Use `make lab-*` and `scripts/lab_device.py` for anything touching real
  hardware; never hardcode a `ttyACMn` path.
- Never target the `[protected]` board in `lab/devices.ini`.
- Keep `src/ota/` changes covered by the matching native test suite before
  touching firmware integration.
- Update `docs/lora_ota_design.md`'s hardware-evidence sections when you add
  a new verified result, and keep unproven claims explicitly marked as such.
