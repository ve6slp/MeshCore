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
make test-ota-rf-to-boot      # signed RF handoff into the real nRF boot processor
make test-ota-lab-host        # host-side unittest suite for lab scripts (below)
make test-ota-lab-host OTA_LAB_HOST_TEST_PATTERN=test_lab_device.py

make build-ota-targets        # compile the OTA-enabled firmware targets
make build-ota-nrf52-targets  # XIAO/SenseCAP, companion and repeater roles
make build-ota-esp32-targets  # XIAO S3/Wio, companion and repeater roles
make build-ota-baseline-targets  # same targets, OTA disabled, for size diffing
make build-non-ota-targets    # regression guard: platforms that never enable OTA

make verify-ota-software      # full tests, RF-to-boot proofs and profile builds
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

A healthy stock-loader nRF uploader can retain ordinary MeshCore settings,
contacts and filesystem writes while caching an image for another device.
Before filesystem mounting, this requires a blank custom-loader marker,
fresh stable SDK bank, CRC and image-hash evidence, no pending bank and a fully
erased install journal. Cache integrity is checked separately and cannot
revoke that positive ordinary-write proof. Backend attachment rechecks the
stock proof. This permits ordinary writes, not
filesystem formatting or identity replacement; the device remains cache-only
and cannot install an image. Trial, unknown, corrupt marker or SDK, present
install journal and unreadable boot-proof contexts retain the write guard.
A failed stock-cache attachment reports
`CACHE_UNAVAILABLE` with its reason instead of silently enabling installation.

The stock vendor loader uses stored SDK CRC zero to disable its optional
CRC check. Stock-only preflight honours that documented convention while
still computing the full CRC and stable SHA; nonzero stored CRC must match.
This does not change qualified installation or trial CRC checks.

For a qualified loader, an original vendor bank with unused CRC zero is
accepted only through a separate baseline resolver: valid SDK geometry,
successful fresh CRC reads and a full SHA matching the app-bound original
hash at admission, or the verified backup hash during continuation.
Nonzero stored CRC must still match. New-image trial confirmation and
CONFIRMED floor repair keep strict CRC equality, including genuinely
computed zero. Rollback restores the exact original SDK28; it does not
normalize vendor metadata. A genuinely blank target still needs durable
initial floor creation before this transition is physically qualified.

The qualified loader now initializes that floor only after verified QSPI
JEDEC identification, a full erased-byte scan of all eight journal sectors
and a healthy, repeat-stable vendor SDK/image proof. It rechecks both floor
sectors immediately before the only erase, then uses the existing durable
floor writer for sequence 1, counter 0, extent 0 and an all-zero hash.
This records an initial counter, not a confirmed original image. Existing
history, damage, ambiguity or failed reads cannot authorize initialization.
An interrupted initial write leaves the original SDK, application and user
configuration untouched and permits ordinary boot; a nonblank torn floor is
not automatically cleared or retried. The application must distinguish a
present valid floor from blank storage: blank means staging-only and no
COMMIT, not an assumed trusted counter 0. App-side integration passed the
immutable software gate for `e62cf33b`; actual first-boot floor readback
remains a separate hardware qualification gate.

Cache slots with bad magic or CRC are ignored exactly as in the candidate
store, without importing their owner or phase. Interrupted record-body
writes, torn commit markers and partial metadata erases can therefore
attach cache-only for an explicit retry or reupload. Neither boot proof
nor attachment erases storage. Valid ownership and progress remain protected;
CRC-valid unsigned, nonlocal, committed, inconsistent or unreadable cache
state does not gain attachment or installer authority.

Read-only stock diagnostics expose the actual latched write permission and
the captured early refusal separately from later backend capability. The
companion accepts payload `420001` for preflight and `420002` for capability,
returning response code 29 followed by ASCII; the repeater accepts
`ota preflight` and `ota capability`. These diagnostics do not alter the
existing `4200` reply, canonical 86-byte OTA replies, storage or boot state.
Older applications ignore the selector, so a lifecycle-only reply is not
preflight evidence.

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

`make test-ota-rf-to-boot` regenerates signed command and flash fixtures
through the current native RF integration, then passes them to the actual
boot processor for both nRF boards and both roles. It proves trial entry
and confirmation, pre-admission refusal after a valid application reflash,
and persistent cancellation before candidate replacement. The cancellation
case restores the previous running bank while the replacement is only
`READY`; a surviving-command negative control demonstrates that the old
intent would otherwise install. This target is part of
`verify-ota-software` and remains a software proof, not a physical test.
`make test-nrf-unadmitted-boot-process` runs the processor directly;
`OTA_NRF_REMOTE_BOOT_PROOF_PREFIX` selects exported fixtures.

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
| CacheBegin | `0x10` | flags1, ownerPK32, canonical59, signature64 |
| CachePut | `0x11` | blockIndex16, exactLength8, data1..84 |
| CacheSeal | `0x12` | none |
| AddTarget | `0x13` | full target PK32 |
| Start | `0x14` | mode8, channel8, frequencyKHz32, leaseMs16, dutyMilliPercent32 |
| Commit | `0x15` | target PK32, manifestHash32, counter32 |
| Abort | `0x16` | target PK32, imageHash32; all-zero target selects local cache |
| Status | `0x17` | target PK32; all zero selects the local cache |
| SetContactAdmin | `0x18` | target PK32, enabled8 |

CacheBegin flag 1 means explicit reupload. Its 32-byte owner public key is
the companion's existing local identity, read from normal self-info. The
complete command is 158 bytes, including command and operation; the public
key is not a new OTA identity or private-key export. A local cache must not
become an install command for the uploader.
CacheSeal validates it for transmission; target admission separately checks
that same signer against the target's live administrator policy.
Reupload does not override ownership: an active candidate can be restarted
only by its original owner, for the same image content and cache or install
purpose. A different image or owner requires an explicit abort first.
`make ota-lab-abort-cache` selects the local cache with zero target32 and
the old image's content hash. The companion binds its internally signed
abort to its own full identity and applies it locally, without RF traffic.

Start modes are direct 0, directed 1 and background 2. Direct requires one
target, channel 255 and a frequency with a 250..60,000 ms lease. Directed
requires one target and channel 255; background requires a configured group
channel and accepts up to 32 targets. On-mesh frequency and lease are zero.
Positive airtime shares are 1..100,000 milli-percent; 2,000 means 2%.

`OtaAirtimeLimiter` retains up to 256 same-category accounting buckets,
not 256 individual packets. A bucket's first completion bounds coalescing
to 15 seconds, and its latest completion controls conservative expiry.
The default on-mesh allowance is 72,000 ms per sliding 3,600,000 ms
window. Dispatcher debits actual completed transmission time; direct
off-frequency sends are excluded. Retuning preserves history, and a
genuinely full ring still refuses admission before sending.
On-mesh admission reserves `floor(1.5 * estimatedMs) + 20` for both the
quota and available accounting capacity. Recording still charges the actual
completed duration, not that conservative bound.

Every reply for operations `0x10` through `0x18` is exactly 86 bytes:
response code 31, ABI version 1, echoed
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

### Read-only radio and airtime evidence

USB-enabled nRF52 OTA lab builds expose two additional read-only selectors,
without changing the signed uploader ABI or normal statistics layouts.
The companion accepts `42 00 03` for radio evidence and `42 00 04` for
airtime evidence. A successful reply is `1D` followed by ASCII, without a
trailing NUL. The repeater accepts the USB-local commands `ota radio` and
`ota budget`; remote commands cannot access these lab measurements.

Radio evidence has this exact field order:

```text
src=driver-applied f=<decimal> b=<decimal> s=<decimal> c=<decimal> v=<0|1> a=<0|1> e=<HEX8> d=<HEX8> r=<HEX8> td=<HEX8> tr=<HEX8> h=<0|1> x=<HEX8> af=<HEX8> n=<HEX8>
```

`f` and `b` are frequency in kHz and bandwidth in Hz; `s` and `c` are
spreading factor and coding-rate denominator. `v` means that the checked
driver application succeeded. A partial or failed application invalidates
the previous tuple. `a` and `e` are direct-active state and lease expiry.
`d` and `r` count successful direct applications and normal restorations;
initial normal setup is not a restoration. `td`, `tr` and `n` are device
milliseconds. `h` requires both a valid applied tuple and driver health;
`x` counts driver faults and `af` counts failed applications. This is
**driver-applied evidence**, not independent readback of the chip's PHY
registers. Pair it with actual RF delivery and durable bitmap progress.

Airtime evidence has this exact field order:

```text
n=<HEX8> w=<HEX8> b=<HEX8> u=<HEX8> tx=<HEX8> to=<HEX8> af=<HEX8>
```

`n`, `w`, `b`, `u` and `tx` are milliseconds: device clock, sliding
window, OTA budget, recorded on-mesh OTA usage and completed all-traffic
TX duration. Direct transmissions do not contribute to `u`. `to` counts
TX timeouts and `af` counts failed airtime records; neither is cleared by
normal statistics reset. These durations are completed software timing,
not external RF measurements. A run with missing accounting or uncertain
transmissions cannot establish its airtime allowance. A before-and-after
total alone cannot establish sliding-window compliance or ordinary service.

Direct continuation is expiry, normal restoration, a fresh authenticated
handshake and resume from the durable bitmap. Qualifying continuation
requires observations of at least two applied direct intervals, intervening
restoration and retained progress; it is not indefinite lease renewal.
These software observation surfaces do not themselves constitute a
successful hardware campaign.

The lab helper's `--inspect-measurements` reads both approved roles, or
only the companion with `--client-only`, into a new evidence directory.
It preserves explicit unhealthy observations without claiming qualification.
The signed runner samples between existing STATUS transactions; it does
not re-enter an exchange or require another uploader. Qualification rejects
nonzero failure counters, inconsistent budgets and regressing clocks,
counters or fresh candidate-bound progress. Full-window sampled software
evidence is not a continuous external PHY measurement. The STATUS ABI's
durable counts also do not expose individual bitmap bits or handshake
tokens; missing wire-handshake evidence stays incomplete.

### Boot lifecycle and subsequent updates

USB status, the ordinary text CLI and requested-manifest RF census use the
same read-only boot view. On ESP32, signed provenance can be in the running
slot while writable staging belongs to the inactive slot. Reading that
provenance does not attach the running slot as staging or change candidate
metadata. An active newer candidate or local cache retains precedence.
`Installed` requires the matching original signature, image hash, counter,
nonce and confirmed boot evidence with a known version floor; a COMMIT
acknowledgement alone is insufficient.

On nRF52840, the next authorized BEGIN may replace a committed candidate
only after matching terminal boot evidence proves a confirmed install or
completed rollback. An active trial, unknown outcome, mismatched provenance
or failed reception does not release the slot. The new image must still
pass admission, including the version floor, before an erase begins.
For an install command refused before admission, nRF recovery instead
requires an explicit, signed administrator ABORT. The board must match
the original signed command, validate the running SDK bank, CRC and full
image hash, and obtain consistent state, sidecar and floor reads proving
that no installation transaction is active. Durable Aborted intent precedes
command cancellation: every bound command sector is erased and independently
verified blank before replacement is allowed. An unbound surviving command
blocks recovery unless its authenticated counter is permanently excluded by
the protected floor. Restoring the previous running bank cannot revive a
cancelled command. Candidate bytes, the original owner and the floor
remain intact until authorized replacement. Missing or corrupt command
evidence does not become a generic unlock.
An unrelated consumed command from a completed rollback does not block
aborting a newer, uncommitted candidate when the newest authenticated
command's nonce, counter and image hash match the terminal rollback and
the running bank matches the restored backup. A strictly older authenticated
command may remain shadowed by that proof only when no current-candidate
command is bound and neither slot is erased. Sequence ordering follows the
bootloader's wrap-aware comparison; ambiguous ordering stays protected.
A command bound to the current candidate,
including READY after an uncertain commit journal write, still requires
the full cancellation proof.

A newly durable remote nRF COMMIT arms the existing application reboot
helper. It allows two seconds for the reply, requires direct-profile
restoration, and gives queued traffic up to 15 seconds before controlled
reset may interrupt normal transmission. Authenticated duplicate COMMIT
does not rewrite the intent or extend the deadline. READY, denied,
failed or uncertain COMMIT does not arm it, and a proven refusal ABORT
cancels the old timer. A reboot is still not confirmation or Installed.

On ESP32, startup retires only authenticated, obsolete inactive-slot
selection metadata covered by the durable floor. It preserves the original
provenance and bitmap and does not erase image bytes. A normal USB reflash
can leave a healthy running image without matching OTA provenance. That
known, unproven state is distinct from a storage error: preserve the floor,
do not report `Installed`, and allow normal candidate admission where safe.
Trial, unknown SDK state and actual I/O failures remain protected.

### Radio packet geometry

All three modes use the dedicated, unencrypted MeshCore OTA payload type
`0x0C`, with Ed25519 authentication. They do not put bulk blocks inside an
encrypted group-message envelope. The canonical descriptor is 59 bytes;
admission is 156 bytes, or 164 bytes with the production target tag.
A signed block uses `99 + dataLength` bytes, with at most 84 data bytes:
183 payload bytes in total.

Serialization adds two header bytes and the path, plus four bytes for a
scoped flood. A full block is 185 bytes at zero hops, at most 249 bytes
with a 64-byte path, or 253 bytes with scoped flooding. The generic payload
limit is 184 bytes and the raw radio limit is 255 bytes; the largest
supported scoped packet is 254 bytes. Native tests exercise actual Mesh
packet construction and Dispatcher serialization at these boundaries.
These are software geometry results, not measured radio throughput or a
campaign-duration guarantee.

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
with an exact byte-for-byte match. Those comparisons issued no flash, reset,
power cycle or installation command, and the protected board was not opened.
Neither result establishes production mesh service.
Immutable `bda99d13` companion and repeater applications
were subsequently flashed to the approved pair, but the first companion
NAME setter returned `0104 BAD_STATE` before mutation. Radio settings
and administrator commissioning were blocked at that revision.
Reviewed and gated `7e3066b9` diagnostic applications
were then flashed. Both captured early readbacks identify the stored SDK
CRC `0000` sentinel as the refusal: calculated image CRCs are `19D3`
(companion) and `F59D` (repeater). The stock vendor loader deliberately
disables its optional CRC check at zero, and its normal serial DFU writer
sets that sentinel. Qualified loader, installation and rollback integrity
must not gain a blanket zero bypass.

On 2026-10-02, reviewed and gated `6e0b63be` applications restored ordinary
stock-loader writes on both boards. Their actual preflight readbacks were
healthy, writes allowed and cache-only. Normal commissioning set
`OTA-LAB-CLIENT`/`OTA-LAB-TARGET`, 907.525 MHz, 250 kHz, SF7, CR5 and
three-byte path preferences, preserving both public keys. A separate
normal administrator grant added only client permission 3.
After the six-second save opportunity and normal protocol reboots,
read-only inspection at `06:25:47Z` confirmed both identities, names and
radio preferences, client path mode 2 and the complete target ACL.
The inspection used no setters or fallback grant. Its evidence retains
`reboot_persistence_verified: false` because the inspection does not itself
reboot a device; persistence follows from comparison with the separately
recorded commissioning and reboot operations.
At `07:27:09Z`, the bounded ordinary-peer probe passed on this profile:
two advert requests produced a native companion notification for the actual
target in 4.194 seconds, with an independently signature-verified raw
MeshCore advert. Complete before/after reads preserved both identities,
names, radio preferences, both observed path modes and the target ACL.
Packet/radio counters were diagnostics, not the success witness. This
establishes only target-to-client ordinary reception; the two earlier
timeouts remain failures, and neither bidirectional nor OTA operation is
implied.

Reviewed recovery changes in `e62cf33b` passed the immutable software gate
for tree `0aec89d94991625f31aa620646470e438005daee`. The gate generated fresh
application fixtures, ran all four production-C board/role boot drivers
and imported their actual FailedMax rollback outputs into the C++ application.
Both vendor-unused CRC 0 and matching nonzero CRC policies passed, including
restored ordinary configuration writes and subsequent update admission.
Cache cut-and-retry coverage, 345 host tests and all six OTA firmware profiles
also passed. This closes the software recovery defects, not physical
rollback qualification.

The immutable, role-specific `e62cf33b` applications were then flashed to
the approved pair. Read-only inspection at `09:15:35Z` confirmed both
identities, names, 907.525 MHz/250 kHz/SF7/CR5 preferences, both path modes
and the complete target ACL without setters or replacement grants.
Both reported healthy stock boot, ordinary writes allowed and cache-only
OTA. The subsequent target-only loader installer passed artifact validation
but refused the vendor's actual stable boot-port product name before writing.
The host guard was corrected to use the existing lab identity resolver,
without relaxing serial, vendor, bootloader mode, stable by-id, volume
ancestry, Board-ID or artifact checks. Read-only inspection showed CDC
without mass storage in the mode selected by the 1200-baud helper.
Vendor and Arduino source inspection established that the helper requests
serial-only DFU; the loader deliberately hides MSC in that mode. The
separate vendor UF2 API and physical double-reset entry must not be
confused with that application-flash path. Historical archive metadata
cannot substitute for fresh observations.
The bench-only USB adapter and `make lab-bootloader-uf2-target` use the
existing vendor API rather than a parallel updater. The paired read-only
address gate and host application-to-bootloader mass-storage check qualify
only those observed conditions, not an installed recovery loader.
The reviewed `47b40e59` bench application was subsequently flashed to
the target only. At `10:33:47Z`, fresh metadata showed erased flash
address words, UICR boot address `000F4000`, parameter address `000FE000`
and matching effective addresses, with healthy stock boot and ordinary
writes allowed. At `10:33:49Z`, read-only configuration inspection
confirmed both identities, names, 907.525 MHz/250 kHz/SF7/CR5 preferences,
path modes and the complete target ACL unchanged, without setters.
The guarded vendor UF2 entry then passed on the actual target, including
USB disappearance and bootloader re-enumeration with mass storage.
The serial-matched volume reported current Board-ID
`Seeed_XIAO_nRF52840_Sense` and USB identity `2886:0045`; it was mounted
read-only. These observations rule out commissioning the preserved
base-board package with CF2 USB identity `2886:0044`.
The volume's virtual `CURRENT.UF2` excludes the bootloader region, so it
does not provide a current CF2 readback. No plaintext firmware was copied,
and historical CF2 evidence remains historical. A genuine Sense-profile
package must match the current public board and USB identities before
installation; a string change or relaxed Board-ID check is not a fix.
Subsequent retained-source review stopped UF2 self-update commissioning:
its indirect staging erases `0xE0000..0xEA000`, inside protected ExtraFS.
The suspected InternalFS overlap was not confirmed. The exact installed
Seeed binary's source lineage remains unverified, so the footprint is
reported as a source finding, not physical binary attestation. The normal
serial bootloader-only alternative stages 40,192 bytes at
`0x27000..0x30D00`, excluding both filesystems, and requires separate
immutable application restoration and preservation readbacks. The Make
UF2 flash target refuses operation while that guarded serial path is
being qualified.
The target's qualified custom loader is not installed, and no
replacement-protocol radio OTA installation has been demonstrated.
The uploader remains on the stock bootloader. Pine is untouched, and
destructive shared-domain power-cut qualification remains deferred.

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
    four reviewed factory-initialization no-SWD packages use 38,324 of
    38,912 bytes, including initialized-data load bytes, leaving 588 bytes
    free. Their source fingerprint is `23384fd9…`; the earlier
    `7861fdc0` packages lack initialization and must not commission a
    blank target. App-side integration and actual floor readback are
    still required before claiming commissioning.
    Historical footprints do not describe this build.
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
