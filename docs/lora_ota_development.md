# LoRa over-the-air updates: developer guide

## Scope

This is the entry point for working on the LoRa OTA subsystem itself:
where the code lives, how to build and test it, the on-wire/binary command
surface, and the current hardware validation status. For the design
rationale and policy model, start with
[docs/lora_ota_design.md](lora_ota_design.md). For nRF52840 QSPI/bootloader
specifics, see [docs/lora_ota_nrf52840_qspi.md](lora_ota_nrf52840_qspi.md)
and `bootloader/xiao_nrf52840_ota/README.md`, both owned by the bootloader
work stream — this guide does not duplicate them.

## Source layout

```
src/ota/
  protocol/   wire types, byte-stream codec, envelope, canonical descriptor
  runtime/    chunk geometry, receipt bitmap, session identity, receiver/
              coordinator/fleet state machines, radio-profile lease,
              airtime limiter, AEAD framing and durable sequence/replay
              primitives
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

The portable OTA core is mostly header-only. ESP32 partition and NVS
adapters also have `.cpp` SDK boundaries. It is gated by the `MESHCORE_LORA_OTA`
build flag, currently set in `variants/xiao_nrf52/platformio.ini`,
`variants/sensecap_solar/platformio.ini`, and
`variants/xiao_s3_wio/platformio.ini`.

Campaign staging delegates to `OtaFirmwareStorageSink`, including its
optional durable command handoff. `beginSession()` erases the candidate;
`resumeSession()` only attaches RAM state to existing bytes and clears
prior authorization. The receiver must re-verify durable metadata and
restore the exact verified descriptor and consented session before
committing a resumed install. Attaching alone proves neither image
integrity nor installation.

The shared nRF install nonce derives the first BE64 hash bytes from
`"MeshCore/OTA/install-attempt/v1"` (no NUL), controller32, campaignBE32,
sessionBE32, attemptBE16 and SHA256(canonical59). Independent golden
vectors cover each binding component. This pure calculation does not
authenticate the controller: durable immutable attempt ownership,
collision refusal and integration remain separate acceptance gates.

## Building and testing

All entry points are `make` targets; do not invoke `pio` directly for OTA
work so the repo-local `.tmp` scratch directory and target lists stay
consistent.

```sh
make test-ota                # all native OTA tests
make test-ota-protocol        # one layer at a time, for fast iteration
make test-ota-runtime
make test-ota-storage
make test-ota-trust
make test-ota-aead-cipher     # actual firmware Crypto library, not native mocks
make test-ota-boot
make test-ota-integration
make test-ota-campaign       # portable controller/receiver and install handoff
make test-ota-lab-host        # host-side unittest suite for lab scripts (below)
make test-ota-maintenance-host # host maintenance wire-codec tests
make test-ota-maintenance     # shared protocol and native maintenance codecs

make build-ota-targets        # compile the OTA-enabled firmware targets
make build-ota-nrf52-targets  # XIAO/SenseCAP, companion and repeater roles
make build-ota-baseline-targets  # same targets, OTA disabled, for size diffing
make build-non-ota-targets    # regression guard: platforms that never enable OTA

make verify-ota-software      # native tests + both build passes, in one gate
```

`verify-ota-software` is explicitly a **software-only** qualification gate.
Its own summary output says so: passing it means native tests are green and
firmware links, not that any device can be updated.

`build-ota-nrf52-targets` builds all four nRF52840 USB application profiles.
It does not substitute the ESP32-S3 profile for the XIAO nRF52840 companion
or qualify custom-loader installation.

### Public nRF52840 boot references

```sh
make generate-ota-boot-catalogue
make test-ota-boot-catalogue
```

Generation first validates and clean-builds the unmodified pinned public loader,
its ELF flash load addresses, and the public MBR/SoftDevice artifacts.
It does not read a device or approve an observed loader hash. The generated
header contains the XIAO USB profile's reference bytes; the provenance
sidecar records artifact hashes, source/submodule pins, compiler identity,
build options, and fixed build epoch. Pre-existing HEX/ELF pairs are replaced
by that fresh build, not trusted as proof of their source. A shared memory
layout does not authorize another board profile.

`XIAO_OTA_UPSTREAM` selects the public checkout. Override
`OTA_BOOT_CATALOGUE_HEADER` and `OTA_BOOT_CATALOGUE_PROVENANCE` to write
qualification outputs beneath `.tmp/` instead of replacing the source
header. Generation neither flashes hardware nor grants commissioning
authority. Acceptance still requires fresh live measurements of the
complete catalogue conjunction, the raw MBR/UICR selector policy, and the
separate blank retained-command parameter page.

For a complete stock-plus-custom catalogue:

```sh
make generate-ota-boot-catalogue-custom \
  OTA_BOOT_CATALOGUE_CUSTOM_MANIFEST=/absolute/path/to/qualified-builds.json
```

The explicit manifest must contain all four board/role pairs, their exact
ELF/packaged HEX/UF2 paths, trusted public-key header and qualified overlay
provenance. Missing, duplicate or unapproved custom inputs refuse generation;
neither shared pins nor successful compilation licenses a SenseCAP stock row.
Both outputs are generated into staging before publication, with the source
header replaced last. Stock-only generation remains available without a
custom manifest.

`make qualify-xiao-ota-bootloader` builds and packages both nRF board
profiles for companion role 0 and repeater role 1, then runs each native
gate with matching boot-process identity. Its metadata harness must run
against that board/role's actual prepared source; a missing tree fails
qualification rather than silently skipping. This remains an offline
gate, not an installation or live-commissioning result.

`test-ota-aead-cipher` links the installed firmware Crypto library's actual
ChaCha20-Poly1305 implementation in a separate host executable, so ordinary
native suites can retain their existing deterministic hash mocks. It
checks the RFC 8439 known-answer vector, full-tag and associated-data
tampering, plaintext quarantine, every allowed plaintext length, and the
exact 28-byte associated-data / 179-byte maximum protected frame. It is a
dependency of `test`, `test-ota`, and `test-ota-trust`. The default library
comes from `Xiao_nrf52_companion_radio_usb`; a missing dependency fails
explicitly with the corresponding PlatformIO package-install command.
These checks do not qualify authenticated transport, durable replay
protection, installation, or hardware.

The key schedule uses immutable public salt bytes, avoiding concurrent
first-call initialization races. Native SHA-256 and independently computed
HKDF known-answer vectors pin the exact no-NUL protocol domain and
directional key/nonce outputs.

The native runtime suite also exercises the durable TX/RX primitives
through 103 erase/body/marker/readback fault cases each, reconstructing
fresh objects over the resulting NOR bytes. Corrupt or unreadable slots
cannot fall back to older authorization, an RX watermark loaded at boot
remains a permanent replay floor for that boot, and uncertain writes
freeze the current instance. Both runtime constructors default to
`OtaSequenceInitialization::RequireExisting`; their explicit
`CommissionVirgin` mode requires independently verified commissioning
facts from the caller, not merely blank records. The production transport
and commissioning-store wiring are still pending.

`OtaSequenceBackingPort` separates those runtime algorithms from physical
storage. TX reservations compare the expected global counter before
claiming a new range; after a conflict, the allocator skips ranges owned
by other writers and reserves its own before emitting a sequence. RX
refresh closes the externally advanced replay window rather than
reopening earlier admissions. `WouldBlock` and `Conflict` remain
retryable at every open, read and mutation boundary; uncertain or
regressing durable facts freeze the instance.

The two-sector flash adapters are existing-record-only references, not
commissioning authorities or a production wear solution. Missing records
do not prove first use. Full-identity collision and bounded-capacity
fixtures exercise the port in RAM; they do not qualify a persistent
350-peer store, compaction, endurance or firmware transport.

`make test-ota-counter-ports-index` archives the prospective Git index
under `.tmp/` and runs its runtime, actual-cipher and lab-host gates.
Unstaged work is excluded, and the output identifies the exact tree.

Combine native suite selectors in one invocation when working across
layers, for example:

```sh
make test-ota OTA_TEST_FILTER='test_lora_ota_trust test_lora_ota_runtime'
```

`test-ota-lab-host` runs `python3 -m unittest discover -s scripts/tests` —
real unit tests for the lab tooling itself (for example, the protected-
power-domain refusal logic in `scripts/lab_device.py`), not a proxy for
hardware or firmware qualification. It is now a dependency of both `make
test` and `make test-ota`. Before running it, or any other lab script,
install the lab's Python dependencies:

```sh
python3 -m pip install -r requirements-ota.txt   # cryptography>=43.0, pyserial>=3.5
```

## Binary protocol (companion frame codes)

Handled in `examples/companion_radio/MyMesh.cpp::handleCmdFrame`:

- `CMD_OTA_CONTROL` (66), sub-operations in byte 1 of the frame:
  - `OTA_CTRL_GET_STATUS` (0) → `RESP_CODE_OTA_STATUS` (29)
  - `OTA_CTRL_SET_MODE` (1): byte 2 selects `0`=direct, `1`=routed, `2`=fleet
  - `OTA_CTRL_SET_DUTY` (2): bytes 2–5 are a little-endian `uint32_t`
    milli-percent value
  - `OTA_CTRL_ABORT` (3)
  - `OTA_CTRL_ROLLBACK` (4)
  - `OTA_CTRL_DIRECT_LEASE` (5): frequency (kHz-scaled `uint32_t`),
    bandwidth (kHz-scaled `uint32_t`), spreading factor, coding rate, and a
    16-bit lease timeout in minutes, validated by
    `mesh::ota::isValidOtaDirectLease` before
    `mesh::ota::requestOtaDirectLease` applies it
- `CMD_OTA_LAB` (67): currently one operation, `OTA_LAB_QUEUE_PRECEDENCE`
  (0), which builds and floods a synthetic `OtaAnnouncementPayload` plus a
  self-advert to exercise OTA-vs-normal traffic precedence. This exists for
  lab/test harnesses, not as a fleet-management primitive.

`src/helpers/CommonCLI.cpp` also parses text-CLI equivalents (`ota status`,
`ota abort`, `ota rollback`, `ota direct ...`, `set ota.mode`,
`set ota.dutycycle`, `get ota.mode`, `get ota.dutycycle`), but they do
**not** work today: the underlying `CommonCLICallbacks` OTA methods
(`src/helpers/CommonCLI.h:221-244`) default to no-op/"unsupported" stubs,
and `companion_radio` does not use `CommonCLI` at all, so no example
currently overrides them. `simple_repeater`, `simple_room_server`, and
`simple_sensor` are the only examples that use `CommonCLI`, and none of
them wires these callbacks up to `src/ota/`. If you're adding OTA support to
one of those examples, this is the gap to close. See the
[administrator guide](lora_ota_administration.md) for the operator-facing
writeup of this gap and the binary protocol used in the meantime.

## Hardware lab workflow

Every physical-board operation goes through `scripts/lab_device.py` and the
roles pinned in `lab/devices.ini` — never a raw `ttyACMn` path. See
[Hardware lab device workflow](hardware_lab.md) for the full rationale
(mode detection, DFU entry, power cycling, recovery). The current lab pair
is two XIAO nRF52840 + SX1262 boards, addressed as `client` and `target`.
A third board, listed under `[protected]`, belongs to an unrelated project
and must never be reset, flashed, or power-cycled by any MeshCore command.

Relevant targets:

```sh
make lab-devices                       # list attached boards and roles
make lab-doctor                        # check host tooling/power control
make build-xiao-nrf52-ota-lab          # build companion firmware, OTA enabled
make upload-xiao-nrf52-lab             # flash both client and target
make configure-xiao-nrf52-ota-lab      # apply lab radio/name configuration
make test-xiao-nrf52-ota-lab           # run the two-node RF harness (scripts/ota_rf_lab.py)
make test-xiao-nrf52-ota-stage         # same harness, signed-descriptor/staging path only
                                        # (skips the airtime-budget-exhaustion pass below)
make test-xiao-nrf52-ota-airtime       # same harness, airtime/duty-cycle stress only
                                        # (skips normal-traffic precedence, direct-mode
                                        # lease, fleet-control probes, and signed staging)
make validate-xiao-nrf52-qspi-hardware # run the on-target QSPI hardware test
make test-xiao-ota-bootloader-tools    # host tests for installer and artifact tooling
make verify-xiao-ota-boot-info-artifacts # check actual HEX/UF2 markers, keys and UF2 admissibility
                                        # (XIAO_OTA_BOARD=xiao_nrf52840 default, or
                                        # XIAO_OTA_BOARD=sensecap_solar_p1)
```

`make test-xiao-nrf52-ota-airtime` exercises only the airtime/duty-cycle
budget check against whatever firmware is already flashed on `client` and
`target` — it does not build or flash first, so it's independent of the
current state of the source tree. It accepts the same `OTA_LAB_DUTY_TIMEOUT`
override as `test-xiao-nrf52-ota-lab` (default 420 seconds) for longer
stress runs, e.g. `make test-xiao-nrf52-ota-airtime OTA_LAB_DUTY_TIMEOUT=900`.
The latest full RF harness passed on 2026-09-30T12:26:14Z: usage reached
71,822 of 72,000 ms, and an ordinary advert allocated and reached the
expected peer in 0.983 s without changing OTA usage. This supersedes
earlier pressure runs that enforced the quota but failed ordinary advert
allocation with `ERR_TABLE_FULL`. A numerical quota pass alone is still
not a passing background-service result.

`scripts/ota_rf_lab.py` drives both boards over serial, sends and waits for
OTA envelopes and adverts, and writes machine-readable evidence
(`serial-events.jsonl`, `summary.json`) into the run's artifact directory.
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

The diagnostic replaces the running application, so its internal-flash
capture contains the diagnostic application and its SDK settings, not the
previous stock application. Preserve the original immutable application
artifact separately. These archives are evidence only: they do not
authorize restoring old counters, floors, identity, or firmware, and
capturing them does not qualify OTA installation or rollback.

## Current hardware evidence

This reflects the most recent lab runs and should be re-checked against
`docs/lora_ota_design.md` and `docs/lora_ota_nrf52840_qspi.md` before relying
on it, since hardware qualification is ongoing.

Verified:

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
- The previous 160-byte OTA chunk size, which didn't fit the companion
  serial frame, has been replaced with a 128-byte chunk (fitting the
  184-byte `kOtaMaxFrameSize`, the 255-byte LoRa payload limit, and the
  64-byte mesh path field). The required strong transport is
  ChaCha20-Poly1305 with a 16-byte tag and a 4-byte sequence number;
  it has no padding or transmitted IV. Its 156-byte plaintext ceiling
  includes the 21-byte envelope. A 128-byte chunk therefore becomes a
  155-byte plaintext, a 178-byte protected payload and up to 248 bytes
  on the worst-case RF path. The full 156-byte plaintext ceiling becomes
  a 179-byte protected payload and up to 249 bytes on the wire — under the
  255-byte RF limit but over the 176-byte companion serial limit. Do not
  use the smaller, weaker 2-byte MAC variant instead, and do not claim
  the raw serial link can hold an encrypted, full-path frame at this
  size. This is a transport budget, not proof of an integrated encrypted
  transfer. The autonomous updater must cache bounded serial uploads and
  construct authenticated RF frames locally; that production integration
  is not yet qualified.

**Fixed, previously failed** — a signed wire-descriptor transfer (`recv7`)
failed in an earlier run. The root cause was a byte-order (little-endian
vs. big-endian) mismatch in how the descriptor was framed on the wire. As
described above, the descriptor format is now defined and used as a single
59-byte big-endian layout end to end, and the fix is exercised by both a
new native C++ test in `test/test_lora_ota_protocol/` and the RF lab
harness. The on-flash command-version-2 bootloader record carrying this
descriptor is 188 bytes; it is not a companion wire frame. Legacy install
command version 1 uses an independently signed 71-byte little-endian
descriptor. Command versions are separate from the durable state, floor
and confirmation record versions: those remain version 1, with the state
record exactly 152 bytes and the confirmation record 64 bytes.

The install-attempt contract binds a 32-byte controller public key, a
32-bit campaign ID, a 32-bit session ID, a 16-bit attempt ID and the
descriptor's SHA-256 digest. A stable, full 64-bit nonce is reused for the
same context; retrying a failed image requires a new explicitly
consented attempt after recovery, with a counter above the confirmed
floor. Receiving or staging
group chunks does not by itself grant install authority — only an
explicit, consented attempt can do that.

**Boot-trial and confirmation acceptance criteria — design only, not yet
implemented or proven.** The adopted (not yet built) contract for
deciding whether a staged install becomes "Installed/Confirmed" is:
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
hardware yet — treat it strictly as acceptance criteria to build and test
against, not as a result.

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
    profiles, in their own board-specific output directories/names, for
    both the 66 KiB fallback and the no-SWD (34,612 of 38,912 bytes
    used, 4,300 free) package variants.
  - The boot candidate region is capped at 708,608 bytes, preserving the
    extra-filesystem range `0xD4000`–`0xED000` until that region is
    migrated. The full candidate-plus-backup capacity (811,008 bytes) is
    still permitted, but only as storage/backup space — not as
    installable code. A fresh, live read of `BANK_VALID`, the app flag,
    size, and CRC16 is now required before a candidate is trusted; a
    stale floor value or a guessed extent is no longer accepted.
  - The application-to-bootloader hand-off, and commissioning/installing
    that bootloader on physical hardware, are **not qualified** — no
    device has gone through commissioning, a real install, or a confirmed
    boot from an image delivered this way. The backend/integrated
    firmware side of OTA is also still work in progress: there is no
    installed image, no full-mesh repeater delivery, and none of the
    three transfer modes are working yet.
  Do not describe the marker or SenseCAP profile as "not implemented" —
  they exist and are tested; the gap is specifically the hand-off and
  physical hardware qualification.
- Anti-rollback protection is a mix of levels, not uniformly RAM-only:
  the generic `src/ota/trust/MonotonicCounter.h` is an interface with no
  backing implementation of its own. The bootloader **does** implement a
  durable, confirmed A/B floor record — but that has not been exercised
  through an actual hardware install/confirmation cycle. The currently
  flashed experimental lab backend increments its counter in RAM and would
  seed from that durable floor if a valid one is present, but the current
  lab board pair has no qualified floor flashed, so on today's lab
  hardware the counter is, in practice, RAM-only and does not survive a
  reset. Do not describe anti-rollback as entirely unimplemented, and do
  not describe it as durable on today's lab hardware — both are wrong.
- Fleet-state probes and raw QSPI read/write results are evidence of
  protocol and flash-driver correctness — they are **not** evidence of a
  completed firmware installation. Do not conflate the two when reporting
  status.
- SenseCAP Solar (P1 Pro) hardware qualification: not started.
- ESP32 (XIAO S3 WIO): builds with OTA enabled; no hardware validation.
- Heltec v3/v4: out of scope until the nRF52840 pattern is proven.

## Development status and branch

This work lives on the dedicated `feat/lora-ota-nrf52840` branch, built on
top of companion/repeater v1.17.1 ancestry, and has not been pushed to or
merged into upstream `main`. Do not treat anything in these guides as
released or upstream-approved until that branch merges.

If you are debugging a flash-upload failure, note that the lab's
`upload-xiao-nrf52-*` targets previously piped `lab_device.py` output
through `tee`, which could mask a non-zero exit code from a failed flash.
That has since been corrected so a failed upload fails the `make` target
instead of appearing to succeed.

## Host tooling status

`scripts/ota_rf_lab.py` and `tools/ota_qspi_hw_test.py` are lab test
scripts, not a production host uploader or client product. If you are
building a companion app or CLI feature against `CMD_OTA_CONTROL` /
`CMD_OTA_LAB`, treat these scripts as protocol examples, not as a reference
implementation to ship.

## Contributing safely

- Use `make lab-*` and `scripts/lab_device.py` for anything touching real
  hardware; never hardcode a `ttyACMn` path.
- Never target the `[protected]` board in `lab/devices.ini`.
- Keep `src/ota/` changes covered by the matching native test suite before
  touching firmware integration.
- Update `docs/lora_ota_design.md`'s hardware-evidence sections when you add
  a new verified result, and keep unproven claims explicitly marked as such.
