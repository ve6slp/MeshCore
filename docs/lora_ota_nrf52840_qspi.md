# SenseCAP Solar nRF52840 QSPI staging design

## Decision

The SenseCAP Solar can support recoverable LoRa firmware updates without
placing two applications in the nRF52840 internal flash.

The recommended architecture is an **external dual-bank copy/restore design**:

- the running application remains in internal flash
- a complete candidate image is downloaded into QSPI
- a complete copy of the last-known-good application is retained in QSPI
- a custom signed bootloader validates and copies the candidate into internal
  flash
- the previous image remains available until the new application confirms a
  successful trial boot
- an interrupted install resumes in the bootloader or restores the backup

This is not execute-in-place and it is not the stock Adafruit dual-bank mode.
It requires a MeshCore bootloader derived from the existing Adafruit nRF52
bootloader with QSPI, journaled copy/restore, and trial-boot support.

## Verified current state

### Internal flash

The repository's S140 v7 linker script gives the application
`0x27000..0xED000`, or `0xC6000` bytes (811,008 bytes). The installed Adafruit
nRF52840 layout starts the bootloader at `0xF4000`; the framework uses the
seven 4 KiB pages at `0xED000..0xF4000` as `InternalFS`.

Current layout:

| Range | Size | Owner |
|---|---:|---|
| `0x00000..0x27000` | 156 KiB | MBR + S140 v7 |
| `0x27000..0xED000` | 792 KiB | MeshCore application |
| `0xED000..0xF4000` | 28 KiB | `InternalFS` |
| `0xF4000..0xFD800` | 38 KiB | Adafruit bootloader code |
| `0xFD800..0xFE000` | 2 KiB | bootloader configuration |
| `0xFE000..0xFF000` | 4 KiB | MBR parameters |
| `0xFF000..0x100000` | 4 KiB | bootloader settings |

The companion builds additionally reserve `0xD4000..0xED000` as `ExtraFS`,
reducing their maximum application size to 708,608 bytes.

Evidence:

- `boards/nrf52840_s140_v7.ld`
- `boards/nrf52840_s140_v7_extrafs.ld`
- `variants/sensecap_solar/platformio.ini`
- Adafruit framework `InternalFileSystem.cpp` fixes its filesystem at
  `0xED000` for seven flash pages.
- [Adafruit nRF52840 bootloader linker layout](https://github.com/adafruit/Adafruit_nRF52_Bootloader/blob/master/linker/nrf52840.ld)

### External QSPI

The board variant declares a P25Q16H on the nRF52840 QSPI peripheral:

- capacity: 2 MiB (`0x200000`)
- erase sector: 4 KiB
- program page: 256 bytes

The SenseCAP Solar PlatformIO environments do **not** define `QSPIFLASH`.
Therefore current SenseCAP MeshCore firmware does not mount or allocate this
device. The QSPI is available for OTA staging.

Other nRF52840 variants enable `QSPIFLASH` for companion data, but the current
`CustomLFS_QSPIFlash` implementation mounts the entire chip from offset zero.
It cannot safely coexist with raw OTA banks because its address calculation is
`block * block_size + offset` and its block count spans the complete device.
A partition-aware replacement is required before enabling QSPI storage on
SenseCAP.

Evidence:

- `variants/sensecap_solar/variant.h`
- `variants/sensecap_solar/platformio.ini`
- `examples/companion_radio/main.cpp`
- [`CustomLFS_QSPIFlash` P25Q16H geometry and whole-device configuration](https://github.com/oltaco/CustomLFS/blob/0.2.3/src/CustomLFS_QSPIFlash.cpp)

### Existing bootloader limitation

The stock Adafruit bootloader supports signed updates and an optional internal
dual-bank mode, but its dual-bank mode halves available internal application
space. It does not consume a candidate from external QSPI. The SenseCAP image
capacity therefore cannot use stock dual-bank mode.

External QSPI staging requires a custom bootloader. This is a one-time
commissioning dependency; LoRa OTA must reject a target whose bootloader
version predates QSPI staging support.

Evidence:

- [Adafruit nRF52 bootloader README](https://github.com/adafruit/Adafruit_nRF52_Bootloader/blob/master/README.md)
- [Nordic external-flash DFU guidance](https://academy.nordicsemi.com/courses/nrf-connect-sdk-intermediate/lessons/lesson-9-bootloaders-and-dfu-fota/topic/exercise-3-dfu-with-external-flash/)

## Implemented XIAO bootloader overlay

`bootloader/xiao_nrf52840_ota/` provides a reproducible overlay pinned to
Adafruit_nRF52_Bootloader commit `c67f0bcf0fa8e841426335b1bbde91cda6ca1f50`.
It includes native record and recovery tests, OpenSSL signing and key tools,
and Makefile fetch/build/package targets. Full details, including how to
build, package, sign, and install each artifact, live in the overlay's own
`README.md`; this section gives the project-level summary.

The preferred profile keeps the mandatory USB UF2 mass storage and CDC serial
DFU recovery paths, leaves out optional BLE DFU, and fits inside the stock
38 KiB bootloader slot. Its FLASH load footprint is 38,900 bytes (99.97
percent used, **12 bytes free**): 38,652 bytes of code and read-only data,
plus 248 bytes of initialized data. This margin is razor-thin; see the
overlay's own `README.md` "Size and boot start" section for the exact
refactors that closed a real 452-byte overflow down to this fit, and for
the caveat that any future addition to this profile needs a matching size
reduction elsewhere first. It keeps the stock `0xF4000` UICR boot
start address, verifies signatures with a compact TweetNaCl-based Ed25519
implementation, and is packaged as a bootloader-update UF2 file. The older
BLE-enabled 66 KiB SWD build is still available and behaves the same as
before; its FLASH load footprint is 54,448 bytes.

The overlay also now bakes an immutable boot-info/capability marker
(`xiao_ota_boot_info_t`, fixed address `0xFDC00`) into every build, and
supports a build-time-selectable board-target profile (`--board
{xiao_nrf52840,sensecap_solar_p1}` in `tools/prepare_upstream.py` and
`tools/sign_image.py`) so the install-policy target check and the marker's
`board_target_id` are never a hardcoded single value nor a wildcard match.
`sensecap_solar_p1` is a real, distinct target id sharing the XIAO profile's
checked QSPI pin mapping, but is explicitly **not physically qualified on
any real SenseCAP hardware** -- see the overlay's `README.md` "Boot-info/
capability marker" and "Board profiles" sections for the exact struct
layout, address, and the end-to-end cross-board rejection proof.

The commissioning sequence is: physically double-reset the board if software
bootloader entry fails, run `make package-xiao-ota-bootloader-noswd`, run the
guarded `make install-xiao-nrf52-target-ota-bootloader`, and keep the pinned
stock recovery artifact produced by `make build-xiao-stock-bootloader`. The
installer authorizes only serial numbers declared in `lab/devices.ini`. It
checks the stable `/dev/serial/by-id` bootloader identity, the mounted
volume's USB serial ancestry, and the UF2 board ID, and it never selects a
device by `ttyACM` number.

The XIAO framework variant maps its QSPI logical pins to physical `P0.21`
(SCK), `P0.25` (CS), `P0.20` (IO0), `P0.24` (IO1), `P0.22` (IO2), and `P0.23`
(IO3). The overlay uses those same physical pin assignments.

**Lab and hardware gap:** this bootloader overlay has been software-tested
(native unit tests) and confirmed to build and package to the sizes above,
including the boot-info marker and the SenseCAP board profile (both proven
by parsing the real compiled `.hex` output and independently recomputing
their CRC-32 in Python, and by an end-to-end cross-board-rejection test, not
just asserted). It has not yet been installed on the authorized lab target
and has not yet performed a real signed install, trial boot, confirmation,
or rollback on physical hardware. Treat it as ready for review and
installation, not as already qualified in the field.

## Memory map

### Internal nRF52840 flash

| Range | Size | Owner |
|---|---:|---|
| `0x00000..0x27000` | 156 KiB | unchanged MBR + S140 v7 |
| `0x27000..0xD4000` | 692 KiB | active MeshCore application |
| `0xD4000..0xED000` | 100 KiB | preserved `InternalExtraFS` |
| `0xED000..0xF4000` | 28 KiB | preserved `InternalFS` |
| `0xF4000..0xFD800` | 38 KiB | QSPI-capable signed bootloader |
| `0xFD800..0xFE000` | 2 KiB | immutable bootloader configuration |
| `0xFE000..0xFF000` | 4 KiB | MBR parameters |
| `0xFF000..0x100000` | 4 KiB | redundant boot status/settings |

OTA application image capacity is 708,608 bytes (`0x027000..0x0D4000`).
The existing `InternalExtraFS` range (`0x0D4000..0x0ED000`) is not image
capacity and remains unmoved. The bootloader build must fail if its code
exceeds `0x9800` bytes. Its UICR
boot start address and `BOOTLOADER_REGION_START` both remain `0xF4000`.
The 66 KiB BLE-enabled fallback still uses `0xED000` and requires SWD for its
first installation.

### External P25Q16H QSPI

| Range | Size | Owner |
|---|---:|---|
| `0x000000..0x0AD000` | 692 KiB (708,608 B) | candidate application (image capacity) |
| `0x0AD000..0x0C6000` | 100 KiB | candidate security tail (`securityA`) |
| `0x0C6000..0x173000` | 692 KiB (708,608 B) | last-known-good backup (image capacity) |
| `0x173000..0x18C000` | 100 KiB | backup security tail (`securityB`) |
| `0x18C000..0x194000` | 32 KiB | redundant OTA journal |
| `0x194000..0x200000` | 432 KiB | external filesystem reservation |

All boundaries are 4 KiB erase-sector aligned. The physical bank stride
(`0x0C6000` bytes between the start of the candidate bank and the start of
the backup bank) is fixed and unchanged, but it is NOT itself writable
image capacity: each bank now exposes only its first 692 KiB (708,608 B) as
image capacity, with the remaining 100 KiB reserved as a
security-tail region (`securityA`/`securityB`). `securityA` and
`securityB` are NOT independent per-bank signature/descriptor material --
together they are the two halves (A/B generations) of one global,
identity-owned append/compaction store; this document and the app-side
layout headers only publish their raw capability boundaries, not a store
implementation.

App-side, `src/ota/platform/SenseCapQspiLayout.h` and
`src/ota/platform/Nrf52FlashLayoutContract.h` are the authoritative source
for these exact byte offsets (the latter is a plain-C header so
boot/signing code can reuse the same constants). `FlashRegion`'s own
bounds checking means any erase/program starting at or past the first
tail byte via the candidate/backup accessors is rejected as out-of-range,
not merely discouraged by convention. The internal nRF52840 application
image slot (`0x027000..0x0D4000`, 708,608 B, immediately followed by the
unmoved 100 KiB `InternalExtraFS` at `0x0D4000..0x0ED000`) matches this
same 708,608-byte capacity exactly, so a candidate/backup image is always
exactly self-install-sized.

The lab-only hardware-qualification destructive scratch carve-out --
historically `0x0C2000..0x0C6000` (see the qualification log below), which
the new `securityA` tail would otherwise overlap -- is relocated to
`0x0A9000..0x0AD000`: entirely inside the candidate bank's own image
capacity, immediately before `securityA`. It is maintenance/lab-only
destructive scratch space, never ordinary shared/spare capacity. A blank
journal or a false result from `ota::storage::XiaoOtaCommissioningGuard`
is absence of evidence only, not proof the device was never
commissioned; any use of this scratch range must be gated on explicit
maintenance authorization plus confirmation that no live candidate image
or backup/recovery state exists, never on the guard's signals alone.

This reserves space; it does not move or mount a filesystem. The USB lab
profiles retain their existing internal filesystem ownership. No security
tail may be provisioned until both the baseline and rollback artifacts
are tail-safe and existing data has been archived.

`make test-ota-image-layout-index` qualifies the prospective Git index
against the native runtime, storage and boot suites. These checks prove
app-side region behavior, not custom-loader commissioning or physical
installation.

## Shared QSPI ownership

The application must have one QSPI device owner and expose non-overlapping
views:

- `OtaCandidatePartition`
- `OtaBackupPartition`
- `OtaJournal`
- `QspiLittleFsPartition`

Each operation validates `offset + length <= partition.size`. LittleFS receives
only the final 432 KiB view. OTA code cannot address the filesystem partition,
and filesystem code cannot address OTA banks. The existing whole-device
`CustomLFS_QSPIFlash` must not be used unchanged.

The bootloader uses its own minimal polling QSPI driver after reset. It
recognizes only the three OTA partitions and never mounts LittleFS.

## Signed image contract

The bootloader is the root of trust.

- Signature algorithm: Ed25519, as implemented in `src/ota/trust/` (vendored
  orlp/ed25519) and, for the no-SWD XIAO overlay, a compact TweetNaCl
  implementation. An earlier draft of this design specified ECDSA P-256;
  Ed25519 was chosen instead for its smaller, fixed-size signatures and its
  simpler constant-time implementation on these microcontrollers. A
  QSPI-aware bootloader must verify Ed25519, not the curve used by the stock
  signed-firmware facility.
- Verification key: compiled into the bootloader configuration.
- Signed fields, command v1 (legacy, the bootloader's own canonical form):
  image SHA-256 hash, target id, role id, device address, allow-broadcast
  flag, required boot capability flags, security counter, image size in
  bytes, application start address, and the format/key/algorithm ids. This
  is the 71-byte layout serialized by `src/ota/trust/CanonicalDescriptor.h`
  and reproduced exactly by
  `bootloader/xiao_nrf52840_ota/include/xiao_ota_record.h`'s
  `xiao_ota_canonical_descriptor_t`; `tools/sign_image.py` in that same
  directory produces this signature offline, with the private key.
- Signed fields, command v2 (current, closes the 59-vs-71-byte
  incompatibility): the bootloader directly authenticates the LoRa
  transport's own 59-byte big-endian canonical wire descriptor
  (`src/ota/protocol/OtaDescriptor.h`'s `encodeOtaDescriptorCanonical()`:
  board family/variant, role, application address, exact size, SHA-256,
  security counter, minimum boot capability flags, format/key/algorithm
  ids) and its Ed25519 signature -- the exact same bytes and signature the
  transport itself already verifies (`src/helpers/ota/
  OtaFirmwareBackend.h` / `DescriptorVerifier::verifyPolicy()`), never a
  re-derived or re-signed form. `xiao_ota_boot.c` dispatches strictly on a
  `record_version` field to exactly one of the two signature checks above;
  there is no fallback or "either form" acceptance. The wire descriptor
  carries no device-targeting field, so a command v2 install is always
  broadcast-installable (device address/allow-broadcast are forced to
  `0`/`1` after decoding, since neither is part of the signed bytes).
  `tools/sign_image.py --command-version 2` produces this bundle; command
  v1 (`--command-version 1`, the default, matching the existing
  `make sign-xiao-ota-image` target unchanged) remains fully supported for
  back-compat and real per-device targeting. See
  `bootloader/xiao_nrf52840_ota/README.md`'s "Install command contract: v1
  and v2" and "LoRa OTA transport bridge" sections for the exact field
  layout and for what a durable application-side install bridge built
  against command v2 still needs to implement (it is not implemented yet;
  see "XIAO nRF52840 application-backend qualification" below).
- Integrity: SHA-256 over the exact candidate image.
- Anti-rollback: the bootloader refuses a security counter that is less than
  or equal to the highest confirmed counter.
- LoRa or group authentication authorizes the transport session, but it never
  substitutes for the bootloader's own signature verification.

The first production bootloader must be installed over SWD, USB, or the
existing signed DFU path. LoRa OTA updates application images only.
Bootloader and SoftDevice OTA are out of scope until a separate,
recovery-safe design is proven.

## Power-loss-safe install transaction

The 32 KiB journal is divided into four pairs of independently erasable 4 KiB
sectors, each with one exact owner:

- install command A/B: `0x18C000`, `0x18D000`
- boot transaction state A/B: `0x18E000`, `0x18F000`
- trial confirmation A/B: `0x190000`, `0x191000`
- anti-rollback floor A/B: `0x192000`, `0x193000`

Every record carries a magic value, format version, record length, sequence
number, and a CRC-32 covering everything before it. A record counts as valid
only once its final commit-marker word has been programmed, so a power cut
partway through a write leaves the older, still-valid copy in charge. These
eight sectors belong entirely to the bootloader/application install contract.
Transport receipt bitmaps must live in the filesystem partition instead (or
be rebuilt from other state); they may never share, or erase, the bootloader
journal.

The bootloader's implemented states, as defined in
`bootloader/xiao_nrf52840_ota/include/xiao_ota_record.h`, are:

1. `EMPTY`
2. `REQUESTED` (reserved; the current install flow moves straight from
   `EMPTY`/`CONFIRMED` to `BACKUP_COPYING` once a valid command is found, so
   this value is not produced by the flow below, but a valid record with
   this phase is still recognized)
3. `BACKUP_COPYING`
4. `BACKUP_READY`
5. `INSTALL_COPYING`
6. `TRIAL_BOOT`
7. `CONFIRMED`
8. `ROLLBACK_COPYING`
9. `FAILED`

Install sequence:

1. The application writes chunks to the candidate bank and tracks its own
   receipt progress.
2. The application verifies the complete SHA-256 of the staged candidate.
3. Out of band, and only with the signing private key, someone produces a
   signed install command -- command v1's 71-byte bootloader-canonical form,
   or command v2's real 59-byte transport wire descriptor -- (see "Signed
   image contract" above) and the application writes it durably to
   the command journal sectors, then resets.
4. On boot, the bootloader independently verifies the candidate's signature,
   hash, target identity, address, size, and security counter before
   touching anything else. The install size is capped at 708,608 bytes
   (`XIAO_OTA_INSTALL_MAX_SIZE`, `0x27000..0xD4000`) regardless of command
   version -- distinct from, and smaller than, the 811,008-byte backup/
   active-image extent below, because installing a larger candidate could
   erase into MeshCore v1.17's own internal filesystem region
   (`0xD4000..0xED000`). See the overlay's `README.md` "Fixed: install-
   command size cap..." section for the exact boundary proof.
5. The bootloader copies the complete active application to the backup bank,
   journaling and verifying each 4 KiB page as it goes.
6. Only once the backup's hash is verified does the bootloader erase any
   internal application page.
7. The bootloader copies and verifies the candidate page by page. If power
   is lost partway through, the next boot resumes from the journal rather
   than starting over.
8. Once the whole image is verified, the bootloader records `TRIAL_BOOT`,
   starts a 60-second watchdog, and boots the candidate. Trial firmware must
   not feed or reconfigure that watchdog before it commits confirmation.
9. The application confirms only after its filesystem mount, radio
   initialization, and its normal loop are all healthy.
10. Confirmation is a CRC/commit-protected token containing the transaction
    nonce, counter, and candidate hash. Three unconfirmed boots cause the
    bootloader to restore and verify the backup. Confirmation durably
    advances the anti-rollback floor. The candidate and backup images are
    left in place, not erased.

The transaction journals the previous upstream bank-0 validity, size, and
CRC before erasing any application flash. After the candidate is verified, the
bootloader writes its size and CRC-16 to the pinned upstream bootloader
settings before trial boot; rollback restores the prior values before
returning to the old application. The active-image extent used for both
backup sizing and command validation is *always* recomputed fresh from
bank-0 metadata every boot (current `BANK_VALID_APP` marker, non-zero
bounded size, and a live CRC-16 match against internal flash) -- a durable
floor value left over from an earlier confirmed install is never consulted
for this, so a later USB/CDC reflash cannot leave a stale extent trusted.
Missing or invalid fresh bank-0 metadata fails closed (no command accepted,
any in-flight transaction rolled back), never a guessed full-size fallback.
Explicit UF2/CDC DFU reset requests
bypass the OTA hook so upstream recovery can always consume GPREGRET.

At no point is internal application flash erased unless both a verified
candidate and a verified backup exist in QSPI.

**Lab and hardware gap:** every step above is covered by native host tests
(`bootloader/xiao_nrf52840_ota/tests/`), including simulated power loss at
each commit boundary. None of it has yet been exercised on real XIAO
hardware: no real signed install, trial boot, confirmation, or rollback has
happened on a physical board. Step 3 also depends entirely on the "app
bridge" described in `bootloader/xiao_nrf52840_ota/README.md`, which does not
exist yet; without it, no application can currently reach step 3 at all. A
code review of this transaction also caught six real correctness bugs, all
now fixed: the backup step's QSPI write was sourcing internal code flash
directly through EasyDMA, which the nRF52840 cannot do reliably; a device
that rolled back once could never accept another signed install afterward;
a corrupt (not erased) anti-rollback floor sector silently defaulted the
floor counter to 0 instead of refusing new installs; the active-image
extent preferred a stale post-install floor value over freshly-verified
bank-0 metadata, which a later USB/CDC reflash could leave disagreeing with
reality; the exact same failed (rolled-back) signed command could be
silently re-accepted forever, since its counter never advanced the floor,
producing an endless reinstall loop instead of a controlled failure; and a
trial-boot confirmation token could advance the durable anti-rollback
floor without re-verifying that the image *actually running* still
matched what was installed, which a USB/CDC reflash during the trial
window could defeat. A follow-up review then caught a regression in that
last fix: the initial version compared the fresh post-install extent
against the OLD image's extent (required unchanged for a correctly-sized
rollback restore), not the NEW candidate's own recorded size, which made
every differently-sized update always roll back. The corrected version
relies on `installed_hash_sha256` already cryptographically binding both
the new image's content and its exact length (a fresh hash match at a
given extent proves that extent is correct), so no new durable state
field or ABI change was needed -- the 152-byte v1 state layout is
unchanged -- with a boot-decision sequence regression test (using a real
SHA-256 over real buffer content, not a placeholder digest) covering both
growth and shrink updates and a real isolated ARM cross-compile
re-verifying the fix links, fits flash, and preserves the 152-byte
layout. See
`bootloader/xiao_nrf52840_ota/README.md`'s "Fixed" sections for the details.
A separate review of the same transaction's host-side installer,
`install_uf2.py`, found it checked only UF2 magic bytes and block
numbering -- not payload size, UF2 family ID, or the target flash
address -- so a malformed or mistargeted UF2 could in principle reach the
application image, ExtraFS, or this project's own durable
bootloader-settings page. That validator now enforces a payload-size
bound, the real bootloader-update family ID, and a target-address
whitelist derived from a genuine packaged artifact, plus an independent
boot-info marker/board/key check, all before any volume copy, and now also
supports a `--validate-only` mode that runs those artifact checks with no
serial/port/device resolution at all; see the same README section for
details.
Separately, the real target board's floor-A sector currently holds
leftover pre-commissioning diagnostic bytes from earlier hardware harness
runs, not a genuine confirmed floor -- the third fix above means this now
correctly fails closed (refuses new installs) rather than defaulting to
counter 0, but the sector still needs a deliberate commissioning
erase/re-provision before a real install can proceed on that board.

The transaction processor above is now also verified by literally
compiling and running it (not a parallel re-simulation): `xiao_ota_boot.c`
is split into a portable `xiao_ota_boot_io.c` (the processor itself,
zero SDK dependency) and a thin hardware-adapter `xiao_ota_boot.c`, and a
host test drives the exact same `xiao_ota_boot_process_io()` entry point
against an in-memory fake device, covering resize confirmations both
directions, failed-command replay refusal with genuine-new-nonce
acceptance, crash-mid-install fail-closed rollback, stale-confirmation
rejection, and DFU/recovery bypass. See
`bootloader/xiao_nrf52840_ota/README.md`'s "Literal-execution
boot-process tests" section for the design and build recipe.

A subsequent review of that same processor found every IO callback
returning `void`, so a real failed/timed-out flash read, erase, or write
had no way to be reported: the processor could confirm a transaction, or
advance the anti-rollback floor, on top of a write that never actually
landed. Every callback in `xiao_ota_boot_io.h` now returns `bool`, and
`xiao_ota_boot_io.c` checks every call; `write_record()` reads back both
the record body and its commit marker before either is trusted; the
first `persist_state()` at fresh command-acceptance time may safely just
refuse on failure, but every later persist call forces bounded recovery
instead of proceeding. The same review found trial confirmation was not
re-deriving `freshHash == candidateHash` (only `== installedHash`, which
should always agree but was never re-checked), had no floor
non-regression/idempotent-finish handling for a cut between the floor and
state writes, and found `ROLLBACK_COPYING` erasing the live application
before ever authenticating the QSPI backup it was about to restore from
-- a corrupt backup could lose the only remaining valid image. All three
are now fixed: confirmation requires
`freshHash == installedHash == candidateHash` plus a bounded non-zero
extent and matching nonce/counter, never regresses or double-writes an
already-durable floor, and the backup is hashed and authenticated before
the first destructive erase. A last-found gap, `state.sequence` being
reset to zero on every new transaction, could make a fresh transaction's
first record lose the A/B tie-break to a stale record left over in the
other slot; `sequence` now carries forward monotonically across
transactions. The literal-execution test harness above grew from 6 to 14
scenarios covering all of the above (idempotent floor/state resume,
sequence continuity, backup authentication before erase, pure I/O
failure, torn writes, corrupt/newer floor refusal, floor non-regression,
and no-CONFIRMED-without-durable-floor), and a fresh isolated ARM
cross-compile re-verified a clean link with the 152-byte v1 state layout
unchanged. See `bootloader/xiao_nrf52840_ota/README.md`'s "Fixed:
unchecked IO..." and "Fixed: trial confirmation..." sections for the
full detail.

A further review pass corrected five more gaps in the same processor:
metadata reads that conflated "missing" with "unreadable" (now a typed
Found/Missing/Damaged/IO-error result per slot pair, checked before any
buffer is trusted); a confirmation shortcut that could set `CONFIRMED`
on an idempotent floor-already-set resume without re-verifying the live
image; slot selection that inferred the physical A/B slot from sequence
parity instead of tracking it, with no sequence-wrap guard; persisted
phase/progress/extent used as an erase/copy address without being
bounds-checked first, and backup authenticated only once instead of on
every resumed rollback boot; and `qspi_init` returning `void` with one
coarse busy-wait timeout instead of per-operation calibrated bounds and
a real P25Q16H Quad-Enable check. The transaction processor now has 21
native scenarios, all passing, plus a settings-page torn-write test that
exercises a previously-unused fault model. See
`bootloader/xiao_nrf52840_ota/README.md`'s "Fixed: five review
regressions..." section for full detail, including the grounding of the
Quad-Enable opcodes/completion-signal choice against this repo's real
vendored `nrfx_qspi.c` driver and the companion firmware's own
`CustomLFS_QSPIFlash.cpp` flash-chip table -- read-only cross-checks,
not physical hardware confirmation.

A further hardware-grounded pass corrected QSPI custom-instruction
WP#/HOLD# pin levels, replaced a guessed loop-count timeout with a real
DWT cycle-counter deadline, and closed an idempotent-`CONFIRMED` gap that
skipped re-checking the floor's stored image extent. The same pass then
found the settings-page install/rollback path was still a read-modify-
write against whatever the settings page currently held, not a frozen
snapshot from when the transaction was admitted -- so a rollback could
durably re-commit unrelated page damage instead of recovering the
device's real prior settings. This is now closed with a new 88-byte
"settings sidecar" record, co-located inside each existing state sector,
that captures the exact 28-byte settings page once at admission and is
what every later install/rollback restores from or overlays onto,
alongside a new pre-erase check that the settings page's unused tail
reads genuinely blank, and a boot-time gate that force-recovers any
active transaction whose sidecar is missing or does not match its state
record. None of this changes the 152-byte state-v1 or 188-byte command-v2
wire layouts. The transaction processor now has 26 native scenarios, all
passing; a fresh isolated ARM cross-compile links cleanly at
36,916/38,912 bytes FLASH. See
`bootloader/xiao_nrf52840_ota/README.md`'s "Fixed: QSPI WP#/HOLD#..." and
"Fixed: settings-page rollback rebuilt from whatever the page currently
held..." sections for the full detail. As with every fix in this
document, this has been exercised only in the native fault-injected test
harness and cross-compiles -- it has not run on either authorized lab
board.

A follow-up security review found that once the anti-rollback floor
advances past 0, the boot processor stopped checking which compiled
role the surviving floor-activation receipt belonged to. A physical
swap of the compiled loader for the OTHER role (same device, same
floor/backup sectors left untouched) could present a validly signed
install command for its own role and have it silently accepted against
the other role's already-confirmed floor history -- a cross-role
anti-rollback bypass, even though the install itself is explicitly
unsupported. This is now closed: the role carried in the durable
floor-activation receipt is re-verified identity+signature+role before
every floor-dependent accept, the receipt is carried forward into the
other physical window on every floor advance (so both ping-pong windows
independently attest the compiled role, not just the genesis one), and
a single unconditional gate at the end of `xiao_ota_boot_process_io`
refuses the command whenever neither window's receipt matches this
binary's own compiled role -- signature verification still runs first,
and only a role mismatch is newly refused, never a reset of the floor,
counter, or trust anchor. Two new native regressions exercise this
directly: a real genesis-to-CONFIRMED flow is driven to floor 1, both
physical receipt windows are overwritten with a validly-signed
wrong-role receipt (simulating a loader swap), and a fresh counter-
advancing command signed for this binary's own role is asserted
refused with the floor, hash, and state unchanged; a second test drives
six real confirm/advance cycles and asserts both windows independently
verify role-correctly after every single advance, proving ordinary
same-role continuity is unaffected. The transaction processor now has
28 native scenarios for each compiled role, all passing for both roles.

This fix could not be re-qualified on real hardware this pass: an
isolated ARM cross-compile of all four board x role combinations
(`xiao_nrf52840` and `sensecap_solar_p1`, role 0 and role 1) now fails
to link, identically across all four, with a fixed-address overlap --
`section .bootloaderConfig LMA [000fd800,000fd857] overlaps section
.data LMA [000fd7fc,000fd8f3]`, a 243-byte overrun past the fixed
`0xfd800` `.bootloaderConfig` address (reported FLASH usage
38,908/38,912 bytes, 99.99%, which understates the real geometric
constraint). Disabling only this fix's new role-evidence gate (and
letting the linker garbage-collect the now-unreachable code) still
fails to link, at 38,716 bytes with a 51-byte overlap -- so roughly
51 of the 243 overflow bytes pre-exist this fix in the current
uncommitted tree (most likely from other in-flight role-1 work layered
on top of the 36,916-byte baseline recorded above), and this fix adds
the remaining 192 bytes on top. No code-size reduction attempted so
far (removing an `__attribute__((noinline))` hint, and sharing one
stack buffer across both receipt-window reads instead of two) recovered
any of this margin without touching the fix's behaviour, and no
crypto/recovery/slot-layout shortcut was used to make it fit artificially.
**Flashing any of the four combinations from the current source tree is
therefore unsafe and blocked on either a genuine size reduction found
elsewhere in the bootloader or an explicit decision upstream about the
pre-existing (fix-independent) 51-byte overrun**; this has been
reported, not silently resolved.

A follow-up review of this same fix (Root/Astra) found two further
gaps, both now closed, both of which make the ARM overflow above
strictly worse, not better: (1) the CONFIRMED-state floor-reconstruction
path could durably erase/rewrite a floor slot *before* the final
role-continuity gate ran, so a role-unproven or damaged device's
reconstruction request could complete before anything caught it --
`floor_role_evidence_ok()` is now checked, fail-closed to Recovery, as a
precondition of that reconstruction, not only after it; (2)
`persist_floor()`'s own receipt carry-forward could itself erase the
ONLY remaining physical window still holding a verifying receipt, if an
earlier advance's best-effort copy into the other window had silently
failed -- it now reads and classifies BOTH windows before touching
either slot, and if only the about-to-be-erased TARGET window still
verifies, durably programs and reads back those exact bytes into the
non-erased SOURCE window first, failing the advance closed (nothing
erased) if that propagation does not durably confirm. Both are
behavioural-only; no schema, wire, or trust-anchor change. A fresh ARM
rebuild with both of these closed now reports a *clean, linker-computed*
`region FLASH overflowed by 188 bytes` at 39,100/38,912 bytes (100.48%)
for `xiao_nrf52840`/role0 -- up from the 38,908-byte/243-byte-geometric-
overrun figure above, confirming this status remains unresolved and has
gotten larger, not smaller. See
`bootloader/xiao_nrf52840_ota/README.md`'s "Fixed: cross-role
floor-continuity bypass..." section for full detail.

A closer re-read of this same property found two further gaps, both now
closed, both behavioural-only (no schema/wire/trust-anchor change): the
final role-continuity gate now calls `force_recovery()` directly on
*any* evidence failure (not only a QSPI read failure) instead of
quietly demoting trust and letting an already-active trial/confirmation
resume reinterpret that as an ordinary "command no longer matches";
and `persist_floor()` now erases the target floor sector exactly once
and then writes the receipt into that target's own window *before*
committing the floor body and its final marker, never after -- matching
`write_state_with_sidecar()`'s existing "one erase, two body writes"
shape. Both roles still pass `TMPDIR=.tmp make test-xiao-ota-bootloader`
(80/80, exit 0). A fresh ARM rebuild of all four board x role
combinations confirms this reordering is size-neutral: all four report
the identical `region FLASH overflowed by 188 bytes` at 39,100/38,912
bytes (100.48%). The four-combination ARM blocker remains open and
unresolved. See `bootloader/xiao_nrf52840_ota/README.md`'s matching
"Fixed: role-evidence failure was a soft trust demotion..." section for
full detail.

Two further file-scoped, behaviour-preserving size reductions were then
tried (a `-Oz` compiler pragma for this one translation unit only, and
removing a redundant stack copy in the shared receipt-window helper) --
both verified test-neutral (80/80, both roles). They also exposed and
corrected a measurement error in this document and the README: the
earlier "188 bytes"/"39,100 bytes" figures came from the linker's
summary table, which stops accounting for the vendor `.data` section
(a fixed 248-byte TinyUSB/CDC block, unrelated to this work) once
`.text` itself no longer overlaps the fixed `.bootloaderConfig` window.
Reading the true overflow directly from the linker's explicit
`.data`/`.bootloaderConfig` overlap diagnostic shows the real remaining
gap, after both reductions, is **243 bytes** on all four combinations
-- not 60. The known-good qualified baseline rebuilds clean with no
such overlap at all (`38,652 B`/`99.33%`, 260 bytes of genuine
headroom), confirming the summary line is reliable only in the
no-overlap case. The four-combination ARM artifact remains **not safe
to flash**; see the README's "Size reduction, and a correction to the
real remaining gap" section for the full accounting and next options.

## Migration for the BLE-enabled 66 KiB fallback

The preferred no-SWD build keeps `0xF4000` and does not touch `InternalFS`.
Only the optional BLE-enabled fallback moves the bootloader start to
`0xED000`, and only that build needs this migration. Companion firmware may
also keep data in `ExtraFS`. That fallback migration must be staged as
follows:

1. Install a migration application under the existing bootloader.
2. Initialize only the QSPI LittleFS partition at `0x194000`.
3. Copy identities, preferences, keys, contacts, channels, and queued data
   from `InternalFS` and `ExtraFS`, then read it all back and verify it.
4. Write a redundant `storage_migrated` record inside the partitioned QSPI
   filesystem — never in the bootloader-owned journal.
5. Refuse to replace the bootloader unless migration and the QSPI
   JEDEC/erase/write self-tests all pass.
6. Install the QSPI-capable bootloader through a recoverable local method.
7. Install firmware that treats the partitioned QSPI LittleFS as its primary
   storage.

The migration firmware must never format the whole QSPI device. If anything
fails before step 6, the original bootloader and internal data are still
usable.

**Lab and hardware gap:** this migration path is a design only. No migration
firmware has been written, and it has not been tried on the authorized lab
boards. Anyone planning to move a device from the BLE-enabled 66 KiB build to
the preferred no-SWD build should treat this as future work, not as a proven
procedure.

## XIAO nRF52840 application-backend qualification

The XIAO nRF52840 + SX1262 lab target uses the same physical nRF52840 QSPI
signals as this layout: P0.21 SCK, P0.25 CS, and P0.20/P0.24/P0.22/P0.23 IO0-3.
`Nrf52FlashAdapter` now binds `FlashDevice` to nrfx QSPI with asynchronous
completion waits and word-aligned EasyDMA bounce buffers. Public reads and
programs remain byte-granular, while erase remains strictly 4 KiB aligned.

The reproducible application-side hardware command is:

```sh
make validate-xiao-nrf52-qspi-hardware
```

It runs against the `target` lab role, resolved to a stable
`/dev/serial/by-id` path by `scripts/lab_device.py` from the serial pinned in
`lab/devices.ini`. The firmware accepts only the `run` command. The
historical hardware runs below used these destructive windows:

- (historical) candidate test: `0x0C2000..0x0C6000` (16 KiB) -- this was the
  full-bank-era address of the lab firmware's destructive scratch probe,
  captured here as the actual hardware evidence log for that run and left
  unaltered. It is superseded by the tail-safe relocated carve-out at
  `0x0A9000..0x0AD000` documented above; new qualification runs must target
  the relocated range, not this historical address.
- (historical) journal test: `0x192000..0x194000` (8 KiB) -- these are the
  anti-rollback floor sectors, not safe scratch space. New qualification
  runs must not erase or program them.

The current candidate probe is `0x0A9000..0x0AD000` (16 KiB), and the
current record-test scratch is `0x0AB000..0x0AD000` (8 KiB), including the
deprecated `journalTestRegion()` alias. Both are candidate-owned image
space, subject to the explicit maintenance authorization described above;
neither is boot-journal storage. These relocated windows have not yet
been qualified on hardware.
The test never mounts `CustomLFS_QSPIFlash`, never formats the chip, and never
addresses the LittleFS partition.

Hardware evidence captured on XIAO serial `3BE94917B92DC5E9`:

- JEDEC `85:60:15`
- geometry 2,097,152 bytes / 4,096-byte erase / byte-granular adapter writes
- status registers SR1 `00`, SR2 `02`, SR3 `00`
- journal-test erase read back as `FF`
- unaligned byte-range program and readback passed after adding the required
  nRF EasyDMA word-aligned bounce buffer
- attempted NOR 0-to-1 rewrite returned `PartialProgramViolation`
- unaligned erase returned `Unaligned`
- out-of-bounds read returned `OutOfRange`

The first harness revision then exhausted the Arduino task stack while running
an additional in-firmware `Journal` round trip. That redundant step was
removed; journal-area erase/program/read coverage remains. The board then
temporarily stopped enumerating after a bad recovery attempt (see below); it
has since returned to service as one of the two boards this project is
authorized to touch (serial `3BE94917B92DC5E9`, alongside client board
`4186AE911D94CDB1`). It has since passed a signed candidate stage/readback
with real Ed25519 signature verification: an 8,192-byte signed candidate
staged to QSPI, read back, and its image SHA-256 checked, using the rweather
Ed25519 library, via `make validate-xiao-nrf52-qspi-hardware`. The captured
log is `.tmp/xiao-nrf52-qspi-3BE94917B92DC5E9.log`.

That earlier enumeration loss was caused by recovering boards with the sysfs
`authorized` toggle, which leaves the nRF52840 USB stack wedged (`can't set
config #1, error -32`).
Lab tooling now power-cycles the hub port with `uhubctl -f` instead, and never
touches `authorized`; see `make lab-power-cycle-target`.

**Important limits on what the passing test above proves:** staging an
8 KiB signed candidate to QSPI, reading it back, and checking its SHA-256 and
Ed25519 signature is not the same as a bootloader install. It proves the raw
QSPI path, the signed-stage/readback path, and the signing/verification
libraries work together on real hardware. It does not prove the bootloader
itself has installed, trial-booted, confirmed, or rolled back a real image on
this or any board -- that remains untested on hardware; see the "Lab and
hardware gap" notes earlier in this document for exactly what is still
missing. Do not read the pass above as evidence that installing this
bootloader, or running an OTA install through it, is proven safe yet.

**Journal-blank preflight is not bootloader qualification.**
`scripts/ota_boot_preflight.py` (host tooling, outside this section's scope)
reads the eight boot-journal sectors (COMMAND/STATE/CONFIRMATION/FLOOR,
`0x18C000..0x194000`) and, when all of them read as fully erased, records
`journal_transactions_blank=True` alongside `bootloader_qualification=
"not-evaluated"` rather than asserting the loader is unqualified or that no
custom bootloader is installed. A blank journal establishes only that its
bytes currently read as erased, not that no transaction was ever recorded
or that destructive maintenance is authorized. This is
exactly what a factory-fresh stock Adafruit bootloader looks like, but it is
*also* exactly what this custom bootloader looks like immediately after a
correct install that has simply never processed a transaction yet. Journal
purity cannot distinguish "no custom bootloader present" from "custom
bootloader present, never yet used." Whether a qualified MeshCore custom
bootloader is actually installed is a separate, independent check: the
fixed-address boot-info/capability marker at `0xFDC00` (see
`bootloader/xiao_nrf52840_ota/README.md`'s "Boot-info/capability marker"
section and `tools/verify_boot_info_artifact.py`), which a stock bootloader
can never satisfy (that address reads all-`0xFF`) but which journal state
alone says nothing about either way. Preflight tooling correctly leaves
qualification unevaluated rather than inferring it from journal blankness.

**Further bootloader-side correctness fixes (read-only source review,
no device access).** A follow-up review found, and this pass corrected,
four more gaps in the bootloader's QSPI register adapter and confirmation
logic: custom QSPI instructions were leaving IO2/IO3 at their register-
reset LOW level (asserting the flash's WP#/HOLD# pins during exactly the
commands meant to reach it) and a status-register write's completion was
verified only at the peripheral level, not the flash's own WIP bit; the
busy-wait timeout calibration used an overestimated cycles-per-iteration
guess (which produces a *shorter* real bound, not a conservative one),
now replaced with a genuine Cortex-M4 DWT cycle-counter deadline; the
idempotent trial-boot confirmation resume path checked the durable
floor's counter and hash against the current transaction but not its
`active_image_extent`, letting an internally inconsistent floor record
finish `CONFIRMED`; and the bank-0 settings read/write path is now a
single hardware-independent codec shared by the real hardware adapter
and native tests, expressed through the same internal-flash callbacks
every other durability check already uses, replacing a hand-modelled
settings-fault mirror. See
`bootloader/xiao_nrf52840_ota/README.md`'s "Fixed: QSPI WP#/HOLD#
assertion on custom instructions, torn timeout calibration, and a
floor-extent identity gap" section for full detail, exact source
citations, and what remains genuinely unverified without hardware
access.

## Hardware acceptance gates

The design is accepted only after all of these pass on the actual SenseCAP
Solar:

1. QSPI JEDEC ID is `85 60 15`; geometry is 2 MiB / 4 KiB / 256 B.
2. Existing identity and configuration survive the storage migration.
3. A signed candidate installs and confirms.
4. Wrong-key, wrong-board, truncated, corrupt, and downgraded candidates are
   rejected before internal flash erase.
5. Power is removed at every journal state and several page boundaries; every
   restart resumes or restores without SWD intervention.

The design is accepted only after all of these pass on the actual SenseCAP
Solar:

1. QSPI JEDEC ID is `85 60 15`; geometry is 2 MiB / 4 KiB / 256 B.
2. Existing identity and configuration survive the storage migration.
3. A signed candidate installs and confirms.
4. Wrong-key, wrong-board, truncated, corrupt, and downgraded candidates are
   rejected before internal flash erase.
5. Power is removed at every journal state and several page boundaries; every
   restart resumes or restores without SWD intervention.
6. A deliberately crashing trial image automatically restores the prior image
   and rejoins the mesh.
7. A completely erased candidate bank cannot affect the confirmed image.
8. USB/SWD recovery remains available.

Until these gates pass, the SenseCAP LoRa OTA path is experimental and must
not be enabled in production builds.
