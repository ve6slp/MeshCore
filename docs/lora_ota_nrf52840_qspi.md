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

`bootloader/xiao_nrf52840_ota/` now provides a reproducible overlay pinned to
Adafruit_nRF52_Bootloader commit
`c67f0bcf0fa8e841426335b1bbde91cda6ca1f50`, native record/state recovery
tests, OpenSSL signing/key tools, and Makefile fetch/build/package targets.

The preferred optimized profile preserves mandatory UF2 mass storage and CDC
serial DFU, omits optional BLE DFU, and fits the stock 38 KiB bootloader slot.
Its exact FLASH load footprint is 33,652 bytes (`86.48%`, 5,260 bytes free):
33,020 bytes of code/rodata plus 632 bytes of initialized data. It retains
the stock `0xF4000` UICR boot start, uses a compact TweetNaCl Ed25519 verifier,
and is packaged as a bootloader-update UF2. The original BLE-enabled 66 KiB
SWD build remains available and unchanged in behavior; its FLASH load footprint
is 54,448 bytes.
Exact commands and recovery artifact handling are in the overlay README.
The commissioning sequence is: physically double-reset if software bootloader
entry fails, run `make package-xiao-ota-bootloader-noswd`, run the guarded
`make install-xiao-nrf52-target-ota-bootloader`, and retain the pinned stock
recovery artifact produced by `make build-xiao-stock-bootloader`. The installer authorizes only serials declared in `lab/devices.ini`; it
validates the stable `/dev/serial/by-id` bootloader identity, mounted-volume
USB serial ancestry, and UF2 board ID without selecting a `ttyACM` number.

The XIAO framework variant maps its QSPI logical pins to physical P0.21 SCK,
P0.25 CS, P0.20 IO0, P0.24 IO1, P0.22 IO2, and P0.23 IO3. The overlay uses
those physical values.

## Memory map

### Internal nRF52840 flash

| Range | Size | Owner |
|---|---:|---|
| `0x00000..0x27000` | 156 KiB | unchanged MBR + S140 v7 |
| `0x27000..0xED000` | 792 KiB | active MeshCore application |
| `0xED000..0xF4000` | 28 KiB | preserved `InternalFS` |
| `0xF4000..0xFD800` | 38 KiB | QSPI-capable signed bootloader |
| `0xFD800..0xFE000` | 2 KiB | immutable bootloader configuration |
| `0xFE000..0xFF000` | 4 KiB | MBR parameters |
| `0xFF000..0x100000` | 4 KiB | redundant boot status/settings |

The application capacity remains 811,008 bytes. The bootloader build must fail if its code exceeds `0x9800` bytes. Its UICR
boot start address and `BOOTLOADER_REGION_START` both remain `0xF4000`.
The 66 KiB BLE-enabled fallback still uses `0xED000` and requires SWD for its
first installation.

### External P25Q16H QSPI

| Range | Size | Owner |
|---|---:|---|
| `0x000000..0x0C6000` | 792 KiB | candidate application |
| `0x0C6000..0x18C000` | 792 KiB | last-known-good backup |
| `0x18C000..0x194000` | 32 KiB | redundant OTA journal |
| `0x194000..0x200000` | 432 KiB | partitioned LittleFS |

All boundaries are 4 KiB erase-sector aligned. The candidate and backup banks
each equal the maximum internal application range. Detached manifests,
signatures, hashes, copy progress, and trial state live in the journal rather
than consuming image capacity. The filesystem remains substantially larger
than the current 28 KiB `InternalFS` plus 100 KiB companion `ExtraFS`.

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

- signature algorithm: Ed25519, as implemented in `src/ota/trust/`
  (vendored orlp/ed25519). The earlier draft specified ECDSA P-256; Ed25519
  was chosen instead for its smaller, constant-size signatures and simpler
  constant-time implementation on these MCUs. A QSPI-aware bootloader must
  therefore verify Ed25519, not the stock signed-firmware facility's curve.
- verification key: compiled into the bootloader configuration
- signed fields: image bytes, image length, image SHA-256 hash, board family,
  target/variant, role, application start address, manifest format id, key id,
  signature algorithm id, firmware security counter, and the minimum
  bootloader capability bitmask. This list is the canonical signed descriptor
  serialised by `src/ota/trust/CanonicalDescriptor.h`; every install-relevant
  wire field in `src/ota/protocol/OtaDescriptor.h` is covered by the
  signature.
- integrity: SHA-256 over the exact candidate image
- anti-rollback: bootloader refuses a security counter less than or equal to
  the highest confirmed counter
- LoRa/group authentication authorizes transport but never substitutes for
  bootloader signature verification

The first production bootloader must be installed over SWD, USB, or the
existing signed DFU path. LoRa OTA updates application images only. Bootloader
and SoftDevice OTA are out of scope until a separate recovery-safe design is
proven.

## Power-loss-safe install transaction

The 32 KiB journal is divided into four pairs of independently erasable 4 KiB
sectors with exact ownership:

- install command A/B: `0x18C000`, `0x18D000`
- boot transaction state A/B: `0x18E000`, `0x18F000`
- trial confirmation A/B: `0x190000`, `0x191000`
- anti-rollback floor A/B: `0x192000`, `0x193000`

Records contain a format version, sequence number, state, image descriptors,
completed 4 KiB page index, and CRC. A record is valid only when its final
commit word has been programmed. These eight sectors are now wholly reserved
for the bootloader/application install contract. Transport receipt bitmaps
must be stored in the filesystem partition (or reconstructed) and may not
share or erase the bootloader journal.

States:

1. `EMPTY`
2. `CANDIDATE_RECEIVING`
3. `CANDIDATE_READY`
4. `BACKUP_COPYING`
5. `BACKUP_READY`
6. `INSTALL_COPYING`
7. `TRIAL_BOOT`
8. `CONFIRMED`
9. `ROLLBACK_COPYING`
10. `FAILED`

Install sequence:

1. The application writes chunks only to the candidate bank and persists
   receipt progress.
2. The application verifies the complete SHA-256 and requests installation.
3. After reset, the bootloader independently verifies the candidate signature,
   hash, board identity, address, size, and security counter.
4. The bootloader copies the complete active application to the backup bank,
   journaling and verifying each 4 KiB page.
5. Only after the backup hash is verified may the bootloader erase internal
   application pages.
6. The bootloader copies and verifies the candidate page by page. Restarting
   after power loss resumes from the journal.
7. After whole-image verification, the bootloader records `TRIAL_BOOT`, starts
   a 60-second watchdog, and boots the candidate. Trial firmware must not feed
   or reconfigure it before committing confirmation.
8. The application confirms only after filesystem mount, radio initialization,
   and its normal loop are healthy.
9. Confirmation is a CRC/commit-protected token containing the transaction
   nonce, counter, and candidate hash. Three unconfirmed boots cause the
   bootloader to restore and verify the backup. Confirmation durably advances
   the anti-rollback floor. Candidate and backup remain preserved.

The transaction journals the previous upstream bank-0 validity, size, and
CRC before erasing application flash. After candidate verification it writes
the candidate size and CRC-16 to the pinned upstream bootloader settings before
trial boot; rollback restores the prior values before returning to the old
application. A legacy extent is trusted only when bank 0 is valid and its
nonzero CRC-16 matches flash; otherwise a full `0x27000..0xED000` backup is
required. Explicit UF2/CDC DFU reset requests bypass the OTA hook so upstream
recovery can always consume GPREGRET.

At no point is internal application flash erased unless both a verified
candidate and a verified backup exist in QSPI.

## Migration for the BLE-enabled 66 KiB fallback

The preferred no-SWD build keeps `0xF4000` and does not consume `InternalFS`.
Only the optional BLE-enabled fallback moves the bootloader start to `0xED000`
and therefore requires this migration. Companion firmware may also have data
in `ExtraFS`. That fallback migration must be staged:

1. Install a migration application with the existing bootloader.
2. Initialize only the QSPI LittleFS partition at `0x194000`.
3. Copy identities, preferences, keys, contacts, channels, and queued data from
   `InternalFS` and `ExtraFS`; read them back and verify them.
4. Write a redundant `storage_migrated` record inside the partitioned QSPI
   filesystem, not in the bootloader-owned journal.
5. Refuse bootloader replacement unless migration and QSPI JEDEC/erase/write
   tests pass.
6. Install the QSPI-capable bootloader through a recoverable local method.
7. Install firmware that treats partitioned QSPI LittleFS as primary storage.

The migration firmware must never format the complete QSPI device. Failure
before step 6 leaves the original bootloader and internal data usable.

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
`lab/devices.ini`. The firmware accepts only the `run` command and destructively touches only:

- candidate test: `0x0C2000..0x0C6000` (16 KiB)
- journal test: `0x192000..0x194000` (8 KiB)

Both are OTA-owned subregions below the LittleFS boundary at `0x194000`.
The test never mounts `CustomLFS_QSPIFlash`, never formats the chip, and never
addresses the LittleFS partition.

Hardware evidence captured on XIAO serial `3BE94917B92DC5E9`, a board that
has since been retired from the lab:

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
removed; journal-area erase/program/read coverage remains. The board then stopped
enumerating entirely and was removed from the lab; the signed-image
stage/readback firmware built successfully but was never flashed to it. The
captured log is `.tmp/xiao-nrf52-qspi-3BE94917B92DC5E9.log`.

That loss was caused by recovering boards with the sysfs `authorized` toggle,
which leaves the nRF52840 USB stack wedged (`can't set config #1, error -32`).
Lab tooling now power-cycles the hub port with `uhubctl -f` instead, and never
touches `authorized`; see `make lab-power-cycle-target`.

Therefore the raw QSPI backend is hardware-validated, while the signed
`StorageManager` stage/readback remains a hardware gap rather than a claimed
pass. It must be re-run against the current `target` role board.

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
6. A deliberately crashing trial image automatically restores the prior image
   and rejoins the mesh.
7. A completely erased candidate bank cannot affect the confirmed image.
8. USB/SWD recovery remains available.

Until these gates pass, the SenseCAP LoRa OTA path is experimental and must
not be enabled in production builds.
