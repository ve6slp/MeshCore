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

## Proposed memory map

### Internal nRF52840 flash

| Range | Size | Owner |
|---|---:|---|
| `0x00000..0x27000` | 156 KiB | unchanged MBR + S140 v7 |
| `0x27000..0xED000` | 792 KiB | active MeshCore application |
| `0xED000..0xFD800` | 66 KiB | QSPI-capable signed bootloader |
| `0xFD800..0xFE000` | 2 KiB | immutable bootloader configuration |
| `0xFE000..0xFF000` | 4 KiB | MBR parameters |
| `0xFF000..0x100000` | 4 KiB | redundant boot status/settings |

The application capacity remains 811,008 bytes. The current 28 KiB
`InternalFS` region becomes additional bootloader space. All application
persistence moves to the QSPI filesystem partition.

The bootloader build must fail if its code exceeds `0x10800` bytes. Its UICR
boot start address and `BOOTLOADER_REGION_START` must both be `0xED000`.

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

- signature algorithm: ECDSA P-256, matching the signed-firmware facility
  already supported by the Adafruit bootloader toolchain
- verification key: compiled into the bootloader configuration
- signed fields: image bytes, image length, board family, variant, application
  start address, firmware security counter, minimum bootloader version, and
  manifest format version
- integrity: SHA-256 over the exact candidate image
- anti-rollback: bootloader refuses a security counter lower than the highest
  confirmed counter
- LoRa/group authentication authorizes transport but never substitutes for
  bootloader signature verification

The first production bootloader must be installed over SWD, USB, or the
existing signed DFU path. LoRa OTA updates application images only. Bootloader
and SoftDevice OTA are out of scope until a separate recovery-safe design is
proven.

## Power-loss-safe install transaction

The 32 KiB journal is divided into four pairs of independently erasable 4 KiB
sectors:

- manifest and campaign state A/B
- chunk-receipt bitmap snapshots A/B
- boot copy/restore transaction state A/B
- reserved format-upgrade area

Records contain a format version, sequence number, state, image descriptors,
completed 4 KiB page index, and CRC. A record is valid only when its final
commit word has been programmed. Bitmap snapshots are checkpointed in batches;
losing the newest snapshot can cause bounded retransmission but never a false
claim that an unwritten chunk is present.

The receipt bitmap is sized from the negotiated chunk size, not from a small
fixed packet count. At a 160-byte data payload, the maximum 811,008-byte image
requires 5,069 chunks and a 634-byte bitmap. The current
`LoraOtaSession::kMaxChunkBitmapBytes` prototype is only 256 bytes and must be
replaced by this persisted, image-sized representation before transport
integration.

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
   a watchdog, and boots the candidate.
8. The application confirms only after filesystem mount, radio initialization,
   and its normal loop are healthy.
9. A reset before confirmation causes the bootloader to restore and verify the
   backup. Confirmation records the new security counter and permits lazy
   erasure of the old banks.

At no point is internal application flash erased unless both a verified
candidate and a verified backup exist in QSPI.

## Migration from existing SenseCAP firmware

Moving the bootloader start from `0xF4000` to `0xED000` consumes the existing
`InternalFS`. Companion firmware may also have data in `ExtraFS`. Migration
must therefore be staged:

1. Install a migration application with the existing bootloader.
2. Initialize only the QSPI LittleFS partition at `0x194000`.
3. Copy identities, preferences, keys, contacts, channels, and queued data from
   `InternalFS` and `ExtraFS`; read them back and verify them.
4. Write a redundant `storage_migrated` record in the QSPI journal.
5. Refuse bootloader replacement unless migration and QSPI JEDEC/erase/write
   tests pass.
6. Install the QSPI-capable bootloader through a recoverable local method.
7. Install firmware that treats partitioned QSPI LittleFS as primary storage.

The migration firmware must never format the complete QSPI device. Failure
before step 6 leaves the original bootloader and internal data usable.

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
