# XIAO nRF52840 external-QSPI OTA bootloader overlay

This directory is a reproducible overlay for Adafruit_nRF52_Bootloader commit
`c67f0bcf0fa8e841426335b1bbde91cda6ca1f50`. The upstream checkout and all
build products stay under `.tmp/`; no upstream source is vendored here.

The preferred no-SWD profile keeps USB UF2 mass storage and USB CDC serial DFU
recovery, but deliberately omits optional BLE DFU. It adds P25Q16H candidate
verification, backup, install, trial confirmation, and rollback before the
upstream boot flow starts. The original larger BLE-enabled profile remains
available for SWD commissioning.

## Build

```sh
make test-xiao-ota-bootloader
make package-xiao-ota-bootloader-noswd
```

No-SWD artifacts are written to
`.tmp/xiao_nrf52840_ota_artifacts/custom-noswd/`:

- `xiao_nrf52840_ota_noswd.hex`
- `xiao_nrf52840_ota_noswd_update.uf2`

The no-SWD profile uses the public-domain TweetNaCl Ed25519 verifier. Its
detached-signature wrapper is host-tested against RFC 8032 test vector 1. The
BLE-enabled profile continues to use MeshCore's existing orlp-derived
verify-only sources, including their license and notice.

## Size and boot start

The optimized no-SWD image has a 33,652-byte FLASH load footprint in the 38 KiB
region (`86.48%`, 5,260 bytes free) at `0xF4000..0xFD800`: 33,020 bytes of
code/rodata plus 632 bytes of initialized data. It uses `-Os`, LTO,
function/data sections, linker garbage collection, and removes BLE DFU sources
and code. UICR boot start and `BOOTLOADER_REGION_START` both remain `0xF4000`,
so the generated update UF2 is suitable for stock-address bootloader update.
The application remains compatible with S140: the normal MBR initialization
and SoftDevice-disable path before application start is retained.

The prior BLE-enabled build remains intact:

```sh
make package-xiao-ota-bootloader
```

It has a 54,448-byte FLASH load footprint in the 66 KiB
`0xED000..0xFD800` region and requires SWD
for the first relocation because it changes UICR boot start and consumes the
former InternalFS range. Keep the matching pinned stock artifact:

```sh
make build-xiao-stock-bootloader
```

Without SWD the exact currently installed bootloader cannot be read back.
The target above instead saves the reproducible matching upstream stock HEX
and update UF2 under `.tmp/xiao_nrf52840_ota_artifacts/stock/`.

Initial commissioning of the BLE-enabled fallback with a Nordic-compatible
SWD probe is:

```sh
nrfjprog -f nrf52 --program \
  .tmp/xiao_nrf52840_ota_artifacts/custom/xiao_nrf52840_ota_nosd.hex \
  --sectoranduicrerase --verify --reset
```

To restore the matching pinned stock bootloader over SWD:

```sh
nrfjprog -f nrf52 --program \
  .tmp/xiao_nrf52840_ota_artifacts/stock/xiao_nrf52840_ble_stock_c67f0bcf0fa8e841426335b1bbde91cda6ca1f50_nosd.hex \
  --sectoranduicrerase --verify --reset
```

Both commands alter UICR and must be run only after preserving device data.
Build the preferred no-SWD package and matching pinned stock recovery artifact:

```sh
make package-xiao-ota-bootloader-noswd
make build-xiao-stock-bootloader
```

Then request bootloader mode for the authorized target. If software entry fails,
physically double-reset the XIAO and wait for its `XIAO-BOOT` volume:

```sh
make enter-xiao-nrf52-target-bootloader
# If that fails: physically double-reset, then continue.
make install-xiao-nrf52-target-ota-bootloader
```

The guarded installer resolves the `target` role through `lab/devices.ini`,
requires the stable `/dev/serial/by-id` `XIAO-BOOT` identity for that serial,
matches the mounted UF2 volume through its udev/sysfs USB serial ancestry,
requires `Board-ID: nRF52840-SeeedXiao-v1` in `INFO_UF2.TXT`, and refuses
missing, wrong, or ambiguous devices. It never selects a `ttyACM` number.
The stock recovery UF2 is
`.tmp/xiao_nrf52840_ota_artifacts/stock/xiao_nrf52840_ble_stock_c67f0bcf0fa8e841426335b1bbde91cda6ca1f50_update.uf2`.

## QSPI ownership and records

The P25Q16H pins were checked against the framework variant's physical mapping:
SCK P0.21, CS P0.25, IO0 P0.20, IO1 P0.24, IO2 P0.22, IO3 P0.23.

The geometry is fixed:

| Range | Owner |
|---|---|
| `0x000000..0x0C6000` | candidate |
| `0x0C6000..0x18C000` | byte-verified active-image backup |
| `0x18C000..0x194000` | OTA journal |
| `0x194000..0x200000` | application filesystem |

The journal's eight independently erasable sectors are:

| Sector | Contract |
|---|---|
| `0x18C000`, `0x18D000` | install command A/B |
| `0x18E000`, `0x18F000` | boot transaction state A/B |
| `0x190000`, `0x191000` | application confirmation A/B |
| `0x192000`, `0x193000` | confirmed anti-rollback floor A/B |

All records use alternating monotonically sequenced copies, CRC-32 over bytes
before `crc32`, and a final separately programmed `0x434F4D54` commit marker.
The application must coordinate exclusive QSPI access and must never mount,
erase, or allocate these sectors as filesystem space.

`xiao_ota_command_t` contains the exact 71-byte canonical descriptor defined by
`src/ota/trust/{TrustTypes,CanonicalDescriptor}.h`, its 64-byte Ed25519
signature, transaction nonce, current active-image extent and SHA-256. The
bootloader checks format/key/algorithm, target, role, device/broadcast address,
application address, required boot capability, size, candidate SHA-256,
signature, and a strictly increasing durable counter.

## Install and confirmation contract

The application stages `candidate.bin`, writes a committed command copy, and
resets. `make sign-xiao-ota-image` creates both using OpenSSL:

```sh
make sign-xiao-ota-image \
  XIAO_OTA_IMAGE=.pio/build/ENV/firmware.bin \
  XIAO_OTA_ACTIVE_IMAGE=installed-firmware.bin \
  XIAO_OTA_COUNTER=2
```

The active image file must be the exact installed binary extent beginning at
`0x27000`; the maximum end is `0xED000`. The bootloader authenticates the
complete candidate and hashes the current internal extent before copying it.
The extent must match the upstream bootloader's word-rounded bank-0 size for
the first install and the last confirmed durable extent thereafter. The first
install trusts the upstream size only when bank 0 is valid and its nonzero
CRC-16 matches internal flash. If validity, size, or CRC is absent, stale, or
outside `0x27000..0xED000`, the complete 792 KiB application region must be
supplied as the active image so rollback cannot be shortened by stale metadata.
It does not erase an internal application page until the complete backup is
durable and its full SHA-256 matches.

Before destructive installation, the transaction state journals the prior
upstream bank-0 validity, size, and CRC. A verified candidate's size and CRC-16
are written to the upstream settings page before trial boot; rollback restores
the journaled metadata before the old application is allowed to boot.

Explicit UF2, CDC serial, and legacy DFU GPREGRET requests bypass OTA processing
and are consumed by upstream `check_dfu_mode()`, including during a persistent
install or rollback transaction.

On trial boot the application writes `xiao_ota_confirmation_t` to the older
confirmation sector, programs the commit marker last, then resets. The token
must repeat the transaction nonce, candidate counter, and candidate hash.
Confirmation should happen only after storage mount, radio initialization,
and the normal loop are healthy.

The bootloader starts a 60-second watchdog for a trial. Trial firmware must not
feed or reconfigure that watchdog until it has committed confirmation. At most
three unconfirmed boots are allowed; then the byte-verified backup is restored.
Power loss in backup/install/rollback resumes from the last committed 4 KiB
boundary. Candidate and backup are not erased by the bootloader.

## Lab key

The committed key is a non-secret lab public key. Its private key exists only
as `.tmp/xiao-ota-keys/lab-ed25519-private.pem`. To create or deliberately
rotate the lab key and update the public header:

```sh
make provision-xiao-ota-lab-key
```

Review and commit only `include/xiao_ota_public_key.h`; never commit `.tmp`.
Production commissioning must replace this lab key under controlled key
management.
