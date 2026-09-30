# XIAO nRF52840 external-QSPI OTA bootloader overlay

This directory is a reproducible overlay for Adafruit_nRF52_Bootloader commit
`c67f0bcf0fa8e841426335b1bbde91cda6ca1f50`. The upstream checkout and all
build products stay under `.tmp/`; no upstream source is vendored here.

The preferred no-SWD profile keeps USB UF2 mass storage and USB CDC serial DFU
recovery, but deliberately omits optional BLE DFU. It adds P25Q16H candidate
verification, backup, install, trial confirmation, and rollback before the
upstream boot flow starts. The original larger BLE-enabled profile remains
available for SWD commissioning.

## Fixed: no-SWD Ed25519 wrapper stack overflow

`src/xiao_ota_ed25519_tweetnacl.c`'s `ed25519_verify()` previously sized its
`opened_message` scratch buffer to only `message_length` (71) bytes, but
TweetNaCl's `crypto_sign_open(m, mlen, sm, n, pk)` copies the *entire*
signature-plus-message (`n = 64 + message_length`, up to 135 bytes) into `m`
before validating and truncating it. Verifying any real, full-size 71-byte
install-command descriptor -- the exact signature check that gates a
candidate install in `command_policy_valid()` -- overflowed that buffer by up
to 64 bytes on the stack. The prior unit test only exercised the RFC 8032
empty-message vector (`message_length == 0`, so `n == 64`, which happened to
fit), so it never caught this. `opened_message` is now sized to match
`signed_message` (`64 + 71` bytes). `tests/test_descriptor_contract.c` adds
behavioural coverage with real, full 71-byte-message Ed25519 signatures
(verified independently with `openssl pkeyutl -verify`) to prevent
regression. This fix changes only bootloader-internal scratch sizing; the
signed record formats, layout, and journal contract are unchanged.

## Fixed: QSPI EasyDMA cannot read from internal code flash

`copy_internal_to_qspi()` (used by the backup step, `BACKUP_COPYING`) called
`qspi_write()` with a pointer built from `XIAO_OTA_APP_START` -- internal
code flash -- as the EasyDMA source. The nRF52840's QSPI peripheral EasyDMA
can only address Data RAM; it cannot DMA directly out of code flash. On real
hardware this made the backup step's own page-by-page readback verification
unreliable, which meant `copy_internal_to_qspi()` could return `false` (or
worse, silently pass with corrupt data) and trip `force_recovery()` before an
install was ever attempted. The fix stages each 256-byte chunk into a new
`flash_stage_buffer` (Data RAM) with a CPU `memcpy()` first, then hands that
RAM pointer to `qspi_write()`; the readback compare now checks against the
same RAM buffer instead of re-reading flash through EasyDMA rules that don't
apply to it. `tests/test_source.py` adds a source-level regression check that
`copy_internal_to_qspi()`'s `qspi_write()` call is never given a
`XIAO_OTA_APP_START`-based pointer. A genuine behavioural test (mocking the
`NRF_QSPI` peripheral itself) is not included: `xiao_ota_boot.c` depends on
the vendored Adafruit bootloader's hardware headers and isn't host-buildable
without a much larger register-mock harness, and building a partial one that
only covers this call site risked more confidence than it earns. The
source-level check is what's actually shipped; treat this fix as verified by
code review and the corrected size/behaviour above, not by an executed test,
until real QSPI hardware confirms it.

## Fixed: OTA permanently disabled after any rollback

After a successful rollback, the boot flow persisted `state.phase =
XIAO_OTA_PHASE_FAILED` -- but the top-level gate that decides whether a new
signed install command may be accepted only allowed `EMPTY` or `CONFIRMED`.
`FAILED` was a dead end: every later boot hit `if (state.phase ==
XIAO_OTA_PHASE_FAILED) return;` and never looked at a new command again,
even one signed with a fresh, higher security counter. In practice, one
rejected or interrupted OTA attempt would permanently disable OTA on that
device (the application itself kept running fine, since rollback already
restored the verified backup and bank_0 settings before FAILED was written
-- only future installs were blocked). The fix adds `FAILED` to the accepted
phases alongside `EMPTY`/`CONFIRMED`, since a device in `FAILED` is already
confirmed-safe (its bank_0 settings and hash were checked before FAILED was
persisted); a new command still has to pass the same
`command_policy_valid()` signature/counter/hash checks as any other install.
The accept-phase decision now lives in a single, host-testable function,
`xiao_ota_command_acceptable_phase()` (`xiao_ota_record.c`/`.h`), called
directly from `xiao_ota_boot_process()` instead of being re-inlined as an OR
chain; `tests/test_record.c` behaviourally exercises it for every phase
value (not just FAILED), so this can't silently regress again.
`tests/test_source.py` also keeps a source-level check that the boot hook
calls that real function and still reaches `command_policy_valid()` before
re-arming `BACKUP_COPYING`.

## Fixed: corrupt (not erased) anti-rollback floor no longer silently defaults to counter 0

Before this fix, if neither floor A/B copy passed structural validation
(bad magic/CRC), `xiao_ota_boot_process()` unconditionally zeroed the
in-memory floor -- treating a genuinely-blank, never-provisioned floor
(legitimate: this device has never completed an OTA install, counter floor
0 is correct) exactly the same as a *damaged* or *unrelated* floor sector
(e.g. a torn write, or leftover raw bytes from a hardware diagnostic run
before OTA provisioning). That second case silently reopened the
anti-rollback counter at 0, which a corrupted-but-otherwise-unremarkable
flash sector could achieve without any cryptographic bypass at all. The fix
adds `xiao_ota_bytes_erased()` (`xiao_ota_record.c`/`.h`, host-tested) and
uses it to distinguish "both floor slots fully erased" (safe: counter floor
0) from any other invalid floor content (unsafe: `floor_trustworthy =
false`). A new command is now refused outright when the floor is untrustworthy,
and an in-flight transaction is forced into its existing, already-safe
`ROLLBACK_COPYING` recovery path instead of proceeding on a fabricated
counter floor of 0. See "QSPI ownership and records" below for the
operational note this implies for any board whose floor-A sector currently
holds pre-commissioning diagnostic bytes.

## Fixed: install-command size cap no longer allows erasing into v1.17's filesystem region

v1.17's actual internal application code region is only `0x27000..0xD4000`
(708,608 bytes); `0xD4000..0xED000` (102,400 bytes) is where v1.17's own
internal filesystem (LittleFS/ExtraFS) lives today. Before this fix,
`xiao_ota_install_command_policy_valid()` capped a signed command's
`image_size_bytes` (the candidate/install size) against the *full*
`XIAO_OTA_CANDIDATE_SIZE` (811,008 bytes, `0x27000..0xED000`) -- the same
bound used for the QSPI staging slot and for the backup/active-image
extent, where accepting the full range is correct (backing up that many
bytes is always safe: a protective read+copy of whatever is really there,
filesystem included). Applied to the *install* size instead, that same
bound would have let an otherwise cryptographically valid, correctly
signed command install a candidate large enough to erase/overwrite into
v1.17's filesystem region -- nothing else in the wire contract stopped it.

The fix adds a distinct cap, `XIAO_OTA_INSTALL_MAX_SIZE` (`include/
xiao_ota_layout.h`, 708,608 bytes / `0xAD000`, derived from
`XIAO_OTA_INSTALL_ALLOWED_END = 0xD4000`), and uses it (not
`XIAO_OTA_CANDIDATE_SIZE`) for the `image_size_bytes` check only; the
active-image/backup extent check is unchanged and still accepts the full
811,008-byte extent. `tools/sign_image.py` enforces the same two bounds
independently (`INSTALL_MAX_SIZE` for `--image`, `BACKUP_MAX_SIZE` for
`--active-image`) so an over-cap candidate is rejected before it is ever
signed. This is a safety cap, not a wire-format change: no schema,
role/target/format field changes, and both command v1 and v2 share the
identical check. No sweeping filesystem migration is required for this --
every real firmware image today is comfortably under 708,608 bytes; this
cap only stays in force until an explicit filesystem-relocation migration
proves the FS no longer lives past `0xD4000` (no such migration-complete
signal exists yet, so there is nothing to opt into today).

`tests/test_record.c` proves the exact boundary behaviourally: exactly
708,608 bytes is accepted, 708,609 is rejected, and the active-image/backup
extent still accepts the full 811,008 bytes when it matches the expected
active extent.

## Fixed: active-image extent no longer trusts a stale post-install floor value

Before this fix, `xiao_ota_boot_process()` derived the currently-trusted
`expected_active_extent` as `floor.active_image_extent != 0 ?
floor.active_image_extent : active_extent_from_settings(...)` --
preferring a durable value the bootloader itself only ever wrote once, at
the moment a *previous* OTA install was confirmed. If a user has since
reflashed a different image over USB/CDC (bypassing this bootloader
entirely, which is an explicitly supported recovery path), that floor
value goes stale, yet boot would keep trusting it for backup/rollback
sizing and for the extent bound `command_policy_valid()` checks a signed
command against. Separately, `active_extent_from_settings()` itself
silently substituted a full-size guess (`XIAO_OTA_APP_MAX_SIZE`) on any
invalid bank-0 metadata (bad marker, zero/oversized size, or a live CRC-16
mismatch), masking real corruption or a missing image as if it were a
legitimate full-size install.

The fix makes extent derivation unconditional and fail-closed on every
boot: `expected_active_extent` is now always recomputed from *fresh*
bank-0 metadata (current `BANK_VALID_APP` marker, nonzero bounded
`bank_0_size`, and a live CRC-16 recomputed over that exact extent in
internal flash right now) via the new pure, host-tested
`xiao_ota_resolve_active_extent()` (`xiao_ota_record.c`/`.h`); `boot.c`'s
`active_extent_from_settings()` is now a thin wrapper that only performs
the actual flash CRC-16 read and defers the accept/reject decision to it.
`floor.active_image_extent` is no longer read for this purpose at all
(the stale-floor code path is gone); the field is still *written* on
confirmation for record-schema/telemetry stability (no record-version
bump, no counter reset), but is now dead for extent derivation, which is
called out with a comment at the write site. A missing/invalid fresh
bank-0 read fails closed exactly like an untrustworthy floor already did
-- both the command-acceptance gate and the in-flight
backup/install-transaction gate now require `have_active_extent` in
addition to `floor_trustworthy`, so no new command is accepted and no
in-flight transaction is allowed to proceed on a guessed extent; an
in-flight transaction instead takes its existing `ROLLBACK_COPYING`
recovery path. This does not touch `floor.confirmed_counter_floor`, which
remains the sole, unconditional anti-rollback authority regardless of
bank-0 state.

`tests/test_record.c` proves `xiao_ota_resolve_active_extent()`
behaviourally: a fresh, valid, *different*-sized bank-0 image is accepted
on its own CRC-verified size (never a caller-supplied stale value -- the
function does not even take one as an argument, closing the bug at the
API level, not just in one call site); and each of a bad marker, zero
CRC, zero size, oversized size, and a CRC mismatch independently fails
closed with `out_extent` left untouched.



```sh
make test-xiao-ota-bootloader
make package-xiao-ota-bootloader-noswd
```

`tests/test_descriptor_contract.c` and `tests/test_boot_info.c` are both
wired into `test-xiao-ota-bootloader` and run on every invocation.

This test now covers both command versions with real, independently
generated (`openssl pkeyutl -sign -rawin`) Ed25519 signatures: a genuine
59-byte big-endian wire descriptor accepted end-to-end through
`xiao_ota_command_v2_valid()`/`xiao_ota_install_command_from_v2()`/
`ed25519_verify()`/`xiao_ota_install_command_policy_valid()` (the exact call
chain `xiao_ota_boot.c` uses), a legacy 71-byte descriptor accepted the same
way, and proof that a signature made for one form is rejected against the
other even when every logical field value matches.

No-SWD artifacts are written to
`.tmp/xiao_nrf52840_ota_artifacts/custom-noswd/`:

- `xiao_nrf52840_ota_noswd.hex`
- `xiao_nrf52840_ota_noswd_update.uf2`

The no-SWD profile uses the public-domain TweetNaCl Ed25519 verifier. Its
detached-signature wrapper is host-tested against RFC 8032 test vector 1. The
BLE-enabled profile continues to use MeshCore's existing orlp-derived
verify-only sources, including their license and notice.

## Size and boot start

The optimized no-SWD image has a 34,612-byte FLASH load footprint in the 38 KiB
region (`88.95%`, 4,300 bytes free) at `0xF4000..0xFD800`: 33,980 bytes of
code/rodata plus 632 bytes of initialized data. This grew from the prior
34,548-byte build with the addition of the boot-info/capability marker, the
build-time-selectable board-target profile, and the floor-corruption
fail-closed fix (see "Boot-info/capability marker" and "Board profiles"
below). It uses `-Os`, LTO, function/data sections, linker garbage
collection, and removes BLE DFU sources and code. UICR boot start and
`BOOTLOADER_REGION_START` both remain `0xF4000`, so the generated update UF2
is suitable for stock-address bootloader update. The application remains
compatible with S140: the normal MBR initialization and SoftDevice-disable
path before application start is retained.

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

**Erased-vs-corrupt floor is fail-closed.** If neither floor A/B copy passes
structural validation, `xiao_ota_boot_process()` now checks whether *both*
raw slots are fully erased (`0xFF` throughout, via `xiao_ota_bytes_erased()`
in `include/xiao_ota_record.h`/`src/xiao_ota_record.c`, host-tested in
`tests/test_record.c`). Only that genuinely-blank case is treated as "no
confirmed install yet" (counter floor 0, safe for a first install). Any
other invalid floor content -- a torn write, bit rot, or leftover unrelated
data such as a stale hardware-diagnostic write from before OTA provisioning
-- is floor damage, not "no floor yet": the bootloader refuses to accept any
new install command and forces an in-flight transaction to roll back rather
than silently reopening the anti-rollback counter at 0. **A target board
whose floor-A sector still holds leftover raw diagnostic bytes from before
OTA commissioning will hit this fail-closed path and refuse new installs
until that sector is properly erased/commissioned** -- this is a
commissioning/lab-provisioning action for the operator, not something this
bootloader can safely infer or clear on its own.

`xiao_ota_command_t` (command v1) contains the exact 71-byte canonical
descriptor defined by `src/ota/trust/{TrustTypes,CanonicalDescriptor}.h`, its
64-byte Ed25519 signature, transaction nonce, current active-image extent and
SHA-256. `xiao_ota_command_v2_t` (command v2) instead carries the LoRa OTA
transport's own 59-byte big-endian canonical wire descriptor plus its
signature, unchanged (see next section). Both versions share one
structural/policy layout family: `record_version` at a fixed offset (4)
selects which command form and which signed message the bootloader
authenticates; there is no fallback between them. Both are checked for
format/key/algorithm, target, role, device/broadcast address, application
address, required boot capability, size, candidate SHA-256, signature, and a
strictly increasing durable counter, via one shared policy function
(`xiao_ota_install_command_policy_valid()`).

## Install command contract: v1 and v2

`sign_image.py --command-version {1,2}` produces one of two independently
authenticated, mutually exclusive signed install commands. This bootloader
dispatches strictly on the `record_version` field (offset 4 of the command
record) to exactly one of two verification paths -- never both, never a
fallback:

- **Command v1 (legacy, default)**: signs/verifies the 71-byte
  `xiao_ota_canonical_descriptor_t` (`include/xiao_ota_record.h`,
  byte-for-byte identical to `ota::trust::CanonicalDescriptor::serialize()` /
  `ImageDescriptor`): `image_hash_sha256[32]` first, then
  `target_id`/`role_id` as full u32s, `device_address` (u64),
  `allow_broadcast_address` (u8),
  `required_boot_capability_flags`/`monotonic_counter`/`image_size_bytes`/
  `app_address` (u32 each), `format_id`/`key_id`/`algorithm_id` (u16 each).
  Supports real per-device targeting via `device_address`.
- **Command v2 (current)**: signs/verifies the LoRa OTA transport's own
  59-byte big-endian canonical wire descriptor
  (`meshcore::ota::protocol::OtaDescriptor::encodeOtaDescriptorCanonical()`,
  `src/ota/protocol/OtaDescriptor.h`): `boardFamily` (u16), `boardVariant`
  (u16), `role` (u8), `appAddress` (u32), `exactSizeBytes` (u32),
  `sha256[32]`, `securityCounter` (u32), `minBootloaderCapabilities` (u32),
  `formatId/keyId/algorithmId` (u16 each) -- **the exact same 59 bytes and
  the exact same signature the transport already verifies**
  (`src/helpers/ota/OtaFirmwareBackend.h` / `DescriptorVerifier::verifyPolicy()`),
  authenticated directly (`ed25519_verify(sig, wire_descriptor, 59, pubkey)`
  in `command_policy_valid()`, `xiao_ota_boot.c`), never re-derived or
  re-signed into another form. This wire descriptor has no
  `device_address`/`allow_broadcast_address` field at all, so
  `xiao_ota_install_command_from_v2()` unconditionally normalizes a decoded
  v2 command to `device_address=0`/`allow_broadcast_address=1` (always
  broadcast-installable) -- safe because neither field is part of the
  signed bytes, so nothing attacker-controlled is trusted by this
  normalization; it is a documented, permanent limitation of the wire
  format, not a policy relaxation.

Because Ed25519 signs exact message bytes, a signature valid over one form
can never verify against the other, even when every logical field value is
identical -- proven with real signatures in `tests/test_descriptor_contract.c`
(a signature over the 59-byte wire form is rejected against the 71-byte form
and vice versa). Both forms share one policy-check function
(`xiao_ota_install_command_policy_valid()`) operating on a decoded,
version-neutral `xiao_ota_install_command_t`, so target/role/app-address/
format/capability/counter/extent/hash rules are defined exactly once and
apply identically regardless of which command version is presented.
State, transaction, confirmation, and durable-floor journal records are
unaffected by this and remain fixed at record version 1 (`XIAO_OTA_FORMAT_VERSION`);
only the two *command* record types are version-dispatched.

## Boot-info/capability marker

A small, fixed-address, fixed-layout record -- `xiao_ota_boot_info_t`
(`include/xiao_ota_boot_info.h`) -- is baked as a genuine compile-time `const`
object into every custom-bootloader build at `XIAO_OTA_BOOT_INFO_ADDRESS`
(`0xFDC00`), inside the existing 2 KiB `BOOTLOADER_CONFIG` flash region
(`0xFD800..0xFE000`), 1 KiB clear of the stock Adafruit `.bootloaderConfig`
CF2 config-key table and 1 KiB clear of the region end. It exists so the
*application* can, at any time, read this one well-known address and fail
closed if it is not talking to a qualified MeshCore custom bootloader: a
stock/unmodified Adafruit bootloader leaves this address erased (`0xFF`
throughout), which can never satisfy the marker's magic or CRC-32, so
detection needs no special-casing.

```c
typedef struct __attribute__((packed)) {
  uint32_t magic;             /* 0x584F4249 ("XOBI") */
  uint16_t format_version;    /* 1 */
  uint16_t struct_bytes;      /* sizeof(xiao_ota_boot_info_t) == 60 */
  uint32_t board_target_id;   /* this binary's XIAO_OTA_BOARD_TARGET */
  uint32_t role_id;           /* XIAO_OTA_ROLE_ANY */
  uint32_t capability_flags;  /* e.g. XIAO_OTA_CAP_QSPI_INSTALL */
  uint16_t key_id;
  uint16_t algorithm_id;      /* XIAO_OTA_ALGORITHM_ED25519 */
  uint8_t trusted_public_key[32]; /* the exact Ed25519 key this binary verifies with */
  uint32_t crc32;             /* IEEE CRC-32 over every byte above */
} xiao_ota_boot_info_t;        /* 60 bytes, at 0xFDC00 */
```

`xiao_ota_boot_info_valid()` (`include/xiao_ota_record.h`,
`src/xiao_ota_boot_info.c`) validates magic/format/size/CRC; the application
**must** treat a `false` result -- including the fully-erased-stock-bootloader
case -- as "cannot confirm a qualified custom boot", and fail closed rather
than assume install capability or trust an unverified public key.

There is no runtime write path to this object anywhere in this bootloader:
it is `const`, lives in true flash ROM, and a Cortex-M plain store to it
would fault rather than silently succeed even if something attempted it.
Every field except `crc32` is a compile-time literal; `crc32` cannot be
written as a hand-computed C constant without risking silent drift from the
real field values, so the committed source carries a deliberately-invalid
placeholder (`0xFFFFFFFF`, which can never be a real CRC-32 of the 56
preceding bytes) that `tools/prepare_upstream.py` replaces with the real
value -- computed in Python by independently replicating
`xiao_ota_crc32()`'s exact algorithm over the exact packed byte layout --
before the copied source is compiled. A build that skips
`prepare_upstream.py`'s patch step therefore fails `xiao_ota_boot_info_valid()`
immediately rather than shipping a plausible-looking but wrong marker. Both
real no-SWD builds performed while implementing this (default XIAO profile
and the SenseCAP Solar P1 profile below) were independently verified by
parsing the compiled `.hex` and recomputing the CRC-32 in Python: both match
byte-for-byte.

`xiao_ota_boot_info_build()`/`_valid()` are pure and host-tested in
`tests/test_boot_info.c` (see "Build" above for the run recipe): positive
round-trip, magic/format/size/field/key tamper rejection, an explicit
all-`0xFF` (simulated stock bootloader) rejection, an explicit all-zero
rejection, and cross-board-profile distinctness.

## Board profiles

The install-policy target check (`xiao_ota_install_command_policy_valid()`)
and the boot-info marker's `board_target_id` both now read from one macro,
`XIAO_OTA_BOARD_TARGET` (`include/xiao_ota_record.h`), which defaults to
`XIAO_OTA_TARGET_XIAO_NRF52840` (`0x584E3430`) and is overridable at compile
time. `tools/prepare_upstream.py --board {xiao_nrf52840,sensecap_solar_p1}`
selects it (default `xiao_nrf52840`, unchanged behaviour); `tools/sign_image.py
--board {xiao_nrf52840,sensecap_solar_p1}` signs a descriptor's
target/board-family/board-variant fields to match.

`sensecap_solar_p1` (`XIAO_OTA_TARGET_SENSECAP_SOLAR_P1`, `0x53435031`,
"SCP1") is a **real, distinct, non-wildcard** target id -- never a
`0xFFFFFFFF`-style value that matches anything -- documented as sharing the
same checked P25Q16H QSPI physical pin mapping as the XIAO profile (see
"QSPI ownership and records" above), for a SenseCAP Solar P1-class board.
**It has NOT been physically qualified on any real SenseCAP hardware.**
Selecting it only changes what this bootloader compiles/signs for; it makes
no claim that a SenseCAP Solar P1 board has been tested, flashed, or
verified to work. Treat any `sensecap_solar_p1` build strictly as
build-only/unqualified until real hardware confirms it.

Cross-board rejection was verified end-to-end (not just asserted): a
descriptor signed with `--board sensecap_solar_p1` is a fully valid,
correctly-signed v2 command, but a bootloader compiled with the default
`xiao_nrf52840` target rejects it at the policy stage (`target_id` mismatch),
and vice versa -- proving the two profiles are genuinely non-interchangeable,
not merely differently labelled.

If a dedicated `Makefile` package target is wanted for the SenseCAP profile
(e.g. `package-xiao-ota-bootloader-noswd-sensecap`), that is outside this
directory's edit scope; the invocation is otherwise identical to the
existing no-SWD target with `--board sensecap_solar_p1` added to the
`prepare_upstream.py` call.

`prepare_upstream.py --work-dir PATH` overrides the disposable build tree
it copies the pinned upstream into and compiles from (default:
`.tmp/xiao_nrf52840_ota_{noswd_,}upstream`, selected by `--no-ble`, same as
before). A build invoking more than one `--board` profile in the same
`Makefile` run **must** pass a distinct `--work-dir` per profile -- the
default path does not vary by `--board`, so two profiles sharing it would
clobber or relabel each other's build tree and artifacts (e.g.
`--work-dir .tmp/xiao_nrf52840_ota_noswd_upstream_sensecap_solar_p1` for a
SenseCAP no-SWD build run alongside a default-profile no-SWD build).

`PATH` is validated (`validate_work_dir()`) before any git/copy/delete
action: it must resolve (symlinks included) to a strict descendant of
`ROOT/.tmp`, and must not resolve to `.tmp` itself, the repo root, or the
pinned upstream clone -- because the script unconditionally
`shutil.rmtree()`s an existing `WORK` before copying into it, an
unvalidated caller-controlled path here would be a recursive-delete
vulnerability. Rejection happens first: no git, submodule, or filesystem
action runs beforehand.

### Independent artifact-level marker verification

`tools/verify_boot_info_artifact.py` is a standalone, read-only check that
never calls `xiao_ota_boot_info_build()`/`_valid()` (the C helpers this
bootloader itself uses) and never reuses `prepare_upstream.py`'s CRC-patch
logic. It parses the bytes at `0xFDC00` straight out of a real packaged
`.hex` or `.uf2` artifact, decodes them against its own independently
re-declared 60-byte little-endian layout and golden constants, and
separately recomputes and checks the CRC-32, magic, format/size, and every
profile/key field (`board_target_id`, `role_id`, `capability_flags`,
`key_id`, `algorithm_id`, `trusted_public_key`). It is meant to catch
drift or a bad build even if the C helpers and the patch step ever agreed
on the same wrong value:

```sh
python3 bootloader/xiao_nrf52840_ota/tools/verify_boot_info_artifact.py \
  --board xiao_nrf52840 \
  --key-header bootloader/xiao_nrf52840_ota/include/xiao_ota_public_key.h \
  .tmp/xiao_nrf52840_ota_artifacts/custom-noswd/xiao_nrf52840_ota_noswd.hex
```

Run against a real `make package-xiao-ota-bootloader-noswd` output this
session: passes on both the `.hex` and `.uf2` artifacts for the default
`xiao_nrf52840` profile, and passes against a real SenseCAP `--board
sensecap_solar_p1 --work-dir ...` build's own `.hex` and the matching
`--key-header` copied into that build's work tree. Confirmed to genuinely
fail (not silently pass) on: a `--board` argument that does not match the
artifact's real compiled target, and a hand-corrupted marker byte (both
the public-key mismatch and the recomputed-CRC mismatch are reported).
For a SenseCAP artifact, point `--key-header` at the copied
`src/xiao_ota/xiao_ota_public_key.h` inside that build's own `--work-dir`
tree (the same key file that build actually compiled from), not the
top-level `include/` copy, in case they ever diverge.

The lab public key this script (and the marker itself) checks against is
the **publicly-reproducible bench/lab test fixture** generated by
`tools/provision_lab_key.py` -- explicitly bench-only, never a production
key, and its private half is never written anywhere this tool touches or
outputs.

The reader is strict on purpose: it validates every Intel HEX record's
declared byte count and checksum, rejects unsupported (data-address-
affecting) HEX record types instead of silently skipping them, rejects a
UF2 block whose declared payload exceeds 476 bytes or whose trailing magic
is wrong, and rejects two UF2 blocks that write conflicting bytes to the
same address -- rather than letting the last one silently win. The public
key is parsed from the actual `#define ... \` macro block (line-continued,
terminated by the first non-backslash-continued line), not a fixed
character window that could pick up bytes from an unrelated neighbouring
macro. `tests/test_tools.py` proves all of this behaviourally (synthetic
HEX/UF2 fixtures, no real build required): valid extraction, bad checksum,
truncated record length, an unsupported address record type, oversized
UF2 payload, conflicting overlapping UF2 blocks, bad trailing magic, wrong
`--board`, wrong key, and a bad CRC. The same file also proves
`prepare_upstream.py --work-dir`'s path-traversal guard (below) rejects an
unsafe path before any subprocess or delete call -- 22 cases total, all
passing, plus a real end-to-end run of the validator against genuine build
output.

Main has wired a `verify-xiao-ota-boot-info-artifacts` `Makefile` target
that runs this validator against both profiles' real packaged `.hex`/`.uf2`
output. `tests/test_tools.py` is picked up by
`python3 -m unittest discover -s bootloader/xiao_nrf52840_ota/tests -p
test_tools.py`, wired into `test-xiao-ota-bootloader` alongside the
existing `test_source.py`/`test_install_uf2.py` invocations.


## LoRa OTA transport bridge: what still needs to be built (read-only findings)

Read-only inspection of `src/helpers/ota/OtaFirmwareBackend.h`,
`src/ota/trust/{TrustTypes,DescriptorVerifier}.h`, and
`variants/xiao_nrf52/OtaLabBackend.cpp` (all outside this directory's edit
scope) found the following absences. These are reported, not fixed here;
command v2 above removes the *signature-format* incompatibility, but a
durable, working application-side install bridge is still absent:

1. `OtaFirmwareStorageSink::commit()` (`OtaFirmwareBackend.h`) only sets
   `active_ = false`; it never builds or durably journals a command v2
   record into `XIAO_OTA_COMMAND_A`/`_B`, so this bootloader never sees a
   pending install after a LoRa transfer completes.
2. `OtaFirmwareTrustProvider::commitSecurityCounter()` always `return false`
   (stubbed); there is no durable application-side counter store wired to
   `LabMonotonicCounter`'s in-RAM `value_`, which resets to 0 on every boot.
3. `variants/xiao_nrf52/OtaLabBackend.cpp` stages into
   `SenseCapQspiLayout::candidateTestRegion(flash)`, a 16 KiB destructive-test
   subregion, not the production `0x000000..0x0C6000` candidate partition
   this bootloader reads from (`XIAO_OTA_CANDIDATE_BASE`/`_SIZE`).
4. Nothing computes the current internal active-image extent/SHA-256 the
   command record's `active_image_extent`/`active_image_hash_sha256` fields
   require, and nothing tracks/increments a durable transaction nonce.
5. Nothing on the application side reads or checks the new
   `xiao_ota_boot_info_t` marker at `0xFDC00` (see "Boot-info/capability
   marker" above). Before trusting install capability or a public key, the
   bridge should read this address, call `xiao_ota_boot_info_valid()` (or
   equivalent app-side logic against the same layout), and fail closed
   (report "not a qualified custom bootloader" / decline to attempt
   install) on any invalid result, including full erasure (stock
   bootloader) -- this is how the application is meant to distinguish a
   qualified custom boot from stock without any separate out-of-band
   signal.

**The coherent bridge shape** (for the owning agent to implement in
`src/helpers/ota/` and `variants/xiao_nrf52/`, outside this scope): after the
transport verifies the 59-byte canonical descriptor's signature and the
staged-image-hash check passes (`verifyStagedImageHash()`), the bridge must:
(a) read the true current internal active-image extent and SHA-256 rather
than assume any value; (b) build a `xiao_ota_command_v2_t` around the
already-verified 59-byte descriptor bytes and its signature -- **verbatim,
byte-for-byte, from the transport's own verified message and signature, never
re-signed** -- and durably write it as an alternating A/B copy (CRC-32 over
all preceding bytes, then a separately programmed `0x434F4D54` commit
marker, per the record contract above) into `XIAO_OTA_COMMAND_A`/`_B`; (c)
stage the image into the real `0x000000..0x0C6000` candidate partition, not
a test subregion; (d) persist `commitSecurityCounter()` to non-volatile
storage so the anti-rollback floor survives reset; and (e) after reboot,
follow the trial-boot confirmation contract above (write
`xiao_ota_confirmation_t` only once storage, radio, and the main loop are
healthy, and do so before the bootloader's 60-second trial watchdog
expires). `xiao_ota_command_v2_t`, `xiao_ota_wire_descriptor_t`, and the
codec/validation functions in `include/xiao_ota_record.h` are the shared,
host-testable module this bridge should build against; they have no
hardware dependency and are exercised in `tests/test_record.c` and
`tests/test_descriptor_contract.c`.

Separately, `variants/xiao_nrf52/OtaLabBackend.cpp`'s
`DeviceTrustAnchor::expected_target_id = 0x52840001` was an arbitrary
numeric scheme used only for wire-transport policy checks, reported by
another reviewing agent as mismatched against
`XIAO_OTA_TARGET_XIAO_NRF52840 == 0x584E3430` ('XN40') used in
`command_policy_valid()`; that value is owned by `src/` and out of this
directory's edit scope to change.

## Install and confirmation contract

The application stages `candidate.bin`, writes a committed command copy, and
resets. `make sign-xiao-ota-image` creates both using OpenSSL:

```sh
make sign-xiao-ota-image \
  XIAO_OTA_IMAGE=.pio/build/ENV/firmware.bin \
  XIAO_OTA_ACTIVE_IMAGE=installed-firmware.bin \
  XIAO_OTA_COUNTER=2
```

This produces a command v1 (legacy, 71-byte) bundle by default, matching the
Makefile target's current behaviour unchanged. To produce a command v2
bundle around the transport's real 59-byte wire descriptor instead, run
`tools/sign_image.py` directly with `--command-version 2` (not yet wired as
a separate Makefile target/flag; ask before adding one). Output is a
188-byte `install-command.bin` (versus 200 bytes for v1) plus the same
`candidate.bin`/`descriptor.bin`/`descriptor.sig` files, where `descriptor.bin`
is the real 59-byte big-endian wire form, not the 71-byte legacy form.

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
