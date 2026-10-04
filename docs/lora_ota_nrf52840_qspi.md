# SenseCAP Solar nRF52840 QSPI staging and recovery

## Decision and status

The SenseCAP Solar P1 Pro and XIAO nRF52840 can support recoverable LoRa
updates without fitting two applications in internal flash. The design
retains the running application internally, stages a candidate in external
QSPI, and backs up the working application before an install changes it.
A QSPI-aware bootloader copies or restores the image through a durable
journal. This is not execute-in-place or the stock Adafruit dual-bank mode.

**The signed, single-candidate implementation remains experimental.**
Earlier native tests, ARM packages and raw-QSPI lab results do not qualify
the replacement. No physical board has completed a LoRa-delivered install,
trial confirmation or rollback. No SenseCAP board has been physically
qualified. Do not install an artifact solely because an earlier revision
fit or passed a native suite.

The approved target stopped returning on USB after a bootloader activation
request. Transfer acknowledgement does not establish installed bytes or a
working loader. Recovery remains paused pending the bounded, non-erasing
diagnosis gates in the [incident notes](lora_ota_bootloader_failure_notes.md).
Do not retry commissioning, unlock, erase or reset it to test a hypothesis.
The working companion remains stock `CACHE_ONLY`; its local staging proof
does not qualify this target's installation or recovery.

The duplicate authority, commissioning receipts, lifetime-role proofs and
transport-key ledgers are removed from the accepted design. MeshCore's
application authorizes the administrator. Boot independently checks the
image using the admitted administrator's public key, not a second registry.

See the [design](lora_ota_design.md), [administrator guide](lora_ota_administration.md)
and [developer guide](lora_ota_development.md) for the common update policy.

## Bootloader reliability review and isolation options

The code-only review of baseline `ccc0a77b` found two mandatory reliability
defects. They are not diagnoses of the original board's missing USB:

| Finding | Required safety boundary |
| --- | --- |
| QSPI command completion was treated as physical erase/program completion | Wait for flash WIP to clear with bounded operation-specific deadlines. Stop peripheral/DMA access before returning an error so a queued transfer cannot outlive its buffer. Wake and wait for flash idle before startup admission |
| QSPI failure forced recovery, while interrupted APP copies could retain SDK bank VALID | Durably invalidate the existing SDK bank before every destructive install/rollback entry or resume. Publish bank/CRC validity last, only after complete image verification and the other settings. Permit unavailable-QSPI fallback only when intact-bank evidence is sufficient; erased/torn/pending settings are not evidence |

The existing SDK settings and original-settings sidecar are sufficient for
this boundary; another authority, journal or replay ledger is not needed.
An SDK page erase/rewrite can use the named INVALID value without relying on
an uncertain number of repeated per-word programming pulses. Every successful
barrier must be read back before the first APP erase. Restoration must retain
the original 28 settings bytes, including an original zero CRC; a zero CRC
alone is never integrity evidence.

If QSPI is unavailable after a complete candidate has been published, an
otherwise admissible internal image may be an **unconfirmed trial candidate**,
not the previous healthy firmware. Such fallback must not count trials,
confirm the candidate or advance the version floor. No bootloader arrangement
can restore an application from a physically unavailable external backup.

The current custom overlay is pinned to Adafruit
`c67f0bcf0fa8e841426335b1bbde91cda6ca1f50`. It is **not** the official
OTAFIX 2.3 source `a62825be4733f500271c89b5ec489fd609748e97`, whose unmodified
release has returned USB and booted ordinary/OTA applications on replacement
`77CD...`. That vendor result does not qualify our custom installer.

The reviewed baseline's four board/role ELF snapshots consume **38,460 of
38,912 code-region bytes**, including initialized data: only **452 bytes**
remain. This is baseline arithmetic, not fit proof for either correction.

| Architecture | Capacity and recovery tradeoff |
| --- | --- |
| Correct the current single loader | No repartition, but corrected artifacts must fit. Recovery and installer remain in the same replacement image |
| Two complete loader slots plus a selector | Two 40 KiB slots cannot fit the existing 40 KiB boot area. An example 80 KiB APP reservation lowers its limit to 626,688 bytes, before any additional selector cost. A second valid image does not itself detect a running loader hang |
| Frozen OTAFIX recovery primary plus one fixed internal installer | A proposed 64 KiB reservation at `0xC4000..0xD4000` lowers APP capacity to 643,072 bytes. Primary-owned USB/BLE recovery can avoid QSPI and installer execution after an explicit reset escape. Target/client images of 538,360/548,772 bytes leave 104,712/94,300 bytes respectively |

The integrated single-loader result now makes the capacity constraint
concrete: all four board/role profiles need **39,436 bytes** (39,188 code plus
248 initialized data), exceeding the 38,912-byte region by **524 bytes**.
No valid ELF/HEX/UF2 was produced. Checks, cryptography and layout were not
weakened to obtain a fit. The flash-completion/wake correction is source-reviewed
at `c67d30db`; its separate pre-F2 build leaves 52 bytes, not integrated headroom.

**The user approved the fixed OTAFIX-primary/internal-installer architecture
for source implementation and qualification.** The later development-hardware
review selected a supervised compound APP preload, one serial primary
replacement and final APP restoration on the authorized canary; it did not
qualify an unattended fleet rollout. Both components are initially frozen,
with no remote bootloader update path. The approved reservation is:

| Range | Owner and limit |
| --- | --- |
| `0x27000..0xC4000` | APP, 643,072 bytes (628 KiB) |
| `0xC4000..0xD4000` | fixed internal installer, 65,536 bytes |
| `0xD4000..0xF4000` | both existing filesystems, unchanged |
| `0xF4000..0xFE000` | minimally modified OTAFIX primary/configuration, unchanged start |
| `0xFE000..0x100000` | MBR parameters and SDK settings, unchanged |

Live integration must wire the reservation into application/boot contracts.
Moving a binary is not sufficient: the existing monolithic runtimes use
overlapping RAM, and a returning installer call is not the vendor's
non-returning reset-vector jump. A source prototype must establish a small typed ABI, disjoint runtime
storage, retained reset escape and actual paired-artifact fit. Every
USB/BLE/LoRa writing path must exclude the secondary, filesystems and primary.
The vendor UF2 APP upper bound currently does not protect the new reservation.

The F2 kernel's native cut model covers SDK invalidation and validity-last
publication, but **vendor recovery writers are a coupled integration dependency**.
Pinned SDK11 `dfu_single_bank.c` starts APP erasure before the completed-erase
callback invalidates bank0. That invalidates a global CRC0-fallback claim.
Every destructive APP/staging writer needs a verified pre-erase barrier;
compare the exact OTAFIX 2.3 implementation rather than assuming vendor-source
versions are interchangeable. A valid image or recovery gate alone does not
close that erase window. Whole-loader A/B, QSPI execution and an APP-resident
shim are not substitutes for these copy/write invariants.

The retained F2 review also found a recovery regression in the proposed strict
SDK execution check: stock UF2 completion publishes VALID with CRC0 and **size0**,
which that check correctly refuses as an unbounded extent. Preserving UF2
recovery therefore requires fixing its actual writer to invalidate before the
first APP write and publish the real bounded written extent with VALID last.
Do not weaken the extent check or call native kernel cuts a UF2 recovery proof.
The existing serial DFU path also publishes CRC0; simply rejecting CRC0
fallback would disable it without closing interrupted UF2 writes.

Neither A/B nor chaining protects the first replacement of the working
primary. The selected bench route preloads the matched installer under the
working vendor loader and verifies bounded APP/installer bytes before that
replacement. SWD remains the recovery requirement if the canary then loses
all USB access; optional automatic fault handling is deferred, not proven.
Keep the vendor loader unchanged until the complete Sense role1 pair,
ordinary recovery writers and ordered source sequence pass final review.
See the
[incident notes](lora_ota_bootloader_failure_notes.md) for the distinction
between source findings, the supervised commissioning sequence and the
unresolved original activation failure.

## Hardware and existing storage

The P25Q16H QSPI device has a 2 MiB capacity, 4 KiB erase sectors and
256-byte program pages. The lab target reported JEDEC `85:60:15`.
The XIAO framework maps the physical signals as follows:

| Signal | Pin |
| --- | --- |
| SCK | P0.21 |
| CS | P0.25 |
| IO0 | P0.20 |
| IO1 | P0.24 |
| IO2 | P0.22 |
| IO3 | P0.23 |

The SenseCAP profile uses the checked corresponding pin mapping. Matching
MCU, flash and radio parts supports using XIAO boards for initial
qualification; it does not replace testing the actual SenseCAP hardware.

The framework's whole-device `CustomLFS_QSPIFlash` starts at QSPI offset
zero and cannot safely coexist with raw OTA banks. OTA profiles must use
partitioned ownership or retain their existing internal filesystem. Neither
the application nor bootloader may format the whole QSPI device.

Repository evidence includes `variants/sensecap_solar/variant.h`,
`variants/sensecap_solar/platformio.ini`, the XIAO framework variant and
`examples/companion_radio/main.cpp`. The underlying layouts are documented
in the [Adafruit linker](https://github.com/adafruit/Adafruit_nRF52_Bootloader/blob/master/linker/nrf52840.ld)
and [CustomLFS implementation](https://github.com/oltaco/CustomLFS/blob/0.2.3/src/CustomLFS_QSPIFlash.cpp).

## Fixed memory map

The live OTA application contract reserves the following installer region;
paired-primary integration and hardware commissioning remain separate gates.
Neither table is evidence of an installed custom loader: the replacement
still runs the official vendor loader.

### Internal nRF52840 flash

| Range | Size | Owner |
| --- | ---: | --- |
| `0x00000..0x27000` | 156 KiB | unchanged MBR and S140 v7 |
| `0x27000..0xC4000` | 628 KiB | active OTA MeshCore application |
| `0xC4000..0xD4000` | 64 KiB | fixed internal installer |
| `0xD4000..0xED000` | 100 KiB | preserved `InternalExtraFS` |
| `0xED000..0xF4000` | 28 KiB | preserved `InternalFS` |
| `0xF4000..0xFD800` | 38 KiB | recovery primary code and flash loads |
| `0xFD800..0xFE000` | 2 KiB | fixed bootloader configuration |
| `0xFE000..0xFF000` | 4 KiB | MBR parameters |
| `0xFF000..0x100000` | 4 KiB | upstream bootloader settings |

The nRF OTA installation limit is **643,072 bytes**, selected only by OTA
application profiles. The ordinary shared linker is unchanged. External
candidate/backup regions and generic/ESP transfer limits remain **708,608
bytes**; those physical sizes do not authorize installing across the fixed
internal installer or MeshCore's ExtraFS.

Bootloader commissioning must preserve these filesystems too. The retained
vendor UF2 self-update implementation stages its payload at
`0xE0000..0xEA000`, inside ExtraFS; a destination-address whitelist does
not protect against that indirect erase. Do not use mass-storage UF2
self-update for this layout. The ordinary serial bootloader-only workflow
uses application staging instead and requires a separate qualified
application restore before healthy boot and genesis-floor acceptance.
See the [hardware workflow](hardware_lab.md#bootloader-commissioning)
for the current commissioning gate and evidence limits.
The OTA source contracts are `boards/nrf52840_s140_v7_ota.ld` and
`src/ota/platform/Nrf52FlashLayoutContract.h`.

The USB-recoverable bootloader keeps the stock `0xF4000` start address.
Its fit must include every file-backed flash load address, including
initialized `.data`, and must not overlap the fixed configuration at
`0xFD800`. A `.text` size or linker percentage alone is not proof of fit.
The boot-info marker remains at `0xFDC00`.

An earlier build qualification covered XIAO nRF52840 and SenseCAP Solar P1,
each in companion and repeater roles. Those four packages used **37,812 of
38,912 bytes**, leaving 1,100 bytes free. Independent ELF section inspection
includes `.text`, `.ARM.exidx` and initialized `.data`: their flash loads
end at `0xFD3B4`, below the `0xFD800` configuration boundary. Configuration,
boot-info and UICR records occupy their separately reserved locations.
Uninitialized sections do not carry flash payloads.
These are historical footprints, not current package limits or installed
byte evidence; qualify the complete load of each new artifact.

`make qualify-xiao-ota-bootloader` retains each actual ELF, HEX, UF2, linker
map and section report, and checks package board, role, capabilities and
integrity. This qualifies the build artifacts and simulated boot recovery,
not installed hardware. Physical power-cut and failed-trial recovery remain
mandatory before deployment.

### External P25Q16H QSPI

| Range | Size | Owner |
| --- | ---: | --- |
| `0x000000..0x0AD000` | 692 KiB | candidate application |
| `0x0AD000..0x0C6000` | 100 KiB | reserved receiver progress/metadata space |
| `0x0C6000..0x173000` | 692 KiB | last-known-good backup |
| `0x173000..0x18C000` | 100 KiB | reserved, not image capacity |
| `0x18C000..0x194000` | 32 KiB | install and recovery journal |
| `0x194000..0x200000` | 432 KiB | external filesystem reservation |

All boundaries are erase-sector aligned. The physical placement stride
`0xC6000` is not installable image capacity. Both image banks expose only
708,608 bytes. The former `securityA` and `securityB` names do not imply a
continuing authority or global security store; that system has been deleted.
The receiver uses `OtaCandidateStore` for durable candidate metadata and
receipt bits inside its reserved view, separate from the boot journal.

`SenseCapQspiLayout.h` and `Nrf52FlashLayoutContract.h` define the boundaries.
Partition accessors must reject writes and erases outside their own view.
The filesystem reservation is not a claim that a filesystem is mounted or
that existing data has been migrated.

### Shared QSPI ownership

The application has one physical flash owner with non-overlapping views for
the candidate, durable reception metadata, backup, boot journal and any
partitioned filesystem. Boot uses a minimal polling driver after reset and
does not mount LittleFS. Reception progress must not erase sectors owned by
boot recovery.

Destructive hardware probes use candidate-owned scratch:
`0x0A9000..0x0AD000` for the 16 KiB candidate probe and
`0x0AB000..0x0AD000` for the 8 KiB record probe. These are overlapping
maintenance windows, not simultaneously available storage. They require
explicit maintenance authorization and confirmation that no candidate or
recovery operation owns the affected bytes.

A blank journal is not permission to erase anything and is not proof that
the board is uncommissioned. The relocated probe windows have not yet been
qualified on physical hardware.

## Identity and signed-image contract

The application uses current MeshCore administrator policy to admit the
manifest signer. A supplied public key or a known group secret is not enough.
Ed25519 verifies the signature with that public key; the administrator's
private key is never stored on the target.

The install command durably snapshots the app-admitted public key and the
original signed manifest. Boot independently validates the signature,
candidate SHA-256, board, firmware role, application address, exact size,
capabilities and confirmed version floor. It must not authenticate a
reconstructed or differently signed descriptor.

The sole command is version 3, exactly 220 bytes. It carries the original
canonical 59-byte descriptor, the admitted signer public key and its
64-byte Ed25519 signature. The signature covers those same 59 descriptor
bytes, with no extra prefix or alternate encoding. Boot verifies with the
command's admitted key, never a compiled fallback. The application writer
must bind that key to the admitted owner at explicit commit. See
`xiao_ota_record.h` and the [developer guide](lora_ota_development.md)
for the byte layout. Legacy command v1/v2 descriptions and fixed-key
commissioning recipes are not supported.

This protects against local corruption and interrupted installation. It is
not a physical-attacker secure-boot or APPROTECT claim. There is no locked
mirror of the application's administrator ACL in boot.

The stock Adafruit bootloader cannot consume a QSPI-staged candidate. An
unsupported or mismatched loader must cause an explicit update refusal
without stopping ordinary mesh operation. The initial QSPI-aware loader
must be installed through a recoverable local method. LoRa OTA updates
application images only; bootloader and SoftDevice OTA are out of scope.

## Durable reception and explicit commit

The receiver retains one candidate and its original owner. Signed frames
bind the full manifest identity and their block contents. Bad frames do
not destroy valid progress. Durably received duplicates do not program
flash again. A reboot resumes from durable metadata.

The complete image is checked through the same validation path in direct,
routed and background modes. Successful validation records durable
`READY`, **not an install command**. The current application stays on the
mesh while waiting.

Only the original owner, still trusted as an administrator, may commit the
validated image to that individual target. Any trusted administrator may
abort before commit and suppress reception of that image until an explicit
restart. Once boot installation begins, recovery is local; it cannot wait
for another radio packet or an abort command.

## Power-loss-safe installation

The boot journal contains four independently erasable A/B pairs:

| Pair | Sector addresses |
| --- | --- |
| install command | `0x18C000`, `0x18D000` |
| transaction state | `0x18E000`, `0x18F000` |
| trial confirmation | `0x190000`, `0x191000` |
| confirmed version floor | `0x192000`, `0x193000` |

Records use a version, bounded length, sequence, CRC and final commit
marker. A torn write must leave the previous valid copy usable. Storage
errors must be reported, not treated as empty records or successful writes.
Receipt bitmaps belong outside these eight boot sectors.

Required install sequence:

1. Accept the explicit commit and durably publish the signed install command.
2. Independently validate the candidate and command before destructive work.
3. Back up the working application to QSPI and verify its complete hash.
   Preserve the exact original upstream SDK settings in durable metadata.
4. Publish upstream `BANK_INVALID` before the first internal application
   erase. A cut during settings publication or copying must resume from the
   journal or restore the verified backup, never execute a partial image.
5. Copy and verify the candidate with bounded page operations and durable
   progress. Preserve ExtraFS, InternalFS, MBR, SoftDevice and bootloader.
6. Verify the complete installed image. Publish validated SDK settings and
   the valid-bank marker last, with the durable trial state in place.
7. Trial-boot under a bounded watchdog. Confirm only after the filesystem,
   radio and ordinary application loop are healthy.
8. On confirmation, durably advance the version floor without regression.
   If the trial fails, authenticate and restore the backup, including the
   original SDK settings, then return to ordinary mesh service.

The SDK settings snapshot is exactly the 28 bytes at
`0xFF000..0xFF01C`: bank-0 state at offset 0, CRC-16 at 2, bank-1 state at
4, padding at 6–7, image size at 8 and the words at 12, 16, 20 and 24.
Rollback must restore those bytes, not rebuild settings from a potentially
torn live page. A computed CRC-16 of zero is valid.

Active image bounds and CRC must come from current validated SDK metadata,
not a stale confirmed-image extent after a USB reflash. A baseline too
large for the backup bank must refuse OTA before erase, not truncate the
backup. An unreadable journal with invalid SDK bank state must never
fall through to a half-written application.

A healthy idle application does not need a genesis receipt, role proof or
OTA floor-activation ceremony to boot. Explicit local DFU requests retain
the upstream recovery path.

These are acceptance requirements for the replacement. Native fault
injection must drive the actual `xiao_ota_boot_process_io()` processor and
compare real application bytes and all 28 SDK settings bytes after cuts,
not merely assert an outcome enum. Physical recovery is still unverified.

### Startup escape and application integrity

The overlay completes the vendor's pending bootloader or SoftDevice update
handling before starting OTA checks. A reset-pin boot arms the existing
double-reset marker throughout those checks and restores its previous value
when they return. A second pin reset can therefore select vendor DFU without
entering a stalled OTA hook. Physical double-reset DFU has no startup timeout.

Explicit local DFU requests also bypass the OTA hook. A boot that bypasses
the hook must reset rather than jump into the application when DFU ends or
times out; the next ordinary boot must run the recovery checks first.
Otherwise, the vendor's optional-CRC application policy could accept an
incomplete copy. These guards do not add a startup watchdog, journal format
or separate authorization system.

This escape point follows vendor initialization and pending-update handling;
it cannot bypass a fault before that point. These are replacement-software
requirements, not a capability readback or recovery result from the target
that stopped re-enumerating after commissioning.

## Reproducible qualification and installation gates

The selected Sense role1 commissioning pair uses the OTAFIX 2.3 source at
`oltaco/Adafruit_nRF52_Bootloader_OTAFIX` commit
`a62825be4733f500271c89b5ec489fd609748e97`, with its preserving recovery
primary and the fixed installer. Use the qualified local vendor checkout and
provenance inputs; these bench targets do not yet provide a clean-checkout
vendor fetch workflow.

```sh
make build-xiao-ota-bootloader-pair
make test-xiao-ota-bootloader-pair
make package-xiao-ota-bootloader-pair \
  XIAO_OTA_PAIR_APP_PACKAGE=/path/to/saved-working-application.zip
make verify-xiao-ota-bootloader-pair-packages \
  XIAO_OTA_PAIR_APP_PACKAGE=/path/to/saved-working-application.zip
```

The compound constructor requires the canary's saved 538,360-byte working APP,
not a newly built replacement. It validates the exact prefix, erased-byte gap,
matching installer, source/artifact binding and standard application-only DFU
package. Package verification is offline, not installed-byte evidence. Bounded
APP/installer readback and final host-command review still precede the primary
replacement; see [the selected sequence](lora_ota_bootloader_failure_notes.md#selected-development-commissioning-sequence).

The older monolithic overlay remains pinned to Adafruit_nRF52_Bootloader commit
`c67f0bcf0fa8e841426335b1bbde91cda6ca1f50`. Its legacy qualification targets
remain available, but are **not the selected canary commissioning route**:

```sh
make test-xiao-ota-bootloader
make qualify-xiao-ota-bootloader
make test-ota-image-layout-index
```

The four-profile gate covers XIAO and SenseCAP for companion role 0 and
repeater role 1. It must validate actual flash loads, board/role markers and
UF2 packages. Offline success is not hardware qualification.

Offline gates alone do not authorize installation. The failed target first
requires current diagnosis and a separately approved recovery boundary; do not
use the generic installer to retry it. For subsequent authorized commissioning,
keep a validated stock recovery artifact and preserve
identity and configuration first. Hardware targets resolve stable serial
identities from `lab/devices.ini`; they must not select a transient tty or
power-cycle a protected shared hub domain.

The optional older BLE-enabled 66 KiB loader moves its start to `0xED000`
and conflicts with the existing InternalFS region. Its data-migration
design is unimplemented and out of scope for the fixed-address USB profile.
Do not use it as a size workaround or move filesystems to make a package fit.

## Historical XIAO QSPI evidence

The application-side qualification entry point is:

```sh
make validate-xiao-nrf52-qspi-hardware
```

Earlier runs on target serial `3BE94917B92DC5E9` reported:

- JEDEC `85:60:15`; 2,097,152-byte capacity and 4,096-byte erase sectors
- status registers SR1 `00`, SR2 `02`, SR3 `00`
- erased bytes reading as `FF`
- unaligned byte-range write/readback through word-aligned EasyDMA buffers
- NOR 0-to-1 rewrite refused as `PartialProgramViolation`
- unaligned erase refused as `Unaligned`
- out-of-bounds read refused as `OutOfRange`
- an 8,192-byte signed candidate staged and read back with matching SHA-256
  and real Ed25519 verification

The captured log is `.tmp/xiao-nrf52-qspi-3BE94917B92DC5E9.log` in the
original lab checkout. These results qualify the raw flash/signature path
of that revision, not the replacement's receiver or a bootloader install.

The historical candidate test used `0x0C2000..0x0C6000`, and its journal
test used `0x192000..0x194000`. Those are **not safe current scratch
addresses**: the latter are the confirmed-floor sectors. New runs must use
the authorized candidate-owned windows above and preserve boot metadata.

An early test exhausted the task stack, and a subsequent sysfs USB
`authorized` toggle wedged enumeration. The target later returned to service.
Those incidents do not explain the later bootloader-commissioning failure
on Oct. 2, 2026. The target remains inaccessible pending non-erasing SWD
diagnosis; do not repeat historical power-cycle or flashing procedures.
See the [current commissioning record](hardware_lab.md#bootloader-commissioning)
and [incident analysis](lora_ota_bootloader_failure_notes.md). A first SWD
capture is bounded public metadata, not a full-media archive or loader hash;
fixture continuity, probe identity, the RESET-contact decision and explicit
authorization remain physical prerequisites.
The other authorized board is client serial `4186AE911D94CDB1`; the unrelated
Pine device is excluded.

The historical binary journal reader and floor-cleanup helper have been
removed. They do not match the replacement's text repeater or candidate
protocol. Journal blankness alone cannot distinguish a stock loader from
an installed custom loader that has not processed an update. The boot-info
marker is a separate capability check, not proof of an end-to-end install.
Do not erase floor sectors or reinterpret unknown records as counter zero.

## Physical acceptance

Initial XIAO bench qualification must establish:

1. Stable MeshCore service on the two authorized nodes at 907.525 MHz.
2. Signed direct, routed and background transfers, with reboot resume,
   duplicate no-write behaviour, bad-frame isolation and busy-owner refusal.
3. Durable `READY` without installation, administrator abort suppression,
   and explicit per-target commit.
4. A real firmware install and late confirmation, with identity and
   configuration unchanged.
5. Power interruption during settings publication and image copy, followed
   by resume or verified rollback without SWD.
6. A failed trial returning the previous application to the mesh.
7. Measured OTA airtime within policy and ordinary traffic still usable
   under sustained update load.
8. Local USB recovery still available.

Two boards can test routed packet handling over a direct RF path. They
cannot demonstrate physical multi-hop delivery or fleet contention.
SenseCAP qualification must additionally repeat the storage and recovery
checks on an actual P1 Pro, including its power arrangement. A matching
chip and pin map is not a substitute for those results.

Until these gates pass, the nRF52840 LoRa OTA path remains experimental.
