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
slot. A competing image or administrator receives a busy refusal. Any currently
trusted administrator may abort before commit and suppress reception of that
image until an explicit restart.

All three transfer modes converge on the same image validation. Complete
reception leaves durable `READY` state, not an install command. Only an explicit,
target-bound commit by the original owner, still trusted as an administrator,
publishes the bootloader handoff. The current image remains operational during
reception and while waiting for commit. These are software contracts, not
physical hardware results.

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
existing `4200` reply, versioned signed-upload replies, storage or boot state.
Older applications ignore the selector, so a lifecycle-only reply is not
preflight evidence.

The USB-only XIAO nRF52840 OTA-lab companion accepts the exact framed
CMD_REBOOT payload `13 72 65 62 6f 6f 74 20 75 66 32` (`reboot uf2`, no
terminator). Provenance comes from the actual USB reader, not command data.
Mixed-transport and other profiles are unsupported. Accepted requests reply
with the ordinary one-byte OK frame, then wait at least two seconds for RF,
outbound and interface queues to drain, with the target's fifteen-second
bound. Permission is checked again during the wait and immediately before
entry; cancellation emits a standard bad-state error. Eligible dirty contacts
are saved before entry; a failed save emits file-I/O error and cancels entry.
The existing ordinary `reboot` and its persistence eligibility are unchanged.

UF2 entry refuses trial/unknown-write state, pending boot verification or OTA
RF work, and erasing, receiving, verifying, ready, cache-sealed, commit-pending
or trial phases. Explicitly abort a sealed local cache through the existing
control before requesting entry; entry never aborts or erases it implicitly.
Malformed UF2 payloads return illegal-argument error without ordinary reset.
This uses the framework's `enterUf2Dfu()` (`GPREGRET=0x57`), not the
1200-baud serial-only path (`0x4e`). Source support does not prove installed
MSC availability or bootloader version; those still require ROOT readback.

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

The qualified ESP OTA-on images intercept Arduino 2.0.17's NVS initialization
through a build-local linker wrapper. `NO_FREE_PAGES` and
`NEW_VERSION_FOUND` remain visible initialization failures, but cannot trigger
Arduino's automatic whole-NVS erase. Explicit factory-reset erase remains
available. OTA-off builds forward the original SDK result unchanged; old,
stock and foreign/unwrapped images can still perform the legacy automatic
erase. Protection is an image property, not a bootloader-wide guarantee.

After the SDK marks an image VALID, uncertain floor persistence does not
invalidate it. A plain restart lets the existing signed running-image proof
reconcile the floor forward; a persistent floor fault disables OTA rather than
repeatedly restarting a VALID image. Invalidation is reserved for a freshly
checked, coherent running/selected partition in PENDING_VERIFY.

A coherent Undefined SDK state, including blank otadata selecting the default
slot after USB programming, retains stock behavior. A validated running /
selected partition disagreement blocks destructive userdata writes before
ordinary startup and attempts two RTC-retained plain restarts. If the selected
image stays invalid and the bootloader repeatedly falls back, the device holds
reported Unknown state, read-only userdata and disabled OTA while servicing
normal radio through the shared health tick. Only that positively qualified
hold suppresses the StateUnreadable reboot; genuine SDK I/O failures and
confirmation/deadline failures retain the existing reboot behavior.
Arbitrary permanent SDK I/O recovery and BLE startup with uninitialized NVS
are not qualified. These source, native and linked-framework checks do not
establish physical ESP installation, rollback or power-failure acceptance.

### nRF52840 bootloader qualification

`make qualify-xiao-ota-bootloader` builds and packages both nRF board
profiles for companion role 0 and repeater role 1, then runs each native
gate with matching boot-process identity. Its metadata harness must run
against that board/role's actual prepared source; a missing tree fails
qualification rather than silently skipping. This remains an offline
gate, not an installation result. Package validation must include every
file-backed flash load segment, including initialized `.data`, and preserve
the fixed configuration and boot-info addresses.

An earlier four-profile no-SWD qualification found
37,812 bytes of code, unwind metadata and initialized data within the
38,912-byte load slot. The final file-backed load ends at `0xFD3B4`,
leaving 1,100 bytes before configuration at `0xFD800`. Each package
retains its ELF and section report alongside HEX, UF2 and linker map.
These historical build-artifact and simulated-recovery measurements do not
describe current packages or installed bytes. Qualify each new artifact's
complete load; physical installation and power-cut recovery remain unverified.

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

### Opt-in routed retry attempts

Legacy RF bytes, 14-byte START, direct 15-byte profile START, lease negotiation
`0x0C/0x0D` and `0x0F/0x10`, and REUPLOAD `0x0E` remain unchanged by default.
New directed/background campaigns may request a **16-byte START**: the original
14 bytes followed by profile `0` (legacy) and flags `1` (retry attempts).
Unknown flags/profiles and direct-mode 16-byte requests return `BadRequest`.
The PC adapter exposes this as `ota_uploader.py upload --routed-retry`;
`--lab-fast` and direct mode cannot be combined with it. Other orchestration
adapters continue sending legacy START; they do not silently enable retries.
Matching upgraded receiving firmware is required. Old relays can forward the
unchanged outer Mesh payload type; old OTA receivers reject the new inner kind.
START queue acceptance is not remote admission or installation evidence.

RF retry encoding is `[kind:u8][attempt:BE32][original inner frame]`.
Kind `0x11` is a control/initial-data attempt; `0x12` is a repair-data attempt,
restricted to compact signed block kind `0x01`. The outer identifier is
authority-free and never enters a signing domain. The original canonical
manifest and every signed owner/target/full hash/index/counter/generation/data
byte remain intact and independently verified. The native uploader uses the
existing compact signed construction in this mode (155 bytes for 84 data
bytes, 160 with wrapper); the final short block keeps its exact length.
Legacy mode still uses the full-owner `0x09` frame and its original domain.

Each originator uses a volatile incrementing nonzero BE32 attempt sequence,
randomly seeded by firmware's existing RNG token at the first retry START.
START/stop do not reset that sequence; exhaustion at `UINT32_MAX` refuses
further new attempts rather than wrapping. Boot reseeding gives probabilistic,
not durable globally unique identity. Preparing a frame only peeks the current
identifier: it advances exactly once after send/queue admission succeeds,
never on budget, busy, pool or queue refusal. Passing an already-wrapped frame
through another sender boundary does not advance it again. Actual TX completion
still charges airtime independently. After the final identifier is admitted,
the uploader stops at its next pump; another retry START fails with the existing
`BadRequest` result, without reseeding or falling back. A pending reply retains
its identifier across local queue pressure.
Census/status/commit replies reflect the soliciting attempt identifier, so a
new poll produces a different native hash even when progress is unchanged.
That reflection is correlation/diversity only, **not authenticated receipt
evidence**; census and status remain unsigned.

The retry flag and attempt sequence are RAM-only, not a durable campaign
setting. After sender restart, a separate COMMIT is unwrapped unless a new
directed/background retry START enables wrapping again. Do not treat restart
or reboot as an exhaustion recovery or dedup workaround: this change adds no
durable sequence or retry-flag storage.

The codec caps wrappers at 171 bytes and rejects zero attempts, nested or
unknown kinds, bad fixed lengths, full-owner blocks, and lease negotiation
frames. Authorization is 164+5=169; COMMIT 133+5=138; ABORT/REUPLOAD
165+5=170; census poll/report 67/102+5=72/107. A 171-byte signed lease frame
cannot be wrapped without exceeding this ceiling, so reliable relayed lease
negotiation is explicitly unsupported, not truncated or re-signed.

Mesh hashes type plus the entire payload, not route/path. A relay inserts one
hash per actual new received attempt through its existing 160-entry FIFO,
with no TTL, flush, refresh or dedup bypass. Forwarding copies of the same
attempt remain suppressed; wrapped zero-hop duplicates also remain suppressed
locally. The existing legacy-only zero-hop idempotent delivery exception stays
unchanged. An unauthenticated nonce cannot grant OTA authority, but, like other
new Mesh payloads, a malicious fresh-nonce stream can churn native dedup; no
anti-flooding or durable nonce registry is claimed here.

Path validation includes hash width/count and optional four-byte transport
codes: raw length is `2 + width*count + payload + transport_codes`.
Native limits remain 184 payload, 64 path bytes (widths 1..3), 255 raw.
All legal native paths fit the largest 170-byte retry control frame, including
transport codes (240 raw bytes maximum). Invalid paths fail START with
`BadRequest`; malformed injected wrappers fail CMD65 with the existing
`ERR_CODE_ILLEGAL_ARG`, before queueing. Truncated/overflow input is rejected
before dispatch/forwarding; a syntactically short compact block still has to
pass the original signature and exact candidate geometry checks at reception.

Stock RAW notifications are **at most 176 bytes**, including three notification
bytes and two packet-header/path-length bytes. Thus their observable path
allowance is `171 - payload_length`: wrapped block=11 bytes, authorization=2,
ABORT/REUPLOAD=1, census report=64 (native path maximum), signed lease=0.
CMD65 also includes two command bytes; its independent bound is
`payload + path_bytes + 4 <= 176`. No path is stripped to meet either bound.
The existing stock adapter has no routed sender/ordinary-queue-priority
contract, and remains zero-hop only: `--routed-retry` explicitly refuses
**before any binding, USB or hardware access**, with no legacy-success
fallback. This outcome does not modify stock signing/radio firmware.

Normal traffic queue/pool reserves and priority 250 remain unchanged. Actual
Dispatcher TX completion charges wrapped control, initial data and repair to
Control/Relay/Repair respectively under the same default 2% shared on-mesh
budget; unsigned category hints confer no exemption. Direct 250/500 behavior
and its bounded off-frequency lease accounting remain legacy-only.

Validation uses existing `test-ota-integration`, `test-ota-native`, and
`test-ota-lab-host` Make targets. New native cases exercise actual
`Packet::calculatePacketHash`, `Mesh::onRecvPacket`, two real
`SimpleMeshTables` relays, same-attempt dedup, last-mile admission/data loss,
return census, and byte-exact verified receiver storage. A legacy negative
control demonstrably stalls with fewer than 160 unique FIFO entries.
This is native/modelled RF evidence, **not physical routed qualification**;
no relay hardware, ARM image build, installation or throughput claim follows.

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
| Abort | `0x16` | target PK32, imageHash32, generation32; all-zero target selects local cache |
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
ABORT signs `MeshCore/OTA/abort/v2 || target32 || imageHash32 || generationBE32`.
The USB command is 70 bytes; its signed RF frame is 165 bytes, with generation
at offset 97 and signature at 101. There is no generationless fallback.
Active candidates require their current durable generation. An already
ABORTED candidate also accepts the immediately preceding generation to finish
the same authorized cleanup after lost acknowledgement or reboot, without
advancing the journal again. Explicit reupload advances the generation and
invalidates those older cancellations.

Start modes are direct 0, directed 1 and background 2. Direct requires one
target, channel 255 and a frequency with a 250..60,000 ms lease. Directed
requires one target and channel 255; background requires a configured group
channel and accepts up to 32 targets. On-mesh frequency and lease are zero.
Positive airtime shares are 1..100,000 milli-percent; 2,000 means 2%.

### Versioned direct profiles and lab-fast host opt-in

Legacy signed RF REQ `0x0C` and ACK `0x0D` retain their exact 171-byte
wire image and `MeshCore/OTA/direct/v1` signing domain. Frequency at97 is
still BE32 kHz; their profile remains 250 kHz/SF5/CR5. REUPLOAD `0x0E`
is unchanged and is never a profile command.

Versioned profile REQ `0x0F` and ACK `0x10` instead sign
`MeshCore/OTA/direct-profile/v2 || frame[0:107]`. Both are exactly171
bytes, fitting the stock176-byte RX-log ceiling (three log bytes + two
zero-hop packet bytes +171). Prefix offsets stay sender PK32@1,
target PK32@33, manifest hash32@65, lease BE16@101, token BE32@103;
signature64 starts at107. Only these new kinds interpret selector U8@97
and frequency BE24@98. Selectors1 and2 mean 250 and500 kHz respectively,
both fixed SF5/CR5. Selector0, other/reserved values, wrong lengths,
frequency outside150000..2500000 kHz, normal frequency, and lease outside
250..60000 ms are rejected. Full signature/owner/admin/manifest checks and
the non-renewing volatile token rules still apply. ACK kind and the whole
106-byte request body must match before applying the selected bandwidth.
Legacy-only callbacks refuse500 rather than signing an impossible ACK.
Both ACK kinds are sent zero-hop by `Mesh::pumpOtaControl`, retaining the
stock RX ceiling even while still on the normal channel.

USB Start retains its legacy14-byte request. An optional fifteenth byte
is the explicit selector1/2 and is legal only in direct mode; no frequency
bits or reply ABI are repurposed. `OtaRfUploader`, both MyMesh callbacks
and driver-applied diagnostics carry the selected bandwidth through to
the checked driver. Restoration always uses normal preferences, never the
temporary profile. Native RF tests also preserve the legacy callback API.

The stock host's single upload opt-in `--lab-fast` chooses selector2 and
sixteen-block bounded bursts instead of four. Every block still uses
CMD33/34/35 signing and exclusive queue/sent/direct-TX checks. Lab-fast
polls core+packet stats while waiting and samples airtime once at completion,
then waits a50ms inter-packet processing guard instead of duplicating the
already completed TX duration. Normal-channel accounting still samples
actual airtime and enforces the caller's unchanged share (2% by default).
The22s pre-sign budget, absolute USB/signing/TX deadlines and2s safe-end
lease margin remain conservative. No live renewal, firehose or count-only
storage proof is introduced. Fresh bitmap polls and at most eight sends per
block govern repair; READY is re-observed across all windows on normal
radio before returning a receipt, and COMMIT remains separate.

`make test-ota-integration`, `make test-ota-stock-companion` and
`make test-ota-lab-host OTA_LAB_HOST_TEST_PATTERN=test_ota_uploader.py`
cover compatibility, signed profile matching, bounded leases/restoration,
USB/signing stalls, lost ACKs, repair and fake-clock elapsed comparisons.
Simulation is not physical qualification: matching ROLE0 application
builds, actual500 kHz driver measurements/throughput, normal-service returns
and legal RF limits require separate supervised acceptance.

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

Every reply for operations `0x10` through `0x18` is exactly 90 bytes:
response code 31, ABI version 2, echoed
operation, result, phase, flags, target PK32, hash32, received16, total16,
counter32, statusAgeMs32, retryAfterMs32 and generation32. Generation is appended
at offset 86; preceding field offsets are unchanged. Flags are snapshot-valid 1 and
remote 2. A reply without a snapshot has unknown phase, zero hash, counts,
counter and generation, and age `0xFFFFFFFF`. A valid wrapped-zero generation
is permitted. The reply still reports the actual operation
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

Legacy temporary-profile commands are separate from signed direct leases.
Their shared C++11 helper tracks timer presence independently of the deadline,
including a deadline of zero after clock rollover. On nRF OTA profiles,
normal-profile restoration remains pending until the checked backend apply
succeeds; failed restores retry only while idle, at most once per second.
Repeated cancellation cannot reset that backoff. Ordinary profiles retain
their existing unchecked apply interface; compilation is not proof of
successful physical restoration.

Initial on-mesh DATA sweeps re-offer the existing 164-byte Authorization,
which occupies one OTA packet. Successful re-offers require both 32 accepted
DATA frames and a 15-second interval. A quota refusal retains the selected
target until credit is available, but 32 accepted DATA frames during refusals
rotate that target so an unavailable peer cannot monopolize later offers.
Multicast DATA does not wait for admission acknowledgements.

Native full-image regressions drop the initial Authorization and deliver
537,816 bytes (6,403 blocks) under a shared 72,000 ms / 3,600,000 ms budget,
ordinary-ready priority and clock rollover. With modeled DATA estimate /
completed duration of 200 / 300 ms and Authorization of 300 / 400 ms, both
on-mesh modes renew admission after 32 blocks and finish byte-exact without
COMMIT. Directed/background simulated completion is 28.03 / 28.04 hours,
with control traffic accounting for 4.01 / 4.03% of sender OTA airtime.
These are conditional software-model results, not measured PHY airtime,
hardware delivery or field completion guarantees.

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

The target no longer enumerates after its bootloader activation request.
The commands below are reference entry points, not authorization to retry
that board. Recovery is paused pending the physical gates and explicit
authorization in the [incident notes](lora_ota_bootloader_failure_notes.md).
Offline package checks cannot replace fresh installed-state evidence.

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
`0x18`, with ABI2 90-byte replies. It matches the operation and full
target identity, rejects unavailable or malformed replies, and uses
snapshot age rather than reply arrival time when waiting for READY.
An old failure snapshot does not invalidate a newer candidate; a fresh
failure or abort ends the wait explicitly. Companion signing shares the
upload deadline, rather than starting a separate timeout for each command.
ABORT requires fresh, valid, correctly scoped STATUS before supplying its
observed generation and image-content SHA-256. It then waits for fresh,
generation-bound durable ABORTED state, not merely an accepted command.
ABI1 is refused before an abort can be sent. COMMIT supplies the canonical
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

The other Make entry points are `ota-lab-cache`, `ota-lab-upload`,
`ota-lab-status`, `ota-lab-commit`, `ota-lab-abort`, `ota-lab-abort-cache`
and `ota-lab-admin`. Supply a raw image
with `OTA_UPLOAD_IMAGE`, its exact canonical 59-byte descriptor with
`OTA_UPLOAD_MANIFEST`, and the full target public key with
`OTA_UPLOAD_TARGET`. Upload signs the descriptor using the companion,
fills and seals its cache, then requests a campaign. It never commits.
Set `OTA_UPLOAD_WAIT_READY=1` to wait for fresh, complete target snapshots;
the default returns the campaign request result without claiming target
completion. `OTA_UPLOAD_DUTY_MILLI_PERCENT=2000` selects 2% airtime; the
host also accepts lower positive shares.

`ota-lab-cache` signs and stages only the local cache, then requires fresh,
complete, image-bound `CACHE_SEALED`. It sends no ADD_TARGET, START, COMMIT or
administrator operation. A same-image BEGIN already in VERIFYING or
CACHE_SEALED waits for matching local STATUS rather than sending PUT or SEAL
again. This is local storage evidence, not remote READY, radio delivery or
installation. See the [working-client workflow](hardware_lab.md#one-client-application-and-local-cache-validation)
for the separately scoped hardware checks.

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

The [hardware lab guide](hardware_lab.md) owns the detailed operation and
evidence record; the [incident notes](lora_ota_bootloader_failure_notes.md)
own failed-target analysis and first-capture restrictions. This summary
does not authorize hardware access.

### Current preservation evidence

Earlier paired checks preserved normal identities, settings and the complete
administrator ACL across reboot and established ordinary target-to-client
radio reception. They did not establish OTA delivery.

The target stopped returning on USB after the Oct. 2, 2026, `13:46:21Z`
loader activation request. Positive transport acknowledgement does not prove
the installed loader, completed MBR copy or USB startup. The cause remains
unproven. Do not retry commissioning, reset, unlock or erase it. The first
SWD capture requires explicit authorization, verified target/probe identity,
fixture continuity and a resolved RESET-contact decision. It captures bounded
public metadata, not a full loader hash, RAM or encrypted-media archive.

The working client runs the immutable `18ca2dcc` companion application,
548,276 bytes, with healthy stock proof and `CACHE_ONLY`, not installation
capability. Its full 537,816-byte, 6,403-block local cache sealed and survived
an ordinary reboot. Same-image sealed retries sent no PUT or SEAL, and an
explicit image-bound local ABORT was independently confirmed. Captured public
settings remained unchanged; no ADD_TARGET, START, COMMIT, administrator or
radio-setting request was made. The failed target and Pine were not accessed.

These are application and local-cache results only. Current three-mode radio
READY/COMMIT, trial/install/floor and normal-service qualification, physical
power-loss rollback, full-window 2% operation, ESP/P1 hardware, fleet contention
and multihop remain unverified. Shared-domain power cuts remain prohibited.
New preservation evidence cannot recover the lost original 502,300-byte
application or establish its missing public-key baseline.

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
  These are offline artifact checks — they do **not** establish installed
  loader bytes or usable recovery on physical hardware. Do not describe this
  historical gate as proof of the later target activation.
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

**nRF boot-trial and confirmation acceptance criteria — healthy XIAO direct
installation observed; interrupted-trial qualification pending.** The contract for deciding whether a staged
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
Installed/Confirmed. Unit41 has now completed three healthy signed direct RF
installations, including the diagnostic image after reader-free500kHz reception.
Its current image-bound confirmation is floorsequence4/counter4/extent555876,
hash7a583..., running `ota-41-diag-conf05` and native Installed8. These are
physical results, not inferred from a package or a source test. The latest
prearmed observer failed and a separate late read-only capture established
confirmation; the missing trial/reset history is not recovered by that capture.
Separate post-install readbacks matched the actual pre-upload protocol-visible
snapshot across all identity/settings/contact/channel checks. Ordinary signed
zero-hop reception at2dBm passed in both directions through the unchanged stock
companion, with native acceptance events and fresh image/floor/profile checks.
Those bounded recovery results do not establish full private storage or
sustained service: the receiver's lifetime radio fault count increased0 to1
across the peer exchange. A separate passive retained-fault read classified an
ActiveProbe mode mismatch: expected transmit, observed STDBY_RC, latched TX_DONE,
successful checked SPI reads and no device-error bits. That classifies the
retained diagnostic, not its triggering command or fresh completion.
A transmit-completion ordering fix is integrated in source: it services the
current owned send and rearms receive before checking trial health, without
accepting stale completion flags or hiding SPI/device errors. Both companion
and repeater callsites use the shared dispatcher's completion/accounting path,
and ISR-during-probe reconciliation is bounded to one fresh probe. The native
product gate passed32 cases, including20 completion cases. XIAO nRF, Solar and
Wio companion/repeater OTA plus XIAO nRF BLE compile/link boundaries passed.
The fix is not yet installed on41; continuous physical reliability remains open.
A distinct healthy `ota-41-tx-conf06` APP built from the exact published fix tree
fits the Sense ROLE0 installer layout:560084 bytes,174332 bytes static RAM.
Its new completion/cleanup path has a closed conservative1848-byte stack bound
including IRQ104; the selected OTA-root maximum remains3348/4096. These are
artifact/static-analysis results, not runtime stack certification or a running
update. Its separate exact healthy observer profile is now source-qualified:
one isolated source-view decoder binding admits the exact APP06 version while
retaining the frozen classifier and evidence implementation. Seven focused
product groups passed using26 synthetic public USB fixtures; the failed first
run remains unchanged. Actual deployment still requires genuine completed
counter5 rollback lineage, a new signed descriptor and measured session,
independent fresh ROOT admission, real prearm and bounded separate COMMIT.
This source result does not install the fix or prove physical reliability.
Actual counter5 trial evidence subsequently exposed an additional ABI mismatch:
the frozen rollback and healthy trial classifiers accept only a deferred floor,
but the running diagnostic trial exposes the exact existing floor as present,
with successful I/O, `STAGING_ONLY` capability and blocked writes. That sample
was refused; the source-qualified APP06 profile therefore remains blocked for
actual deployment. A prospective correction must validate the available floor's
exact baseline identity without hiding it or granting trial writes.
The separate exact floor4 rollback profile passed16 combined offline cases,
including missing-trial refusal, unchanged-floor return and once-only approval
binding. This source result does not authorize a hardware campaign or prove
autonomous rollback.
The subsequent distinctly admitted counter5 nonconfirming-image RF upload
completed with measured READY generation15 and stock-radio restoration.
Its fresh observer was genuinely armed before a separate signed COMMIT child,
which completed with actual aggregate TX evidence, exact result, restoration
and seal. The observer stopped on the trial-floor ABI mismatch above; its failed
receipt has no accepted trial/post-trial-gap/return sequence. One separately
admitted read-only capture later established the exact original floor4 and
diag-conf05 failed-candidate return state, not the missing autonomous history.
No retry, host reset or reflash was used. This campaign
uses the older diagnostic rollback image, not the transmit-fixed healthy APP.
See the hardware lab guide for the actual receipt fingerprints
and the limits of native-event correlation and emission freshness.
A new prospective rollback profile now accepts the actual available trial floor
only with successful I/O, `STAGING_ONLY`/blocked writes and exact baseline
sequence/counter/extent/hash, while retaining legacy deferred-floor support and
all native session, core, normal-radio and trial-deadline requirements.
Its focused Make boundary passed27 source product cases, including the captured
ABI and synthetic ordered trial/gap/return/seal coverage. The frozen evidence
and ordered observer are unchanged; failed counter5 receipts remain failed.
These results correct the source mismatch, not the missing physical history.

After distinct ROOT source review and admission, fresh counter6 campaign
readbacks established diag-conf05/floor4, the failed counter5/generation15
baseline and healthy sampled normal TX2. The new five-contact/40-channel
protocol-visible snapshot matches the actual counter5 pre-upload comparison
hash. A new counter6 descriptor for the same older nonconfirming image was
USB-signed and Ed25519-verified through the unchanged stock companion.
Its separately admitted once-only reader-free500kHz upload completed under
the unchanged2% airtime policy: exact counter6 manifest, complete READY,
native measured generation16 and stock-radio restoration. This unsigned RF
READY result is staging evidence, not installation confirmation. After the
lease-expiry wait, a distinct ROOT launch approval bound the actual session and
all prior nonce exclusions. A fresh physical USB READY sample established
core0/healthy normal radio/TX2, and the real observer armed before the separate
bounded signed COMMIT invocation under the original2010-second parent deadline.
That stock COMMIT completed with exact counter6/generation16 result, aggregate
transmission evidence and sealed radio restoration. The corrected observer
accepted eight genuine trial samples at uptime2 through41 seconds, confirming
the available-floor ABI, then stopped at an open-UART physical-binding check
before any identity reply. It did not accept the post-trial USB gap or return.
The guard did not record which binding comparison changed; a kernel epoch
change or reset cause cannot be inferred. A separately admitted read-only
capture later found diag-conf05, the exact floor4, failed counter6/generation16,
core0 and healthy sampled normal TX2. That late return does not recover the
missing ordered history. No retry, host reset or reflash was performed.
New source-only post-return recovery and
healthy-deployment wiring is now qualified against genuine counter6 lineage
and the corrected floor ABI, without relaxing the old failed campaign's gates.
Its focused Make boundary passed12 cases with30 MODEL fixtures through the
real scoped observer/recovery/coordinator; these are synthetic operation inputs,
not actual trial history or ROOT authority. Live admission requires actual
source-bound ordered rollback and COMMIT/restoration receipts, independent full
userdata comparison and ordinary two-way RF recovery, plus a separate exact
contact-timestamp diff review when needed. The corrected healthy observer still
requires the exact APP06 image/new floor/native Installed8. A later healthy
campaign must use an independently selected counter above the actual rolled6,
measured READY generation above the actual rollback session, prior-session
nonce exclusions and separately admitted prearm-before-bounded-COMMIT.
Missing prerequisites deny live execution; no counter/generation is defaulted.
The failed counter6 history cannot satisfy this source-qualified chain's live
gate. Four distinct prospective USB-epoch observer/recovery/deployment capsules
now pass21 focused Make product cases using47 MODEL fixtures, with an
independent rerun matching the qualified receipt. They require exact same-board
kernel device-number and owner-token changes plus old-handle/new-device
discontinuity, exclusive reopening and completely fresh coherent native
samples. Stable old-handle identity tolerates Linux unlink ctime changes;
receipt replay retains the actual token/type and refuses timestamp-only
discontinuity. Wrong identity, ownership, ambiguous epoch and protocol failures stay
fatal; arbitrary errors, tty changes and no-response are not boot/reset proof.
No reset cause or atomic sampling is claimed. Recovery requires the genuine
new campaign's ordered trial, qualified post-trial kernel gap, exact floor4
return and bounded COMMIT/restoration seal, never a failed receipt or later
snapshot. Fresh ROOT preparation must remeasure failed counter6/generation16
and full userdata; the future counter is explicitly selected above6 and actual
READY generation measured above16, without defaults. Healthy deployment then
requires independently higher actual lineage and separate userdata/ordinary RF
recovery. An unobserved short healthy trial needs an explicit ROOT boolean.
Source qualification supplies none of the five live stage admissions.
After independent ROOT acceptance and explicit counter7 selection, new admitted
preparation freshly remeasured the failed counter6/generation16 floor4 baseline
and matched the prior five-contact/40-channel protocol-visible userdata hashes.
Separate descriptor and unchanged-stock USB signing admissions produced a new
verified counter7 descriptor for the older nonconfirming image. Its separately
admitted once-only reader-free500kHz AUTH/upload completed under the unchanged2%
policy with exact counter7 READY, native measured generation17 and stock-radio
restoration. A distinct ROOT launch approval then bound the actual session and
all four prior nonce exclusions. After the lease-expiry wait, fresh physical
READY/core0/normal-TX2 checks and real observer prearm, the separately bounded
signed COMMIT invocation began under the original2010-second parent deadline.
Historical radio-fault count796 was stable within the fresh healthy sample;
it is not zeroed or explained by that sample. The unchanged stock COMMIT
subsequently completed with exit0, exact-session transmission evidence and a
sealed stock-radio restoration. The campaign completed with exit2: its physical
callback hit an absent serial anchor before the kernel guard captured removal.
No trial, qualified kernel gap, new epoch or exact floor4 return was accepted.
Generic `ENOENT` cannot establish removal or a reset. The final READY sample
had lifetime fault count847,51 above the initial sample, with no established
cause or continuous-health claim.
A separately ROOT-admitted read-only capture later found diag-conf05, the
exact floor4, failed counter7/generation17, core0 and healthy sampled normal
TX2 with actual lifetime fault count0. That later state does not repair the
missing ordered history, qualify autonomous rollback, compare userdata or
exercise ordinary RF; recovery and healthy deployment remain blocked.
No retry, host reset or reflash was performed.
A distinct source-only correction now independently qualifies proved removal
of the previously owned kernel USB epoch before anchor resolution across
physical/framed/serial/reopen paths. It probes the saved kernel owner rather
than treating an absent anchor as evidence, closes the old descriptor and
bounds return to120 seconds within the original deadline. Startup absence,
missing independent proof, wrong identity, permissions and ambiguous metadata
remain fatal. Exact identity, fresh native samples and a distinct post-trial
gap/new-epoch return are still required; a pre-trial removal cannot substitute.
The focused Make product boundary passed25 cases with64 MODEL fixtures and an
independent parent rerun matched the final receipt. Real scoped callpaths cover
the absent-anchor failure before capture, full ordered history, default-denial,
userdata/ordinary RF and conditional exact-APP06 deployment gates. Actual
stable fault counts0 and847 pass without mutation; changing counts are refused.
These synthetic inputs are not live ROOT authority or hardware evidence.
All old sources and failed receipts remain frozen.
A new campaign requires fresh ROOT baseline review, an explicitly selected
counter above7, actually measured READY generation above17 and all five prior
nonce exclusions, without counter/generation defaults. Source correction does
not supply live admission or replace genuine ordered history and independent
userdata/ordinary RF recovery.
After separate ROOT source acceptance, ROOT explicitly selected counter8.
Fresh read-only preparation remeasured failed counter7/generation17, the exact
floor4 and healthy sampled normal TX2 with actual stable count0, and the full
new exposed-userdata inventory matched the prior ROOT comparison hashes.
Separate descriptor and unchanged-stock USB signing admissions produced a new
verified counter8 descriptor for the older nonconfirming image. Its distinctly
admitted once-only reader-free500kHz AUTH/upload completed with exit0 under the
unchanged2% policy. Actual READY generation18 was measured, not assigned, with
all6617 blocks and true stock-radio restoration. The reviewed upload handoff
SHA256 is
`a883dd68ab7db2012fbc09468e675ba20a3a353b0c89a5c47aa36fc183e4029d`.
Independent native binding review established attempt1 nonce
`47ea9339f9b20a5c`, excluding all five prior nonces.
After the65-second fast-lease expiry wait, a distinct fresh ROOT launch approval
started the attached campaign. Fresh local USB READY confirmed the exact
counter8/generation18/floor4 session, core0 and normal TX2 with actual stable
fault count796, not forced zero. A genuine ARM preceded the separate bounded
signed-COMMIT child on the exact stock USB4.2.4 path. The original2010-second
budget is unchanged. The campaign subsequently completed with exit0 and both
children reaped. Actual COMMIT request/sent/result/restoration were sealed.
The154-row journal contains23 genuine native trial samples and four qualified
owned-kernel removal/new-enumeration intervals, including a distinct post-trial
gap before the exact floor4 failed return. Diag-roll05 trial at uptime1 and
diag-conf05 return at uptime9 both bound the actual counter8/generation18
session; trial floor writes were blocked, and the returned original floor was
unchanged. Independent review of all29 pinned receipts passed the unchanged
strict history validator. The observer receipt SHA256 is
`855d2fa6e77d968aa3c4df0566fe023d48b6cefe56953ebbb885988871e1a12b`.
The return sampled healthy normal TX2 with actual stable count0, but49 recovered
faults were observed before the trial; their cause and continuous reliability
remain unqualified. No reset cause, running-image hash or atomicity is claimed.
Independent post-return recovery initially stopped because source
admission refused the two identical accepted product-qualification and parent
rerun files because its frozen lookup requires one matching file. No authority,
hardware access, source mutation, receipt removal/rename or bypass followed
that refusal.
A separately admitted source-only correction is now independently qualified:
new recovery05 and healthy observation/deployment10 accept one or more
byte-identical valid qualification copies, retaining explicit hash, content,
current source/schema and default-denial checks. Frozen04/09 sources and
archived receipts remain untouched. The focused Make boundary passed13 cases
with28 MODEL fixtures, and independent parent rerun matched the agent's final
receipt SHA256
`773d73f7867f1b6014dc44fcc9c2f17ed3fc10a8bf66e3b9a46f5eb78225e073`.
These paths retain the genuine campaign04 and all independent recovery,
exact-APP06 and hardware-admission gates. No new rollback trial or old-history
promotion is required or permitted merely to correct the source lookup.
Source qualification supplies no hardware authority. Distinct actual ROOT
readbacks then passed the full exposed five-contact/40-channel/settingsACL and
self-info comparison, retaining normalized userdata hash a9846106 and stable
sampled normal TX2 count0. The receipt SHA256 is
`93db23689b575331eab8b0b578e8b332f8f1c37e87f7fa339e0e2b4ccf0742ac`.
A separately admitted once-each ordinary RF stage observed signature
verification and native acceptance in both directions, but its overall result
was failure: same-session receiver radio count increased0->1. The later
healthy/stable count1 does not satisfy the no-new-fault gate. Its immutable
receipt SHA256 is
`15bae4ddf895bc1321e088978ba9437b411c0c52671a36f39aaf2adf0fe2b330`.
Only the stock contact's permitted timestamp fields differed after RF; no
metadata-acceptance stage followed the failed radio gate. No fresh-emission
cryptographic causation, fault cause or continuous reliability is claimed.
Frozen sources and the consumed failed stage remain intact, with no retry,
reset, reflash, new AUTH or failed-receipt promotion. Recovery and transmit-fix
deployment remain blocked pending a distinct legitimate next admission.
The separately selected degraded-radio bootstrap now has independently
accepted production wiring: recovery06, deployment11 and owned observer11.
The agent and parent Make product runs matched SHA256
`0cc6cc9ddf55df26a5fda0f39912efbe4dd65aea1515caec427996408c01ad3f`,
passing13 production-path MODEL and21 API cases. Positive Ed25519/native-frame
cryptography used synthetic fixtures; physical/process/history leaves were
simulated. The source/schema/custody review SHA256 is
`0600b12b26b1d2cd78cca9a1c86384fb700aa7b63f4ccdd301afdc9eb92ffa70`;
all14 new source bindings and the known frozen/shared/archive pins matched.
This is executable production integration, but not live authority or an install.
An explicit default-deny ROOT budget0 or1 applies only to newly observed
preinstall ordinary-RF faults, with current health, stable within-read samples
and all physical/crypto/native-floor guards retained. Fresh userdata and an
independent exact changed-timestamp baseline review must precede fresh RF;
a separate exact post-RF review follows it. Failed05 remains failed.
Preparation/signing/upload/launch remain separate once-only admissions.
The exact APP06 requires device-measured READY, trueARM, bounded COMMIT and
stock restoration, native Installed8/new floor, then independent strict
userdata and both-way native RF with zero new faults. No fault causation,
continuous reliability or userdata atomicity is inferred.
Subsequent accessor review exposed a genuine-history dataflow blocker:
strict preparation fills the history namespace, but policy materialization
and recovery admission read a separate earlier namespace lacking the validated
original-userdata summary. MODEL setup had supplied the missing field, so
the passing product receipt does not establish this transition. The frozen06/11
live path is blocked before any actual policy, admission, consumed stage or
hardware operation. A new recovery07/deployment12/observer12 source-only correction
must carry strictly derived preparation through unprimed namespaces and retain
the original inventory reference across later healthy preparation. Accepted
06/11 sources and all receipts remain frozen; no fallback or bypass is used.
The distinct07/12 correction is now independently accepted: agent and fresh
parent Make runs matched product SHA256
`c4ad8b8ca5721110c2adccb6cadf620857e6c41493cb3a008e70eacd9b686e28`,
with16 production-path MODEL and21 API cases. Strict preparation now derives
immutable original context from unprimed namespaces; failed validation clears
it, and later candidate preparation cannot replace the original inventory.
The paired source/schema/custody handoff SHA256 is
`097e877031cf5712ff224633d96c036280d01f52b72da5ad9b24f1e9344003f6`;
all17 source and30 preservation bindings matched. A separate parent read-only
unprimed preflight passed the genuine campaign04 review and all29 original pins
through the corrected API, with SHA256
`4c88038e865f77cd22088eb30dd3c2768016da5100d3eaa2ffb90535e08d3fde`.
Only private input proposals were produced: no policy, approval, stage
consumption or hardware operation. Actual fresh ROOT admissions and strict
postinstall acceptance remain separate; no old failed receipt is promoted.
Separate actual policy/readbacks admissions subsequently captured fresh full
exposed userdata in1.714 seconds, with receipt SHA256
`bc20728c15054e85dba49e9816f5d3eb1caacf3e08178ee977ba3e1e34a24cba`.
All other protocol-visible fields matched; only the two already observed
stock timestamp fields differed, retaining normalized userdata c3107e6f and
metadata diff120d0035. The parent missed the time windows: metadata review was
materialized49.91 seconds after capture instead of within30, and the separate
RF-approval materializer refused the expired300-second policy. No peer
approval/start/receipt, fresh RF, signing, upload or COMMIT followed.
The stopped cycle's artifacts remain unchanged. A fresh isolated08/13 scope
is being prepared with all review helpers staged before starting policy time;
no expiry extension, stale capture, marker reuse or failed05 promotion is used.
The isolated08/13 source is now independently accepted with identical agent
and parent product SHA256
`c4d5647bdf8b2683bb09248a6a3c5e53ddf7b96e96c3e1ba4cd0a20ce6ea1945`,
passing16 production-path MODEL and21 API cases without behavior or deadline
changes. All17 sources and52 frozen preservation pins matched. The paired
parent handoff SHA256 is
`83c9982dd75b1f061a2e5dda877ead2b96b16d73f2faa6095e3f96ae223cc04b`.
A new unprimed read-only genuine29-pin history preflight passed with SHA256
`a7ef6e5677730ece6cbccf8623b8c391a39c67d3c87ebdcec787fbe0d5880465`.
All parent review and later stage input helpers were staged before any new
policy clock; the private pre-stage record SHA256 is
`856d657638358da8c223ce8289532763da451ed611c1518e76fbe133ed970112`.
The helpers emit input candidates, not authority. Exact independent timed
timestamp reviews, explicit ROOT stage decisions, device-measured READY and
strict zero-new-fault postinstall acceptance remain mandatory. No new policy,
stage consumption or hardware operation followed source/pre-stage qualification;
all stopped07/12 evidence remains unchanged.
Separate fresh08/13 policy/readbacks admissions then captured full exposed
userdata in1.767 seconds, with receipt SHA256
`22ebe1945f32f62d5bc2774c4dc34574bb7b892088ff7fe7dcdd06235a4417f1`.
All other exposed fields matched the original; only the known two stock
timestamps differed. The independent baseline review completed16.394 seconds
after capture, and the peer stage began18.382 seconds after capture, both
within30 seconds and under a fresh300-second policy. Current samples remained
healthy/core0 with the exact floor4 and stable lifetime fault count1.
The once-only peer stage failed after2.836 seconds with
`independent-selected-epoch-snapshots-required`, receipt SHA256
`2040f38e2d7c7be4d8185ed12e56b7d763d16b482b7b774274a0f2f782e30ba9`.
Only RF-before was captured; both-way native RF was not qualified.
No post-RF inventory/review, bootstrap acceptance, signing, upload or COMMIT
followed. The readers exited and the consumed08/13 evidence remains frozen.
This real-adapter failure is distinct from the corrected timing issue; its
diagnosis and any correction require a new source scope, not replay or waiver.
Source diagnosis found that inherited initialization overwrites the legitimate
stock physical-selection checker with the41-only owned epoch checker. Stock
selections are therefore absent from the required receiver snapshot registry.
MODEL setup had supplied per-node routing, masking the construction-time
defect. The failed guard precedes the stock-core USB write and all requested
ordinary advert commands; ambient RF and fault causation are not inferred.
A separate09/14 source-only correction must preserve both proper node guards,
deny unknown anchors and qualify the actual production adapter without a
MODEL dispatcher replacement. It must reproduce the old refusal before any
ordinary advert and exercise real native signatures through the corrected
adapter. Frozen08/13 sources and consumed actual artifacts are not modified;
new hardware admissions remain separate.
The distinct09/14 correction is now independently accepted: agent and parent
Make runs matched product SHA256
`ac5125fbf22cb5c3f5beee586897ef3bc1ced032669120af643b9db088e17774`,
passing17 production-path MODEL and21 API cases. The new case exercises real
construction/dispatch and native peer/signature bodies with external leaves
and principals simulated; no dispatcher or stock-checker replacement masks
the old refusal. Wrong bindings, missing receiver snapshots and unknown
anchors remain fatal. All18 sources and74 preservation pins matched.
The parent paired handoff SHA256 is
`68525fa68c5b1e38afd2f111e0b9b4cde82a60c28b4fc369db8a1765bc33c9c1`.
A separate unprimed genuine29-pin preflight passed with SHA256
`755c8bbf499d382ecf338138f43616a757d08a16a13068cf80ef980ca4f158bc`;
fresh parent helpers were fully pre-staged before policy time, record SHA256
`18d978b8cbf453706c8e75ca3ef6b8f9d5be38b692c36a1e6baa37427b3f51ba`.
Only input proposals were created. Actual ROOT admissions, timed independent
metadata reviews and strict postinstall acceptance remain mandatory; no
hardware operation followed source qualification and no08/13 artifact changed.
Separate fresh09/14 admissions then captured exposed userdata in1.800 seconds,
receipt SHA256
`e780399e2ace647405c01890715cbc21a6de25b60eded2454334a49dfc35e315`.
All other exposed fields matched the original; only the two known stock
timestamps differed. Independent baseline review completed20.118 seconds
after capture and peer execution began22.097 seconds after capture, both
within30 seconds under a fresh policy.
The corrected adapter passed stock-core checks, issued one ordinary advert
per direction and verified both private signatures/post-command RF with normal
profile guards. Healthy/core0 receiver samples showed one new old-firmware
fault1->2, stable within reads and within the explicit budget.
The once-only stage nevertheless failed with
`real-private-SIG-and-fresh-native-accepted-event-required`, receipt SHA256
`3ec8a73e8acb22f75145c48738c99325f0318d69f93d688f40e571b48e1e33f0`.
Within the configured window, native acceptance was observed at stock, not41;
cryptographic signatures do not substitute for that timing requirement or
prove commanded fresh emission.
No post-RF inventory/review, bootstrap acceptance, signing, upload or COMMIT
followed. Readers exited; all09/14 evidence remains frozen,
without replay, native-event waiver or fault-causation inference.
Read-only classification verified the frozen receipt/trace raw pins,
canonical direction-bucket pin and complete fresh userdata replay. All16
host-parsed frames contained exactly one expected signed advert per direction.
41's matching native key notification was parsed1.145135 seconds after the
forward signature, outside the unchanged1-second window and after the reverse
advert command; stock's matching notification was parsed0.462991 seconds after
the reverse signature, inside the window. The forward advert timestamp was
newer than the fresh stored stock contact. No contact-update frame was present.
These are host parse times, not proven USB arrival or firmware emission times;
collector ordering versus genuinely late delivery remains under source-only
investigation. No failed receipt is promoted or new hardware attempt authorized.
Agent and independent parent execution each passed11 actual-adapter/parser/
transport timing cases, preserving timely acceptance and terminal denial of
late, fragmented-after-deadline, missing or mismatched native events. All97
frozen pins remained unchanged. No deterministic host collection defect was
established. Read-only inspection of the bound floor4 firmware found no native
notification timer, coalescing or next-command gate: advert handling calls the
native notification directly and USB writes immediately. Signature verification,
synchronous advert-blob persistence and underlying writes have unproven latency
bounds; neither actual delay causation nor a radio-fault-caused stall is proven.
No corrective source was selected. A distinct qualified timing-only hardware
diagnosis and fresh admissions would be required to resolve the remaining
uncertainty, without changing this attempt's deadline or promoting its failure.
Preparation and source qualification of a distinct timing-only observer are
now approved. It must retain the real native parser, adapter and owned
transport, capture count/time provenance without exposing payloads, and leave
the existing acceptance guards unchanged. Execution still requires separate
fresh admissions; this is not permission to install firmware or retry a
consumed attempt.
The separate timing observer now passes seven focused actual-adapter cases in
both agent and independent parent execution;102 frozen pins remain unchanged.
Timely native acceptance, late/fragmented rejection, scheduler-stall provenance,
pre-write ordering and explicit read/instrumentation errors are preserved.
Parent unprimed read-only preflight passed the genuine29 original-history
checks. The handoff's nonexistent original-review path was replaced through the
existing argument by the established immutable review, with a sealed path-only
supplement rather than a source or evidence rewrite.
Observed kernel byte counts, read/UART-write boundaries and parser completion
times are diagnostic provenance, not proven arrival/emission times or hardware
authority; recording can add host overhead. Complete explicit ROOT helpers are
being prestaged before any fresh policy or timed capture. No hardware admission
or execution has followed this qualification.
The first parent helper also passed six actual workflow cases and genuine
read-only prestaging, but it is not full-plan-ready for unchanged userdata.
Integration review found that inherited ROOT materialization requires nonempty
timestamp changes while peer admission requires no baseline review for zero;
the parent instead correctly holds for mandatory independent review. Its MODEL
forced two changes, leaving zero unqualified.
A fresh scoped correction must permit strict zero-change materialization and
require a validated, pinned, fresh review before CMD7 for every allowed0–2
known-stock timestamp changes. Materialization, admission and parent proposals
required coupled wiring without changing native/deadline, crypto, preservation,
identity or fault-budget guards. All earlier sources and artifacts remain frozen.
This is a preparation integration defect, not proof of the earlier RF delay's
cause or permission to execute hardware.
The fresh correction is now independently source-qualified: both agent and
parent passed two core-admission and seven coupled ROOT/native workflow cases
for zero, one or two exact known-stock timestamp changes, including either
single field. Every case requires validated, pinned, fresh independent review
before CMD7. Missing, stale, mismatched and unrelated changes fail closed;
late native failures still withhold post-RF review.
All160 frozen pins remain unchanged. Parent unprimed genuine29 read-only
preflight and core helper prestaging passed without creating policy or
authority or opening hardware ports. The backend initially exposed JSONL
stdin/stdout only, without a cross-call client or production ROOT decision-authoring
command; MODEL decision authoring is not production authority.
A thin private local operator frontend was required before any policy or
timed capture. It must retain the actual preloaded parent, provide independent
write-once reviewed decisions and keep authoring, approval and capture separate,
without adding acceptance logic or changing guards.
The frontend now passes six actual RPC/parent/native cases in both agent and
independent parent execution, with171 frozen pins unchanged. It provides a
private same-UID retained local server, bounded clients and separate explicit
reviewed decision authoring, approval and capture without changing backend guards.
Actual read-only startup passed genuine preflight; two separate client calls
returned the same preloaded parent instance and exact product/prestage bindings.
Graceful shutdown completed with private write-once lifecycle receipts and no
execution runtime, policy, ROOT decision or hardware-stage ledger created.
Preparation/qualification is complete. Autonomous lab testing was subsequently
authorized, without waiving fresh independent ROOT admissions.
One execution session passed guarded current userdata readbacks in1.700s:
the body matched the original, only the two allowed known-stock timestamps
changed, core errors were0, floor4/counter4 and counter8/generation18 were
unchanged, and sampled normal radio health had no fault growth (2->2).
Independent baseline review completed at18.595s after capture and peer
admission at26.863s. The separately invoked peer capture failed the unchanged
`fresh-bounded-capture` guard before `Execution.execute(peer)`: the baseline
was then older than30s. No ordinary RF command, timing instrumentation,
peer-start ledger, peer receipt or event chunk came from this session.
The parent and operator preserved terminal failure receipts; client/server
exited2 and both serial endpoints were released. The exact entry age was not
persisted, so no more precise rejection time is claimed. No post-RF review,
retry, receipt promotion or timing waiver followed.
This is orchestration latency at the pre-execution freshness gate, not an
RF/native delay measurement. A distinct campaign needs faster explicit stage
transitions while preserving independent reviews and the existing deadlines.
No RF cause, continuous health, installation or broader release gate is claimed.
The transmit-fixed healthy APP is still unsigned and uninstalled. Source
qualification, baseline readbacks and signing do not establish autonomous
rollback or continuous radio reliability.
The new observed failed-trial return does not establish every internal
transition or the broader platform/mode acceptance gates.
ESP32 uses vendor slot states, an independent RTC watchdog and late
confirmation rather than the Nordic register and copy/restore sequence.

Not verified, and not to be represented as done in any documentation or
release notes:
- Full three-mode signed firmware transfer and install on real hardware.
  Historical signed staging and the full stock-only RF harness passed, but
  neither transfers and installs a bootable firmware through all three
  autonomous modes. Healthy direct RF installs have passed on XIAO unit41;
  actual routed/background installation, Solar and ESP32 acceptance remain open.
- Routed (directed, mesh-relayed) image delivery to an out-of-reach target
  has not been attempted yet; only direct-mode application-layer traffic and
  fleet-mode state probes have been run over real RF so far.
- Sustained multi-node and multihop fairness during a real background
  campaign remains unverified. The historical two-board pressure run does
  pass both the quota and ordinary-service witness, but it does not model
  fleet contention, autonomous byte repair or a 24-72-hour campaign.
- Turning a staged image into a running update across all required platforms
  and modes is not proven end to end,
  but the pieces are at different stages, not all "not started":
  - The bootloader's boot marker (at flash offset `0xFDC00`) and a
    distinct SenseCAP flash profile **are implemented and covered by
    native tests**. Packaged HEX and UF2 build artifacts with marker
    verification now build separately for both the XIAO and SenseCAP
    profiles, in their own board/role-specific output directories. All
    board/role artifacts must pass complete flash-load and marker checks;
    earlier package footprints do not describe a new build. Actual installed
    bytes and first-boot floor readback remain board-specific hardware gates,
    not deductions from package validation. The supervised unit41 profile has
    actual installation/floor evidence; Solar does not.
  - The candidate and backup regions each hold at most 708,608 bytes,
    preserving the extra-filesystem range `0xD4000`–`0xED000`.
    The 811,008-byte staging stride includes receiver metadata; it is
    not image capacity. A fresh, live read of `BANK_VALID`, the app
    flag, size and CRC16 is required before destructive installation.
    A stale floor value or a guessed extent is not sufficient.
  - The application-to-bootloader hand-off and supervised commissioning have
    physical installation evidence on unit41. Unit77's defective modified
    recovery loader remains a separate repair issue, not evidence that unit41
    cannot install. Native tests exercise all three transfer modes; routed and
    background installations and the other required boards remain unqualified.
  Do not describe the marker or SenseCAP profile as "not implemented" —
  they exist and are tested; the gap is specifically the hand-off and
  remaining board/mode qualification and observed failed-trial recovery.
- Anti-rollback has durable implementations: Nordic uses confirmed A/B
  floor records, and ESP32 stores its confirmed numeric floor in NVS.
  Unit41 has advanced its confirmed Nordic floor through real healthy
  installation/confirmation cycles, most recently sequence4/counter4 with an
  exact verified running-image hash. Interrupted floor transactions, autonomous
  failed-trial recovery and the ESP32 confirmation cycle remain unqualified.
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
- Keep these guides' contracts and status aligned with verified results.
  Record detailed hardware chronology in `docs/hardware_lab.md` and incident
  analysis in `docs/lora_ota_bootloader_failure_notes.md`; link rather than
  duplicate it, and keep unproven claims explicit.
