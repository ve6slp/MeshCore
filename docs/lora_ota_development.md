# Building and testing optional LoRa OTA

Base this feature on `dev`, keep unrelated changes out, and follow
[CONTRIBUTING](../CONTRIBUTING.md): 2-space C++ indentation,
camelCase/PascalCase, roughly 100-column lines (`.clang-format` permits 110), and
public API documentation/examples. For this embedded feature, prefer static
resources and direct helpers over new abstraction layers or runtime allocation.

Normal board environments remain OTA-disabled. Only the explicit `_ota_usb`
environments enable `MESHCORE_LORA_OTA=1`; ordinary environment RF/path defaults
are unchanged. See [the product guide](lora_ota_users.md) for environments,
installation, deployment and recovery, and [design](lora_ota_design.md) for
transaction boundaries. Soak work stays in the public fork; no upstream PR.

## Reproducible Make workflows

`build`, `upload` and `clean` require an explicit `ENV`; an unselected command
does not silently build every board or opt-in OTA environment.

```sh
make build ENV=Xiao_nrf52_companion_radio_usb
make build ENV=Xiao_nrf52_companion_radio_ota_usb
make build ENV=Xiao_S3_WIO_companion_radio_ota_usb
make test-ota-host
make test-xiao-ota-bootloader-tools
make test-ota-native
make test-ota-disabled
make test-ota-queue-compatibility
```

`make test` runs ordinary native and KISS-modem tests plus retained host tests.
Per-layer targets are `test-ota-protocol`, `test-ota-runtime`, `test-ota-storage`,
`test-ota-trust`, `test-ota-boot`, `test-ota-integration` and `test-ota-esp32`.
The six native OTA suites cover the shared product and ESP backend.
`test-ota-boot` runs the actual nRF C bootloader transaction/crypto tests through
`test-xiao-ota-bootloader`, not a duplicate portable installer.
`OTA_TEST_FILTER` narrows `test-ota-native`; `OTA_GTEST_FILTER` (exported as
`GTEST_FILTER`) selects Google Test cases for `test-ota-native`, the per-layer
targets, `test-ota-disabled` and `test-ota-queue-compatibility`, for example
`make test-ota-integration OTA_GTEST_FILTER='LoraOtaRoutedRetry.*'`.
`PLATFORMIO` selects the installed runner.

Focused regressions:

```sh
# Default reliable directed/background framing: real relay loss reaches READY.
make test-ota-integration OTA_GTEST_FILTER='LoraOtaRoutedRetry.AutonomousUploaderActuallyRepairsLossAcrossTwoRealRelaysAtTwoPercent:LoraOtaRfProduct.DirectedLostBeginReadmitsBeforeInitialSweepAtTwoPercent:LoraOtaRfProduct.BackgroundLostBeginReadmitsWithoutBlockingHealthyFleetAtTwoPercent'
# Startup provisioning, identity store and contact-permission migration.
make test-ota-storage OTA_GTEST_FILTER='BExampleStartupTest.*:BIdentityStoreStartupTest.*:BContactPermissionTest.*:DataStoreRecordCodecTest.*:OtaTrialSafeFilesystemMountTest.*:IdentityIntegrityCodecTest.*'
```

`make test-ota-host` covers the native and stock hosts on wire version 3. It
checks golden COMMIT (153-byte RF, 90-byte USB request), census (123-byte),
lease-domain and 107-byte USB status frames against the C++ encoders. It also
checks refusal of old companions and receivers before any upload, the default
reliable framing parser, and a stock session with more than 256 interleaved
ordinary notifications.

`test-ota-disabled` (environment `native_lora_ota_disabled`) compiles the real
`Mesh`, `Dispatcher`, `Packet` and `StaticPoolPacketManager` with
`MESHCORE_LORA_OTA=0` and checks that ordinary routing, priorities, airtime
scheduling and packet ownership match upstream `dev`; unknown payload type
`0x0C` is handled like any other unknown type. `test-ota-queue-compatibility`
(environment `native_lora_ota_queue`) runs the same fixture with OTA compiled in
to check the queue reserve, priorities and ownership. Both are part of
`make test-ota`. `build-ota-nrf52-targets` and `build-ota-esp32-targets` compile the explicit
opt-in environments; callers can override the corresponding environment lists.

### Installer-independent repeater relay

`make build ENV=Xiao_nrf52_repeater_ota_relay_usb` builds an APP-only USB
repeater with `MESHCORE_LORA_OTA=0`, `MESHCORE_LORA_OTA_RELAY=1` and
`MESHCORE_REPEATER_RELAY_PROFILE=1`. The relay gate defaults off. It classifies
payload type `0x0C` for routing/queueing only, never instantiates the installer,
staging/image storage, RF authorization, qualification or boot-command backend.
The linker ends APP at `0xC4000`; do not replace the paired bootloader, fixed
installer, stage, floor or filesystem when changing to this profile. This
profile does not become install-capable by changing its advertised role.

Directed requests consume the selected next-hop prefix (width 1/2/3).
Flood replies append that same-width relay prefix once; their original payload,
including `0x11`/`0x12` and BE32 retry attempt, is opaque and unchanged. Normal
transport, flood policy, hop limits, native packet-hash deduplication and path
capacity limits still apply. There is no direct-bypass fallback or duplicate
delivery exception at the relay. Traffic uses priority 250 and preserves four
packet buffers for ordinary traffic. The dispatcher requires the full estimated
airtime in its normal mesh budget and additionally defaults to at most 72,000 ms per
rolling hour (2%), conservatively checking the 1.5x send-timeout envelope before
TX. All opaque OTA packets share the Relay category, including control/replies.
Completed and timed-out sends are charged; accounting failure blocks further
OTA TX for this boot. Ready ordinary traffic takes precedence; budget-deferred
OTA frames retry the queue after 60 seconds without globally stalling normal
traffic. This is an airtime limit, not permission to use a restricted frequency.

The isolated profile mounts InternalFS without format-on-failure and requires
its existing `/_main.id`; absent/unreadable identities result in no mesh
dispatch, no new key and no writes. Only `/relay_prefs.json` is used for repeater
preferences, with no `/prefs.json`, `/com_prefs` or legacy companion preference
migration. Identity rekey/export, filesystem erase, ACL persistence and region
persistence are disabled in this profile. Ordinary-to-OTA repeater preference
fallback remains unchanged when this isolation opt-in is off. No ExtraFS/QSPI
mount or OTA stage/floor access is enabled.

Generic defaults inherit ordinary board settings; no lab channel, power or
identity is embedded. An operator can supply controlled `LORA_FREQ`, `LORA_BW`,
`LORA_SF`, `LORA_CR`, `LORA_TX_POWER`, `ADVERT_NAME` build overrides before the
first boot, or use the standard repeater USB CLI (`set radio`, `set tx`,
`set name`, `set repeat`, followed by `get radio`/`get tx`/`get repeat`). Existing
isolated preferences override build defaults. Changing mesh `airtime.factor`
does not raise the relay's independent OTA ceiling. To change inherited
preprocessor definitions, use an explicit local environment with matching
`build_unflags` and new `build_flags`; avoid relying on duplicate `-D` ordering.

For a private extending environment, retain the relay environment's
`build_unflags` (`-std=gnu++11 -std=gnu++14 -D EXTRAFS=1`) and remove the
inherited `-D LORA_FREQ=869.618`, `-D LORA_BW=62.5`, `-D LORA_SF=8`,
`-D LORA_TX_POWER=22` and `-D ADVERT_NAME='"Xiao_nrf52 Repeater"'` before
supplying replacements alongside the inherited `build_flags`. `LORA_CR` has
no inherited command-line definition to remove. Build with
`make build ENV=<private-relay-env>`; the APP-only DFU ZIP is
`.pio/build/<private-relay-env>/firmware.zip`. Flash APP only, preserving the
paired bootloader and userdata; verify identity, radio, name and repeat setting
again after reboot. The advertised repeater role is not a paired installer-role
qualification.

The relay-only OTA cap can be explicitly changed at compile time with
`-D MESHCORE_LORA_OTA_RELAY_DUTY_PERCENT=<integer-percent>`; valid values are
1–100 inclusive, and an omitted flag retains the production default of 2%.
Out-of-range definitions fail compilation. The existing rolling-hour limiter,
timeout accounting, queue reserve and ordinary-traffic precedence remain in
force; this flag does not enable an installer or change RF power/frequency.
For the explicitly authorized accelerated functional RF lab, add
`-D MESHCORE_LORA_OTA_RELAY_DUTY_PERCENT=80` only to the private extending
environment's `build_flags` (2,880,000 ms/hour), retaining TX2 and its existing
channel overrides. The normal mesh airtime budget is a separate, additional
limit: configure its duty to 80% through the standard repeater CLI and verify
readback. Do not infer regulatory permission from a higher software cap, and
do not change generic environment defaults or treat acceleration as a raw
throughput benchmark. The earlier hardware milestone below was at 2%, not
proof of the subsequent accelerated campaign.

For an installer receiver's native OTA CLI, `ota duty 80` changes only the
in-memory OTA airtime budget; it does not reset the candidate, generation,
BEGIN nonce or bitmap, and it is not persisted across reboot. An unwired
CommonCLI `get ota.dutycycle` callback is not readback of this native setting.
Keep critical APP-only DFU packages outside `.pio/build`: PlatformIO may
invalidate the project-wide build cache when configuration changes.

#### Parent-observed hardware milestone — 2026-10-09

A private APP-only build using 907.525 MHz, BW250, SF7, CR5 and TX2 produced a
362,868-byte APP (SHA-256 prefix `19ef6692`, exclusive flash end `0x7F974`).
The isolated name `OTA-LAB-RELAY`, 2% duty setting and repeat-on state persisted
across reboot; the existing companion public identity was retained and the
node advertised as a genuine repeater. These are private lab settings, not
generic environment defaults.

The reproducible negative/positive route probe used a stock sender with one
explicit selected-relay hop and accepted only the current poll attempt's
exact single-relay return trail. Repeat-off yielded no accepted route during
25 seconds; repeat-on yielded 5/5 v3 census replies from the target's unchanged
generation-1/floor-1 baseline (6,017 blocks). A bare target reply was received
but correctly rejected. No retune, fallback or candidate mutation was used.

**Full counter-2 campaign remains pending.** The subsequent stock-sender →
dedicated-repeater → target campaign was running on the normal channel at 2%
with a 172,800-second timeout. Its observed generation-2 state was Receiving,
6,031 total blocks, with live census reporting four received blocks at 90.243
seconds. This proves relay necessity and early RF admission/progress, not
completed transfer, installation, reboot confirmation or counter-2 floor
advancement.

The subsequent accelerated lab run preserved the same counter-2 image and
generation. After a graceful host pause, one routed census captured 129/6,031
received blocks and the existing nonce as unsigned observations. Strict resume
then used an 80% sender budget, an APP-only relay build with the private 80%
flag (362,868 bytes, SHA-256 prefix `08096e47`, end `0x7F974`), relay mesh duty
80%, and the receiver's native `ota duty 80`. RF profile and TX2 were unchanged.

A six-second relay-forwarding outage left the four-block batch 2056-2059
missing: window 2048 still reported eight present blocks. The sender retried
those individual indices, and a later current-attempt census reported twelve
present blocks at 563.726 seconds on the resumed clock. Generation and nonce
were unchanged; no BEGIN, REUPLOAD or direct fallback was used. This establishes
bounded RF outage recovery and selective block repair, not full-image
installation or post-reboot floor advancement, which remain pending.

Focused native routing (real Mesh/Dispatcher/StaticPool/SimpleMeshTables, installer
off), startup safety and gate-off compatibility use existing Make targets:

```sh
PLATFORMIO_BUILD_FLAGS='-D MESHCORE_LORA_OTA_RELAY=1 -D MESHCORE_REPEATER_RELAY_PROFILE=1' make test-ota-disabled
PLATFORMIO_BUILD_FLAGS='-D MESHCORE_LORA_OTA_RELAY=1 -D MESHCORE_REPEATER_RELAY_PROFILE=1 -D MESHCORE_LORA_OTA_RELAY_DUTY_PERCENT=80' make test-ota-disabled
make test-ota-storage OTA_GTEST_FILTER='RelayStartup.*:BExampleStartupTest.*'
make test-ota-disabled
make test-ota-queue-compatibility
make test-ota-native OTA_TEST_FILTER=test_config_serializer OTA_GTEST_FILTER='RepeaterPrefsMigration.*'
```

Both relay runs exercise the configured cap's admission, rolling expiry and
timeout charging alongside unchanged routing/isolation behavior. With the same
relay flags, `MESHCORE_LORA_OTA_RELAY_DUTY_PERCENT=0`, `-1` or `101` must fail
the native build at the explicit compile-time guard; these are expected build
failures, not runtime tests.

### PacketManager compatibility

Existing `PacketManager` implementations compile and behave unchanged, with or
without OTA. The legacy `allocNew()`, `void queueOutbound(...)` and
`getNextOutbound(now)` methods keep their signatures; `queueOutbound` always
takes ownership of the packet. OTA support is optional and defaults to
unsupported: `supportsOtaQueue()` is false, `allocOtaPacket()` returns `nullptr`,
`tryQueueOutbound()` returns false, `getNextOutboundWithPriority()` returns
`nullptr` and `getOutboundScheduleByIdx()` returns false. On `tryQueueOutbound`,
success transfers ownership and failure leaves it with the caller. OTA traffic
fails closed on a manager without OTA support.

`Dispatcher::sendPacket` always consumes the packet. With an OTA-capable manager
its result reports whether the packet was actually queued; with a legacy manager
`true` only means it was submitted, since a drop cannot be observed.
`Mesh::sendFlood` leaves ownership with the caller for an invalid payload type
or path, as before, and otherwise consumes the packet.

Code written against earlier feature-branch hooks migrates as follows:

| Earlier hook | Current hook |
|---|---|
| `allocNew(true)` | `allocOtaPacket()` |
| `allocNew(false)` | `allocNew()` |
| Boolean queue result | `tryQueueOutbound()`; release the packet yourself on `false` |
| Priority dequeue | `getNextOutboundWithPriority()` |
| Schedule getter | `getOutboundScheduleByIdx(i, out)` |

Standalone causal targets retain real boot transaction, descriptor/Ed25519,
radio-fault attribution and transmit-completion behavior:
`test-xiao-ota-bootloader`, `test-ota-radio-fault-attribution`,
`test-ota-radio-tx-completion` and `test-ota-rf-to-boot`.
The latter exchanges actual durable records between native RF admission and
the boot processor, including interrupted install and rollback cases. No
hardware inventory, policy campaign or observer ledger is needed.

For a real ESP application image, `test-ota-esp32-image` accepts
`ESP32_OTA_IMAGE_ARGS='--output <fixture> --qualified-build <PIO-build-dir> cache
--image <firmware.bin> --manifest <canonical59>'`. It checks the vendor image
and emits real signed cache packets for `ESP32_OTA_IMAGE_PATH_FIXTURE=<fixture>
make test-ota-esp32`; no USB/device is opened.

Build scratch is repo-local `.tmp`; PlatformIO outputs remain `.pio` or caller
selected build directories. No container framework or system `/tmp` output is
required. Host dependencies are `requirements-ota.txt`; bootstrap additionally
uses ARM GNU tools, the pinned public OTAFIX source/submodules, and standard
Adafruit nrfutil packaging.

Tests use synthetic keys and fake serial/NOR/SDK I/O. They cover signing,
board/role/counter binding, durable transfer/READY, one COMMIT, matching Installed,
refusal/timeouts, restored radio and interrupted storage/rollback semantics.
Software tests and successful builds do not qualify ESP/Solar hardware,
routed fleet delivery or power-failure behavior on an untested board.
