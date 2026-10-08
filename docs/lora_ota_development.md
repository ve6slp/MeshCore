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
