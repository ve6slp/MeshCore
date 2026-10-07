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
```

`make test` runs ordinary native and KISS-modem tests plus retained host tests.
Per-layer targets are `test-ota-protocol`, `test-ota-runtime`, `test-ota-storage`,
`test-ota-trust`, `test-ota-boot`, `test-ota-integration` and `test-ota-esp32`.
The six native OTA suites cover the shared product and ESP backend.
`test-ota-boot` runs the actual nRF C bootloader transaction/crypto tests through
`test-xiao-ota-bootloader`, not a duplicate portable installer.
`OTA_TEST_FILTER` narrows `test-ota-native`; `PLATFORMIO` selects the installed
runner. `build-ota-nrf52-targets` and `build-ota-esp32-targets` compile the explicit
opt-in environments; callers can override the corresponding environment lists.

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
