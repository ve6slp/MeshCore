PLATFORMIO ?= pio

# Keep build/test scratch inside the repo. The system /tmp is a small
# memory-backed tmpfs and cannot hold toolchain intermediates.
TMPDIR := $(CURDIR)/.tmp
export TMPDIR
export TEMP = $(TMPDIR)
export TMP = $(TMPDIR)

NATIVE_TEST_ENVS ?= native native_kiss_modem

OTA_TEST_FILTER ?= test_lora_ota_*
OTA_TARGET_ENVS ?= SenseCap_Solar_companion_radio_usb Xiao_S3_WIO_companion_radio_usb
XIAO_NRF52_LAB_ENVS ?= Xiao_nrf52_companion_radio_usb

# Lab boards are addressed by role, never by ttyACMn. scripts/lab_device.py
# resolves a role to the current stable /dev/serial/by-id path using the
# serials pinned in lab/devices.ini, so USB renumbering is a non-event.
# These use recursive `=` on purpose: they are resolved only when a hardware
# target actually runs, not on every make invocation.
LAB_DEVICE ?= python3 $(CURDIR)/scripts/lab_device.py
XIAO_NRF52_CLIENT_PORT = $(shell $(LAB_DEVICE) path client)
XIAO_NRF52_TARGET_PORT = $(shell $(LAB_DEVICE) path target)
XIAO_NRF52_BOOT_PORT = $(shell $(LAB_DEVICE) path target --mode bootloader)
XIAO_NRF52_TARGET_SERIAL = $(shell $(LAB_DEVICE) serial target)
XIAO_NRF52_QSPI_TEST_ENV ?= Xiao_nrf52_ota_qspi_hardware_test
XIAO_NRF52_QSPI_EVIDENCE = $(TMPDIR)/xiao-nrf52-qspi-$(XIAO_NRF52_TARGET_SERIAL).log
XIAO_OTA_UPSTREAM ?= $(TMPDIR)/Adafruit_nRF52_Bootloader
XIAO_OTA_WORK ?= $(TMPDIR)/xiao_nrf52840_ota_upstream
XIAO_OTA_NOSWD_WORK ?= $(TMPDIR)/xiao_nrf52840_ota_noswd_upstream
XIAO_OTA_ARTIFACTS ?= $(TMPDIR)/xiao_nrf52840_ota_artifacts
XIAO_OTA_PIN ?= c67f0bcf0fa8e841426335b1bbde91cda6ca1f50
XIAO_OTA_SOURCE_DATE_EPOCH ?= 1779344629
XIAO_OTA_PRIVATE_KEY ?= $(TMPDIR)/xiao-ota-keys/lab-ed25519-private.pem
XIAO_OTA_IMAGE ?=
XIAO_OTA_ACTIVE_IMAGE ?=
XIAO_OTA_COUNTER ?= 1
OTA_LAB_ARTIFACT_DIR ?= $(TMPDIR)/ota-rf-lab/$(shell date -u +%Y%m%dT%H%M%SZ)
OTA_LAB_DUTY_TIMEOUT ?= 420
OTA_LAB_MONITOR_SECONDS ?= 60

# Representative non-OTA targets, used to prove the OTA build-filter and
# platformio.ini changes did not regress platforms that never enable OTA.
NON_OTA_TARGET_ENVS ?= Heltec_v3_repeater RAK_4631_repeater

.PHONY: tmpdir test test-ota test-ota-protocol test-ota-runtime test-ota-storage \
        test-ota-trust test-ota-boot test-ota-integration clean-ota-targets \
        lab-devices lab-doctor lab-reset-client lab-reset-target lab-reset-all \
        lab-bootloader-client lab-bootloader-target \
        lab-power-cycle-client lab-power-cycle-target lab-power-cycle-all \
        lab-wait-client lab-wait-target \
        build-ota-targets build-ota-baseline-targets build-non-ota-targets \
        clean-xiao-nrf52-lab build-xiao-nrf52-lab build-xiao-nrf52-ota-lab upload-xiao-nrf52-client upload-xiao-nrf52-target upload-xiao-nrf52-lab \
        enter-xiao-nrf52-target-bootloader \
        install-xiao-nrf52-target-ota-bootloader \
        configure-xiao-nrf52-ota-lab configure-xiao-nrf52-ota-client \
        monitor-xiao-nrf52-ota-lab monitor-xiao-nrf52-ota-client test-xiao-nrf52-ota-lab \
        build-xiao-nrf52-qspi-test upload-xiao-nrf52-qspi-test \
        run-xiao-nrf52-qspi-test validate-xiao-nrf52-qspi-hardware \
        fetch-xiao-ota-bootloader provision-xiao-ota-lab-key \
        test-xiao-ota-bootloader build-xiao-stock-bootloader \
        build-xiao-ota-bootloader package-xiao-ota-bootloader \
        build-xiao-ota-bootloader-noswd package-xiao-ota-bootloader-noswd \
        sign-xiao-ota-image verify-xiao-ota-bootloader \
        verify-ota-software clean-tmp

tmpdir:
	@mkdir -p $(TMPDIR)

## Full native unit-test suite (pre-existing tests plus OTA).
test: tmpdir
	$(PLATFORMIO) test $(foreach e,$(NATIVE_TEST_ENVS),-e $(e))

## All OTA native tests.
test-ota: tmpdir
	$(PLATFORMIO) test -e native -f '$(OTA_TEST_FILTER)'

## Per-layer OTA tests, for fast iteration on a single scope.
test-ota-protocol: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_protocol'

test-ota-runtime: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_runtime'

test-ota-storage: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_storage'

test-ota-trust: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_trust'

test-ota-boot: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_boot'

test-ota-integration: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_integration'

## Compile the OTA-capable firmware targets.
build-ota-targets: tmpdir
	@for env in $(OTA_TARGET_ENVS); do \
	  echo "==> building $$env"; \
	  $(PLATFORMIO) run -e $$env || exit 1; \
	done

## Compile the same firmware targets with OTA disabled for size comparison.
build-ota-baseline-targets: tmpdir
	@for env in $(OTA_TARGET_ENVS); do \
	  echo "==> baseline building $$env"; \
	  PLATFORMIO_BUILD_FLAGS='-D MESHCORE_LORA_OTA=0' $(PLATFORMIO) run -e $$env || exit 1; \
	done

clean-ota-targets: tmpdir
	@for env in $(OTA_TARGET_ENVS); do \
	  echo "==> cleaning $$env"; \
	  $(PLATFORMIO) run -e $$env -t clean || exit 1; \
	done

## Regression guard: platforms that never enable OTA must still build.
build-non-ota-targets: tmpdir
	@for env in $(NON_OTA_TARGET_ENVS); do \
	  echo "==> building $$env (OTA disabled)"; \
	  $(PLATFORMIO) run -e $$env || exit 1; \
	done

## ---------------------------------------------------------------------------
## Lab device control. One command shape for every board operation; roles come
## from lab/devices.ini so no target ever names a ttyACMn or a raw serial.
## ---------------------------------------------------------------------------

## Show every attached XIAO and the role it resolves to.
lab-devices:
	@$(LAB_DEVICE) list

## Check the host can drive the boards (sudo, uhubctl, pyserial, power control).
lab-doctor:
	@$(LAB_DEVICE) doctor

## Restart the application firmware without entering the bootloader.
lab-reset-client:
	@$(LAB_DEVICE) reset client
lab-reset-target:
	@$(LAB_DEVICE) reset target
lab-reset-all: lab-reset-client lab-reset-target

## Enter the serial DFU bootloader (1200-baud touch).
lab-bootloader-client:
	@$(LAB_DEVICE) bootloader client
lab-bootloader-target:
	@$(LAB_DEVICE) bootloader target

## Cut and restore USB port power. Use this to recover an unresponsive board.
lab-power-cycle-client:
	@$(LAB_DEVICE) power-cycle client
lab-power-cycle-target:
	@$(LAB_DEVICE) power-cycle target
lab-power-cycle-all: lab-power-cycle-client lab-power-cycle-target

## Block until a board enumerates in application mode.
lab-wait-client:
	@$(LAB_DEVICE) wait client
lab-wait-target:
	@$(LAB_DEVICE) wait target

## Compile the XIAO nRF52840 + SX1262 lab firmware with OTA enabled.
clean-xiao-nrf52-lab: tmpdir
	$(PLATFORMIO) run -e Xiao_nrf52_companion_radio_usb -t clean
	$(PLATFORMIO) run -e $(XIAO_NRF52_QSPI_TEST_ENV) -t clean

build-xiao-nrf52-lab: tmpdir
	@for env in $(XIAO_NRF52_LAB_ENVS); do \
	  echo "==> building $$env"; \
	  $(PLATFORMIO) run -e $$env || exit 1; \
	done

## Compile the XIAO nRF52840 + SX1262 target with the OTA core enabled.
build-xiao-nrf52-ota-lab: tmpdir
	@for env in $(XIAO_NRF52_LAB_ENVS); do \
	  echo "==> building $$env (OTA enabled)"; \
	  $(PLATFORMIO) run -e $$env || exit 1; \
	done

## Flash the companion lab firmware to a role. Both variants of the fragile
## PlatformIO upload path (app port and bootloader port) collapse into one
## deterministic command.
XIAO_NRF52_LAB_PACKAGE ?= .pio/build/Xiao_nrf52_companion_radio_usb/firmware.zip

upload-xiao-nrf52-client: build-xiao-nrf52-lab
	@mkdir -p $(OTA_LAB_ARTIFACT_DIR)
	@$(LAB_DEVICE) flash client --package $(XIAO_NRF52_LAB_PACKAGE) \
	  > $(OTA_LAB_ARTIFACT_DIR)/flash-client.log 2>&1; \
	  result=$$?; cat $(OTA_LAB_ARTIFACT_DIR)/flash-client.log; exit $$result

upload-xiao-nrf52-target: build-xiao-nrf52-lab
	@mkdir -p $(OTA_LAB_ARTIFACT_DIR)
	@$(LAB_DEVICE) flash target --package $(XIAO_NRF52_LAB_PACKAGE) \
	  > $(OTA_LAB_ARTIFACT_DIR)/flash-target.log 2>&1; \
	  result=$$?; cat $(OTA_LAB_ARTIFACT_DIR)/flash-target.log; exit $$result

upload-xiao-nrf52-lab: upload-xiao-nrf52-client upload-xiao-nrf52-target

enter-xiao-nrf52-target-bootloader: tmpdir
	@$(LAB_DEVICE) bootloader target

configure-xiao-nrf52-ota-lab: tmpdir
	python3 scripts/ota_rf_lab.py --artifact-dir $(OTA_LAB_ARTIFACT_DIR) --configure-only

configure-xiao-nrf52-ota-client: tmpdir
	python3 scripts/ota_rf_lab.py --artifact-dir $(OTA_LAB_ARTIFACT_DIR) --client-only --configure-only

monitor-xiao-nrf52-ota-lab: tmpdir
	python3 scripts/ota_rf_lab.py --artifact-dir $(OTA_LAB_ARTIFACT_DIR) --monitor-seconds $(OTA_LAB_MONITOR_SECONDS)

monitor-xiao-nrf52-ota-client: tmpdir
	python3 scripts/ota_rf_lab.py --artifact-dir $(OTA_LAB_ARTIFACT_DIR) --client-only --monitor-seconds $(OTA_LAB_MONITOR_SECONDS)

test-xiao-nrf52-ota-lab: tmpdir
	python3 scripts/ota_rf_lab.py --artifact-dir $(OTA_LAB_ARTIFACT_DIR) --duty-timeout $(OTA_LAB_DUTY_TIMEOUT)

build-xiao-nrf52-qspi-test: tmpdir
	$(PLATFORMIO) run -e $(XIAO_NRF52_QSPI_TEST_ENV)

upload-xiao-nrf52-qspi-test: build-xiao-nrf52-qspi-test
	@$(LAB_DEVICE) flash target --package .pio/build/$(XIAO_NRF52_QSPI_TEST_ENV)/firmware.zip

run-xiao-nrf52-qspi-test: tmpdir
	python3 tools/ota_qspi_hw_test.py --role target --output $(XIAO_NRF52_QSPI_EVIDENCE)

validate-xiao-nrf52-qspi-hardware: upload-xiao-nrf52-qspi-test run-xiao-nrf52-qspi-test
	@echo "QSPI hardware evidence: $(XIAO_NRF52_QSPI_EVIDENCE)"

fetch-xiao-ota-bootloader: tmpdir
	@if [ ! -d "$(XIAO_OTA_UPSTREAM)/.git" ]; then \
	  git clone https://github.com/adafruit/Adafruit_nRF52_Bootloader.git "$(XIAO_OTA_UPSTREAM)"; \
	fi
	@git -C "$(XIAO_OTA_UPSTREAM)" fetch --quiet origin "$(XIAO_OTA_PIN)"
	@git -C "$(XIAO_OTA_UPSTREAM)" checkout --quiet --detach "$(XIAO_OTA_PIN)"
	@test "$$(git -C "$(XIAO_OTA_UPSTREAM)" rev-parse HEAD)" = "$(XIAO_OTA_PIN)"

provision-xiao-ota-lab-key: tmpdir
	python3 bootloader/xiao_nrf52840_ota/tools/provision_lab_key.py

test-xiao-ota-bootloader: tmpdir
	@mkdir -p "$(TMPDIR)/xiao-ota-host"
	$(CC) -std=c11 -Wall -Wextra -Werror \
	  -Ibootloader/xiao_nrf52840_ota/include \
	  -Ibootloader/xiao_nrf52840_ota/src \
	  bootloader/xiao_nrf52840_ota/src/xiao_ota_record.c \
	  bootloader/xiao_nrf52840_ota/src/xiao_ota_sha256.c \
	  bootloader/xiao_nrf52840_ota/tests/test_record.c \
	  -o "$(TMPDIR)/xiao-ota-host/test_record"
	"$(TMPDIR)/xiao-ota-host/test_record"
	$(CC) -std=c11 -O2 -ffunction-sections -fdata-sections \
	  -Wall -Wextra -Werror \
	  -Ibootloader/xiao_nrf52840_ota/third_party/tweetnacl \
	  bootloader/xiao_nrf52840_ota/src/xiao_ota_ed25519_tweetnacl.c \
	  bootloader/xiao_nrf52840_ota/third_party/tweetnacl/tweetnacl.c \
	  bootloader/xiao_nrf52840_ota/tests/test_ed25519.c \
	  -Wno-unused-function -Wno-sign-compare -Wno-shadow \
	  -Wno-unterminated-string-initialization \
	  -Wl,--gc-sections \
	  -o "$(TMPDIR)/xiao-ota-host/test_ed25519"
	"$(TMPDIR)/xiao-ota-host/test_ed25519"
	python3 bootloader/xiao_nrf52840_ota/tests/test_source.py
	python3 bootloader/xiao_nrf52840_ota/tests/test_install_uf2.py

build-xiao-stock-bootloader: fetch-xiao-ota-bootloader
	@$(MAKE) -C "$(XIAO_OTA_UPSTREAM)" BOARD=xiao_nrf52840_ble clean
	@out="$$( $(MAKE) -s --no-print-directory -C "$(XIAO_OTA_UPSTREAM)" BOARD=xiao_nrf52840_ble print-OUT_NAME | sed 's/^OUT_NAME = //' )"; \
	  SOURCE_DATE_EPOCH="$(XIAO_OTA_SOURCE_DATE_EPOCH)" $(MAKE) -C "$(XIAO_OTA_UPSTREAM)" BOARD=xiao_nrf52840_ble \
	    "_build/build-xiao_nrf52840_ble/$${out}.out" \
	    "_build/build-xiao_nrf52840_ble/$${out}_nosd.hex" \
	    "_build/build-xiao_nrf52840_ble/update-$${out}_nosd.uf2"
	@mkdir -p "$(XIAO_OTA_ARTIFACTS)/stock"
	@cp "$$(find "$(XIAO_OTA_UPSTREAM)/_build/build-xiao_nrf52840_ble" -maxdepth 1 -name '*_nosd.hex' | head -1)" \
	  "$(XIAO_OTA_ARTIFACTS)/stock/xiao_nrf52840_ble_stock_$(XIAO_OTA_PIN)_nosd.hex"
	@cp "$$(find "$(XIAO_OTA_UPSTREAM)/_build/build-xiao_nrf52840_ble" -maxdepth 1 -name 'update-*_nosd.uf2' | head -1)" \
	  "$(XIAO_OTA_ARTIFACTS)/stock/xiao_nrf52840_ble_stock_$(XIAO_OTA_PIN)_update.uf2"

build-xiao-ota-bootloader: fetch-xiao-ota-bootloader
	python3 bootloader/xiao_nrf52840_ota/tools/prepare_upstream.py
	@$(MAKE) -C "$(XIAO_OTA_WORK)" BOARD=xiao_nrf52840_ble clean
	@out="$$( $(MAKE) -s --no-print-directory -C "$(XIAO_OTA_WORK)" BOARD=xiao_nrf52840_ble print-OUT_NAME | sed 's/^OUT_NAME = //' )"; \
	  SOURCE_DATE_EPOCH="$(XIAO_OTA_SOURCE_DATE_EPOCH)" $(MAKE) -C "$(XIAO_OTA_WORK)" BOARD=xiao_nrf52840_ble \
	    "_build/build-xiao_nrf52840_ble/$${out}.out" \
	    "_build/build-xiao_nrf52840_ble/$${out}_nosd.hex" \
	    "_build/build-xiao_nrf52840_ble/update-$${out}_nosd.uf2"
	@arm-none-eabi-size "$$(find "$(XIAO_OTA_WORK)/_build/build-xiao_nrf52840_ble" -maxdepth 1 -name '*.out' | head -1)"
	@python3 bootloader/xiao_nrf52840_ota/tools/report_size.py \
	  "$$(find "$(XIAO_OTA_WORK)/_build/build-xiao_nrf52840_ble" -maxdepth 1 -name '*.out' | head -1)" \
	  --slot-bytes 67584

package-xiao-ota-bootloader: build-xiao-ota-bootloader
	@mkdir -p "$(XIAO_OTA_ARTIFACTS)/custom"
	@cp "$$(find "$(XIAO_OTA_WORK)/_build/build-xiao_nrf52840_ble" -maxdepth 1 -name '*_nosd.hex' | head -1)" \
	  "$(XIAO_OTA_ARTIFACTS)/custom/xiao_nrf52840_ota_nosd.hex"
	@cp "$$(find "$(XIAO_OTA_WORK)/_build/build-xiao_nrf52840_ble" -maxdepth 1 -name 'update-*_nosd.uf2' | head -1)" \
	  "$(XIAO_OTA_ARTIFACTS)/custom/xiao_nrf52840_ota_update.uf2"
	@sha256sum "$(XIAO_OTA_ARTIFACTS)"/custom/*

build-xiao-ota-bootloader-noswd: fetch-xiao-ota-bootloader
	python3 bootloader/xiao_nrf52840_ota/tools/prepare_upstream.py --no-ble
	@$(MAKE) -C "$(XIAO_OTA_NOSWD_WORK)" BOARD=xiao_nrf52840_ble clean
	@out="$$( $(MAKE) -s --no-print-directory -C "$(XIAO_OTA_NOSWD_WORK)" BOARD=xiao_nrf52840_ble print-OUT_NAME | sed 's/^OUT_NAME = //' )"; \
	  SOURCE_DATE_EPOCH="$(XIAO_OTA_SOURCE_DATE_EPOCH)" $(MAKE) -C "$(XIAO_OTA_NOSWD_WORK)" BOARD=xiao_nrf52840_ble \
	    "_build/build-xiao_nrf52840_ble/$${out}.out" \
	    "_build/build-xiao_nrf52840_ble/$${out}_nosd.hex" \
	    "_build/build-xiao_nrf52840_ble/update-$${out}_nosd.uf2"
	@arm-none-eabi-size "$$(find "$(XIAO_OTA_NOSWD_WORK)/_build/build-xiao_nrf52840_ble" -maxdepth 1 -name '*.out' | head -1)"
	@python3 bootloader/xiao_nrf52840_ota/tools/report_size.py \
	  "$$(find "$(XIAO_OTA_NOSWD_WORK)/_build/build-xiao_nrf52840_ble" -maxdepth 1 -name '*.out' | head -1)" \
	  --slot-bytes 38912

package-xiao-ota-bootloader-noswd: build-xiao-ota-bootloader-noswd
	@mkdir -p "$(XIAO_OTA_ARTIFACTS)/custom-noswd"
	@cp "$$(find "$(XIAO_OTA_NOSWD_WORK)/_build/build-xiao_nrf52840_ble" -maxdepth 1 -name '*_nosd.hex' | head -1)" \
	  "$(XIAO_OTA_ARTIFACTS)/custom-noswd/xiao_nrf52840_ota_noswd.hex"
	@cp "$$(find "$(XIAO_OTA_NOSWD_WORK)/_build/build-xiao_nrf52840_ble" -maxdepth 1 -name 'update-*_nosd.uf2' | head -1)" \
	  "$(XIAO_OTA_ARTIFACTS)/custom-noswd/xiao_nrf52840_ota_noswd_update.uf2"
	@cp "$$(find "$(XIAO_OTA_NOSWD_WORK)/_build/build-xiao_nrf52840_ble" -maxdepth 1 -name '*.out.map' | head -1)" \
	  "$(XIAO_OTA_ARTIFACTS)/custom-noswd/xiao_nrf52840_ota_noswd.map"
	@sha256sum "$(XIAO_OTA_ARTIFACTS)"/custom-noswd/*

## Install only the packaged no-SWD custom bootloader UF2 on the authorized XIAO.
## Put the board in XIAO-BOOT mode first; this target never selects a ttyACM path.
install-xiao-nrf52-target-ota-bootloader: package-xiao-ota-bootloader-noswd
	python3 bootloader/xiao_nrf52840_ota/tools/install_uf2.py \
	  --serial "$(XIAO_NRF52_TARGET_SERIAL)" \
	  --boot-port "$(XIAO_NRF52_BOOT_PORT)" \
	  --artifact "$(XIAO_OTA_ARTIFACTS)/custom-noswd/xiao_nrf52840_ota_noswd_update.uf2"

sign-xiao-ota-image: provision-xiao-ota-lab-key
	@test -n "$(XIAO_OTA_IMAGE)" && test -n "$(XIAO_OTA_ACTIVE_IMAGE)"
	python3 bootloader/xiao_nrf52840_ota/tools/sign_image.py \
	  --image "$(XIAO_OTA_IMAGE)" --active-image "$(XIAO_OTA_ACTIVE_IMAGE)" \
	  --private-key "$(XIAO_OTA_PRIVATE_KEY)" --counter "$(XIAO_OTA_COUNTER)" \
	  --output-dir "$(XIAO_OTA_ARTIFACTS)/signed-counter-$(XIAO_OTA_COUNTER)"

verify-xiao-ota-bootloader: test-xiao-ota-bootloader package-xiao-ota-bootloader package-xiao-ota-bootloader-noswd
	@echo "XIAO OTA bootloader host tests, 66-KiB fallback, 38-KiB no-SWD link, maps, HEX and UF2 passed."

## Software-level qualification only.
## Passing this gate means the native tests pass and the OTA-enabled and
## non-OTA firmware targets link. It does NOT mean a device can be updated:
## on-device radio behaviour, real flash writes, the custom nRF52840
## QSPI-aware bootloader, trusted boot, the anti-rollback counter backend and
## power-loss rollback all remain hardware acceptance gates.
verify-ota-software: test build-ota-targets build-non-ota-targets
	@echo
	@echo "OTA software checks passed: native tests green, firmware targets link."
	@echo "NOT qualified here: on-device radio, flash, bootloader, anti-rollback, rollback."

clean-tmp:
	rm -rf $(TMPDIR)
