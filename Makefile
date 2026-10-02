PLATFORMIO ?= pio

# Keep build/test scratch inside the repo. The system /tmp is a small
# memory-backed tmpfs and cannot hold toolchain intermediates.
TMPDIR := $(CURDIR)/.tmp
export TMPDIR
export TEMP = $(TMPDIR)
export TMP = $(TMPDIR)

NATIVE_TEST_ENVS ?= native native_kiss_modem

OTA_TEST_FILTER ?= test_lora_ota_*
OTA_LAB_HOST_TEST_PATTERN ?= test_*.py
OTA_INDEX_GOALS ?= test-ota
OTA_TARGET_ENVS ?= SenseCap_Solar_companion_radio_usb $(OTA_ESP32_TARGET_ENVS)
OTA_ESP32_TARGET_ENVS ?= Xiao_S3_WIO_companion_radio_usb Xiao_S3_WIO_repeater_ota_usb
OTA_NRF52_TARGET_ENVS ?= Xiao_nrf52_companion_radio_usb SenseCap_Solar_companion_radio_usb Xiao_nrf52_repeater_ota_usb SenseCap_Solar_repeater_ota_usb
XIAO_NRF52_CLIENT_ENV ?= Xiao_nrf52_companion_radio_usb
XIAO_NRF52_TARGET_ENV ?= Xiao_nrf52_repeater_ota_usb
XIAO_NRF52_LAB_ENVS ?= $(XIAO_NRF52_CLIENT_ENV) $(XIAO_NRF52_TARGET_ENV)
XIAO_NRF52_CANDIDATE_ENV ?= Xiao_nrf52_repeater_ota_usb_candidate
XIAO_OTA_LAB_VERSION ?=

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
XIAO_NRF52_ARCHIVE_ENV ?= Xiao_nrf52_ota_readonly_archive
OTA_LAB_ARCHIVE_KEY ?=
OTA_LAB_ARCHIVE_FILE ?=
OTA_LAB_ARCHIVE_ROLE ?= target
XIAO_NRF52_QSPI_EVIDENCE = $(TMPDIR)/xiao-nrf52-qspi-$(XIAO_NRF52_TARGET_SERIAL).log
XIAO_OTA_UPSTREAM ?= $(TMPDIR)/Adafruit_nRF52_Bootloader
XIAO_OTA_WORK ?= $(TMPDIR)/ota-boot-builds/$(XIAO_OTA_BOARD)_ota$(XIAO_OTA_ROLE_SUFFIX)_upstream
XIAO_OTA_NOSWD_WORK ?= $(TMPDIR)/ota-boot-builds/$(XIAO_OTA_BOARD)_ota$(XIAO_OTA_ROLE_SUFFIX)_noswd_upstream
XIAO_OTA_ARTIFACTS ?= $(TMPDIR)/$(XIAO_OTA_BOARD)_ota$(XIAO_OTA_ROLE_SUFFIX)_artifacts
XIAO_OTA_PIN ?= c67f0bcf0fa8e841426335b1bbde91cda6ca1f50
XIAO_OTA_SOURCE_DATE_EPOCH ?= 1779344629
XIAO_OTA_PRIVATE_KEY ?=
XIAO_OTA_IMAGE ?=
XIAO_OTA_ACTIVE_IMAGE ?=
XIAO_OTA_COUNTER ?= 1
XIAO_OTA_BOARD ?= xiao_nrf52840
XIAO_OTA_ROLE_ID ?= 0
XIAO_OTA_ROLE_SUFFIX = $(if $(filter 0,$(XIAO_OTA_ROLE_ID)),,_role$(XIAO_OTA_ROLE_ID))
XIAO_OTA_TEST_BOARD_TARGET ?= XIAO_OTA_TARGET_XIAO_NRF52840
OTA_NRF_REMOTE_BOOT_PROOF_PREFIX ?=
XIAO_OTA_BOOT_PROCESS_SOURCES = \
	bootloader/xiao_nrf52840_ota/src/xiao_ota_boot_io.c \
	bootloader/xiao_nrf52840_ota/src/xiao_ota_record.c \
	bootloader/xiao_nrf52840_ota/src/xiao_ota_sha256.c \
	bootloader/xiao_nrf52840_ota/src/xiao_ota_ed25519_tweetnacl.c \
	bootloader/xiao_nrf52840_ota/third_party/tweetnacl/tweetnacl.c \
	bootloader/xiao_nrf52840_ota/tests/crc16_host.c \
	bootloader/xiao_nrf52840_ota/tests/fake_io.c
XIAO_OTA_BOOT_PROCESS_CFLAGS = -std=c11 -O2 -Wall -Wextra -Werror \
	-Ibootloader/xiao_nrf52840_ota/include \
	-Ibootloader/xiao_nrf52840_ota/src \
	-Ibootloader/xiao_nrf52840_ota/third_party/tweetnacl \
	-Ibootloader/xiao_nrf52840_ota/tests \
	-Isrc/ota/trust/third_party/ed25519 \
	-DXIAO_OTA_BOARD_TARGET="$(XIAO_OTA_TEST_BOARD_TARGET)" \
	-DXIAO_OTA_COMPILED_ROLE_ID="$(XIAO_OTA_ROLE_ID)" \
	-Wno-unused-function -Wno-sign-compare -Wno-shadow \
	-Wno-unterminated-string-initialization
XIAO_OTA_STEM = $(XIAO_OTA_BOARD)_ota$(XIAO_OTA_ROLE_SUFFIX)
XIAO_NRF52_TARGET_OTA_BOOTLOADER_PACKAGE ?= $(XIAO_OTA_ARTIFACTS)/custom-noswd/$(XIAO_OTA_STEM)_noswd_update.uf2
VERIFY_OTA_BOOT_INFO = python3 bootloader/xiao_nrf52840_ota/tools/verify_boot_info_artifact.py \
	--board "$(XIAO_OTA_BOARD)" --role-id "$(XIAO_OTA_ROLE_ID)"
VERIFY_OTA_INSTALL_ARTIFACT = python3 bootloader/xiao_nrf52840_ota/tools/install_uf2.py \
	--validate-only --board "$(XIAO_OTA_BOARD)" --role-id "$(XIAO_OTA_ROLE_ID)"
OTA_LAB_ARTIFACT_DIR ?= $(TMPDIR)/ota-rf-lab/$(shell date -u +%Y%m%dT%H%M%SZ)
OTA_LAB_MONITOR_SECONDS ?= 60
OTA_LAB_BANDWIDTH_HZ ?= 62500
OTA_LAB_REQUIRE_GENESIS_FLOOR ?= 0
OTA_LAB_REQUIRE_BOOT_ADDRESSES ?= 0
OTA_LAB_CLIENT_PROTOCOL ?= companion
OTA_LAB_TARGET_PROTOCOL ?= repeater
OTA_UPLOAD_IMAGE ?=
OTA_UPLOAD_MANIFEST ?=
OTA_UPLOAD_BOARD ?= xiao_nrf52840
OTA_UPLOAD_ROLE_ID ?= 1
OTA_UPLOAD_COUNTER ?=
OTA_UPLOAD_TARGET ?=
OTA_UPLOAD_MODE ?= directed
OTA_UPLOAD_CHANNEL ?= 255
OTA_UPLOAD_FREQ_KHZ ?= 0
OTA_UPLOAD_LEASE_MS ?= 0
OTA_UPLOAD_DUTY_MILLI_PERCENT ?= 2000
OTA_UPLOAD_TIMEOUT ?= 300
OTA_UPLOAD_REUPLOAD ?= 0
OTA_UPLOAD_WAIT_READY ?= 0
OTA_UPLOAD_ADMIN_ENABLED ?=
OTA_UPLOAD_COMMAND = python3 scripts/ota_uploader.py \
	--artifact-dir "$(OTA_LAB_ARTIFACT_DIR)" --timeout "$(OTA_UPLOAD_TIMEOUT)"
OTA_SIGNED_LAB_MODE ?= $(OTA_UPLOAD_MODE)
OTA_SIGNED_LAB_DUTY ?= $(OTA_UPLOAD_DUTY_MILLI_PERCENT)
OTA_SIGNED_LAB_CHANNEL ?= $(OTA_UPLOAD_CHANNEL)
OTA_SIGNED_LAB_COUNTER ?= $(OTA_UPLOAD_COUNTER)
OTA_SIGNED_LAB_TIMEOUT ?= 259200
OTA_SIGNED_LAB_REBOOT_TIMEOUT ?= 120
OTA_SIGNED_LAB_TRIAL_TIMEOUT ?= 30
OTA_SIGNED_LAB_INSTALL_TIMEOUT ?= 300
OTA_SIGNED_LAB_IMAGE_SHA256 ?=
OTA_SIGNED_LAB_PROVENANCE ?=
OTA_SIGNED_LAB_COMMISSIONING ?=
OTA_SIGNED_LAB_READY_RECORD ?=
OTA_SIGNED_LAB_EXTRA ?=

# Representative non-OTA targets, used to prove the OTA build-filter and
# platformio.ini changes did not regress platforms that never enable OTA.
NON_OTA_TARGET_ENVS ?= Heltec_v3_repeater RAK_4631_repeater
ESP32_OTA_CORE_DIR ?= $(if $(PLATFORMIO_CORE_DIR),$(PLATFORMIO_CORE_DIR),$(HOME)/.platformio)
ESP32_OTA_SDK_DIR ?= $(ESP32_OTA_CORE_DIR)/packages/framework-arduinoespressif32/tools/sdk/esp32s3
ESP32_OTA_BOOTLOADER_ELF ?= $(ESP32_OTA_SDK_DIR)/bin/bootloader_qio_80m.elf
ESP32_OTA_OBJDUMP ?= $(ESP32_OTA_CORE_DIR)/packages/toolchain-xtensa-esp32s3/bin/xtensa-esp32s3-elf-objdump
ESP32_OTA_ENV ?= Xiao_S3_WIO_companion_radio_usb
ESP32_OTA_BUILD_DIR ?= $(if $(PLATFORMIO_BUILD_DIR),$(PLATFORMIO_BUILD_DIR),.pio/build)

.PHONY: tmpdir test test-ota test-ota-native test-ota-index test-ota-protocol test-ota-runtime \
        test-ota-image-layout-index test-ota-storage \
        test-ota-trust test-ota-boot test-ota-integration test-ota-rf-to-boot test-ota-lab-host test-ota-lab-archive clean-ota-targets \
        lab-devices lab-doctor lab-reset-client lab-reset-target lab-reset-all \
        lab-bootloader-client lab-bootloader-target lab-bootloader-uf2-target \
        lab-power-cycle-client lab-power-cycle-target lab-power-cycle-all \
        lab-wait-client lab-wait-target \
        build-ota-targets build-ota-nrf52-targets build-ota-esp32-targets build-ota-baseline-targets build-non-ota-targets \
        inspect-xiao-s3-ota-bootloader \
        clean-xiao-nrf52-lab build-xiao-nrf52-lab build-xiao-nrf52-ota-lab build-xiao-nrf52-ota-candidate upload-xiao-nrf52-client upload-xiao-nrf52-target upload-xiao-nrf52-lab \
        flash-xiao-nrf52-client flash-xiao-nrf52-target flash-xiao-nrf52-lab \
        enter-xiao-nrf52-target-bootloader \
        install-xiao-nrf52-target-ota-bootloader flash-xiao-nrf52-target-ota-bootloader \
        configure-xiao-nrf52-ota-lab configure-xiao-nrf52-ota-client grant-xiao-nrf52-ota-client-admin inspect-xiao-nrf52-ota-preflight inspect-xiao-nrf52-ota-configuration \
        monitor-xiao-nrf52-ota-lab monitor-xiao-nrf52-ota-client test-xiao-nrf52-ota-lab \
        ota-lab-image ota-lab-manifest ota-lab-upload ota-lab-status ota-lab-commit ota-lab-abort ota-lab-abort-cache ota-lab-admin \
        qualify-xiao-nrf52-normal-peer qualify-xiao-nrf52-signed-stage qualify-xiao-nrf52-signed-commit \
        build-xiao-nrf52-qspi-test upload-xiao-nrf52-qspi-test \
        run-xiao-nrf52-qspi-test validate-xiao-nrf52-qspi-hardware \
        build-xiao-nrf52-archive generate-ota-lab-archive-key \
        archive-xiao-nrf52-device archive-xiao-nrf52-client archive-xiao-nrf52-target \
        validate-xiao-nrf52-archive validate-xiao-nrf52-client-archive validate-xiao-nrf52-target-archive \
        verify-xiao-nrf52-archive verify-xiao-nrf52-client-archive verify-xiao-nrf52-target-archive \
        fetch-xiao-ota-bootloader generate-xiao-ota-fixture-key \
        test-xiao-ota-bootloader test-xiao-ota-bootloader-tools test-xiao-ota-boot-process test-nrf-unadmitted-boot-process qualify-xiao-ota-bootloader validate-xiao-stock-source build-xiao-stock-bootloader \
        build-xiao-ota-bootloader package-xiao-ota-bootloader \
        build-xiao-ota-bootloader-noswd package-xiao-ota-bootloader-noswd \
        sign-xiao-ota-image verify-xiao-ota-bootloader verify-xiao-ota-boot-info-artifacts \
        verify-ota-software clean-tmp

tmpdir:
	@mkdir -p $(TMPDIR)

## Full native unit-test suite (pre-existing tests plus OTA).
test: tmpdir test-ota-lab-host
	$(PLATFORMIO) test $(foreach e,$(NATIVE_TEST_ENVS),-e $(e))

## All OTA native and host tests.
test-ota: test-ota-lab-host test-ota-native

test-ota-native: tmpdir
	$(PLATFORMIO) test -e native $(foreach filter,$(OTA_TEST_FILTER),-f '$(filter)')

## Per-layer OTA tests, for fast iteration on a single scope.
test-ota-protocol: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_protocol'

test-ota-runtime: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_runtime'

test-ota-image-layout-index: OTA_TEST_FILTER = test_lora_ota_runtime test_lora_ota_storage test_lora_ota_boot
test-ota-image-layout-index: test-ota-index

test-ota-index: tmpdir
	@set -eu; \
	  tree="$$(git write-tree)"; \
	  work="$(TMPDIR)/ota-index/$$tree"; \
	  mkdir -p "$$work"; \
	  git archive "$$tree" | tar -x -C "$$work"; \
	  echo "==> qualifying prospective tree $$tree"; \
	  PLATFORMIO_LIBDEPS_DIR="$$work/.pio/libdeps" \
	  PLATFORMIO_BUILD_DIR="$$work/pio-build" \
	  $(MAKE) -C "$$work" TMPDIR="$$work/.tmp" \
	    PLATFORMIO="$(PLATFORMIO)" \
	    OTA_TEST_FILTER="$(OTA_TEST_FILTER)" $(OTA_INDEX_GOALS)

test-ota-storage: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_storage'

test-ota-trust: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_trust'

test-ota-boot: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_boot'

test-ota-integration: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_integration'

test-ota-lab-host: tmpdir
	python3 -m unittest discover -s scripts/tests -p '$(OTA_LAB_HOST_TEST_PATTERN)'

test-ota-lab-archive: tmpdir
	python3 -m unittest discover -s scripts/tests -p 'test_ota_lab_archive.py'

## Compile the OTA-capable firmware targets.
build-ota-targets: tmpdir
	@for env in $(OTA_TARGET_ENVS); do \
	  echo "==> building $$env"; \
	  $(PLATFORMIO) run -e $$env || exit 1; \
	done

build-ota-nrf52-targets: tmpdir
	@$(MAKE) --no-print-directory build-ota-targets OTA_TARGET_ENVS="$(OTA_NRF52_TARGET_ENVS)"

build-ota-esp32-targets: tmpdir
	@$(MAKE) --no-print-directory build-ota-targets OTA_TARGET_ENVS="$(OTA_ESP32_TARGET_ENVS)"

## Manual artifact inspection, not an installation or hardware rollback verdict.
inspect-xiao-s3-ota-bootloader: tmpdir
	@sha256sum "$(ESP32_OTA_BOOTLOADER_ELF)" "$(ESP32_OTA_SDK_DIR)/sdkconfig" \
	  "$(ESP32_OTA_BUILD_DIR)/$(ESP32_OTA_ENV)/bootloader.bin"
	@"$(ESP32_OTA_OBJDUMP)" -d --disassemble=bootloader_utility_get_selected_boot_partition \
	  "$(ESP32_OTA_BOOTLOADER_ELF)" > "$(TMPDIR)/xiao-s3-boot-selection.disasm"
	@cat "$(TMPDIR)/xiao-s3-boot-selection.disasm"

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
	@$(LAB_DEVICE) reset client --protocol "$(OTA_LAB_CLIENT_PROTOCOL)"
lab-reset-target:
	@$(LAB_DEVICE) reset target --protocol "$(OTA_LAB_TARGET_PROTOCOL)"
lab-reset-all: lab-reset-client lab-reset-target

## Enter the serial DFU bootloader (1200-baud touch).
lab-bootloader-client:
	@$(LAB_DEVICE) bootloader client
lab-bootloader-target:
	@$(LAB_DEVICE) bootloader target

## Enter vendor UF2 mode through the approved target's bench USB application.
lab-bootloader-uf2-target:
	@$(LAB_DEVICE) bootloader-uf2 target --timeout 30

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
	@for env in $(XIAO_NRF52_LAB_ENVS); do \
	  $(PLATFORMIO) run -e $$env -t clean || exit 1; \
	done
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

## Build distinct bench firmware without replacing inherited board or OTA flags.
build-xiao-nrf52-ota-candidate: tmpdir
	@test -n "$(XIAO_OTA_LAB_VERSION)" || \
	  { echo "Set XIAO_OTA_LAB_VERSION to an explicit candidate label (1..19 ASCII letters/digits/._-)." >&2; exit 1; }
	XIAO_OTA_LAB_VERSION="$(XIAO_OTA_LAB_VERSION)" $(PLATFORMIO) run -e "$(XIAO_NRF52_CANDIDATE_ENV)"

## Flash the companion client and repeater target. Both variants of the fragile
## PlatformIO upload path (app port and bootloader port) collapse into one
## deterministic command.
# Preserve an explicit legacy common-package override; defaults are role-specific.
XIAO_NRF52_LAB_PACKAGE ?=
XIAO_NRF52_CLIENT_PACKAGE ?= $(if $(strip $(XIAO_NRF52_LAB_PACKAGE)),$(XIAO_NRF52_LAB_PACKAGE),.pio/build/$(XIAO_NRF52_CLIENT_ENV)/firmware.zip)
XIAO_NRF52_TARGET_PACKAGE ?= $(if $(strip $(XIAO_NRF52_LAB_PACKAGE)),$(XIAO_NRF52_LAB_PACKAGE),.pio/build/$(XIAO_NRF52_TARGET_ENV)/firmware.zip)

upload-xiao-nrf52-client: build-xiao-nrf52-lab
	@$(MAKE) --no-print-directory flash-xiao-nrf52-client

upload-xiao-nrf52-target: build-xiao-nrf52-lab
	@$(MAKE) --no-print-directory flash-xiao-nrf52-target

upload-xiao-nrf52-lab: build-xiao-nrf52-lab
	@$(MAKE) --no-print-directory flash-xiao-nrf52-lab

## Flash an existing package without rebuilding the source.
flash-xiao-nrf52-client: tmpdir
	@mkdir -p $(OTA_LAB_ARTIFACT_DIR)
	@$(LAB_DEVICE) flash client --package "$(XIAO_NRF52_CLIENT_PACKAGE)" \
	  > $(OTA_LAB_ARTIFACT_DIR)/flash-client.log 2>&1; \
	  result=$$?; cat $(OTA_LAB_ARTIFACT_DIR)/flash-client.log; exit $$result

flash-xiao-nrf52-target: tmpdir
	@mkdir -p $(OTA_LAB_ARTIFACT_DIR)
	@$(LAB_DEVICE) flash target --package "$(XIAO_NRF52_TARGET_PACKAGE)" \
	  > $(OTA_LAB_ARTIFACT_DIR)/flash-target.log 2>&1; \
	  result=$$?; cat $(OTA_LAB_ARTIFACT_DIR)/flash-target.log; exit $$result

flash-xiao-nrf52-lab: flash-xiao-nrf52-client flash-xiao-nrf52-target

enter-xiao-nrf52-target-bootloader: tmpdir
	@$(LAB_DEVICE) bootloader target

configure-xiao-nrf52-ota-lab: tmpdir
	python3 scripts/ota_rf_lab.py --artifact-dir $(OTA_LAB_ARTIFACT_DIR) --configure-only \
	  --bandwidth-hz "$(OTA_LAB_BANDWIDTH_HZ)"

configure-xiao-nrf52-ota-client: tmpdir
	python3 scripts/ota_rf_lab.py --artifact-dir $(OTA_LAB_ARTIFACT_DIR) --client-only --configure-only \
	  --bandwidth-hz "$(OTA_LAB_BANDWIDTH_HZ)"

grant-xiao-nrf52-ota-client-admin: tmpdir
	@mkdir -p -- "$$(dirname -- "$(OTA_LAB_ARTIFACT_DIR)")"
	@mkdir -- "$(OTA_LAB_ARTIFACT_DIR)" || \
	  { echo "Set OTA_LAB_ARTIFACT_DIR to a new directory for the administrator grant" >&2; exit 1; }
	python3 scripts/ota_rf_lab.py --artifact-dir "$(OTA_LAB_ARTIFACT_DIR)" --grant-client-admin

inspect-xiao-nrf52-ota-preflight: tmpdir
	@mkdir -p -- "$$(dirname -- "$(OTA_LAB_ARTIFACT_DIR)")"
	@mkdir -- "$(OTA_LAB_ARTIFACT_DIR)" || \
	  { echo "Set OTA_LAB_ARTIFACT_DIR to a new directory for the preflight inspection" >&2; exit 1; }
	python3 scripts/ota_rf_lab.py --artifact-dir "$(OTA_LAB_ARTIFACT_DIR)" --inspect-ota-preflight \
	  $(if $(filter 1,$(OTA_LAB_REQUIRE_GENESIS_FLOOR)),--require-target-genesis-floor) \
	  $(if $(filter 1,$(OTA_LAB_REQUIRE_BOOT_ADDRESSES)),--require-target-boot-addresses)

inspect-xiao-nrf52-ota-configuration: tmpdir
	@mkdir -p -- "$$(dirname -- "$(OTA_LAB_ARTIFACT_DIR)")"
	@mkdir -- "$(OTA_LAB_ARTIFACT_DIR)" || \
	  { echo "Set OTA_LAB_ARTIFACT_DIR to a new directory for the configuration inspection" >&2; exit 1; }
	python3 scripts/ota_rf_lab.py --artifact-dir "$(OTA_LAB_ARTIFACT_DIR)" --inspect-configuration

monitor-xiao-nrf52-ota-lab: tmpdir
	python3 scripts/ota_rf_lab.py --artifact-dir $(OTA_LAB_ARTIFACT_DIR) --monitor-seconds $(OTA_LAB_MONITOR_SECONDS)

monitor-xiao-nrf52-ota-client: tmpdir
	python3 scripts/ota_rf_lab.py --artifact-dir $(OTA_LAB_ARTIFACT_DIR) --client-only --monitor-seconds $(OTA_LAB_MONITOR_SECONDS)

test-xiao-nrf52-ota-lab: tmpdir
	python3 scripts/ota_rf_lab.py --artifact-dir $(OTA_LAB_ARTIFACT_DIR)

## Signed uploader commands. Upload never commits; commit selects one full identity.
ota-lab-image:
	@test -n "$(OTA_UPLOAD_IMAGE)" || \
	  { echo "Set OTA_UPLOAD_IMAGE to a new raw application image path." >&2; exit 1; }
	$(LAB_DEVICE) extract-application --package "$(XIAO_NRF52_TARGET_PACKAGE)" \
	  --output "$(OTA_UPLOAD_IMAGE)"

ota-lab-manifest: tmpdir
	@test -n "$(OTA_UPLOAD_IMAGE)" && test -n "$(OTA_UPLOAD_MANIFEST)" && test -n "$(OTA_UPLOAD_COUNTER)" || \
	  { echo "Set OTA_UPLOAD_IMAGE, OTA_UPLOAD_MANIFEST and an explicit OTA_UPLOAD_COUNTER above the target's confirmed floor." >&2; exit 1; }
	python3 bootloader/xiao_nrf52840_ota/tools/build_manifest.py \
	  --image "$(OTA_UPLOAD_IMAGE)" --board "$(OTA_UPLOAD_BOARD)" \
	  --role-id "$(OTA_UPLOAD_ROLE_ID)" --counter "$(OTA_UPLOAD_COUNTER)" \
	  --output "$(OTA_UPLOAD_MANIFEST)"

ota-lab-upload: tmpdir
	$(OTA_UPLOAD_COMMAND) upload --image "$(OTA_UPLOAD_IMAGE)" --manifest "$(OTA_UPLOAD_MANIFEST)" \
	  $(foreach target,$(OTA_UPLOAD_TARGET),--target "$(target)") \
	  --mode "$(OTA_UPLOAD_MODE)" --channel "$(OTA_UPLOAD_CHANNEL)" \
	  --frequency-khz "$(OTA_UPLOAD_FREQ_KHZ)" --lease-ms "$(OTA_UPLOAD_LEASE_MS)" \
	  --duty-milli-percent "$(OTA_UPLOAD_DUTY_MILLI_PERCENT)" \
	  $(if $(filter 1,$(OTA_UPLOAD_REUPLOAD)),--reupload) \
	  $(if $(filter 1,$(OTA_UPLOAD_WAIT_READY)),--wait-ready)

ota-lab-status: tmpdir
	$(OTA_UPLOAD_COMMAND) status $(if $(strip $(OTA_UPLOAD_TARGET)),--target "$(OTA_UPLOAD_TARGET)")

ota-lab-commit: tmpdir
	$(OTA_UPLOAD_COMMAND) commit --target "$(OTA_UPLOAD_TARGET)" --manifest "$(OTA_UPLOAD_MANIFEST)"

ota-lab-abort: tmpdir
	$(OTA_UPLOAD_COMMAND) abort --target "$(OTA_UPLOAD_TARGET)" --image "$(OTA_UPLOAD_IMAGE)"

ota-lab-abort-cache: tmpdir
	$(OTA_UPLOAD_COMMAND) abort-cache --image "$(OTA_UPLOAD_IMAGE)"

ota-lab-admin: tmpdir
	$(OTA_UPLOAD_COMMAND) admin --target "$(OTA_UPLOAD_TARGET)" --enabled "$(OTA_UPLOAD_ADMIN_ENABLED)"

qualify-xiao-nrf52-normal-peer: tmpdir
	python3 scripts/ota_signed_lab.py --artifact-dir "$(OTA_LAB_ARTIFACT_DIR)" \
	  --timeout "$(OTA_SIGNED_LAB_TIMEOUT)" probe-peer --probe-timeout 30

qualify-xiao-nrf52-signed-stage: tmpdir
	python3 scripts/ota_signed_lab.py --artifact-dir "$(OTA_LAB_ARTIFACT_DIR)" \
	  --timeout "$(OTA_SIGNED_LAB_TIMEOUT)" stage \
	  --manifest "$(OTA_UPLOAD_MANIFEST)" --image "$(OTA_UPLOAD_IMAGE)" \
	  --image-sha256 "$(OTA_SIGNED_LAB_IMAGE_SHA256)" \
	  --counter "$(OTA_SIGNED_LAB_COUNTER)" \
	  --provenance "$(OTA_SIGNED_LAB_PROVENANCE)" \
	  --commissioning-evidence "$(OTA_SIGNED_LAB_COMMISSIONING)" \
	  --mode "$(OTA_SIGNED_LAB_MODE)" --channel "$(OTA_SIGNED_LAB_CHANNEL)" \
	  --duty-milli-percent "$(OTA_SIGNED_LAB_DUTY)" $(OTA_SIGNED_LAB_EXTRA)

qualify-xiao-nrf52-signed-commit: tmpdir
	python3 scripts/ota_signed_lab.py --artifact-dir "$(OTA_LAB_ARTIFACT_DIR)" \
	  --timeout "$(OTA_SIGNED_LAB_TIMEOUT)" commit --qualified-commit \
	  --ready-record "$(OTA_SIGNED_LAB_READY_RECORD)" \
	  --manifest "$(OTA_UPLOAD_MANIFEST)" --image "$(OTA_UPLOAD_IMAGE)" \
	  --image-sha256 "$(OTA_SIGNED_LAB_IMAGE_SHA256)" \
	  --counter "$(OTA_SIGNED_LAB_COUNTER)" \
	  --provenance "$(OTA_SIGNED_LAB_PROVENANCE)" \
	  --commissioning-evidence "$(OTA_SIGNED_LAB_COMMISSIONING)" \
	  --reboot-timeout "$(OTA_SIGNED_LAB_REBOOT_TIMEOUT)" \
	  --trial-timeout "$(OTA_SIGNED_LAB_TRIAL_TIMEOUT)" \
	  --install-timeout "$(OTA_SIGNED_LAB_INSTALL_TIMEOUT)"

build-xiao-nrf52-qspi-test: tmpdir
	$(PLATFORMIO) run -e $(XIAO_NRF52_QSPI_TEST_ENV)

build-xiao-nrf52-archive: tmpdir
	$(PLATFORMIO) run -e $(XIAO_NRF52_ARCHIVE_ENV)

generate-ota-lab-archive-key: tmpdir
	@test -n "$(OTA_LAB_ARCHIVE_KEY)" || \
	  { echo "Set OTA_LAB_ARCHIVE_KEY to a new local encryption-key path" >&2; exit 1; }
	python3 scripts/ota_lab_archive.py genkey --output "$(OTA_LAB_ARCHIVE_KEY)"

archive-xiao-nrf52-client: OTA_LAB_ARCHIVE_ROLE = client
archive-xiao-nrf52-target: OTA_LAB_ARCHIVE_ROLE = target
archive-xiao-nrf52-client archive-xiao-nrf52-target: archive-xiao-nrf52-device

archive-xiao-nrf52-device: tmpdir
	@test -n "$(OTA_LAB_ARCHIVE_KEY)" && test -n "$(OTA_LAB_ARCHIVE_FILE)" || \
	  { echo "Set OTA_LAB_ARCHIVE_KEY and OTA_LAB_ARCHIVE_FILE explicitly" >&2; exit 1; }
	python3 scripts/ota_lab_archive.py archive --role "$(OTA_LAB_ARCHIVE_ROLE)" \
	  --key-file "$(OTA_LAB_ARCHIVE_KEY)" --output "$(OTA_LAB_ARCHIVE_FILE)"

verify-xiao-nrf52-client-archive: OTA_LAB_ARCHIVE_ROLE = client
verify-xiao-nrf52-target-archive: OTA_LAB_ARCHIVE_ROLE = target
verify-xiao-nrf52-client-archive verify-xiao-nrf52-target-archive: verify-xiao-nrf52-archive

validate-xiao-nrf52-client-archive: OTA_LAB_ARCHIVE_ROLE = client
validate-xiao-nrf52-target-archive: OTA_LAB_ARCHIVE_ROLE = target
validate-xiao-nrf52-client-archive validate-xiao-nrf52-target-archive: validate-xiao-nrf52-archive

## Check preserved evidence without opening or replacing the running application.
validate-xiao-nrf52-archive:
	@test -n "$(OTA_LAB_ARCHIVE_KEY)" && test -n "$(OTA_LAB_ARCHIVE_FILE)" || \
	  { echo "Set OTA_LAB_ARCHIVE_KEY and OTA_LAB_ARCHIVE_FILE explicitly" >&2; exit 1; }
	python3 scripts/ota_lab_archive.py verify --validate-only --role "$(OTA_LAB_ARCHIVE_ROLE)" \
	  --key-file "$(OTA_LAB_ARCHIVE_KEY)" --archive "$(OTA_LAB_ARCHIVE_FILE)"

verify-xiao-nrf52-archive: tmpdir
	@test -n "$(OTA_LAB_ARCHIVE_KEY)" && test -n "$(OTA_LAB_ARCHIVE_FILE)" || \
	  { echo "Set OTA_LAB_ARCHIVE_KEY and OTA_LAB_ARCHIVE_FILE explicitly" >&2; exit 1; }
	python3 scripts/ota_lab_archive.py verify --role "$(OTA_LAB_ARCHIVE_ROLE)" \
	  --key-file "$(OTA_LAB_ARCHIVE_KEY)" --archive "$(OTA_LAB_ARCHIVE_FILE)"

upload-xiao-nrf52-qspi-test: build-xiao-nrf52-qspi-test
	@$(LAB_DEVICE) flash target --package .pio/build/$(XIAO_NRF52_QSPI_TEST_ENV)/firmware.zip

run-xiao-nrf52-qspi-test: tmpdir
	python3 tools/ota_qspi_hw_test.py --role target --output $(XIAO_NRF52_QSPI_EVIDENCE)

validate-xiao-nrf52-qspi-hardware: upload-xiao-nrf52-qspi-test run-xiao-nrf52-qspi-test
	@echo "QSPI hardware evidence: $(XIAO_NRF52_QSPI_EVIDENCE)"

fetch-xiao-ota-bootloader: tmpdir
	@if [ ! -d "$(XIAO_OTA_UPSTREAM)/.git" ]; then \
	  git clone --recursive https://github.com/adafruit/Adafruit_nRF52_Bootloader.git "$(XIAO_OTA_UPSTREAM)"; \
	fi
	@git -C "$(XIAO_OTA_UPSTREAM)" fetch --quiet origin "$(XIAO_OTA_PIN)"
	@git -C "$(XIAO_OTA_UPSTREAM)" checkout --quiet --detach "$(XIAO_OTA_PIN)"
	@git -C "$(XIAO_OTA_UPSTREAM)" submodule update --init --recursive --quiet
	@test "$$(git -C "$(XIAO_OTA_UPSTREAM)" rev-parse HEAD)" = "$(XIAO_OTA_PIN)"

## Offline test fixtures only; production signing stays on the companion.
generate-xiao-ota-fixture-key: tmpdir
	python3 bootloader/xiao_nrf52840_ota/tools/provision_lab_key.py

test-xiao-ota-bootloader-tools: tmpdir
	python3 bootloader/xiao_nrf52840_ota/tests/test_install_uf2.py
	python3 -m unittest discover -s bootloader/xiao_nrf52840_ota/tests -p 'test_tools.py'

## Package each board/role before running its native gate with real prepared metadata.
qualify-xiao-ota-bootloader: tmpdir
	@set -eu; \
	  for board in xiao_nrf52840 sensecap_solar_p1; do \
	    case "$$board" in \
	      xiao_nrf52840) target=XIAO_OTA_TARGET_XIAO_NRF52840 ;; \
	      sensecap_solar_p1) target=XIAO_OTA_TARGET_SENSECAP_SOLAR_P1 ;; \
	    esac; \
	    for role in 0 1; do \
	      echo "==> qualifying $$board role $$role"; \
	      $(MAKE) --no-print-directory package-xiao-ota-bootloader-noswd \
	        XIAO_OTA_BOARD="$$board" XIAO_OTA_ROLE_ID="$$role"; \
	      $(MAKE) --no-print-directory test-xiao-ota-bootloader \
	        XIAO_OTA_BOARD="$$board" XIAO_OTA_ROLE_ID="$$role" \
	        XIAO_OTA_TEST_BOARD_TARGET="$$target" OTA_REQUIRE_PREPARED_GHOSTFAT=1; \
	    done; \
	  done

test-xiao-ota-boot-process: tmpdir
	@mkdir -p "$(TMPDIR)/xiao-ota-host"
	$(CC) $(XIAO_OTA_BOOT_PROCESS_CFLAGS) \
	  $(XIAO_OTA_BOOT_PROCESS_SOURCES) \
	  bootloader/xiao_nrf52840_ota/tests/test_boot_process.c \
	  -o "$(TMPDIR)/xiao-ota-host/test_boot_process"
	"$(TMPDIR)/xiao-ota-host/test_boot_process"

test-nrf-unadmitted-boot-process: tmpdir
	@mkdir -p "$(TMPDIR)/rf-n1-boot-host"
	$(CC) $(XIAO_OTA_BOOT_PROCESS_CFLAGS) \
	  -DOTA_NRF_UNADMITTED_BOOT_PROCESS_TEST \
	  $(XIAO_OTA_BOOT_PROCESS_SOURCES) \
	  test/test_lora_ota_integration/test_nrf_unadmitted_boot_process.c \
	  -o "$(TMPDIR)/rf-n1-boot-host/test_nrf_unadmitted_boot_process"
	"$(TMPDIR)/rf-n1-boot-host/test_nrf_unadmitted_boot_process" $(if $(OTA_NRF_REMOTE_BOOT_PROOF_PREFIX),"$(OTA_NRF_REMOTE_BOOT_PROOF_PREFIX)")

test-ota-rf-to-boot: tmpdir
	@mkdir -p "$(TMPDIR)/ota-rf-to-boot"
	@set -eu; \
	  for family in 584e3430 53435031; do \
	    for role in 0 1; do \
	      for suffix in command candidate running sdk floor \
	        retired-candidate retired-canonical retired-command-region retired-floor \
	        retired-previous-command retired-running retired-sdk retired-state-region \
	        rollback-command rollback-candidate rollback-running rollback-sdk rollback-floor \
	        rollback-next-candidate rollback-next-canonical rollback-retained-command-region \
	        multi-rollback-command-a multi-rollback-command-b \
	        multi-rollback-candidate-a multi-rollback-candidate-b \
	        multi-rollback-running multi-rollback-sdk multi-rollback-floor \
	        multi-rollback-command-region multi-rollback-next-candidate multi-rollback-next-canonical \
	        original-command original-candidate original-running original-sdk original-floor original-state-region \
	        original-failed-command-region original-failed-state-region original-failed-running original-failed-sdk \
	        original-failed-nonzero-command-region original-failed-nonzero-state-region \
	        original-failed-nonzero-running original-failed-nonzero-sdk; do \
	        rm -f -- "$(abspath $(TMPDIR)/ota-rf-to-boot)/$$family-role$$role-$$suffix.bin"; \
	      done; \
	    done; \
	  done
	env -u GTEST_FILTER -u OTA_NRF_ORIGINAL_FAILED_PROOF_DIR \
	  OTA_NRF_REMOTE_BOOT_PROOF_DIR="$(abspath $(TMPDIR)/ota-rf-to-boot)" \
	  $(MAKE) --no-print-directory test-ota-integration
	@set -eu; \
	  for board in xiao_nrf52840 sensecap_solar_p1; do \
	    case "$$board" in \
	      xiao_nrf52840) target=XIAO_OTA_TARGET_XIAO_NRF52840; family=584e3430 ;; \
	      sensecap_solar_p1) target=XIAO_OTA_TARGET_SENSECAP_SOLAR_P1; family=53435031 ;; \
	    esac; \
	    for role in 0 1; do \
	      $(MAKE) --no-print-directory test-nrf-unadmitted-boot-process \
	        XIAO_OTA_TEST_BOARD_TARGET="$$target" XIAO_OTA_ROLE_ID="$$role" \
	        OTA_NRF_REMOTE_BOOT_PROOF_PREFIX="$(abspath $(TMPDIR)/ota-rf-to-boot)/$$family-role$$role"; \
	    done; \
	  done
	@rm -f -- "$(abspath $(TMPDIR)/ota-rf-to-boot/consumer.json)"
	env -u OTA_NRF_REMOTE_BOOT_PROOF_DIR \
	  GTEST_FILTER='LoraOtaQualifiedOriginal.FullColdFailedMaxBothSdkPoliciesRestoreAfterCommandReplacementAndBindNextCommit' \
	  GTEST_OUTPUT="json:$(abspath $(TMPDIR)/ota-rf-to-boot/consumer.json)" \
	  OTA_NRF_ORIGINAL_FAILED_PROOF_DIR="$(abspath $(TMPDIR)/ota-rf-to-boot)" \
	  $(MAKE) --no-print-directory test-ota-integration
	@# Google Test accepts an empty filter; require the actual returned-proof test.
	@python3 -c 'import json, sys; report = json.load(open(sys.argv[1])); cases = [case for suite in report["testsuites"] for case in suite["testsuite"]]; valid = report["tests"] == 1 and report["failures"] == 0 and len(cases) == 1 and cases[0]["status"] == "RUN" and cases[0]["result"] == "COMPLETED"; sys.exit(0 if valid else "Returned FailedMax proof did not execute exactly one complete passing test")' "$(abspath $(TMPDIR)/ota-rf-to-boot/consumer.json)"

test-xiao-ota-bootloader: tmpdir test-xiao-ota-bootloader-tools test-xiao-ota-boot-process
	@mkdir -p "$(TMPDIR)/xiao-ota-host"
	$(CC) -std=c11 -Wall -Wextra -Werror \
	  -Ibootloader/xiao_nrf52840_ota/include \
	  -Ibootloader/xiao_nrf52840_ota/src \
	  -DXIAO_OTA_COMPILED_ROLE_ID="$(XIAO_OTA_ROLE_ID)" \
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
	$(CC) -std=c11 -O2 -ffunction-sections -fdata-sections \
	  -Wall -Wextra -Werror \
	  -Ibootloader/xiao_nrf52840_ota/include \
	  -Ibootloader/xiao_nrf52840_ota/third_party/tweetnacl \
	  -DXIAO_OTA_COMPILED_ROLE_ID="$(XIAO_OTA_ROLE_ID)" \
	  bootloader/xiao_nrf52840_ota/src/xiao_ota_record.c \
	  bootloader/xiao_nrf52840_ota/src/xiao_ota_ed25519_tweetnacl.c \
	  bootloader/xiao_nrf52840_ota/third_party/tweetnacl/tweetnacl.c \
	  bootloader/xiao_nrf52840_ota/tests/test_descriptor_contract.c \
	  -Wno-unused-function -Wno-sign-compare -Wno-shadow \
	  -Wno-unterminated-string-initialization \
	  -Wl,--gc-sections \
	  -o "$(TMPDIR)/xiao-ota-host/test_descriptor_contract"
	"$(TMPDIR)/xiao-ota-host/test_descriptor_contract"
	$(CC) -std=c11 -Wall -Wextra -Werror \
	  -Ibootloader/xiao_nrf52840_ota/include \
	  -Ibootloader/xiao_nrf52840_ota/src \
	  -DXIAO_OTA_COMPILED_ROLE_ID="$(XIAO_OTA_ROLE_ID)" \
	  bootloader/xiao_nrf52840_ota/src/xiao_ota_record.c \
	  bootloader/xiao_nrf52840_ota/src/xiao_ota_boot_info.c \
	  bootloader/xiao_nrf52840_ota/tests/test_boot_info.c \
	  -o "$(TMPDIR)/xiao-ota-host/test_boot_info"
	"$(TMPDIR)/xiao-ota-host/test_boot_info"
	python3 bootloader/xiao_nrf52840_ota/tests/test_source.py

validate-xiao-stock-source: fetch-xiao-ota-bootloader
	@test "$$(git -C "$(XIAO_OTA_UPSTREAM)" rev-parse HEAD)" = "$(XIAO_OTA_PIN)" || \
	  { echo "Public stock source pin mismatch" >&2; exit 1; }
	@test -z "$$(git -C "$(XIAO_OTA_UPSTREAM)" status --porcelain --untracked-files=all)" || \
	  { echo "Public stock source or submodules contain non-stock changes" >&2; exit 1; }

build-xiao-stock-bootloader: validate-xiao-stock-source
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
	python3 bootloader/xiao_nrf52840_ota/tools/prepare_upstream.py --board "$(XIAO_OTA_BOARD)" --role-id "$(XIAO_OTA_ROLE_ID)" --source-dir "$(XIAO_OTA_UPSTREAM)" --work-dir "$(XIAO_OTA_WORK)"
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
	  "$(XIAO_OTA_ARTIFACTS)/custom/$(XIAO_OTA_STEM)_nosd.hex"
	@cp "$$(find "$(XIAO_OTA_WORK)/_build/build-xiao_nrf52840_ble" -maxdepth 1 -name 'update-*_nosd.uf2' | head -1)" \
	  "$(XIAO_OTA_ARTIFACTS)/custom/$(XIAO_OTA_STEM)_update.uf2"
	$(VERIFY_OTA_BOOT_INFO) "$(XIAO_OTA_ARTIFACTS)/custom/$(XIAO_OTA_STEM)_nosd.hex"
	$(VERIFY_OTA_BOOT_INFO) "$(XIAO_OTA_ARTIFACTS)/custom/$(XIAO_OTA_STEM)_update.uf2"
	@sha256sum "$(XIAO_OTA_ARTIFACTS)"/custom/*

build-xiao-ota-bootloader-noswd: fetch-xiao-ota-bootloader
	python3 bootloader/xiao_nrf52840_ota/tools/prepare_upstream.py --no-ble --board "$(XIAO_OTA_BOARD)" --role-id "$(XIAO_OTA_ROLE_ID)" --source-dir "$(XIAO_OTA_UPSTREAM)" --work-dir "$(XIAO_OTA_NOSWD_WORK)"
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
	  "$(XIAO_OTA_ARTIFACTS)/custom-noswd/$(XIAO_OTA_STEM)_noswd.hex"
	@cp "$$(find "$(XIAO_OTA_NOSWD_WORK)/_build/build-xiao_nrf52840_ble" -maxdepth 1 -name 'update-*_nosd.uf2' | head -1)" \
	  "$(XIAO_OTA_ARTIFACTS)/custom-noswd/$(XIAO_OTA_STEM)_noswd_update.uf2"
	@cp "$$(find "$(XIAO_OTA_NOSWD_WORK)/_build/build-xiao_nrf52840_ble" -maxdepth 1 -name '*.out.map' | head -1)" \
	  "$(XIAO_OTA_ARTIFACTS)/custom-noswd/$(XIAO_OTA_STEM)_noswd.map"
	@cp "$$(find "$(XIAO_OTA_NOSWD_WORK)/_build/build-xiao_nrf52840_ble" -maxdepth 1 -name '*.out' | head -1)" \
	  "$(XIAO_OTA_ARTIFACTS)/custom-noswd/$(XIAO_OTA_STEM)_noswd.elf"
	@arm-none-eabi-objdump -h "$(XIAO_OTA_ARTIFACTS)/custom-noswd/$(XIAO_OTA_STEM)_noswd.elf" \
	  > "$(XIAO_OTA_ARTIFACTS)/custom-noswd/$(XIAO_OTA_STEM)_noswd.sections"
	$(VERIFY_OTA_BOOT_INFO) "$(XIAO_OTA_ARTIFACTS)/custom-noswd/$(XIAO_OTA_STEM)_noswd.hex"
	$(VERIFY_OTA_BOOT_INFO) "$(XIAO_OTA_ARTIFACTS)/custom-noswd/$(XIAO_OTA_STEM)_noswd_update.uf2"
	$(VERIFY_OTA_INSTALL_ARTIFACT) --artifact "$(XIAO_OTA_ARTIFACTS)/custom-noswd/$(XIAO_OTA_STEM)_noswd_update.uf2"
	@sha256sum "$(XIAO_OTA_ARTIFACTS)"/custom-noswd/*

## Install only the packaged no-SWD custom bootloader UF2 on the authorized XIAO.
## Put the board in XIAO-BOOT mode first; this target never selects a ttyACM path.
install-xiao-nrf52-target-ota-bootloader: XIAO_OTA_ROLE_ID = 1
install-xiao-nrf52-target-ota-bootloader: package-xiao-ota-bootloader-noswd
	@$(MAKE) --no-print-directory flash-xiao-nrf52-target-ota-bootloader \
	  XIAO_OTA_BOARD="$(XIAO_OTA_BOARD)" XIAO_OTA_ROLE_ID="$(XIAO_OTA_ROLE_ID)" \
	  XIAO_NRF52_TARGET_OTA_BOOTLOADER_PACKAGE="$(XIAO_NRF52_TARGET_OTA_BOOTLOADER_PACKAGE)"

## Flash an existing bootloader package only after artifact-only validation.
flash-xiao-nrf52-target-ota-bootloader: XIAO_OTA_ROLE_ID = 1
flash-xiao-nrf52-target-ota-bootloader: tmpdir
	@if [ "$(XIAO_OTA_BOARD)" != xiao_nrf52840 ]; then \
	  echo "refusing non-XIAO bootloader profile on the authorized XIAO target" >&2; exit 1; \
	fi
	@if [ "$(XIAO_OTA_ROLE_ID)" != 1 ]; then \
	  echo "refusing non-repeater bootloader profile on the authorized repeater target" >&2; exit 1; \
	fi
	$(VERIFY_OTA_INSTALL_ARTIFACT) --artifact "$(XIAO_NRF52_TARGET_OTA_BOOTLOADER_PACKAGE)"
	python3 bootloader/xiao_nrf52840_ota/tools/install_uf2.py \
	  --serial "$(XIAO_NRF52_TARGET_SERIAL)" \
	  --boot-port "$(XIAO_NRF52_BOOT_PORT)" \
	  --board "$(XIAO_OTA_BOARD)" \
	  --role-id "$(XIAO_OTA_ROLE_ID)" \
	  --artifact "$(XIAO_NRF52_TARGET_OTA_BOOTLOADER_PACKAGE)"

verify-xiao-ota-boot-info-artifacts: tmpdir
	$(VERIFY_OTA_BOOT_INFO) "$(XIAO_OTA_ARTIFACTS)/custom-noswd/$(XIAO_OTA_STEM)_noswd.hex"
	$(VERIFY_OTA_BOOT_INFO) "$(XIAO_OTA_ARTIFACTS)/custom-noswd/$(XIAO_OTA_STEM)_noswd_update.uf2"
	$(VERIFY_OTA_INSTALL_ARTIFACT) --artifact "$(XIAO_OTA_ARTIFACTS)/custom-noswd/$(XIAO_OTA_STEM)_noswd_update.uf2"

sign-xiao-ota-image: tmpdir
	@test -n "$(XIAO_OTA_IMAGE)" && test -n "$(XIAO_OTA_ACTIVE_IMAGE)"
	@test -r "$(XIAO_OTA_PRIVATE_KEY)" || \
	  { echo "Set XIAO_OTA_PRIVATE_KEY to an explicit offline fixture-signing key; no key is generated or compiled into the loader." >&2; exit 1; }
	python3 bootloader/xiao_nrf52840_ota/tools/sign_image.py \
	  --image "$(XIAO_OTA_IMAGE)" --active-image "$(XIAO_OTA_ACTIVE_IMAGE)" \
	  --private-key "$(XIAO_OTA_PRIVATE_KEY)" --counter "$(XIAO_OTA_COUNTER)" \
	  --board "$(XIAO_OTA_BOARD)" \
	  --role-id "$(XIAO_OTA_ROLE_ID)" \
	  --output-dir "$(XIAO_OTA_ARTIFACTS)/signed-counter-$(XIAO_OTA_COUNTER)"

verify-xiao-ota-bootloader: test-xiao-ota-bootloader package-xiao-ota-bootloader package-xiao-ota-bootloader-noswd
	@echo "XIAO OTA bootloader host tests, 66-KiB fallback, 38-KiB no-SWD link, maps, HEX and UF2 passed."

## Software-level qualification only.
## Passing this gate means the native tests pass and the OTA-enabled and
## non-OTA firmware targets link. It does NOT mean a device can be updated:
## on-device radio behaviour, real flash writes, the custom nRF52840
## QSPI-aware bootloader, trusted boot, the anti-rollback counter backend and
## power-loss rollback all remain hardware acceptance gates.
verify-ota-software: test test-ota-rf-to-boot build-ota-nrf52-targets build-ota-esp32-targets build-non-ota-targets
	@echo
	@echo "OTA software checks passed: native tests green, firmware targets link."
	@echo "NOT qualified here: on-device radio, flash, bootloader, anti-rollback, rollback."

clean-tmp:
	@echo "Refusing to delete shared TMPDIR: $(TMPDIR). Remove only explicitly owned scratch paths." >&2
	@exit 1
