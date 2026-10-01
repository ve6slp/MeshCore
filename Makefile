PLATFORMIO ?= pio

# Keep build/test scratch inside the repo. The system /tmp is a small
# memory-backed tmpfs and cannot hold toolchain intermediates.
TMPDIR := $(CURDIR)/.tmp
export TMPDIR
export TEMP = $(TMPDIR)
export TMP = $(TMPDIR)

NATIVE_TEST_ENVS ?= native native_kiss_modem

OTA_TEST_FILTER ?= test_lora_ota_*
OTA_INDEX_GOALS ?= test-ota
OTA_CRYPTO_ENV ?= Xiao_nrf52_companion_radio_usb
OTA_CRYPTO_LIBRARY ?= $(CURDIR)/.pio/libdeps/$(OTA_CRYPTO_ENV)/Crypto
OTA_TARGET_ENVS ?= SenseCap_Solar_companion_radio_usb Xiao_S3_WIO_companion_radio_usb
OTA_NRF52_TARGET_ENVS ?= Xiao_nrf52_companion_radio_usb SenseCap_Solar_companion_radio_usb Xiao_nrf52_repeater_ota_usb SenseCap_Solar_repeater_ota_usb
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
OTA_BOOT_CATALOGUE_HEADER ?= src/ota/platform/Nrf52ApprovedBootCatalogue.h
OTA_BOOT_CATALOGUE_PROVENANCE ?= $(XIAO_OTA_ARTIFACTS)/stock/nrf52-boot-catalogue.provenance.json
OTA_BOOT_CATALOGUE_CUSTOM_MANIFEST ?=
XIAO_OTA_PRIVATE_KEY ?= $(TMPDIR)/xiao-ota-keys/lab-ed25519-private.pem
XIAO_OTA_IMAGE ?=
XIAO_OTA_ACTIVE_IMAGE ?=
XIAO_OTA_COUNTER ?= 1
XIAO_OTA_COMMAND_VERSION ?= 2
XIAO_OTA_BOARD ?= xiao_nrf52840
XIAO_OTA_ROLE_ID ?= 0
XIAO_OTA_ROLE_SUFFIX = $(if $(filter 0,$(XIAO_OTA_ROLE_ID)),,_role$(XIAO_OTA_ROLE_ID))
XIAO_OTA_TEST_BOARD_TARGET ?= XIAO_OTA_TARGET_XIAO_NRF52840
XIAO_OTA_STEM = $(XIAO_OTA_BOARD)_ota$(XIAO_OTA_ROLE_SUFFIX)
VERIFY_OTA_BOOT_INFO = python3 bootloader/xiao_nrf52840_ota/tools/verify_boot_info_artifact.py \
	--board "$(XIAO_OTA_BOARD)" --role-id "$(XIAO_OTA_ROLE_ID)" --key-header bootloader/xiao_nrf52840_ota/include/xiao_ota_public_key.h
VERIFY_OTA_INSTALL_ARTIFACT = python3 bootloader/xiao_nrf52840_ota/tools/install_uf2.py \
	--validate-only --board "$(XIAO_OTA_BOARD)" --role-id "$(XIAO_OTA_ROLE_ID)" --key-header bootloader/xiao_nrf52840_ota/include/xiao_ota_public_key.h
OTA_LAB_ARTIFACT_DIR ?= $(TMPDIR)/ota-rf-lab/$(shell date -u +%Y%m%dT%H%M%SZ)
OTA_LAB_DUTY_TIMEOUT ?= 420
OTA_LAB_MONITOR_SECONDS ?= 60
OTA_BOOT_PREFLIGHT_DIR ?= $(TMPDIR)/ota-boot-preflight/$(shell date -u +%Y%m%dT%H%M%SZ)

# Representative non-OTA targets, used to prove the OTA build-filter and
# platformio.ini changes did not regress platforms that never enable OTA.
NON_OTA_TARGET_ENVS ?= Heltec_v3_repeater RAK_4631_repeater

.PHONY: tmpdir test test-ota test-ota-index test-ota-protocol test-ota-runtime \
        test-ota-counter-ports-index test-ota-image-layout-index test-ota-storage \
        test-ota-authority test-ota-authority-registry test-ota-security-store test-ota-maintenance test-ota-maintenance-host test-ota-boot-catalogue generate-ota-boot-catalogue generate-ota-boot-catalogue-custom \
        test-ota-trust test-ota-boot test-ota-integration test-ota-campaign test-ota-lab-host test-ota-lab-archive test-ota-aead-cipher clean-ota-targets \
        lab-devices lab-doctor lab-reset-client lab-reset-target lab-reset-all \
        lab-bootloader-client lab-bootloader-target \
        lab-power-cycle-client lab-power-cycle-target lab-power-cycle-all \
        lab-wait-client lab-wait-target \
        build-ota-targets build-ota-nrf52-targets build-ota-baseline-targets build-non-ota-targets \
        clean-xiao-nrf52-lab build-xiao-nrf52-lab build-xiao-nrf52-ota-lab upload-xiao-nrf52-client upload-xiao-nrf52-target upload-xiao-nrf52-lab \
        flash-xiao-nrf52-client flash-xiao-nrf52-target flash-xiao-nrf52-lab \
        enter-xiao-nrf52-target-bootloader \
        install-xiao-nrf52-target-ota-bootloader \
        configure-xiao-nrf52-ota-lab configure-xiao-nrf52-ota-client \
        monitor-xiao-nrf52-ota-lab monitor-xiao-nrf52-ota-client test-xiao-nrf52-ota-lab test-xiao-nrf52-ota-stage test-xiao-nrf52-ota-airtime \
        inspect-xiao-nrf52-boot-journal clean-xiao-nrf52-legacy-floor \
        build-xiao-nrf52-qspi-test upload-xiao-nrf52-qspi-test \
        run-xiao-nrf52-qspi-test validate-xiao-nrf52-qspi-hardware \
        build-xiao-nrf52-archive generate-ota-lab-archive-key \
        archive-xiao-nrf52-device archive-xiao-nrf52-client archive-xiao-nrf52-target \
        verify-xiao-nrf52-archive verify-xiao-nrf52-client-archive verify-xiao-nrf52-target-archive \
        fetch-xiao-ota-bootloader provision-xiao-ota-lab-key \
        test-xiao-ota-bootloader test-xiao-ota-bootloader-tools test-xiao-ota-boot-process qualify-xiao-ota-bootloader validate-xiao-stock-source build-xiao-stock-bootloader \
        build-xiao-ota-bootloader package-xiao-ota-bootloader \
        build-xiao-ota-bootloader-noswd package-xiao-ota-bootloader-noswd \
        sign-xiao-ota-image verify-xiao-ota-bootloader verify-xiao-ota-boot-info-artifacts \
        verify-ota-software clean-tmp

tmpdir:
	@mkdir -p $(TMPDIR)

## Full native unit-test suite (pre-existing tests plus OTA).
test: tmpdir test-ota-lab-host test-ota-aead-cipher
	$(PLATFORMIO) test $(foreach e,$(NATIVE_TEST_ENVS),-e $(e))

## All OTA native tests.
test-ota: tmpdir test-ota-lab-host test-ota-aead-cipher
	$(PLATFORMIO) test -e native $(foreach filter,$(OTA_TEST_FILTER),-f '$(filter)')

## Per-layer OTA tests, for fast iteration on a single scope.
test-ota-protocol: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_protocol'

test-ota-maintenance: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_protocol' -f 'test_lora_ota_maintenance'

test-ota-runtime: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_runtime'

test-ota-counter-ports-index: OTA_INDEX_GOALS = test-ota-runtime test-ota-aead-cipher test-ota-lab-host
test-ota-counter-ports-index: test-ota-index

test-ota-image-layout-index: OTA_TEST_FILTER = test_lora_ota_runtime test_lora_ota_storage test_lora_ota_boot
test-ota-image-layout-index: test-ota-index

test-ota-index: tmpdir
	@set -eu; \
	  tree="$$(git write-tree)"; \
	  work="$(TMPDIR)/ota-index/$$tree"; \
	  mkdir -p "$$work"; \
	  git archive "$$tree" | tar -x -C "$$work"; \
	  echo "==> qualifying prospective tree $$tree"; \
	  PLATFORMIO_LIBDEPS_DIR="$(CURDIR)/.pio/libdeps" \
	  PLATFORMIO_BUILD_DIR="$$work/pio-build" \
	  $(MAKE) -C "$$work" TMPDIR="$$work/.tmp" \
	    PLATFORMIO="$(PLATFORMIO)" OTA_CRYPTO_LIBRARY="$(OTA_CRYPTO_LIBRARY)" \
	    OTA_TEST_FILTER="$(OTA_TEST_FILTER)" $(OTA_INDEX_GOALS)

test-ota-storage: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_storage'

test-ota-trust: tmpdir test-ota-aead-cipher
	$(PLATFORMIO) test -e native -f 'test_lora_ota_trust'

test-ota-aead-cipher: tmpdir
	@test -f "$(OTA_CRYPTO_LIBRARY)/ChaChaPoly.h" || \
	  { echo "Missing Crypto dependency: run $(PLATFORMIO) pkg install -e $(OTA_CRYPTO_ENV)" >&2; exit 1; }
	@mkdir -p "$(TMPDIR)/ota-crypto-host"
	$(CXX) -std=c++17 -O2 -Wall -Wextra -Werror -UNDEBUG \
	  -Isrc -I"$(OTA_CRYPTO_LIBRARY)" -DMESHCORE_OTA_CRYPTO_NATIVE=1 \
	  test/test_lora_ota_trust/test_aead_cipher.cpp \
	  $(foreach source,ChaChaPoly ChaCha Poly1305 AuthenticatedCipher Cipher Crypto,"$(OTA_CRYPTO_LIBRARY)/$(source).cpp") \
	  -o "$(TMPDIR)/ota-crypto-host/test_aead_cipher"
	"$(TMPDIR)/ota-crypto-host/test_aead_cipher"

test-ota-boot: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_boot'

test-ota-integration: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_integration'

test-ota-campaign: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_campaign'

test-ota-authority: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_authority'

test-ota-authority-registry: tmpdir
	python3 -m unittest discover -s scripts/tests -p 'test_ota_authority_registry.py'

test-ota-maintenance-host: tmpdir
	python3 -m unittest discover -s scripts/tests -p 'test_ota_maintenance_protocol.py'

test-ota-boot-catalogue: tmpdir
	python3 -m unittest discover -s scripts/tests -p 'test_ota_boot_catalogue.py'

## Rebuild the unmodified public pin before deriving approval bytes.
generate-ota-boot-catalogue: build-xiao-stock-bootloader
	@set -eu; \
	  upstream="$(XIAO_OTA_UPSTREAM)"; \
	  stage="$$(mktemp -d "$(TMPDIR)/ota-boot-catalogue-generation.XXXXXX")"; \
	  test -e "$$upstream/.git" || { echo "Missing public stock source checkout: $$upstream" >&2; exit 1; }; \
	  test "$$(git -C "$$upstream" rev-parse HEAD)" = "$(XIAO_OTA_PIN)" || { echo "Public stock source pin mismatch" >&2; exit 1; }; \
	  test -z "$$(git -C "$$upstream" status --porcelain --untracked-files=no)" || { echo "Public stock source or submodules are modified" >&2; exit 1; }; \
	  out="$$( $(MAKE) -s --no-print-directory -C "$$upstream" BOARD=xiao_nrf52840_ble print-OUT_NAME | sed 's/^OUT_NAME = //' )"; \
	  cc="$$( $(MAKE) -s --no-print-directory -C "$$upstream" BOARD=xiao_nrf52840_ble print-CC | sed 's/^CC = //' )"; \
	  test "$$cc" = arm-none-eabi-gcc || { echo "Unsupported public stock compiler: $$cc" >&2; exit 1; }; \
	  mbr="$$( $(MAKE) -s --no-print-directory -C "$$upstream" BOARD=xiao_nrf52840_ble print-MBR_HEX | sed 's/^MBR_HEX = //' )"; \
	  sd="$$( $(MAKE) -s --no-print-directory -C "$$upstream" BOARD=xiao_nrf52840_ble print-SD_HEX | sed 's/^SD_HEX = //' )"; \
	  elf="_build/build-xiao_nrf52840_ble/$${out}.out"; \
	  cflags="$$( $(MAKE) -s --no-print-directory -C "$$upstream" BOARD=xiao_nrf52840_ble print-CFLAGS | sed 's/^CFLAGS = //' )"; \
	  asflags="$$( $(MAKE) -s --no-print-directory -C "$$upstream" BOARD=xiao_nrf52840_ble print-ASFLAGS | sed 's/^ASFLAGS = //' )"; \
	  includes="$$( $(MAKE) -s --no-print-directory -C "$$upstream" BOARD=xiao_nrf52840_ble print-INC_PATHS | sed 's/^INC_PATHS = //' )"; \
	  ldflags="$$( $(MAKE) -s --no-print-directory -C "$$upstream" BOARD=xiao_nrf52840_ble print-LDFLAGS | sed 's/^LDFLAGS = //' | sed "s@-Wl,-Map=print-LDFLAGS.map@-Wl,-Map=$${elf}.map@" )"; \
	  set -- python3 scripts/ota_boot_catalogue.py \
	    --mbr-hex "$$upstream/$$mbr" --softdevice-hex "$$upstream/$$sd" \
	    --stock-hex "$$upstream/_build/build-xiao_nrf52840_ble/$${out}_nosd.hex" \
	    --stock-elf "$$upstream/$$elf" \
	    --board xiao_nrf52840_ble --out-name "$$out" \
	    --toolchain "$$(arm-none-eabi-gcc --version | head -n 1)" \
	    --source-date-epoch "$(XIAO_OTA_SOURCE_DATE_EPOCH)" \
	    --submodule-pin "Adafruit_nRF52_Bootloader=$(XIAO_OTA_PIN)" \
	    --build-option "BOARD=xiao_nrf52840_ble" \
	    --build-option "SOURCE_DATE_EPOCH=$(XIAO_OTA_SOURCE_DATE_EPOCH)" \
	    --build-option "CFLAGS=$$cflags" --build-option "ASFLAGS=$$asflags" \
	    --build-option "INC_PATHS=$$includes" --build-option "LDFLAGS=$$ldflags" \
	    --out-header "$$stage/Nrf52ApprovedBootCatalogue.h" \
	    --out-provenance "$$stage/provenance.json"; \
	  for name in nrfx tinycrypt tinyusb uf2; do \
	    set -- "$$@" --submodule-pin "$$name=$$(git -C "$$upstream/lib/$$name" rev-parse HEAD)"; \
	  done; \
	  if [ -n "$(OTA_BOOT_CATALOGUE_CUSTOM_MANIFEST)" ]; then \
	    set -- "$$@" --custom-manifest "$(OTA_BOOT_CATALOGUE_CUSTOM_MANIFEST)"; \
	  fi; \
	  "$$@"; \
	  test -s "$$stage/Nrf52ApprovedBootCatalogue.h" && test -s "$$stage/provenance.json"; \
	  mkdir -p "$$(dirname "$(OTA_BOOT_CATALOGUE_HEADER)")" "$$(dirname "$(OTA_BOOT_CATALOGUE_PROVENANCE)")"; \
	  header_tmp="$$(mktemp "$(OTA_BOOT_CATALOGUE_HEADER).XXXXXX")"; \
	  provenance_tmp="$$(mktemp "$(OTA_BOOT_CATALOGUE_PROVENANCE).XXXXXX")"; \
	  cp "$$stage/Nrf52ApprovedBootCatalogue.h" "$$header_tmp"; \
	  cp "$$stage/provenance.json" "$$provenance_tmp"; \
	  chmod 644 "$$header_tmp" "$$provenance_tmp"; \
	  mv -f "$$provenance_tmp" "$(OTA_BOOT_CATALOGUE_PROVENANCE)"; \
	  mv -f "$$header_tmp" "$(OTA_BOOT_CATALOGUE_HEADER)"

generate-ota-boot-catalogue-custom: tmpdir
	@test -n "$(OTA_BOOT_CATALOGUE_CUSTOM_MANIFEST)" && test -f "$(OTA_BOOT_CATALOGUE_CUSTOM_MANIFEST)" || \
	  { echo "Set OTA_BOOT_CATALOGUE_CUSTOM_MANIFEST to the qualified four-build descriptor manifest" >&2; exit 1; }
	@$(MAKE) --no-print-directory generate-ota-boot-catalogue

test-ota-security-store: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_security_store'

test-ota-lab-host: tmpdir
	python3 -m unittest discover -s scripts/tests -p 'test_*.py'

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
	@$(MAKE) --no-print-directory flash-xiao-nrf52-client

upload-xiao-nrf52-target: build-xiao-nrf52-lab
	@$(MAKE) --no-print-directory flash-xiao-nrf52-target

upload-xiao-nrf52-lab: upload-xiao-nrf52-client upload-xiao-nrf52-target

## Flash an existing package without rebuilding the source.
flash-xiao-nrf52-client: tmpdir
	@mkdir -p $(OTA_LAB_ARTIFACT_DIR)
	@$(LAB_DEVICE) flash client --package "$(XIAO_NRF52_LAB_PACKAGE)" \
	  > $(OTA_LAB_ARTIFACT_DIR)/flash-client.log 2>&1; \
	  result=$$?; cat $(OTA_LAB_ARTIFACT_DIR)/flash-client.log; exit $$result

flash-xiao-nrf52-target: tmpdir
	@mkdir -p $(OTA_LAB_ARTIFACT_DIR)
	@$(LAB_DEVICE) flash target --package "$(XIAO_NRF52_LAB_PACKAGE)" \
	  > $(OTA_LAB_ARTIFACT_DIR)/flash-target.log 2>&1; \
	  result=$$?; cat $(OTA_LAB_ARTIFACT_DIR)/flash-target.log; exit $$result

flash-xiao-nrf52-lab: flash-xiao-nrf52-client flash-xiao-nrf52-target

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

test-xiao-nrf52-ota-stage: tmpdir
	python3 scripts/ota_rf_lab.py --artifact-dir $(OTA_LAB_ARTIFACT_DIR) --staging-only

test-xiao-nrf52-ota-airtime: tmpdir
	python3 scripts/ota_rf_lab.py --artifact-dir $(OTA_LAB_ARTIFACT_DIR) --airtime-only --duty-timeout $(OTA_LAB_DUTY_TIMEOUT)

inspect-xiao-nrf52-boot-journal: tmpdir
	python3 scripts/ota_boot_preflight.py --artifact-dir "$(OTA_BOOT_PREFLIGHT_DIR)"

clean-xiao-nrf52-legacy-floor: tmpdir
	python3 scripts/ota_boot_preflight.py --artifact-dir "$(OTA_BOOT_PREFLIGHT_DIR)" --erase-known-residue

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

provision-xiao-ota-lab-key: tmpdir
	python3 bootloader/xiao_nrf52840_ota/tools/provision_lab_key.py --board "$(XIAO_OTA_BOARD)"

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
	$(CC) -std=c11 -O2 -Wall -Wextra -Werror \
	  -Ibootloader/xiao_nrf52840_ota/include \
	  -Ibootloader/xiao_nrf52840_ota/src \
	  -Ibootloader/xiao_nrf52840_ota/third_party/tweetnacl \
	  -Ibootloader/xiao_nrf52840_ota/tests \
	  -Isrc/ota/trust/third_party/ed25519 \
	  -DXIAO_OTA_BOARD_TARGET="$(XIAO_OTA_TEST_BOARD_TARGET)" \
	  -DXIAO_OTA_COMPILED_ROLE_ID="$(XIAO_OTA_ROLE_ID)" \
	  -DXIAO_OTA_TRUST_ANCHOR_PUBLIC_KEY=xiao_ota_test_public_key_ed25519 \
	  -include bootloader/xiao_nrf52840_ota/tests/fake_trust_anchor.h \
	  bootloader/xiao_nrf52840_ota/src/xiao_ota_boot_io.c \
	  bootloader/xiao_nrf52840_ota/src/xiao_ota_record.c \
	  bootloader/xiao_nrf52840_ota/src/xiao_ota_sha256.c \
	  bootloader/xiao_nrf52840_ota/src/xiao_ota_ed25519_tweetnacl.c \
	  bootloader/xiao_nrf52840_ota/third_party/tweetnacl/tweetnacl.c \
	  bootloader/xiao_nrf52840_ota/tests/crc16_host.c \
	  bootloader/xiao_nrf52840_ota/tests/fake_io.c \
	  bootloader/xiao_nrf52840_ota/tests/test_boot_process.c \
	  -Wno-unused-function -Wno-sign-compare -Wno-shadow \
	  -Wno-unterminated-string-initialization \
	  -o "$(TMPDIR)/xiao-ota-host/test_boot_process"
	"$(TMPDIR)/xiao-ota-host/test_boot_process"

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
	$(VERIFY_OTA_BOOT_INFO) "$(XIAO_OTA_ARTIFACTS)/custom-noswd/$(XIAO_OTA_STEM)_noswd.hex"
	$(VERIFY_OTA_BOOT_INFO) "$(XIAO_OTA_ARTIFACTS)/custom-noswd/$(XIAO_OTA_STEM)_noswd_update.uf2"
	$(VERIFY_OTA_INSTALL_ARTIFACT) --artifact "$(XIAO_OTA_ARTIFACTS)/custom-noswd/$(XIAO_OTA_STEM)_noswd_update.uf2"
	@sha256sum "$(XIAO_OTA_ARTIFACTS)"/custom-noswd/*

## Install only the packaged no-SWD custom bootloader UF2 on the authorized XIAO.
## Put the board in XIAO-BOOT mode first; this target never selects a ttyACM path.
install-xiao-nrf52-target-ota-bootloader: package-xiao-ota-bootloader-noswd
	@if [ "$(XIAO_OTA_BOARD)" != xiao_nrf52840 ]; then \
	  echo "refusing non-XIAO bootloader profile on the authorized XIAO target" >&2; exit 1; \
	fi
	python3 bootloader/xiao_nrf52840_ota/tools/install_uf2.py \
	  --serial "$(XIAO_NRF52_TARGET_SERIAL)" \
	  --boot-port "$(XIAO_NRF52_BOOT_PORT)" \
	  --role-id "$(XIAO_OTA_ROLE_ID)" \
	  --artifact "$(XIAO_OTA_ARTIFACTS)/custom-noswd/$(XIAO_OTA_STEM)_noswd_update.uf2"

verify-xiao-ota-boot-info-artifacts: tmpdir
	$(VERIFY_OTA_BOOT_INFO) "$(XIAO_OTA_ARTIFACTS)/custom-noswd/$(XIAO_OTA_STEM)_noswd.hex"
	$(VERIFY_OTA_BOOT_INFO) "$(XIAO_OTA_ARTIFACTS)/custom-noswd/$(XIAO_OTA_STEM)_noswd_update.uf2"
	$(VERIFY_OTA_INSTALL_ARTIFACT) --artifact "$(XIAO_OTA_ARTIFACTS)/custom-noswd/$(XIAO_OTA_STEM)_noswd_update.uf2"

sign-xiao-ota-image: provision-xiao-ota-lab-key
	@test -n "$(XIAO_OTA_IMAGE)" && test -n "$(XIAO_OTA_ACTIVE_IMAGE)"
	python3 bootloader/xiao_nrf52840_ota/tools/sign_image.py \
	  --image "$(XIAO_OTA_IMAGE)" --active-image "$(XIAO_OTA_ACTIVE_IMAGE)" \
	  --private-key "$(XIAO_OTA_PRIVATE_KEY)" --counter "$(XIAO_OTA_COUNTER)" \
	  --command-version "$(XIAO_OTA_COMMAND_VERSION)" \
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
verify-ota-software: test build-ota-targets build-non-ota-targets
	@echo
	@echo "OTA software checks passed: native tests green, firmware targets link."
	@echo "NOT qualified here: on-device radio, flash, bootloader, anti-rollback, rollback."

clean-tmp:
	@echo "Refusing to delete shared TMPDIR: $(TMPDIR). Remove only explicitly owned scratch paths." >&2
	@exit 1
