PLATFORMIO ?= pio
PYTHON ?= python3
.DEFAULT_GOAL := build
TMPDIR := $(CURDIR)/.tmp
export TMPDIR
export TEMP = $(TMPDIR)
export TMP = $(TMPDIR)

# ENV selects an ordinary PlatformIO environment; OTA is never added implicitly.
ENV ?=
NATIVE_TEST_ENVS ?= native native_kiss_modem
OTA_TEST_FILTER ?= test_lora_ota_*
OTA_NRF52_TARGET_ENVS ?= Xiao_nrf52_companion_radio_ota_usb Xiao_nrf52_repeater_ota_usb SenseCap_Solar_companion_radio_ota_usb SenseCap_Solar_repeater_ota_usb
OTA_ESP32_TARGET_ENVS ?= Xiao_S3_WIO_companion_radio_ota_usb Xiao_S3_WIO_repeater_ota_usb
OTA_TARGET_ENVS ?= $(OTA_NRF52_TARGET_ENVS) $(OTA_ESP32_TARGET_ENVS)

OTA_DEPLOY_TRANSPORT ?= native
OTA_DEPLOY_CLIENT_PORT ?=
OTA_DEPLOY_CLIENT_DTR ?= 0
OTA_DEPLOY_INSTALL_TIMEOUT ?= 300
OTA_DEPLOY_ROUTED_RETRY ?= 0
OTA_UPLOAD_IMAGE ?=
OTA_UPLOAD_MANIFEST ?=
OTA_UPLOAD_BOARD ?=
OTA_UPLOAD_ROLE_ID ?=
OTA_UPLOAD_COUNTER ?=
OTA_UPLOAD_TARGET ?=
OTA_UPLOAD_MODE ?= directed
OTA_UPLOAD_CHANNEL ?= 255
OTA_UPLOAD_FREQ_KHZ ?= 0
OTA_UPLOAD_LEASE_MS ?= 60000
OTA_UPLOAD_DUTY_MILLI_PERCENT ?= 2000
OTA_UPLOAD_TIMEOUT ?= 14400
OTA_UPLOAD_REUPLOAD ?= 0
OTA_ARTIFACT_DIR ?=
OTA_STOCK_BINDING ?=
OTA_STOCK_SERIAL ?=
OTA_STOCK_SENDER_KEY ?=
OTA_STOCK_ARGS ?=
OTA_DEVICE_PORT ?= $(OTA_DEPLOY_CLIENT_PORT)
OTA_DEVICE_DTR ?= $(OTA_DEPLOY_CLIENT_DTR)
OTA_DEVICE_TIMEOUT ?= 5
XIAO_OTA_PAIR_BOARD ?=
XIAO_OTA_PAIR_ROLE_ID ?=
XIAO_OTA_PAIR_DIR ?= $(TMPDIR)/ota-boot-builds/$(XIAO_OTA_PAIR_BOARD)-role$(XIAO_OTA_PAIR_ROLE_ID)-pair
XIAO_OTA_PAIR_APP_PACKAGE ?=
XIAO_OTA_PAIR_PACKAGE_DIR ?= $(XIAO_OTA_PAIR_DIR)-packages
XIAO_OTA_PAIR_VERIFY_ONLY ?= 0
XIAO_OTA_VENDOR ?= $(TMPDIR)/Adafruit_nRF52_Bootloader_OTAFIX
XIAO_OTA_PRIVATE_KEY ?=
XIAO_OTA_IMAGE ?=
XIAO_OTA_ACTIVE_IMAGE ?=
XIAO_OTA_BOARD ?=
XIAO_OTA_COUNTER ?=
XIAO_OTA_ROLE_ID ?=
XIAO_OTA_TEST_BOARD_TARGET ?= XIAO_OTA_TARGET_XIAO_NRF52840
XIAO_OTA_TEST_ROLE_ID ?= $(if $(strip $(XIAO_OTA_ROLE_ID)),$(XIAO_OTA_ROLE_ID),0)
XIAO_OTA_UPSTREAM ?= $(XIAO_OTA_VENDOR)
OTA_NRF_REMOTE_BOOT_PROOF_PREFIX ?=

.PHONY: build upload clean tmpdir test test-ota test-ota-host test-ota-native test-ota-deploy test-ota-stock-companion build-ota-targets build-ota-nrf52-targets build-ota-esp32-targets ota-device-inspect ota-deploy ota-stock-companion build-xiao-ota-bootloader-pair test-xiao-ota-bootloader-pair package-xiao-ota-bootloader-pair verify-xiao-ota-bootloader-pair-packages sign-xiao-ota-image test-xiao-ota-bootloader-tools test-xiao-ota-bootloader test-xiao-ota-boot-process test-nrf-unadmitted-boot-process test-ota-rf-to-boot

build: tmpdir
	@test -n "$(strip $(ENV))" || { echo 'Select one firmware environment with ENV=... .' >&2; exit 1; }
	$(PLATFORMIO) run -e "$(ENV)"
upload: tmpdir
	@test -n "$(strip $(ENV))" || { echo 'Select one firmware environment with ENV=... .' >&2; exit 1; }
	$(PLATFORMIO) run -e "$(ENV)" -t upload
clean: tmpdir
	@test -n "$(strip $(ENV))" || { echo 'Select one firmware environment with ENV=... .' >&2; exit 1; }
	$(PLATFORMIO) run -e "$(ENV)" -t clean
tmpdir:
	@mkdir -p "$(TMPDIR)"
test: tmpdir test-ota-host
	$(PLATFORMIO) test $(foreach e,$(NATIVE_TEST_ENVS),-e $(e))
test-ota: test-ota-host test-ota-native test-xiao-ota-bootloader
test-ota-host: tmpdir
	$(PYTHON) -m unittest discover -s scripts/tests -p 'test_*.py'
test-ota-deploy: tmpdir
	$(PYTHON) -m unittest discover -s scripts/tests -p 'test_ota_deploy.py'
test-ota-stock-companion: tmpdir
	$(PYTHON) -m unittest discover -s scripts/tests -p 'test_ota_stock_companion.py'
test-ota-native: tmpdir
	$(PLATFORMIO) test -e native $(foreach filter,$(OTA_TEST_FILTER),-f '$(filter)')
ESP32_OTA_IMAGE_ARGS ?=
.PHONY: test-ota-esp32-image
test-ota-esp32-image: tmpdir
	$(PYTHON) test/test_lora_ota_esp32/esp32_image_pipeline.py $(ESP32_OTA_IMAGE_ARGS)
OTA_LAYERS := protocol runtime storage trust integration esp32
.PHONY: test-ota-boot
test-ota-boot: test-xiao-ota-bootloader
.PHONY: $(addprefix test-ota-,$(OTA_LAYERS))
$(addprefix test-ota-,$(OTA_LAYERS)): test-ota-%: tmpdir
	$(PLATFORMIO) test -e native -f 'test_lora_ota_$*'
build-ota-targets: tmpdir
	@set -e; for env in $(OTA_TARGET_ENVS); do $(PLATFORMIO) run -e "$$env"; done
build-ota-nrf52-targets:
	$(MAKE) --no-print-directory build-ota-targets OTA_TARGET_ENVS="$(OTA_NRF52_TARGET_ENVS)"
build-ota-esp32-targets:
	$(MAKE) --no-print-directory build-ota-targets OTA_TARGET_ENVS="$(OTA_ESP32_TARGET_ENVS)"

# Inspection never resets, configures, or infers OTA capability from USB IDs.
ota-device-inspect:
	$(PYTHON) scripts/ota_devices.py inspect --by-id "$(OTA_DEVICE_PORT)" --timeout "$(OTA_DEVICE_TIMEOUT)" $(if $(filter 1,$(OTA_DEVICE_DTR)),--dtr)
ota-stock-companion:
	$(PYTHON) scripts/ota_stock_companion.py $(OTA_STOCK_ARGS)

# One selected board/role/image/counter: stage -> READY -> signed COMMIT -> matching Installed.
ota-deploy: tmpdir
	@test -n "$(OTA_DEPLOY_CLIENT_PORT)" && test -n "$(OTA_UPLOAD_IMAGE)" && test -n "$(OTA_UPLOAD_TARGET)" && test -n "$(OTA_UPLOAD_BOARD)" && test -n "$(OTA_UPLOAD_ROLE_ID)" && test -n "$(OTA_UPLOAD_COUNTER)" || { echo 'Select explicit client port, image, target, board, role and counter.' >&2; exit 1; }
ifeq ($(OTA_DEPLOY_TRANSPORT),native)
	$(PYTHON) scripts/ota_uploader.py --client-port "$(OTA_DEPLOY_CLIENT_PORT)" $(if $(filter 1,$(OTA_DEPLOY_CLIENT_DTR)),--client-dtr) \
	  $(if $(strip $(OTA_ARTIFACT_DIR)),--artifact-dir "$(OTA_ARTIFACT_DIR)") --timeout "$(OTA_UPLOAD_TIMEOUT)" deploy \
	  --image "$(OTA_UPLOAD_IMAGE)" $(if $(strip $(OTA_UPLOAD_MANIFEST)),--manifest "$(OTA_UPLOAD_MANIFEST)") \
	  --board "$(OTA_UPLOAD_BOARD)" --role-id "$(OTA_UPLOAD_ROLE_ID)" --counter "$(OTA_UPLOAD_COUNTER)" --target "$(OTA_UPLOAD_TARGET)" \
	  --mode "$(OTA_UPLOAD_MODE)" --channel "$(OTA_UPLOAD_CHANNEL)" --frequency-khz "$(OTA_UPLOAD_FREQ_KHZ)" \
	  --lease-ms "$(if $(filter direct,$(OTA_UPLOAD_MODE)),$(OTA_UPLOAD_LEASE_MS),0)" --duty-milli-percent "$(OTA_UPLOAD_DUTY_MILLI_PERCENT)" \
	  --install-timeout "$(OTA_DEPLOY_INSTALL_TIMEOUT)" $(if $(filter 1,$(OTA_UPLOAD_REUPLOAD)),--reupload) $(if $(filter 1,$(OTA_DEPLOY_ROUTED_RETRY)),--routed-retry)
else ifeq ($(OTA_DEPLOY_TRANSPORT),stock)
	@test -n "$(OTA_ARTIFACT_DIR)" && test -n "$(OTA_STOCK_BINDING)" && test -n "$(OTA_STOCK_SERIAL)" && test -n "$(OTA_STOCK_SENDER_KEY)" && test "$(OTA_UPLOAD_MODE)" = direct || { echo 'Stock requires a new artifact directory, binding, serial, sender key and direct mode.' >&2; exit 1; }
	$(PYTHON) scripts/ota_stock_companion.py deploy --by-id "$(OTA_DEPLOY_CLIENT_PORT)" --serial "$(OTA_STOCK_SERIAL)" \
	  $(if $(filter 1,$(OTA_DEPLOY_CLIENT_DTR)),--client-dtr) \
	  --sender-key "$(OTA_STOCK_SENDER_KEY)" --binding "$(OTA_STOCK_BINDING)" --artifacts "$(OTA_ARTIFACT_DIR)" $(OTA_STOCK_ARGS) \
	  --image "$(OTA_UPLOAD_IMAGE)" $(if $(strip $(OTA_UPLOAD_MANIFEST)),--manifest "$(OTA_UPLOAD_MANIFEST)") \
	  --board "$(OTA_UPLOAD_BOARD)" --role-id "$(OTA_UPLOAD_ROLE_ID)" --counter "$(OTA_UPLOAD_COUNTER)" --target "$(OTA_UPLOAD_TARGET)" \
	  --frequency-khz "$(OTA_UPLOAD_FREQ_KHZ)" --lease-ms "$(OTA_UPLOAD_LEASE_MS)" --timeout "$(OTA_UPLOAD_TIMEOUT)" \
	  --normal-duty-percent "$$( $(PYTHON) -c 'print(float("$(OTA_UPLOAD_DUTY_MILLI_PERCENT)") / 1000)' )" \
	  --install-timeout "$(OTA_DEPLOY_INSTALL_TIMEOUT)" $(if $(filter 1,$(OTA_UPLOAD_REUPLOAD)),--reupload) $(if $(filter 1,$(OTA_DEPLOY_ROUTED_RETRY)),--routed-retry)
else
	@echo 'OTA_DEPLOY_TRANSPORT must be native or stock.' >&2; exit 1
endif

build-xiao-ota-bootloader-pair test-xiao-ota-bootloader-pair package-xiao-ota-bootloader-pair: tmpdir
	@test -n "$(XIAO_OTA_PAIR_BOARD)" && test -n "$(XIAO_OTA_PAIR_ROLE_ID)" || { echo 'Select XIAO_OTA_PAIR_BOARD and XIAO_OTA_PAIR_ROLE_ID.' >&2; exit 1; }
	$(MAKE) --no-print-directory -f bootloader/xiao_nrf52840_ota/Makefile $(if $(filter build-%,$@),pair,$(if $(filter test-%,$@),test,package-pair)) \
	  BOARD="$(XIAO_OTA_PAIR_BOARD)" ROLE="$(XIAO_OTA_PAIR_ROLE_ID)" OUTPUT="$(XIAO_OTA_PAIR_DIR)" VENDOR="$(XIAO_OTA_VENDOR)" \
	  APP_PACKAGE="$(XIAO_OTA_PAIR_APP_PACKAGE)" PACKAGE_OUTPUT="$(XIAO_OTA_PAIR_PACKAGE_DIR)" VERIFY_ONLY="$(XIAO_OTA_PAIR_VERIFY_ONLY)"
verify-xiao-ota-bootloader-pair-packages: XIAO_OTA_PAIR_VERIFY_ONLY = 1
verify-xiao-ota-bootloader-pair-packages: package-xiao-ota-bootloader-pair
sign-xiao-ota-image: tmpdir
	@test -n "$(XIAO_OTA_ACTIVE_IMAGE)" && test -n "$(OTA_ARTIFACT_DIR)" || { echo 'Select the exact active APP and an output directory.' >&2; exit 1; }
	$(PYTHON) bootloader/xiao_nrf52840_ota/tools/sign_image.py --private-key "$(XIAO_OTA_PRIVATE_KEY)" \
	  --image "$(XIAO_OTA_IMAGE)" --board "$(XIAO_OTA_BOARD)" --role-id "$(XIAO_OTA_ROLE_ID)" --counter "$(XIAO_OTA_COUNTER)" \
	  --active-image "$(XIAO_OTA_ACTIVE_IMAGE)" --output-dir "$(OTA_ARTIFACT_DIR)"
test-xiao-ota-bootloader-tools: tmpdir
	$(PYTHON) -m unittest discover -s bootloader/xiao_nrf52840_ota/tests -p 'test_*.py'

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
	-DXIAO_OTA_COMPILED_ROLE_ID="$(XIAO_OTA_TEST_ROLE_ID)" \
	-Wno-unused-function -Wno-sign-compare -Wno-shadow \
	-Wno-unterminated-string-initialization
OTA_RADIO_FAULT_GTEST ?= .pio/libdeps/native/googletest/googletest
.PHONY: test-ota-radio-fault-attribution
## Narrow source-only product gate; uses the existing native GTest dependency, never PlatformIO/SDKs.
test-ota-radio-fault-attribution: tmpdir
	@mkdir -p "$(TMPDIR)/ota-radio-fault-attribution"
	$(CXX) -std=c++17 -pthread -DMESHCORE_LORA_OTA=1 -I src -I test/mocks \
	  -I "$(OTA_RADIO_FAULT_GTEST)/include" -I "$(OTA_RADIO_FAULT_GTEST)" \
	  test/test_lora_ota_integration/test_radio_fault_attribution.cpp \
	  "$(OTA_RADIO_FAULT_GTEST)/src/gtest-all.cc" "$(OTA_RADIO_FAULT_GTEST)/src/gtest_main.cc" \
	  -o "$(TMPDIR)/ota-radio-fault-attribution/product-test"
	"$(TMPDIR)/ota-radio-fault-attribution/product-test"

.PHONY: test-ota-radio-tx-completion
## Native real Dispatcher/wrapper completion service plus unchanged strict fault gate.
test-ota-radio-tx-completion: tmpdir
	@mkdir -p "$(TMPDIR)/ota-radio-tx-completion"
	$(CXX) -std=c++17 -pthread -ffunction-sections -fdata-sections -Wl,--gc-sections \
	  -DMESHCORE_LORA_OTA=1 -DMESHCORE_RADIO_TX_COMPLETION_NATIVE=1 \
	  -DLORA_SF=7 -DLORA_FREQ=907.525 -DLORA_BW=250 -DLORA_CR=5 -DLORA_TX_POWER=2 \
	  -I test/test_lora_ota_integration/radio_tx_mocks -I src -I test/mocks \
	  -I "$(OTA_RADIO_FAULT_GTEST)/include" -I "$(OTA_RADIO_FAULT_GTEST)" \
	  src/Dispatcher.cpp src/Packet.cpp src/helpers/radiolib/RadioLibWrappers.cpp \
	  test/test_lora_ota_integration/test_radio_fault_attribution.cpp \
	  test/test_lora_ota_integration/test_radio_tx_completion.cpp \
	  "$(OTA_RADIO_FAULT_GTEST)/src/gtest-all.cc" "$(OTA_RADIO_FAULT_GTEST)/src/gtest_main.cc" \
	  -o "$(TMPDIR)/ota-radio-tx-completion/product-test"
	"$(TMPDIR)/ota-radio-tx-completion/product-test"

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
	  -DXIAO_OTA_COMPILED_ROLE_ID="$(XIAO_OTA_TEST_ROLE_ID)" \
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
	  -DXIAO_OTA_COMPILED_ROLE_ID="$(XIAO_OTA_TEST_ROLE_ID)" \
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
	  -DXIAO_OTA_COMPILED_ROLE_ID="$(XIAO_OTA_TEST_ROLE_ID)" \
	  bootloader/xiao_nrf52840_ota/src/xiao_ota_record.c \
	  bootloader/xiao_nrf52840_ota/src/xiao_ota_boot_info.c \
	  bootloader/xiao_nrf52840_ota/tests/test_boot_info.c \
	  -o "$(TMPDIR)/xiao-ota-host/test_boot_info"
	"$(TMPDIR)/xiao-ota-host/test_boot_info"
	python3 bootloader/xiao_nrf52840_ota/tests/test_source.py
